"""Copy-ready remediation records (SPF, DMARC, MTA-STS, TLS-RPT...)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Set

from .domains import org_domain
from .models import DomainResult
from .util import parse_tags

SPF_PROVIDER_INCLUDES = {
    "Microsoft 365 / EOP": "include:spf.protection.outlook.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "Google Workspace": "include:_spf.google.com",
}


def _dmarc_record(tags: Dict[str, str]) -> str:
    order = ["v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf", "fo", "ri"]
    keys = [k for k in order if k in tags] + [k for k in tags if k not in order]
    return "; ".join(f"{k}={tags[k]}" for k in keys)


def suggest_remediation(r: DomainResult, checks: Set[str]) -> List[dict]:
    """Copy-ready DNS records for the most impactful fixes (to be reviewed before publishing)."""
    out: List[dict] = []
    domain = r.domain
    if not r.exists or r.profile == "unreachable":
        return out

    def rec(title, name, rtype, value, note=""):
        out.append({"title": title, "name": name, "type": rtype, "value": value, "note": note})

    codes = {i.code for i in r.issues}
    report_addr = f"mailto:dmarc-reports@{org_domain(domain)}"
    existing = parse_tags(r.dmarc.record) if r.dmarc.record and not r.dmarc.inherited_from else {}

    if r.profile == "non-mail":
        if "mx" in checks and not r.mx.null_mx:
            rec("Declare that the domain receives no mail (Null MX)", domain, "MX", "0 .")
        if "spf" in checks and "SPF_PARKED_NOT_STRICT" in codes:
            rec("Authorize no sender", domain, "TXT", "v=spf1 -all")
        if "dmarc" in checks and "DMARC_PARKED_NOT_REJECT" in codes:
            tags = {"v": "DMARC1", "p": "reject", "sp": "reject", "adkim": "s", "aspf": "s"}
            if existing.get("rua"):
                tags["rua"] = existing["rua"]
            rec("Reject every message claiming to come from this domain", f"_dmarc.{domain}", "TXT", _dmarc_record(tags))
        if "dkim" in checks:
            rec("Optional: revoke any DKIM key under this domain", f"*._domainkey.{domain}", "TXT", "v=DKIM1; p=",
                "Recommended by M3AAWG for parked domains")
        return out

    if "spf" in checks:
        s = r.spf
        if s.status == "missing":
            mechs = list(dict.fromkeys(SPF_PROVIDER_INCLUDES[p] for p in r.mx.providers if p in SPF_PROVIDER_INCLUDES))
            rec("Publish an SPF record", domain, "TXT", f"v=spf1 {' '.join(mechs or ['mx'])} ~all",
                "Add every other service that sends as this domain, then move to -all")
        elif "SPF_MULTIPLE" in codes and s.records:
            terms = []
            for record in s.records:
                for t in record.split()[1:]:
                    if not re.fullmatch(r"[+\-~?]?all", t, re.I) and t not in terms:
                        terms.append(t)
            rec("Merge the SPF records into one", domain, "TXT", f"v=spf1 {' '.join(terms)} ~all",
                "Delete the other v=spf1 records")
        elif s.record and s.mechanism in ("+all", "?all", None) and not s.permerror:
            base = re.sub(r"\s+[+\-~?]?all\b", "", s.record, flags=re.I).strip()
            rec("Terminate SPF with a fail mechanism", domain, "TXT", f"{base} ~all",
                "Use -all once DMARC reports confirm every sender is listed")
        if "SPF_LOOKUP_LIMIT" in codes:
            rec("Reduce SPF DNS lookups", "", "", "",
                "Remove unused includes, replace a/mx with ip4/ip6 or move bulk senders to a subdomain")

    if "dmarc" in checks and r.dmarc.status != "dns_error":
        d = r.dmarc
        if d.status == "missing":
            rec("Start DMARC in monitoring mode", f"_dmarc.{domain}", "TXT",
                _dmarc_record({"v": "DMARC1", "p": "none", "rua": report_addr, "fo": "1"}),
                "Collect reports for 2-4 weeks, then move to quarantine and reject")
        elif "DMARC_MULTIPLE" in codes:
            rec("Keep a single DMARC record", f"_dmarc.{domain}", "TXT", d.record or "", "Delete the other records")
        elif not d.inherited_from and existing:
            tags = dict(existing)
            nxt = {"none": "quarantine", "quarantine": "reject"}.get((tags.get("p") or "").lower())
            blockers = codes & {"X_ENFORCED_NO_AUTH", "X_DMARC_SPF_BROKEN", "X_DMARC_NO_DKIM", "REPORT_UNALIGNED_SOURCES"}
            changed = False
            if nxt and not blockers:
                tags["p"] = nxt
                changed = True
            elif nxt:
                rec("Fix SPF/DKIM before tightening DMARC", "", "", "",
                    "Moving to a stricter policy now would block legitimate mail: resolve the SPF/DKIM findings first")
                nxt = None
            if "pct" in tags and tags["pct"] != "100":
                tags.pop("pct")
                changed = True
            for key in ("aspf", "adkim"):
                if key in tags and tags[key].strip().lower() not in ("r", "s"):
                    tags.pop(key)
                    changed = True
            if (tags.get("sp") or "").lower() == "none" and tags.get("p") in ("quarantine", "reject"):
                tags["sp"] = tags["p"]
                changed = True
            if not tags.get("rua"):
                tags["rua"] = report_addr
                changed = True
            if changed:
                step = f"Move DMARC to p={tags['p']}" if nxt else "Correct the DMARC record"
                rec(step, f"_dmarc.{domain}", "TXT", _dmarc_record(tags),
                    "Check DMARC reports first: senders that are not aligned will be blocked" if nxt
                    else "Fixes invalid or weakening tags without changing the policy")

    if "dkim" in checks and r.dkim.status == "missing":
        if any("Microsoft" in p for p in r.mx.providers):
            label = domain.replace(".", "-")
            for sel in ("selector1", "selector2"):
                rec(f"Enable DKIM in Microsoft 365 ({sel})", f"{sel}._domainkey.{domain}", "CNAME",
                    f"{sel}-{label}._domainkey.<tenant>.onmicrosoft.com",
                    "Replace <tenant>; copy the exact value from the Defender portal")
        elif "Google Workspace" in r.mx.providers:
            rec("Enable DKIM in Google Workspace", f"google._domainkey.{domain}", "TXT", "v=DKIM1; k=rsa; p=<key>",
                "Generate a 2048-bit key in Admin console > Apps > Gmail > Authenticate email")
        else:
            rec("Enable DKIM signing", "", "", "", "Generate a 2048-bit key with every platform that sends as this domain")
    if "dkim" in checks and r.dkim.weak_keys:
        rec("Rotate weak DKIM keys", "", "", "", "Publish a new 2048-bit selector, switch signing, then revoke the old key (p=)")

    mx_hosts = [m.host for m in r.mx.records if m.host]
    if "mta-sts" in checks and mx_hosts and (r.mta_sts.status in ("missing", "error") or "MTASTS_MX_MISMATCH" in codes):
        patterns = []
        for h in mx_hosts:
            pat = "*.mail.protection.outlook.com" if h.endswith(".mail.protection.outlook.com") else h
            if pat not in patterns:
                patterns.append(pat)
        policy = "version: STSv1\nmode: testing\n" + "".join(f"mx: {p}\n" for p in patterns) + "max_age: 604800"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        rec("Publish the MTA-STS policy record", f"_mta-sts.{domain}", "TXT", f"v=STSv1; id={stamp}",
            "Change the id every time the policy file changes")
        rec("Serve the MTA-STS policy file", f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "FILE", policy,
            "HTTPS with a valid certificate, text/plain, no redirects; switch to mode: enforce after clean TLS reports")
    if "tls-rpt" in checks and r.tls_rpt.status == "missing" and r.profile == "mail":
        rec("Receive TLS failure reports", f"_smtp._tls.{domain}", "TXT",
            f"v=TLSRPTv1; rua=mailto:tls-reports@{org_domain(domain)}")
    if "dnssec" in checks and r.dnssec.status == "missing":
        rec("Enable DNSSEC", "", "", "", "Sign the zone at your DNS provider and publish the DS record at the registrar")
    if "caa" in checks and r.caa.status == "missing":
        iodef = f'0 iodef "mailto:security@{org_domain(domain)}"'
        if r.profile == "non-mail" and not r.mx.records:
            rec("Forbid certificate issuance", domain, "CAA", f'0 issue ";"\n{iodef}',
                "For domains that serve no website or mail: no CA may issue certificates")
        else:
            rec("Restrict certificate issuance to your CAs", domain, "CAA",
                f'0 issue "<your-ca.example>"\n0 issuewild ";"\n{iodef}',
                "Replace <your-ca.example> with each CA you use (e.g. digicert.com, letsencrypt.org, pki.goog); "
                "add an issuewild line only if you use wildcard certificates")
    elif "caa" in checks and r.caa.status == "valid" and not r.caa.iodef and r.caa.issuers != [";"]:
        rec("Get notified of refused certificate requests", r.caa.inherited_from or domain, "CAA",
            f'0 iodef "mailto:security@{org_domain(domain)}"')
    if "axfr" in checks and r.axfr.status == "error":
        servers = ", ".join(s["ns"] for s in r.axfr.servers if s["result"] == "open")
        rec("Refuse zone transfers from the Internet", "", "", "",
            f"On {servers}: allow AXFR/IXFR only to your secondary servers (allow-transfer ACL or TSIG keys)")
    if "takeover" in checks:
        for e in r.takeover.dependencies:
            if e["state"] in ("unregistered", "expired"):
                rec(f"Remove the reference to {e['domain']}", "", "", "",
                    f"Used by: {', '.join(e['used_by'])}. Remove it from DNS or make sure the domain is registered")
        for dgl in r.takeover.dangling:
            rec(f"Remove dangling CNAME {dgl['name']}", dgl["name"], "CNAME", "(delete)",
                f"Points to {dgl['target']}, which does not exist")
    return out
