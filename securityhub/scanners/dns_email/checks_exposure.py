"""MailGuard DNS analyzer mixin: Takeover risk, resolver consistency, lookalike domains and DMARC report evidence."""

from __future__ import annotations

import random
import re
import string
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from .constants import DOMAIN_RE
from .domains import org_domain
from .lookalikes import generate_lookalikes
from .models import (ConsistencyResult, DMARCReportResult, DomainResult, Issue, LookalikeResult, TakeoverResult,
                     make_issue)
from .util import issues_from_problems

# Registrable domains of large providers: never expire in practice, skip RDAP for them.
WELL_KNOWN_PROVIDERS = {
    "outlook.com", "microsoft.com", "office365.com", "onmicrosoft.com", "google.com", "googlemail.com",
    "gmail.com", "amazonses.com", "amazonaws.com", "sendgrid.net", "mcsv.net", "mailchimp.com",
    "mandrillapp.com", "salesforce.com", "exacttarget.com", "zendesk.com", "hubspot.com",
    "hubspotemail.net", "mailgun.org", "sparkpostmail.com", "pphosted.com", "ppe-hosted.com",
    "mimecast.com", "messagelabs.com", "iphmx.com", "zoho.com", "zoho.eu", "protonmail.ch",
    "messagingengine.com", "cloudflare.com", "cloudflare.net", "awsdns-00.com", "azure-dns.com",
    "azure-dns.net", "azure-dns.org", "azure-dns.info", "googledomains.com", "domaincontrol.com",
    "aruba.it", "register.it", "akam.net", "ultradns.com", "ultradns.net", "nsone.net", "dnsmadeeasy.com",
}


class ExposureChecks:
    """Takeover risk, resolver consistency, lookalike domains and DMARC report evidence."""

    # ------------------------------------------------------------------
    # Takeover risk of external dependencies
    # ------------------------------------------------------------------

    def _analyze_takeover(self, r: DomainResult) -> TakeoverResult:
        res = TakeoverResult(rdap=bool(self.rdap and self.rdap.enabled))
        domain = r.domain
        own = org_domain(domain)
        deps: Dict[str, Set[str]] = defaultdict(set)

        def add(host: str, usage: str) -> None:
            host = (host or "").lower().rstrip(".")
            if not host or "%" in host or not DOMAIN_RE.fullmatch(host):
                return
            reg = org_domain(host)
            if reg and reg != own and reg not in self.known_orgs:
                deps[reg].add(usage)

        for node in r.spf.include_tree:
            add(node["domain"], "SPF include")
        for rec in r.spf.records:
            for m in re.finditer(r"(?:^|\s)[+\-~?]?(?:a|mx|exists|ptr):([^\s/]+)", rec, re.I):
                add(m.group(1), "SPF mechanism")
        for mx in r.mx.records:
            if mx.host:
                add(mx.host, "MX")
                if mx.resolves is False:
                    a = self.dns.query(mx.host, "A")
                    if a.canonical:
                        res.dangling.append({"name": mx.host, "target": a.canonical, "used_by": "MX"})
                        add(a.canonical, "MX CNAME")

        ns = self.dns.query(domain, "NS")
        if ns.status != "ok" and own != domain:
            ns = self.dns.query(own, "NS")
        if ns.status == "ok":
            res.ns_hosts = sorted(ns.records)
            lame = []
            for host in res.ns_hosts:
                add(host, "NS")
                if self.dns.has_address(host) is False:
                    lame.append(host)
            if lame:
                res.issues.append(make_issue("TAKEOVER_LAME_NS", ", ".join(lame)))

        for s in r.dkim.selectors:
            if s.cname:
                add(s.cname, f"DKIM {s.name}")
        for d in r.dkim.dangling:
            res.dangling.append({**d, "used_by": "DKIM"})
            add(d["target"], "DKIM CNAME")
        if r.mta_sts.txt_record:
            a = self.dns.query(f"mta-sts.{domain}", "A")
            if a.canonical:
                add(a.canonical, "MTA-STS host")
                if a.status == "nxdomain":
                    res.dangling.append({"name": f"mta-sts.{domain}", "target": a.canonical, "used_by": "MTA-STS"})
        for addr in r.dmarc.rua_destinations:
            add(addr.rsplit("@", 1)[-1], "DMARC rua")
        for uri in (r.tls_rpt.rua or "").split(","):
            uri = uri.strip()
            host = uri[7:].rsplit("@", 1)[-1] if uri.lower().startswith("mailto:") else (urlparse(uri).hostname or "")
            add(host, "TLS-RPT rua")

        rdap_on = bool(self.rdap and self.rdap.enabled)

        def check(reg: str) -> dict:
            entry = {"domain": reg, "used_by": sorted(deps[reg]), "state": "ok", "expires": None}
            soa = self.dns.query(reg, "SOA")
            if soa.status == "nxdomain":
                entry["state"] = "unregistered"
                if rdap_on:
                    info = self.rdap.lookup(reg)
                    if info["state"] in ("registered", "expiring"):
                        entry["state"] = "no-dns"  # registered but not resolving (e.g. on hold)
                    elif info["state"] == "expired":
                        entry["state"] = "expired"
            elif soa.status == "error":
                entry["state"] = "unknown"
            elif rdap_on and reg not in WELL_KNOWN_PROVIDERS:
                info = self.rdap.lookup(reg)
                entry["expires"] = info.get("expires")
                if info["state"] in ("expired", "expiring"):
                    entry["state"] = info["state"]
            return entry

        res.dependencies = list(self._pool.map(check, sorted(deps)))
        problems: List[Tuple[str, str]] = []
        unregistered = set()
        for e in res.dependencies:
            label = f"{e['domain']} ({', '.join(e['used_by'])})"
            if e["state"] == "unregistered":
                unregistered.add(e["domain"])
                problems.append(("TAKEOVER_UNREGISTERED", label))
            elif e["state"] == "expired":
                problems.append(("TAKEOVER_EXPIRED", label))
            elif e["state"] == "no-dns":
                problems.append(("TAKEOVER_UNRESOLVABLE", label))
            elif e["state"] == "expiring":
                problems.append(("TAKEOVER_EXPIRING", f"{label}, expires {(e['expires'] or '')[:10]}"))
        for d in res.dangling:
            if org_domain(d["target"]) not in unregistered:
                problems.append(("TAKEOVER_DANGLING_CNAME", f"{d['name']} -> {d['target']}"))
        res.issues += issues_from_problems(problems, max_details=4)

        if rdap_on:
            info = self.rdap.lookup(own)
            res.domain_expires = info.get("expires")
            if info["state"] == "expired":
                res.issues.append(make_issue("DOMAIN_EXPIRED", own))
            elif info["state"] == "expiring":
                res.issues.append(make_issue("DOMAIN_EXPIRING", f"{own} expires {(info.get('expires') or '')[:10]}"))

        sev = {i.severity for i in res.issues}
        res.status = "error" if "critical" in sev else "warning" if "warning" in sev else "valid"
        return res

    # ------------------------------------------------------------------
    # Resolver vs authoritative consistency
    # ------------------------------------------------------------------

    CONSISTENCY_RECORDS = (("", "MX"), ("", "TXT"), ("_dmarc.", "TXT"), ("", "NS"))

    def _analyze_consistency(self, domain: str) -> ConsistencyResult:
        return self._cached("consistency", domain, ConsistencyResult, lambda: self._consistency_now(domain),
                            ",".join(self.dns.nameservers))

    def _consistency_now(self, domain: str) -> ConsistencyResult:
        res = ConsistencyResult()
        own = org_domain(domain)
        ns = self.dns.query(domain, "NS")
        if ns.status != "ok" and own != domain:
            ns = self.dns.query(own, "NS")
        auth: List[Tuple[str, str]] = []
        for host in (sorted(ns.records)[:4] if ns.status == "ok" else []):
            ips = self.dns.addresses(host)
            ip = next((i for i in ips if ":" not in i), ips[0] if ips else None)
            if ip:
                auth.append((host, ip))
        resolvers = [(f"resolver {ip}", ip) for ip in self.dns.nameservers]
        res.sources = [n for n, _ in resolvers] + [f"auth {h}" for h, _ in auth]
        if not auth:
            res.status = "unknown"
            return res

        def norm(answer):
            st, vals = answer
            if st == "error":
                return None
            return tuple(vals) if st == "ok" else ()

        problems: List[Tuple[str, str]] = []
        for prefix, rdtype in self.CONSISTENCY_RECORDS:
            name = prefix + domain
            auth_vals = {f"auth {h}": norm(self.dns.query_server(name, rdtype, ip, recursion=False)) for h, ip in auth}
            res_vals = {src: norm(self.dns.query_server(name, rdtype, ip)) for src, ip in resolvers}
            auth_vals = {k: v for k, v in auth_vals.items() if v is not None}
            res_vals = {k: v for k, v in res_vals.items() if v is not None}
            answers = {k: list(v) for k, v in {**auth_vals, **res_vals}.items()}
            distinct = set(auth_vals.values())
            if len(distinct) > 1:
                res.differences.append({"name": name, "type": rdtype, "kind": "authoritative", "answers": answers})
                problems.append(("DNS_AUTH_INCONSISTENT", f"{rdtype} {name}"))
            elif distinct:
                truth = next(iter(distinct))
                bad = [k for k, v in res_vals.items() if v != truth]
                if bad:
                    res.differences.append({"name": name, "type": rdtype, "kind": "resolver", "answers": answers})
                    problems.append(("DNS_INCONSISTENT", f"{rdtype} {name} ({', '.join(bad)})"))
        res.issues = issues_from_problems(problems)
        res.status = "warning" if problems else "valid"
        return res

    # ------------------------------------------------------------------
    # Lookalike domains
    # ------------------------------------------------------------------

    def _tld_has_wildcard(self, tld: str) -> bool:
        if tld not in self._wildcard_tlds:
            label = "mg-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            self._wildcard_tlds[tld] = self.dns.query(f"{label}.{tld}", "NS").status in ("ok", "nodata")
        return self._wildcard_tlds[tld]

    def _analyze_lookalikes(self, r: DomainResult) -> LookalikeResult:
        res = LookalikeResult()
        if self.lookalike_tiers and r.tier not in self.lookalike_tiers:
            res.status = "na"
            return res
        org = org_domain(r.domain)
        res.base = org

        def compute():
            if self.cache is not None:  # registered lookalikes change slowly: searched at most once per period
                stored = self.cache.get("lookalikes", org, self.discovery_max_age, str(self.lookalike_limit))
                if isinstance(stored, list) and len(stored) == 2:
                    return stored[0], [e for e in stored[1] if e.get("domain") not in self.known_domains
                                       and org_domain(e.get("domain", "")) not in self.known_orgs]
            n, found = compute_now()
            if self.cache is not None and not any(e.get("dns") == "error" for e in found):
                self.cache.put("lookalikes", org, [n, found], str(self.lookalike_limit))
            return n, found

        def compute_now():
            candidates = generate_lookalikes(org, self.lookalike_limit)

            def check(item):
                cand, kind = item
                if cand in self.known_domains or org_domain(cand) in self.known_orgs:
                    return None
                if self._tld_has_wildcard(cand.split(".", 1)[1]):
                    return None
                ns = self.dns.query(cand, "NS")
                if ns.status == "nxdomain":
                    return None
                mx = self.dns.query(cand, "MX")
                has_mx = mx.status == "ok" and any(h not in ("", ".") for _, h in mx.records)
                entry = {"domain": cand, "kind": kind, "mx": has_mx,
                         "a": bool(self.dns.has_address(cand)), "created": None,
                         "dns": "error" if ns.status == "error" else "ok"}
                if has_mx and self.rdap and self.rdap.enabled:
                    entry["created"] = self.rdap.lookup(cand).get("created")
                return entry

            found = [e for e in self._pool.map(check, candidates.items()) if e]
            return len(candidates), found

        generated, registered = self._once_per_org("lookalikes:" + org, compute)
        res.generated = generated
        res.registered = sorted(registered, key=lambda e: (not e["mx"], e["domain"]))
        now = datetime.now(timezone.utc)
        fresh, with_mx, plain = [], [], []
        for e in res.registered:
            created = None
            if e.get("created"):
                try:
                    created = datetime.fromisoformat(e["created"].replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                except ValueError:
                    created = None
            if e["mx"] and created and (now - created).days <= self.LOOKALIKE_FRESH_DAYS:
                fresh.append(f"{e['domain']} (registered {e['created'][:10]})")
            elif e["mx"]:
                with_mx.append(e["domain"])
            else:
                plain.append(e["domain"])
        problems = [("LOOKALIKE_FRESH", d) for d in fresh] + [("LOOKALIKE_MX", d) for d in with_mx]
        res.issues = issues_from_problems(problems, max_details=5)
        if plain:
            res.issues.append(make_issue("LOOKALIKE_REGISTERED", f"{len(plain)}: " + ", ".join(plain[:5])
                                         + (" ..." if len(plain) > 5 else "")))
        res.status = "error" if fresh else "warning" if with_mx else "partial" if plain else "valid"
        return res

    # ------------------------------------------------------------------
    # DMARC aggregate reports
    # ------------------------------------------------------------------

    def _attach_reports(self, r: DomainResult) -> DMARCReportResult:
        res = DMARCReportResult()
        info = self.report_data.get(r.domain)
        if not info:
            return res
        res.reports, res.messages, res.passed = info["reports"], info["messages"], info["passed"]
        res.pass_rate = round(100.0 * res.passed / res.messages, 1) if res.messages else 0.0
        res.period = [info.get("begin", ""), info.get("end", "")]
        res.reporters = [org for org, _ in info["reporters"].most_common(8)]
        own = org_domain(r.domain)
        res.selectors = sorted({sel for d, sel in info["selector_pairs"] if org_domain(d) == own})
        sources = []
        for ip, s in info["sources"].items():
            cat = max(("aligned", s["passed"]), ("unaligned", s["unaligned"]), ("spoof", s["spoofed"]),
                      key=lambda kv: kv[1])[0]
            sources.append({"ip": ip, "count": s["count"], "passed": s["passed"], "category": cat,
                            "envelope_from": sorted(s["envelope_from"])[:5],
                            "dkim_domains": sorted(s["dkim_domains"])[:5],
                            "dispositions": dict(s["disposition"]), "ptr": None})
        sources.sort(key=lambda x: -x["count"])
        lookup = [s for s in sources if s["category"] != "aligned"][:10] + \
                 [s for s in sources if s["category"] == "aligned"][:5]
        for s in lookup:
            s["ptr"] = self.dns.ptr(s["ip"])
        res.sources = sources[:50]
        res.unaligned = sum(s["count"] for s in sources if s["category"] == "unaligned")
        res.spoofed = sum(s["count"] for s in sources if s["category"] == "spoof")

        if res.messages < 100:
            res.status = "unknown"
            res.verdict = "Not enough data yet (fewer than 100 messages reported)"
            return res
        legit = res.passed + res.unaligned
        unaligned_srcs = [s for s in sources if s["category"] == "unaligned"]
        if legit and res.unaligned / legit > 0.02:
            names = [s["ptr"] or s["ip"] for s in unaligned_srcs[:4]]
            res.issues.append(make_issue("REPORT_UNALIGNED_SOURCES",
                                         f"{res.unaligned} messages from {len(unaligned_srcs)} sources ({', '.join(names)})"))
            res.verdict = "Not ready for p=reject: align the senders listed below first"
        else:
            res.verdict = "Ready for p=reject: legitimate senders pass DMARC"
            if r.dmarc.policy != "reject":
                res.issues.append(make_issue("REPORT_READY_FOR_REJECT", f"{res.pass_rate}% of {res.messages} messages pass"))
        if res.spoofed and (r.dmarc.policy in (None, "none") or r.dmarc.pct < 100):
            res.issues.append(make_issue("REPORT_SPOOFING", f"{res.spoofed} messages"))
        res.status = "warning" if any(i.severity != "info" for i in res.issues) else "valid"
        return res

    # ------------------------------------------------------------------
    # Cross-checks
    # ------------------------------------------------------------------

    def _cross_check(self, r: DomainResult) -> List[Issue]:
        issues: List[Issue] = []
        on = self.checks
        dmarc_present = r.dmarc.status not in ("missing", "dns_error", "skipped")
        enforcing = r.dmarc.policy in ("quarantine", "reject")
        spf_broken = r.spf.status in ("missing", "error")
        no_dkim = r.dkim.status in ("missing", "error")

        if r.profile == "non-mail":
            # a record that is present but not strict is still flagged; no record at all is not
            if "spf" in on and r.spf.status != "dns_error" and r.spf.record is not None and \
                    not re.fullmatch(r"v=spf1\s+-all", r.spf.record.strip(), re.I):
                issues.append(make_issue("SPF_PARKED_NOT_STRICT"))
            if "dmarc" in on and r.dmarc.status != "dns_error" and r.dmarc.policy != "reject":
                issues.append(make_issue("DMARC_PARKED_NOT_REJECT"))
            return issues

        if {"dmarc", "spf", "dkim"} <= on and dmarc_present and enforcing and spf_broken and no_dkim:
            issues.append(make_issue("X_ENFORCED_NO_AUTH"))
        else:
            if {"dmarc", "spf"} <= on and dmarc_present and spf_broken:
                issues.append(make_issue("X_DMARC_SPF_BROKEN"))
            if {"dmarc", "dkim"} <= on and dmarc_present and r.dkim.status == "missing":
                issues.append(make_issue("X_DMARC_NO_DKIM"))

        # ~all is acceptable when DMARC fully enforces: downgrade to info
        if enforcing and r.dmarc.pct == 100:
            for i in r.spf.issues:
                if i.code == "SPF_SOFTFAIL":
                    i.severity = "info"
        return issues
