"""MailGuard DNS analyzer mixin: DNS hygiene - CAA (who may issue certificates) and zone transfer exposure."""

from __future__ import annotations

import re
from typing import List

from .domains import org_domain
from .models import AXFRResult, CAAResult, make_issue

CAA_TAGS = {"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}
CAA_RE = re.compile(r'^\s*(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?\s*$')
AXFR_MAX_SERVERS = 6


def _issuer(value: str) -> str:
    """Issuer domain of an issue/issuewild value ('letsencrypt.org; validationmethods=dns-01' -> 'letsencrypt.org')."""
    v = value.split(";", 1)[0].strip().lower()
    return v or ";"


class DNSHygieneChecks:
    """CAA (RFC 8659) and zone transfer (AXFR) exposure."""

    # ------------------------------------------------------------------
    # CAA: the relevant record set is the first one found climbing from the name to its parents
    # ------------------------------------------------------------------

    def _analyze_caa(self, domain: str) -> CAAResult:
        res = CAAResult()
        names: List[str] = []
        name, stop = domain, org_domain(domain)
        while True:
            names.append(name)
            if name == stop or "." not in name:
                break
            name = name.split(".", 1)[1]
        ans = None
        for n in names:
            ans = self.dns.query(n, "CAA")
            if ans.status == "error":
                res.status = "dns_error"
                res.issues.append(make_issue("CAA_DNS_ERROR", f"{n}: {ans.error or 'error'}"))
                return res
            if ans.status == "ok" and ans.records:
                if n != domain:
                    res.inherited_from = n
                break
        if not ans or ans.status != "ok" or not ans.records:
            res.status = "missing"
            res.issues.append(make_issue("CAA_MISSING"))
            return res
        problems, wild = [], None
        for raw in ans.records:
            m = CAA_RE.match(str(raw))
            if not m:
                problems.append(str(raw))
                continue
            flags, tag, value = int(m.group(1)), m.group(2).lower(), m.group(3)
            res.records.append({"flags": flags, "tag": tag, "value": value})
            if tag not in CAA_TAGS:
                if flags & 128:
                    problems.append(f"unknown critical tag '{tag}'")
                continue
            if tag == "issue":
                res.issuers.append(_issuer(value))
            elif tag == "issuewild":
                wild = (wild or []) + [_issuer(value)]
            elif tag == "iodef":
                res.iodef.append(value)
        res.wildcard_issuers = wild
        res.issuers = sorted(set(res.issuers))
        res.status = "valid"
        if problems:
            res.status = "warning"
            res.issues.append(make_issue("CAA_INVALID", "; ".join(problems[:3])))
        if not res.iodef and res.issuers != [";"]:
            res.issues.append(make_issue("CAA_NO_IODEF"))
        return res

    # ------------------------------------------------------------------
    # Zone transfer: every authoritative server must refuse AXFR from the Internet
    # ------------------------------------------------------------------

    def _analyze_axfr(self, domain: str) -> AXFRResult:
        return self._cached("axfr", domain, AXFRResult, lambda: self._axfr_now(domain))

    def _axfr_now(self, domain: str) -> AXFRResult:
        res = AXFRResult()
        ns = self.dns.query(domain, "NS")
        hosts = sorted(set(ns.records))[:AXFR_MAX_SERVERS] if ns.status == "ok" else []
        if not hosts:
            res.status = "unknown"
            return res
        open_ns = []
        for host in hosts:
            ips = self.dns.addresses(host)
            if not ips:
                res.servers.append({"ns": host, "ip": None, "result": "unreachable", "records": 0})
                continue
            ip = next((a for a in ips if ":" not in a), ips[0])
            result, n = self.dns.axfr(ip, domain)
            res.servers.append({"ns": host, "ip": ip, "result": result, "records": n})
            if result == "open":
                open_ns.append(host)
        if open_ns:
            res.status = "error"
            res.issues.append(make_issue("AXFR_OPEN", ", ".join(open_ns)))
        elif any(s["result"] == "refused" for s in res.servers):
            res.status = "valid"
        else:
            res.status = "unknown"
        return res
