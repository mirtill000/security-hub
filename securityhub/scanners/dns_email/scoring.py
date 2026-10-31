"""MailGuard DNS analyzer mixin: Score (weighted controls with caps) and compliance profiles of a domain."""

from __future__ import annotations

from collections import Counter
from typing import Dict, List

from .constants import CHECKS, CHECK_ATTRS, COMPLIANCE_PROFILES, FINDINGS, SCORE_CAP_CODES
from .models import DomainResult


class Scoring:
    """Score (weighted controls with caps) and compliance profiles of a domain."""

    # ------------------------------------------------------------------
    # Score (0-100)
    #   SPF 25 | DKIM 25 | DMARC 35 | MTA-STS 7 | TLS-RPT 3 | DNSSEC 5
    #   Non-mail domains get DKIM / MTA-STS / TLS-RPT points by design.
    #   With --checks the score is normalized over the selected weights; if only
    #   unweighted checks run it is derived from the findings. Takeover / bogus
    #   DNSSEC / expired registration cap the score (SCORE_CAP_CODES).
    # ------------------------------------------------------------------

    @staticmethod
    def _component_points(r: DomainResult) -> Dict[str, float]:
        parked = r.profile == "non-mail"
        pts: Dict[str, float] = {}

        spf = r.spf
        pts["spf"] = 0.0
        if spf.status in ("valid", "warning") and not spf.permerror:
            pts["spf"] = {"-all": 25, "~all": 20}.get(spf.mechanism or "", 8) - (4 if spf.lookups >= 8 else 0)

        pts["dkim"] = 25 if parked else {"valid": 25, "partial": 15, "error": 5}.get(r.dkim.status, 0)

        d = r.dmarc
        pts["dmarc"] = 0.0
        if d.policy and d.status != "dns_error" and not any(i.code == "DMARC_MULTIPLE" for i in d.issues):
            base = {"none": 8, "quarantine": 25, "reject": 35}.get(d.policy, 0)
            if d.policy in ("quarantine", "reject"):
                if d.pct < 100:
                    base = 8 + (base - 8) * d.pct / 100
                if d.subdomain_policy == "none" or d.nonexistent_policy == "none":
                    base -= 5
            if not d.rua_destinations:
                base -= 3
            pts["dmarc"] = max(base, 0)

        pts["mta-sts"] = 7 if parked else {"valid": 7, "warning": 4, "partial": 4}.get(r.mta_sts.status, 0)
        pts["tls-rpt"] = 3 if parked or r.tls_rpt.status == "valid" else 0
        pts["dnssec"] = 5 if r.dnssec.status == "valid" else 0
        return pts

    def _calculate_score(self, r: DomainResult) -> int:
        weighted = [c for c in CHECKS if c in self.checks and CHECKS[c]]
        max_total = sum(CHECKS[c] for c in weighted)
        if not r.exists or r.profile == "unreachable":
            r.score_breakdown = {"components": {}, "max": max_total, "normalized": False, "cap": None,
                                 "note": "Domain does not exist" if not r.exists else "Name servers unreachable"}
            return 0
        if max_total == 0:
            sev = Counter(i.severity for i in r.issues)
            score = max(0, 100 - 40 * sev["critical"] - 15 * sev["warning"])
            r.score_breakdown = {"components": {}, "max": 0, "normalized": False, "cap": None,
                                 "note": "No weighted check selected: 100 - 40 per critical - 15 per warning finding"}
            return score
        pts = self._component_points(r)
        comps = {c: {"got": round(max(pts.get(c, 0), 0), 1), "max": CHECKS[c]} for c in weighted}
        score = int(round(min(max(100 * sum(v["got"] for v in comps.values()) / max_total, 0), 100)))
        cap = None
        for i in r.issues:
            limit = SCORE_CAP_CODES.get(i.code)
            if limit is not None and score > limit and (cap is None or limit < cap[0]):
                cap = (limit, FINDINGS[i.code][2])
        if cap:
            score = cap[0]
        r.score_breakdown = {"components": comps, "max": max_total, "normalized": max_total != 100,
                             "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}
        return score

    # ------------------------------------------------------------------
    # Compliance (what DNS can show)
    # ------------------------------------------------------------------

    def _evaluate_compliance(self, r: DomainResult) -> Dict[str, str]:
        on = self.checks
        if not r.exists:
            return {k: "n/a" for k in COMPLIANCE_PROFILES}

        def state(ok: bool, needed: List[str], applicable: bool = True) -> str:
            if not set(needed) <= on or not applicable:
                return "n/a"
            if r.profile == "unreachable" or any(
                    getattr(r, CHECK_ATTRS[c]).status == "dns_error" for c in needed):
                return "unknown"
            return "pass" if ok else "fail"

        sending = r.profile == "mail"
        spf_ok = r.spf.status in ("valid", "warning") and not r.spf.permerror and r.spf.mechanism != "+all"
        dkim_ok = any((s.status in ("valid", "weak") and (s.key_size or 0) >= 1000)
                      or (s.algorithm == "ed25519" and s.status == "valid") for s in r.dkim.selectors)
        dmarc_ok = bool(r.dmarc.policy) and not any(i.code == "DMARC_MULTIPLE" for i in r.dmarc.issues)
        d = r.dmarc
        return {
            "gmail_yahoo": state(spf_ok and dkim_ok and dmarc_ok, ["spf", "dkim", "dmarc"], sending),
            "microsoft": state(spf_ok and dkim_ok and dmarc_ok, ["spf", "dkim", "dmarc"], sending),
            "dmarc_enforcement": state(d.policy == "reject" and d.pct == 100 and d.subdomain_policy != "none"
                                       and bool(d.rua_destinations), ["dmarc"]),
            "transport": state(r.mta_sts.status == "valid" and r.tls_rpt.status == "valid",
                               ["mta-sts", "tls-rpt"], sending),
        }
