"""Two reports from one scan: e-mail security and DNS security.

The scan runs once (the takeover check needs SPF, DKIM and DMARC data, and scanning twice would double the
DNS traffic). Each view keeps only its controls and findings and gets its own score, compliance, fixes and
priority, so the two reports read - and trend - independently.
"""

from __future__ import annotations

import copy
import os
from typing import Dict, Iterable, List, Optional, Sequence

from .constants import CHECK_ATTRS, CHECKS, FINDINGS, SCORE_CAP_CODES
from .domains import tier_weight
from .models import DMARCReportResult, DomainResult
from .remediation import suggest_remediation
from .scoring import Scoring

VIEWS: Dict[str, dict] = {
    "email": {
        "title": "Email security posture",
        "checks": ["mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt", "bimi"],
        "protocols": {"MX", "SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "BIMI", "Cross-Check", "Reports"},
    },
    "dns": {
        "title": "DNS security posture",
        "checks": ["dkim", "dnssec", "caa", "takeover", "axfr", "consistency", "lookalikes"],
        "protocols": {"DKIM", "DNSSEC", "CAA", "Takeover", "Registration", "Zone transfer", "Consistency", "Lookalike"},
    },
}
SHARED_PROTOCOLS = {"DNS"}  # domain does not exist / name servers unreachable: true for both reports
COMBINED_TITLE = "Email and DNS security posture"

# DNS score: weights of the DNS view (the e-mail view keeps the historical weights of CHECKS).
# A control that could not be measured is left out of the maximum instead of counting as failed.
# DKIM: the records of dkim.csv verified in DNS (a missing, mismatched or weak record lowers the DNS score);
# 'unknown' (domain not listed) and 'na' (no mail) are not counted.
DNS_WEIGHTS = {"dkim": 25, "dnssec": 30, "caa": 25, "takeover": 30, "axfr": 15}
DNS_POINTS = {
    "dkim": {"valid": 1.0, "partial": 0.5, "error": 0.0, "missing": 0.0},
    "dnssec": {"valid": 1.0, "missing": 0.0, "bogus": 0.0},
    "caa": {"valid": 1.0, "warning": 0.5, "missing": 0.0},
    "takeover": {"valid": 1.0, "warning": 0.5, "error": 0.0},
    "axfr": {"valid": 1.0, "error": 0.0},
}


class _ViewScoring(Scoring):
    def __init__(self, checks: Iterable[str]):
        self.checks = set(checks)


def view_checks(view: str, selected: Sequence[str]) -> List[str]:
    return [c for c in CHECKS if c in VIEWS[view]["checks"] and c in selected]


def views_for(selected: Sequence[str]) -> List[str]:
    """Views that have at least one selected check, e-mail first."""
    return [v for v in ("email", "dns") if view_checks(v, selected)]


def view_of_issue(code: Optional[str]) -> Optional[str]:
    proto = FINDINGS.get(code or "", ("", ""))[1]
    for name, v in VIEWS.items():
        if proto in v["protocols"]:
            return name
    return None


def issue_in_view(code: Optional[str], view: str) -> bool:
    proto = FINDINGS.get(code or "", ("", ""))[1]
    return proto in VIEWS[view]["protocols"] or proto in SHARED_PROTOCOLS or not proto


def dns_score(r: DomainResult, checks: Sequence[str]) -> int:
    weighted = [c for c in checks if c in DNS_WEIGHTS]
    if not r.exists or r.profile == "unreachable":
        r.score_breakdown = {"components": {}, "max": 0, "normalized": False, "cap": None,
                             "note": "Domain does not exist" if not r.exists else "Name servers unreachable"}
        return 0
    comps, got, top = {}, 0.0, 0
    for c in weighted:
        share = DNS_POINTS[c].get(getattr(r, CHECK_ATTRS[c]).status)
        if share is None:  # unknown / DNS error / not applicable: not measured, not counted
            continue
        comps[c] = {"got": round(DNS_WEIGHTS[c] * share, 1), "max": DNS_WEIGHTS[c]}
        got += DNS_WEIGHTS[c] * share
        top += DNS_WEIGHTS[c]
    if not top:
        sev = [i.severity for i in r.issues]
        score = max(0, 100 - 40 * sev.count("critical") - 15 * sev.count("warning"))
        r.score_breakdown = {"components": {}, "max": 0, "normalized": False, "cap": None,
                             "note": "No measurable weighted control: 100 - 40 per critical - 15 per warning finding"}
        return score
    score = int(round(100 * got / top))
    cap = None
    for i in r.issues:
        limit = SCORE_CAP_CODES.get(i.code)
        if limit is not None and score > limit and (cap is None or limit < cap[0]):
            cap = (limit, FINDINGS[i.code][2])
    if cap:
        score = cap[0]
    r.score_breakdown = {"components": comps, "max": top, "normalized": top != 100,
                         "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}
    return score


def view_results(results: List[DomainResult], view: str, selected: Sequence[str]) -> List[DomainResult]:
    """Copies of the scan results restricted to one view, with the view's own score, fixes and priority."""
    checks = view_checks(view, selected)
    scorer = _ViewScoring(checks)
    out = []
    for r in results:
        v = copy.deepcopy(r)
        for c, attr in CHECK_ATTRS.items():
            if c not in checks:
                setattr(v, attr, type(getattr(v, attr))(status="skipped"))
        if view != "email":
            v.dmarc_reports = DMARCReportResult()
        dkim_guessed = view == "dns" and v.dkim.mode != "dkim.csv"
        if dkim_guessed:  # the DNS report evaluates only the DKIM records of dkim.csv, verified in DNS
            v.dkim = type(v.dkim)(status="skipped")
        v.issues = [i for i in v.issues if issue_in_view(i.code, view)
                    and not (dkim_guessed and FINDINGS.get(i.code, ("", ""))[1] == "DKIM")]
        v.change = None
        if view == "email":
            v.overall_score = scorer._calculate_score(v)
            v.compliance = scorer._evaluate_compliance(v)
        else:
            v.overall_score = dns_score(v, checks)
            v.compliance = {}
        crit = sum(1 for i in v.issues if i.severity == "critical")
        v.priority = tier_weight(v.tier) * (100 - v.overall_score + 15 * crit)
        v.remediation = suggest_remediation(v, set(checks))
        out.append(v)
    out.sort(key=lambda x: (-x.priority, x.domain))
    return out


def email_output(dns_output: str) -> str:
    """Path of the e-mail report next to the DNS one: dns.html -> email.html, report.html -> report_email.html."""
    folder, name = os.path.split(dns_output)
    stem, ext = os.path.splitext(name)
    low = stem.lower()
    if "dns" in low:
        i = low.rindex("dns")
        stem = stem[:i] + "email" + stem[i + 3:]
    else:
        stem += "_email"
    return os.path.join(folder, stem + (ext or ".html"))
