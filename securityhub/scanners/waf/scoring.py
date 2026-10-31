"""Website score and compliance evaluation."""

from __future__ import annotations

from typing import Dict, List

from .constants import BLOCKING_ACTIONS, CHECKS, FINDINGS, SCORE_CAPS
from .models import SiteResult


def score_site(r: SiteResult, checks: List[str]) -> None:
    weighted = [(cname, CHECKS[cname]) for cname in checks if CHECKS[cname] and r.checks.get(cname) and r.checks[cname].max > 0]
    total_w = sum(w for _, w in weighted)
    comps = {}
    score = 0.0
    for cname, w in weighted:
        ch = r.checks[cname]
        frac = max(0.0, min(1.0, ch.got / ch.max))
        comps[cname] = {"got": round(frac * w, 1), "max": w}
        score += frac * w
    score = 100 * score / total_w if total_w else max(0, 100 - 40 * sum(i.severity == "critical" for i in r.issues)
                                                      - 15 * sum(i.severity == "warning" for i in r.issues))
    score = int(round(score))
    cap = None
    for i in r.issues:
        limit = SCORE_CAPS.get(i.code)
        if limit is not None and score > limit and (cap is None or limit < cap[0]):
            cap = (limit, FINDINGS[i.code][2])
    if cap:
        score = cap[0]
    r.overall_score = score
    r.score_breakdown = {"components": comps, "max": total_w, "normalized": total_w != 100,
                         "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}


def evaluate_compliance(r: SiteResult, checks: List[str]) -> Dict[str, str]:
    def st(name: str):
        ch = r.checks.get(name)
        return ch.status if ch else "skipped"
    codes = {i.code for i in r.issues}
    out = {}
    waf = r.checks.get("waf")
    rules = {x["rule"]: x["action"] for x in (waf.data.get("rules") if waf else [])}
    if {"onboarding", "waf"} <= set(checks):
        ok = ("SITE_BYPASS" not in codes and "DNS_NOT_ROUTED" not in codes and "WAF_POLICY_DISABLED" not in codes
              and "WAF_NO_POLICY" not in codes and all(a in BLOCKING_ACTIONS | {"ALERT"} for a in rules.values()) and len(rules) == 4)
        out["pci_642"] = "pass" if ok else "fail"
    if "waf" in checks:
        out["owasp_block"] = "pass" if (len(rules) == 4 and all(a in BLOCKING_ACTIONS for a in rules.values())
                                        and "WAF_POLICY_DISABLED" not in codes) else "fail"
    if "ddos" in checks:
        out["ddos"] = "pass" if st("ddos") == "valid" or (st("ddos") == "warning" and "DDOS_OFF" not in codes) else "fail"
    if "tls" in checks:
        tls = r.checks.get("tls")
        out["transport"] = "pass" if tls and not any(i.severity != "info" for i in tls.issues) else "fail"
    if "origin" in checks:
        out["origin_lockdown"] = "n/a" if st("origin") in ("na", "skipped") else \
            "unknown" if st("origin") == "unknown" else ("pass" if "ORIGIN_EXPOSED" not in codes and "DNS_NOT_ROUTED" not in codes else "fail")
    if r.error:
        out = {k: ("unknown" if v == "fail" else v) for k, v in out.items()}
    return out
