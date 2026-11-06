"""
GuardHub - one navigable portal for MailGuard DNS, WAFGuard and ZTAGuard reports

Collects the HTML reports produced by the Guard tools into a single self-contained
HTML file: a landing page with the grade and key figures of every report, a
cross-report list of the top risks with deep links, and each report embedded and
fully usable (filters, details, exports, printing) without leaving the portal.

Each report runs in an isolated (sandboxed) frame: reports keep their own state
while you switch between them, and the portal URL records which report and view is
open, so links can be bookmarked.

Usage:
    securityhub portal mailguard_dns_report.html wafguard_report.html zta_report.html
    securityhub portal ./reports -o security_hub.html --title "Contoso - Q4 2026"
    securityhub portal ./reports --all           # also embed non-Guard HTML files
    securityhub portal ./q1 ./q2 ./q3 ./q4        # several runs: latest embedded, older ones become KPI trends

Requires Python 3.9+ (standard library only).
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import EXIT_OK, EXIT_USAGE, Parser, atomic_open, atomic_write, grade, json_for_html
from . import correlations, inventory, ui

__version__ = "1.2.0"

DATA_RE = re.compile(r'<script type="application/json" id="mg-data">(.*?)</script>', re.S)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S | re.I)
TYPE_ORDER = {"email": 0, "dns": 1, "proofpoint": 2, "waf": 3, "edr": 4, "ias": 5, "pra": 6, "zta": 7, "other": 8}
TYPE_LABEL = {"email": "Email security", "dns": "DNS security", "waf": "Imperva Cloud WAF", "edr": "SentinelOne EDR", "proofpoint": "Proofpoint", "ias": "SAP Cloud Identity", "pra": "BeyondTrust PRA",
              "zta": "Microsoft Zero Trust", "other": "Report"}
DOMAIN_AREAS = ("email", "dns")  # reports whose rows are domains (MailGuard: one scan, two reports)
TIER_W = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Data older than this (days) is flagged as stale: DNS and WAF can be assessed daily, the Zero Trust
# Assessment is a periodic export. Override with --max-age / max_age_days in the configuration.
MAX_AGE_DAYS = {"email": 2, "dns": 2, "proofpoint": 2, "waf": 2, "edr": 2, "ias": 2, "pra": 2, "zta": 35}
STATUS_RANK = {"bad": 0, "warn": 1, "good": 2}




def weighted_avg(rows: List[dict], tiers: Dict[str, int]) -> Optional[float]:
    w = sum(tiers.get(r.get("tier", "medium"), 2) for r in rows)
    return sum(r.get("overall_score", 0) * tiers.get(r.get("tier", "medium"), 2) for r in rows) / w if w else None


def detect(payload: Optional[dict], title: str) -> str:
    if isinstance(payload, dict):
        if isinstance(payload.get("tests"), list) and "tenant" in payload:
            return "zta"
        if (payload.get("meta") or {}).get("tool") == "EDRGuard":
            return "edr"
        if (payload.get("meta") or {}).get("tool") == "PPGuard":
            return "proofpoint"
        if (payload.get("meta") or {}).get("tool") == "IASGuard":
            return "ias"
        if (payload.get("meta") or {}).get("tool") == "PRAGuard":
            return "pra"
        if (payload.get("meta") or {}).get("tool") == "WAFGuard" or "account_issues" in payload:
            return "waf"
        if isinstance(payload.get("results"), list) and "checks" in payload:
            # MailGuard 4 writes an e-mail and a DNS report; older combined reports read as e-mail (their KPIs were)
            return "dns" if (payload.get("meta") or {}).get("view") == "dns" else "email"
    t = title.lower()
    return ("zta" if "zero trust" in t else "proofpoint" if "proofpoint" in t else "edr" if "edr" in t else "waf" if "waf" in t else "dns" if "dns security" in t
            else "email" if "email" in t else "other")


def first_issue(r: dict) -> str:
    issues = r.get("issues") or []
    i = next((x for x in issues if x.get("severity") == "critical"), issues[0] if issues else None)
    return (i or {}).get("message", "")


def _scored(kind: str, r: dict) -> bool:
    """The row was really assessed: domain answered / no read error, and at least one weighted check was measured
    (a row with nothing measurable - e.g. a mail domain Proofpoint does not filter - would count as 100)."""
    if kind in DOMAIN_AREAS:
        return inventory.dns_measured(r)
    if not inventory.waf_measured(r):
        return False
    b = r.get("score_breakdown")
    return not isinstance(b, dict) or "max" not in b or bool(b.get("max"))


def area_score(kind: str, payload: dict) -> Optional[float]:
    """The score of an area, the same for the portal card, the area status, the trends and posture.json:
    tier-weighted average of the items that were really assessed."""
    rows = payload.get("results") or []
    if kind == "ias":
        tot = payload.get("totals") or {}
        active = tot.get("active") or 0
        if tot.get("limited") and active:   # only the users with findings are listed: share of clean users
            return _pct(active - (tot.get("with_findings") or 0), active)
    return weighted_avg([r for r in rows if _scored(kind, r)], payload.get("tiers") or TIER_W)


# ---------------------------------------------------------------------------
# Two figures per area: hygiene (how well things are configured) and active exposure (what an attacker can use,
# or is using, right now). The overall area score keeps both; these split it so a configuration effort and an
# incident do not hide each other.
# ---------------------------------------------------------------------------

# Findings that are an active exposure: threats that reached people or systems, clicks allowed, accounts that can be
# taken over without MFA, systems reachable around their protection, names that can be hijacked.
EXPOSURE_CODES: Dict[str, set] = {
    "email": {"DMARC_MISSING", "DMARC_NONE", "DMARC_INVALID", "SPF_PASS_ALL"},
    "dns": {"TAKEOVER_UNREGISTERED", "TAKEOVER_EXPIRED", "TAKEOVER_LAME_NS", "MX_DANGLING", "AXFR_OPEN", "DNSSEC_BOGUS",
            "DOMAIN_EXPIRED", "LOOKALIKE_FRESH"},
    "waf": {"SITE_BYPASS", "ORIGIN_EXPOSED", "DNS_NOT_ROUTED", "WAF_NO_POLICY", "WAF_POLICY_DISABLED", "WAF_RULE_IGNORED",
            "ALLOW_BROAD_IP", "CERT_EXPIRED"},
    "edr": {"THREAT_ACTIVE", "AGENT_DISABLED", "COVERAGE_GAP"},
    "proofpoint": {"THREAT_DELIVERED", "CLICK_PERMITTED", "SAFELIST_DELIVERY", "IMPOSTOR_DELIVERED", "CLICK_REPEAT",
                   "POD_SPOOF_DELIVERED", "MAIL_BOMB_TARGETED", "BEC_VIP_TARGETED_RISK", "TR_PULLED_AFTER_READ"},
    "ias": {"PASSWORD_NO_MFA", "PASSWORD_LOGIN_PRIVILEGED", "EXPIRED_ACTIVE"},
    "pra": {"ADMIN_NO_MFA", "USER_NO_MFA", "VENDOR_NO_MFA", "API_NO_IP_WRITE"},
}
# Checks that measure exposure, not configuration: left out of the hygiene figure.
EXPOSURE_CHECKS: Dict[str, set] = {"dns": {"takeover", "axfr"}, "edr": {"threats"},
                                   "proofpoint": {"threats", "clicks", "rewrite", "people"}}


def hygiene_exposure(kind: str, payload: dict) -> Optional[dict]:
    """hygiene: tier-weighted score of the configuration checks only, without the caps set by exposures;
    exposure: assessed items with at least one exposure finding, plus organization-level exposures."""
    codes = EXPOSURE_CODES.get(kind)
    if codes is None:
        return None
    rows = [r for r in payload.get("results") or [] if _scored(kind, r)]
    skip = EXPOSURE_CHECKS.get(kind, set())
    tiers = payload.get("tiers") or TIER_W
    hyg_rows = []
    for r in rows:
        comps = {c: v for c, v in ((r.get("score_breakdown") or {}).get("components") or {}).items() if c not in skip}
        top = sum(float(v.get("max") or 0) for v in comps.values())
        if top:
            hyg_rows.append({"tier": r.get("tier", "medium"), "overall_score": 100 * sum(float(v.get("got") or 0) for v in comps.values()) / top})
    exposed = [r for r in rows if {i.get("code") for i in r.get("issues") or []} & codes]
    by_code: Counter = Counter(i.get("code") for r in rows for i in r.get("issues") or [] if i.get("code") in codes)
    org = [i for i in payload.get("account_issues") or [] if i.get("code") in codes]
    hyg = weighted_avg(hyg_rows, tiers)
    return {"hygiene": round(hyg) if hyg is not None else None, "hygiene_items": len(hyg_rows),
            "exposed": len(exposed), "assessed": len(rows), "exposed_pct": _pct(len(exposed), len(rows)),
            "org_exposures": [{"code": i.get("code"), "message": i.get("message")} for i in org[:10]],
            "by_code": by_code.most_common(8)}


NOT_EVALUABLE = {"unknown", "dns_error"}


def coverage(kind: str, payload: dict) -> dict:
    """How much of an area was really measured: items scored, checks that could not be evaluated, API errors."""
    rows = payload.get("results") or []
    missing: Counter = Counter()
    for r in rows:
        for c, v in (r.get("checks") or {}).items():
            status = v.get("status") if isinstance(v, dict) else None
            if status in NOT_EVALUABLE:
                missing[c] += 1
        for c in ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec", "caa", "takeover", "axfr"):   # MailGuard rows
            v = r.get(c)
            if isinstance(v, dict) and v.get("status") in NOT_EVALUABLE:
                missing[c] += 1
    issues = payload.get("account_issues") or []
    return {"items": len(rows), "scored": sum(1 for r in rows if _scored(kind, r)),
            "not_evaluable": sum(missing.values()), "not_evaluable_by_check": dict(missing.most_common(10)),
            "api_errors": [i.get("message") for i in issues if str(i.get("code") or "").endswith("API_ERROR")][:10],
            "not_configured": [i.get("message") for i in issues if str(i.get("code") or "").endswith("NOT_CONFIGURED")]}


def summarize_assets(kind: str, payload: dict) -> dict:
    rows = payload.get("results") or []
    measured = [r for r in rows if _scored(kind, r)]
    avg = area_score(kind, payload)
    sev = Counter(i.get("severity") for r in rows for i in r.get("issues") or [])
    noun = ("domains" if kind in DOMAIN_AREAS + ("proofpoint",) else "endpoints" if kind == "edr" else "users" if kind == "ias" else "objects" if kind == "pra"
            else "websites")
    kpis = [[len(rows), f"{noun} assessed"], *([[len(rows) - len(measured), "not scored (nothing measurable or read error)", "warn"]]
                                               if len(measured) < len(rows) else []),
            [sum(r.get("overall_score", 0) >= 75 for r in measured), "well protected (75+)", "pass"],
            [sum(r.get("overall_score", 0) < 50 for r in measured), "at critical risk (under 50)", "fail"],
            [sev.get("critical", 0), "critical findings", "fail" if sev.get("critical") else ""]]
    if kind == "waf":
        bypass = sum(r.get("profile") == "bypass" for r in rows)
        if bypass:
            kpis.append([bypass, "in bypass mode", "fail"])
        if payload.get("account_issues"):
            kpis.append([len(payload["account_issues"]), "account findings", "warn"])
    elif kind == "email":
        nonmail = sum(r.get("profile") == "non-mail" for r in rows)
        if nonmail:
            kpis.append([nonmail, "do not handle mail", ""])
    top = []
    for r in sorted((r for r in rows if r.get("priority", 0) > 0), key=lambda r: -r.get("priority", 0))[:8]:
        crit = sum(i.get("severity") == "critical" for i in r.get("issues") or [])
        top.append({"item": r.get("domain"), "score": r.get("overall_score"), "detail": first_issue(r),
                    "severity": "critical" if crit else "warning", "tier": r.get("tier", "medium"),
                    "hash": "#/domains?d=" + str(r.get("domain"))})
    diff = payload.get("diff") or {}
    return {"score": round(avg) if avg is not None else None, "kpis": kpis, "top": top,
            "split": hygiene_exposure(kind, payload), "coverage": coverage(kind, payload),
            "subtitle": f"{len(rows)} {noun}", "generated": (payload.get("meta") or {}).get("generated", ""),
            "delta": {"improved": diff.get("improved"), "worsened": diff.get("worsened")} if diff else None}


def summarize_zta(payload: dict) -> dict:
    tests = payload.get("tests") or []
    c = Counter(t.get("status") for t in tests)
    tenant = payload.get("tenant") or {}
    hi = sum(t.get("status") == "failed" and t.get("risk") == "high" for t in tests)
    kpis = [[len(tests), "tests"], [c.get("passed", 0), "passed", "pass"], [c.get("failed", 0), "failed", "fail"],
            [hi, "failed, high risk", "fail" if hi else ""], [c.get("investigate", 0), "to investigate", "warn"]]
    top = []
    for t in sorted((t for t in tests if t.get("priority", 0) > 0), key=lambda t: -t.get("priority", 0))[:8]:
        top.append({"item": t.get("title"), "score": None, "risk": t.get("risk"), "status": t.get("status"),
                    "detail": f"{', '.join(t.get('pillars') or [])}: {t.get('category', '')}".strip(": "),
                    "severity": "critical" if t.get("risk") == "high" and t.get("status") == "failed" else "warning",
                    "hash": "#/tests?d=" + str(t.get("id"))})
    diff = payload.get("diff") or {}
    return {"score": payload.get("score"), "kpis": kpis, "top": top,
            "subtitle": " ".join(x for x in (tenant.get("name"), tenant.get("domain")) if x) or "Tenant",
            "generated": tenant.get("executed_at") or (payload.get("meta") or {}).get("generated", ""),
            "delta": {"improved": diff.get("fixed"), "worsened": diff.get("regressed")} if diff else None}


# ---------------------------------------------------------------------------
# Executive metrics: outcome KPIs, area status, aggregated actions
# ---------------------------------------------------------------------------

def _pct(n: float, d: float) -> Optional[int]:
    return int(round(100 * n / d)) if d else None


def _ci(o: Any, *names: str) -> Any:
    if not isinstance(o, dict):
        return None
    low = {re.sub(r"[^a-z0-9]", "", str(k).lower()): v for k, v in o.items()}
    for n in names:
        v = low.get(re.sub(r"[^a-z0-9]", "", n.lower()))
        if v is not None:
            return v
    return None


def _walk(o: Any, key: str = "", depth: int = 0):
    if depth > 6:
        return
    if isinstance(o, dict):
        yield key, o
        for k, v in o.items():
            if isinstance(v, (dict, list)):
                yield from _walk(v, k, depth + 1)
    elif isinstance(o, list):
        for v in o:
            if isinstance(v, (dict, list)):
                yield from _walk(v, key, depth + 1)


def _links(o: Any) -> List[Tuple[str, str, float]]:
    arr = _ci(o, "nodes", "links", "data") if isinstance(o, dict) else None
    out = []
    for x in arr if isinstance(arr, list) else []:
        if isinstance(x, dict) and _ci(x, "source") is not None and _ci(x, "target") is not None:
            try:
                v = float(_ci(x, "value") or 0)
            except (TypeError, ValueError):
                v = 0.0
            if v > 0:
                out.append((str(_ci(x, "source")), str(_ci(x, "target")), v))
    return out


def _flow_share(info: Any, key_re: str, node_re: str, exclude_re: str = r"^(no|non)\b") -> Optional[Tuple[int, float, float]]:
    """Share of the root flow reaching nodes named like node_re in the sankey whose key matches key_re."""
    for key, obj in _walk(info):
        if re.search(key_re, re.sub(r"[^a-z0-9]", "", key.lower())):
            links = _links(obj)
            if not links:
                continue
            targets = {t for _, t, _ in links}
            total = sum(v for s_, _, v in links if s_ not in targets)
            hit = sum(v for _, t, v in links if re.search(node_re, t, re.I) and not re.search(exclude_re, t, re.I))
            if total:
                return _pct(hit, total), hit, total
    return None


def _device_compliance(info: Any) -> Optional[Tuple[int, float, float]]:
    for _, obj in _walk(info):
        ok = bad = None
        for k, v in obj.items():
            nk = re.sub(r"[^a-z0-9]", "", str(k).lower())
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                if "noncompliant" in nk:
                    bad = v
                elif nk.startswith("compliant"):
                    ok = v
        if ok is not None and bad is not None and ok + bad:
            return _pct(ok, ok + bad), ok, ok + bad
    ok = bad = 0.0
    for key, obj in _walk(info):
        if re.search(r"desktop|mobile", key, re.I):
            for _, t, v in _links(obj):
                if re.match(r"compliant", t, re.I):
                    ok += v
                elif re.search(r"non.?compliant", t, re.I):
                    bad += v
    return (_pct(ok, ok + bad), ok, ok + bad) if ok + bad else None


def _status(score: Optional[float], critical_exposure: bool) -> str:
    """good = grade A/B (75+), warn = C/D (50-74), bad = F; a critical exposure is never 'good'."""
    if score is None:
        return "unknown"
    st = "good" if score >= 75 else "warn" if score >= 50 else "bad"
    return "warn" if st == "good" and critical_exposure else st


def _kpi(key, label, value, unit, detail, target=None, higher_is_better=True, trend=None, area=None, hash_=""):
    return {"key": key, "label": label, "value": value, "unit": unit, "detail": detail, "target": target,
            "hib": higher_is_better, "trend": trend, "area": area, "hash": hash_}


def _asset_actions(kind: str, payload: dict, rows: List[dict]) -> List[dict]:
    findings = payload.get("findings") or {}
    count, weight, crit_tier = Counter(), Counter(), Counter()
    for r in rows:
        for code in {i.get("code") for i in r.get("issues") or [] if i.get("code")}:
            count[code] += 1
            weight[code] += TIER_W.get(r.get("tier", "medium"), 2)
            if r.get("tier") == "critical":
                crit_tier[code] += 1
    out = []
    for code, n in count.items():
        f = findings.get(code)
        if not f or f[0] not in ("critical", "warning"):
            continue
        out.append({"area": kind, "code": code, "severity": f[0], "title": f[2], "rec": f[3], "count": n,
                    "share": _pct(n, len(rows)), "critical_tier": crit_tier[code],
                    "impact": (3 if f[0] == "critical" else 1) * weight[code], "hash": f"#/domains?finding={code}"})
    # ties: critical first, then by code, so the action plan is stable from one run to the next
    return sorted(out, key=lambda a: (-a["impact"], a["severity"] != "critical", a["code"]))


def exec_email(payload: dict) -> dict:
    """E-mail outcomes. Only measured domains count: not checked or failed lookups are 'not verified', never 'exposed'."""
    rows = [r for r in payload.get("results") or [] if r.get("profile") != "nonexistent"]
    checks = payload.get("checks") or []
    measured = [r for r in rows if inventory.dns_measured(r)]
    states = {id(r): inventory.dmarc_state(r) for r in rows}
    known = [r for r in rows if states[id(r)] != "unknown"]
    enforced = [r for r in known if states[id(r)] == "enforced"]
    spoofable = [r for r in known if states[id(r)] == "spoofable"]
    unverified = len(rows) - len(known)
    crit = [r for r in known if r.get("tier") == "critical"]
    note = f", {unverified} not verified" if unverified else ""
    if "dmarc" not in checks:
        spoof_kpi = _kpi("spoof", "Domains protected against spoofing", None, "%", "DMARC was not checked in this assessment", 100, area="email")
    else:
        spoof_kpi = _kpi("spoof", "Domains protected against spoofing", _pct(len(enforced), len(known)), "%",
                         f"{len(enforced)} of {len(known)} verified domains enforce DMARC{note}", 100, area="email",
                         hash_="#/domains?comp=dmarc_enforcement:fail")
    kpis = [spoof_kpi]
    side = []
    if "dmarc" in checks:
        side.append(["Can be impersonated by email", f"{len(spoofable)} domain{'' if len(spoofable) == 1 else 's'}", "bad" if spoofable else "good"])
    if crit and "dmarc" in checks:
        ok = sum(states[id(r)] == "enforced" for r in crit)
        side.append(["Critical-tier domains protected", f"{ok} of {len(crit)}", "good" if ok == len(crit) else "bad"])
    exposure = False
    mail = [r for r in measured if r.get("profile") == "mail" and (r.get("dkim") or {}).get("status") not in inventory.UNKNOWN_STATUSES]
    if mail and "dkim" in checks:
        signed = sum((r.get("dkim") or {}).get("status") in ("valid", "partial") for r in mail)
        side.append(["Mail domains signing with DKIM", f"{_pct(signed, len(mail))}%", "good" if signed == len(mail) else "warn"])
    if unverified or len(measured) < len(rows):
        side.append(["Not verified (control not run, DNS errors)", f"{max(unverified, len(rows) - len(measured))} domains", "warn"])
    score = area_score("email", payload)
    deltas = [r["change"]["score_delta"] for r in measured if r.get("change") and r["change"].get("score_delta") is not None]
    trend = round(sum(deltas) / len(deltas), 1) if deltas else None
    worst = _pct(len(spoofable), len(known))
    return {"status": _status(score, exposure), "kpis": kpis, "side": side, "trend": trend,
            "actions": _asset_actions("email", payload, measured),
            "headline": (worst, f"{len(spoofable)} of {len(known)} verified domains ({worst}%) can be impersonated by email")
            if spoofable else None}


def exec_dns(payload: dict) -> dict:
    """DNS outcomes: zone integrity (DNSSEC), certificate issuance (CAA), takeover, zone transfer, registrations.
    Only measured domains count: a check that was not run or failed is 'not verified', never 'exposed'."""
    rows = [r for r in payload.get("results") or [] if r.get("profile") != "nonexistent"]
    checks = payload.get("checks") or []
    measured = [r for r in rows if inventory.dns_measured(r)]
    st = lambda r, c: (r.get(c) or {}).get("status")
    codes = lambda r: {i.get("code") for i in r.get("issues") or []}
    plural = lambda n: f"{n} domain{'' if n == 1 else 's'}"
    unverified = len(rows) - len(measured)
    note = f", {unverified} not verified" if unverified else ""
    kpis, side = [], []
    if "dnssec" in checks:
        known = [r for r in measured if st(r, "dnssec") in ("valid", "missing", "bogus")]
        signed = sum(st(r, "dnssec") == "valid" for r in known)
        kpis.append(_kpi("dnssec", "Domains signed with DNSSEC", _pct(signed, len(known)) if known else None, "%",
                         f"{signed} of {len(known)} verified domains{note}" if known else "DNSSEC could not be verified "
                         "(the resolver does not validate)", 100, area="dns", hash_="#/domains?finding=DNSSEC_UNSIGNED"))
    if "caa" in checks:
        known = [r for r in measured if st(r, "caa") in ("valid", "warning", "missing")]
        ok = sum(st(r, "caa") != "missing" for r in known)
        kpis.append(_kpi("caa", "Domains restricting certificate issuance (CAA)", _pct(ok, len(known)) if known else None, "%",
                         f"{ok} of {len(known)} verified domains{note}", 100, area="dns", hash_="#/domains?finding=CAA_MISSING"))
    tk = [r for r in measured if st(r, "takeover") == "error"] if "takeover" in checks else []
    ax = [r for r in measured if st(r, "axfr") == "error"] if "axfr" in checks else []
    bogus = [r for r in measured if st(r, "dnssec") == "bogus"]
    expired = [r for r in rows if codes(r) & {"DOMAIN_EXPIRED"}]
    expiring = [r for r in rows if codes(r) & {"DOMAIN_EXPIRING"}]
    if "takeover" in checks:
        side.append(["Exposed to takeover of a dependency", plural(len(tk)), "bad" if tk else "good"])
        side.append(["Registrations expired or expiring", plural(len(expired) + len(expiring)),
                     "bad" if expired else "warn" if expiring else "good"])
    if "axfr" in checks:
        side.append(["Zone transfer open to anyone", plural(len(ax)), "bad" if ax else "good"])
    if bogus:
        side.append(["DNSSEC broken (bogus signatures)", plural(len(bogus)), "bad"])
    if "consistency" in checks:
        inc = sum(st(r, "consistency") in ("warning", "error") for r in measured)
        side.append(["Resolvers and name servers disagree", plural(inc), "warn" if inc else "good"])
    if "lookalikes" in checks:
        lk = sum(any(e.get("mx") for e in (r.get("lookalikes") or {}).get("registered") or []) for r in measured)
        side.append(["Brands with lookalike domains able to receive mail", str(lk), "warn" if lk else "good"])
    if unverified:
        side.append(["Not verified (DNS errors)", plural(unverified), "warn"])
    score = area_score("dns", payload)
    deltas = [r["change"]["score_delta"] for r in measured if r.get("change") and r["change"].get("score_delta") is not None]
    exposure = bool(tk or ax or bogus or expired)
    head = None
    if tk:
        head = (_pct(len(tk), len(measured)), f"{len(tk)} of {len(measured)} domains can be taken over through an "
                                              "unregistered or dangling dependency")
    elif ax:
        head = (_pct(len(ax), len(measured)), f"{plural(len(ax))} let anyone download the whole DNS zone")
    elif bogus or expired:
        head = (_pct(len(bogus) + len(expired), len(measured)),
                f"{plural(len(bogus) + len(expired))} at risk of going offline (broken DNSSEC or expired registration)")
    return {"status": _status(score, exposure), "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "actions": _asset_actions("dns", payload, measured), "headline": head}


def exec_waf(payload: dict) -> dict:
    """WAF outcomes. A website whose WAF rules were not checked or could not be read is 'not verified', not 'unprotected'."""
    rows = payload.get("results") or []
    state = {id(r): inventory.waf_protected(r) for r in rows}
    known = [r for r in rows if state[id(r)] is not None]
    protected = [r for r in known if state[id(r)]]
    unverified = len(rows) - len(known)
    note = f", {unverified} not verified" if unverified else ""
    kpis = [_kpi("waf", "Websites effectively protected by the WAF", _pct(len(protected), len(known)) if known else None, "%",
                 f"{len(protected)} of {len(known)} verified websites active, blocking attacks, not bypassable{note}"
                 if known else "WAF rules were not checked in this assessment", 100, area="waf", hash_="#/domains?comp=owasp_block:fail")]
    def codes(r):
        return {i.get("code") for i in r.get("issues") or []}
    pci = [r for r in rows if (r.get("compliance") or {}).get("pci_642") in ("pass", "fail")]
    side = []
    if pci:
        ok = sum(r["compliance"]["pci_642"] == "pass" for r in pci)
        side.append(["PCI DSS 6.4.2 requirement met", f"{ok} of {len(pci)} websites", "good" if ok == len(pci) else "bad"])
    bypass = sum(r.get("profile") == "bypass" for r in rows)
    side.append(["Websites in bypass (not inspected)", str(bypass), "bad" if bypass else "good"])
    probed = [r for r in rows if r.get("probed")]
    if probed:
        exp = sum("ORIGIN_EXPOSED" in codes(r) for r in probed)
        side.append(["Origins reachable bypassing the WAF", f"{exp} of {len(probed)}", "bad" if exp else "good"])
    tuned = [r for r in rows if ((r.get("checks") or {}).get("ddos") or {}).get("data", {}).get("recommended")]
    if tuned:
        ok = sum(not codes(r) & {"DDOS_THRESHOLD_LOW", "DDOS_THRESHOLD_HIGH", "DDOS_ABOVE_ORIGIN", "DDOS_OFF"} for r in tuned)
        side.append(["DDoS thresholds aligned with traffic", f"{ok} of {len(tuned)}", "good" if ok == len(tuned) else "warn"])
    if unverified:
        side.append(["Not verified (rules not checked, API errors)", f"{unverified} website{'s' if unverified != 1 else ''}", "warn"])
    measured = [r for r in rows if inventory.waf_measured(r)]
    score = area_score("waf", payload)
    deltas = [r["change"]["score_delta"] for r in measured if r.get("change") and r["change"].get("score_delta") is not None]
    unprot = len(known) - len(protected)
    return {"status": _status(score, bool(bypass)), "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "actions": _asset_actions("waf", payload, measured),
            "headline": (_pct(unprot, len(known)), f"{unprot} of {len(known)} verified websites ({_pct(unprot, len(known))}%) are not "
                         "effectively protected by the WAF") if unprot else None}


def exec_edr(payload: dict) -> dict:
    """EDR outcomes: endpoints really protected, agent health, open threats, coverage, risky exclusions.
    An endpoint whose policy could not be read is 'not verified', never 'unprotected'."""
    rows = payload.get("results") or []
    n = len(rows)
    st = lambda r, c: ((r.get("checks") or {}).get(c) or {}).get("status")
    codes = lambda r: {i.get("code") for i in r.get("issues") or []}
    known = [r for r in rows if st(r, "protection") not in (None, "unknown", "skipped") and st(r, "policy") not in (None, "unknown", "skipped")]
    protected = [r for r in known if st(r, "protection") == "valid" and "ANTI_TAMPER_OFF" not in codes(r)
                 and not codes(r) & {"AGENT_STALE", "AGENT_DISABLED"}]
    unverified = n - len(known)
    note = f", {unverified} not verified" if unverified else ""
    healthy = [r for r in rows if st(r, "health") == "valid"]
    kpis = [_kpi("edr_protect", "Endpoints actively protected by the EDR", _pct(len(protected), len(known)) if known else None, "%",
                 f"{len(protected)} of {len(known)} endpoints online, in Protect mode, anti-tamper on{note}", 100, area="edr",
                 hash_="#/domains?comp=edr_baseline:fail"),
            _kpi("edr_health", "Healthy agents", _pct(len(healthy), n) if n else None, "%",
                 f"{len(healthy)} of {n} agents online without pending actions", 100, area="edr", hash_="#/domains?f=health:error")]
    cov = payload.get("coverage")
    if cov and cov.get("inventory"):
        kpis.append(_kpi("edr_coverage", "Inventory hosts with an EDR agent", _pct(cov["covered"], cov["inventory"]), "%",
                         f"{cov['covered']} of {cov['inventory']} expected hosts", 100, area="edr", hash_="#/policies"))
    active = [r for r in rows if "THREAT_ACTIVE" in codes(r)]
    detect = [r for r in rows if "MODE_DETECT" in codes(r)]
    stale = [r for r in rows if codes(r) & {"AGENT_STALE", "AGENT_DISABLED"}]
    acc = payload.get("account_issues") or []
    broad = sum(1 for x in payload.get("exclusions") or [] if x.get("risk") == "critical")
    side = [["Endpoints with an active threat", str(len(active)), "bad" if active else "good"],
            ["Endpoints in Detect mode only", str(len(detect)), "bad" if detect else "good"],
            ["Agents stale or disabled", str(len(stale)), "warn" if stale else "good"],
            ["Overly broad exclusions", str(broad), "bad" if broad else "good"]]
    if unverified:
        side.append(["Not verified (policy not readable)", f"{unverified} endpoint{'s' if unverified != 1 else ''}", "warn"])
    score = area_score("edr", payload)
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    exposure = bool(active or detect or broad or any(i.get("code") == "COVERAGE_GAP" for i in acc))
    head = None
    if active:
        head = (_pct(len(active), n), f"{len(active)} endpoint{'s' if len(active) != 1 else ''} with a threat not mitigated")
    elif cov and cov.get("missing"):
        head = (_pct(len(cov["missing"]), cov["inventory"]), f"{len(cov['missing'])} of {cov['inventory']} inventory hosts have no EDR agent")
    elif detect:
        head = (_pct(len(detect), n), f"{len(detect)} of {n} endpoints only detect malware, they do not block it")
    actions = _asset_actions("edr", payload, rows)
    for i in acc:  # console findings (exclusions, policies, coverage) are actions too
        if i.get("severity") in ("critical", "warning"):
            actions.append({"area": "edr", "code": i.get("code"), "severity": i["severity"], "title": i.get("message"),
                            "rec": i.get("recommendation"), "count": None, "share": None, "critical_tier": 0,
                            "impact": 40 if i["severity"] == "critical" else 10, "hash": "#/policies"})
    # an unmitigated threat is an incident in progress: it always leads the action plan
    actions.sort(key=lambda a: (a["code"] != "THREAT_ACTIVE", -a["impact"], a["severity"] != "critical", str(a["code"])))
    status = _status(score, exposure)
    if active and status != "unknown":  # a threat the EDR did not stop is an incident, whatever the average says
        status = "bad"
    return {"status": status, "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None, "actions": actions, "headline": head}



def exec_proofpoint(payload: dict) -> dict:
    """Email protection outcomes: threats that reached users, clicks allowed, gateway enforcement (routing is informational).
    A domain whose routing could not be read is 'not verified'; TAP figures only when TAP was read."""
    rows = payload.get("results") or []
    codes = lambda r: {i.get("code") for i in r.get("issues") or []}
    direct = [r for r in rows if "DIRECT_DELIVERY" in codes(r)]
    clicked = [r for r in rows if "CLICK_PERMITTED" in codes(r)]
    tap = bool(payload.get("tap"))
    tot = payload.get("totals") or {}
    hours = (payload.get("window") or {}).get("hours")
    users = sorted({u for r in clicked for u in (((r.get("checks") or {}).get("clicks") or {}).get("data") or {}).get("users") or []})
    kpis = []
    if tap:
        kpis.append(_kpi("pp_clicks", f"Users who clicked a malicious URL that was allowed ({hours}h)", len(users), "",
                         f"{tot.get('clicks_permitted', 0)} permitted clicks", 0, higher_is_better=False, area="proofpoint",
                         hash_="#/domains?finding=CLICK_PERMITTED"))
        kpis.append(_kpi("pp_delivered", f"Malicious messages delivered ({hours}h)", tot.get("malicious", 0), "",
                         f"{tot.get('blocked_messages', 0)} blocked in the same window", 0, higher_is_better=False,
                         area="proofpoint", hash_="#/policies"))
        if tot.get("click_block_rate") is not None:
            kpis.append(_kpi("pp_click_block", "Malicious clicks blocked by URL Defense", tot["click_block_rate"], "%",
                             f"{tot.get('blocked_clicks', 0)} blocked, {tot.get('malicious_clicks_permitted', 0)} permitted", 100,
                             area="proofpoint", hash_="#/policies"))
    pod_msg = (payload.get("pod") or {}).get("message") or {}
    if pod_msg.get("inbound"):
        kpis.append(_kpi("pp_auth_enforced", "Inbound mail failing SPF/DMARC that is delivered", pod_msg.get("auth_failed_delivered_pct"), "%",
                         f"{pod_msg.get('auth_failed_delivered', 0)} of {pod_msg['inbound']} inbound messages (PoD log)", 0,
                         higher_is_better=False, area="proofpoint", hash_="#/policies"))
        if pod_msg.get("tls_pct") is not None:
            kpis.append(_kpi("pp_tls", "Inbound mail received with TLS 1.2+", pod_msg["tls_pct"], "%",
                             f"{pod_msg.get('no_tls', 0)} messages without", 100, area="proofpoint", hash_="#/policies"))
    tp_url = ((payload.get("tp") or {}).get("url_rewrite") or {})
    url_cov = tp_url.get("coverage") if tp_url else pod_msg.get("url_coverage")
    if url_cov is not None:
        kpis.append(_kpi("pp_url_rewrite", "URLs rewritten by URL Defense", url_cov, "%",
                         "Threat Protection report" if tp_url else "PoD message log", 100, area="proofpoint", hash_="#/policies"))
    vap = (payload.get("people") or {}).get("vap") or []
    side = [["Direct delivery to Microsoft 365 to verify", str(len(direct)), "warn" if direct else "good"]]
    if tap:
        side += [["Users with a malicious click allowed", str(len(users)), "bad" if users else "good"],
                 ["Very Attacked People", str(len(vap)), "warn" if any(p.get("vip") for p in vap) else "good"]]
    if pod_msg.get("inbound"):
        side.append(["Spoofed messages from your domains delivered", str(pod_msg.get("spoof_delivered", 0)),
                     "bad" if pod_msg.get("spoof_delivered") else "good"])
    q = (payload.get("tp") or {}).get("quarantines")
    if q:
        side.append(["Condemned messages pulled after being read", str(q.get("pulled_read", 0)), "warn" if q.get("pulled_read") else "good"])
    score = area_score("proofpoint", payload)
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    head = None
    if users:
        # possible account compromise: ranked first among the headlines of the portal
        head = (100, f"{len(users)} user{'s' if len(users) != 1 else ''} clicked a malicious URL that Proofpoint allowed")
    elif tot.get("malicious"):
        head = (None, f"{tot['malicious']} malicious message{'s' if tot['malicious'] != 1 else ''} reached users in {hours}h")
    actions = _asset_actions("proofpoint", payload, rows)
    for i in payload.get("account_issues") or []:
        if i.get("severity") in ("critical", "warning"):
            actions.append({"area": "proofpoint", "code": i.get("code"), "severity": i["severity"], "title": i.get("message"),
                            "rec": i.get("recommendation"), "count": None, "share": None, "critical_tier": 0,
                            "impact": 40 if i["severity"] == "critical" else 10, "hash": "#/policies"})
    # a click on a malicious URL that was allowed is a possible compromise: it leads the action plan
    actions.sort(key=lambda a: (a["code"] != "CLICK_PERMITTED", -a["impact"], a["severity"] != "critical", str(a["code"])))
    status = _status(score, bool(users or tot.get("malicious")))
    if users and status != "unknown":
        status = "bad"
    return {"status": status, "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None, "actions": actions, "headline": head}


def exec_ias(payload: dict) -> dict:
    """Identity outcomes: users who can only sign in through the corporate IdP, privileged users with a local
    password, inactive accounts. Figures come from the tenant totals (large directories list only users with findings)."""
    rows = payload.get("results") or []
    tot = payload.get("totals") or {}
    codes = lambda r: {i.get("code") for i in r.get("issues") or []}
    active = tot.get("active") or len(rows)
    unexpected = tot.get("password_unexpected", 0)
    priv = [r for r in rows if "PASSWORD_LOGIN_PRIVILEGED" in codes(r)]
    nomfa = [r for r in rows if "PASSWORD_NO_MFA" in codes(r)]
    expired = [r for r in rows if "EXPIRED_ACTIVE" in codes(r)]
    inactive = [r for r in rows if codes(r) & {"INACTIVE", "NEVER_USED"}]
    kpis = [_kpi("ias_corporate", "Users who sign in only as expected (no unexpected IAS password)",
                 _pct(active - unexpected, active) if active else None, "%",
                 f"{active - unexpected} of {active} active users", 100, area="ias", hash_="#/domains?profile=password"),
            _kpi("ias_priv_pwd", "Privileged users with a local IAS password", len(priv), "",
                 "members of the privileged groups", 0, higher_is_better=False, area="ias", hash_="#/domains?profile=privileged")]
    if tot.get("last_login_visible"):
        kpis.append(_kpi("ias_inactive", "Inactive or never used accounts", len(inactive), "",
                         f"of {active} active users", 0, higher_is_better=False, area="ias", hash_="#/domains?profile=inactive"))
    side = [["Local IAS password (not expected)", str(unexpected), "warn" if unexpected else "good"],
            ["Privileged users with IAS password", str(len(priv)), "bad" if priv else "good"],
            ["Expired but still active", str(len(expired)), "bad" if expired else "good"]]
    if tot.get("mfa_visible"):
        side.append(["IAS password without second factor", str(len(nomfa)), "bad" if nomfa else "good"])
    if tot.get("last_login_visible"):
        side.append(["Inactive or never used", str(len(inactive)), "warn" if inactive else "good"])
    score = area_score("ias", payload)
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    head = None
    if priv:
        head = (100, f"{len(priv)} privileged user{'s' if len(priv) != 1 else ''} can sign in to SAP with a local password")
    elif unexpected:
        head = (_pct(unexpected, active), f"{unexpected} of {active} SAP users can sign in without the corporate identity provider")
    actions = _asset_actions("ias", payload, rows)
    for i in payload.get("account_issues") or []:
        if i.get("severity") in ("critical", "warning"):
            actions.append({"area": "ias", "code": i.get("code"), "severity": i["severity"], "title": i.get("message"),
                            "rec": i.get("recommendation"), "count": None, "share": None, "critical_tier": 0,
                            "impact": 40 if i["severity"] == "critical" else 10, "hash": "#/policies"})
    actions.sort(key=lambda a: (a["code"] != "PASSWORD_LOGIN_PRIVILEGED", -a["impact"], a["severity"] != "critical", str(a["code"])))
    status = _status(score, bool(priv or expired or nomfa))
    if priv and status != "unknown":
        status = "bad"
    return {"status": status, "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None, "actions": actions, "headline": head}


def exec_pra(payload: dict) -> dict:
    """Privileged access outcomes: people with MFA, assets whose sessions are governed and recorded, vendor
    accounts under control, API accounts restricted."""
    rows = payload.get("results") or []
    tot = payload.get("totals") or {}
    codes = lambda r: {i.get("code") for i in r.get("issues") or []}
    kind = lambda r: r.get("account_id")
    people = [r for r in rows if kind(r) in ("user", "vendor_user")]
    assets = [r for r in rows if kind(r) == "asset"]
    no_mfa = [r for r in people if codes(r) & {"ADMIN_NO_MFA", "VENDOR_NO_MFA", "USER_NO_MFA"}]
    admin_nomfa = [r for r in people if "ADMIN_NO_MFA" in codes(r)]
    vendor_risk = [r for r in people if codes(r) & {"VENDOR_NO_MFA", "VENDOR_NO_EXPIRY"}]
    ungoverned = [r for r in assets if codes(r) & {"ASSET_RECORDING_OFF", "ASSET_NO_POLICY"}]
    api_open = [r for r in rows if "API_NO_IP_WRITE" in codes(r)]
    kpis = []
    if people and not tot.get("limited"):
        kpis.append(_kpi("pra_mfa", "People who sign in with MFA (users and vendors)", _pct(len(people) - len(no_mfa), len(people)), "%",
                         f"{len(people) - len(no_mfa)} of {len(people)} enabled accounts", 100, area="pra", hash_="#/domains?profile=critical"))
    if assets and not tot.get("limited"):
        kpis.append(_kpi("pra_recorded", "Assets under a policy that records sessions", _pct(len(assets) - len(ungoverned), len(assets)), "%",
                         f"{len(assets) - len(ungoverned)} of {len(assets)} assets", 100, area="pra", hash_="#/domains?comp=governed_access:fail"))
    kpis.append(_kpi("pra_vendor", "Vendor accounts without MFA or expiration", len(vendor_risk), "",
                     "external access to privileged systems", 0, higher_is_better=False, area="pra", hash_="#/domains?account=Vendor%20user"))
    s = tot.get("sessions") or {}
    side = [["Administrators without MFA", str(len(admin_nomfa)), "bad" if admin_nomfa else "good"],
            ["Vendor accounts without MFA or expiration", str(len(vendor_risk)), "bad" if vendor_risk else "good"],
            ["Assets without recording or policy", str(len(ungoverned)), "warn" if ungoverned else "good"],
            ["API accounts with write access and no allow list", str(len(api_open)), "bad" if api_open else "good"]]
    if s:
        side.append([f"Sessions not recorded ({s.get('days')} days)", f"{s.get('unrecorded', 0)} of {s.get('total', 0)}",
                     "warn" if s.get("unrecorded") else "good"])
    score = area_score("pra", payload)
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    head = None
    if admin_nomfa:
        head = (100, f"{len(admin_nomfa)} PRA administrator{'s' if len(admin_nomfa) != 1 else ''} without MFA")
    elif api_open:
        head = (90, f"{len(api_open)} PRA API account{'s' if len(api_open) != 1 else ''} with write access usable from any address")
    elif vendor_risk:
        head = (_pct(len(vendor_risk), len(people)), f"{len(vendor_risk)} vendor account{'s' if len(vendor_risk) != 1 else ''} without MFA or expiration")
    actions = _asset_actions("pra", payload, rows)
    for i in payload.get("account_issues") or []:
        if i.get("severity") in ("critical", "warning"):
            actions.append({"area": "pra", "code": i.get("code"), "severity": i["severity"], "title": i.get("message"),
                            "rec": i.get("recommendation"), "count": None, "share": None, "critical_tier": 0,
                            "impact": 40 if i["severity"] == "critical" else 10, "hash": "#/policies"})
    lead = ("ADMIN_NO_MFA", "API_NO_IP_WRITE", "VENDOR_NO_MFA")
    actions.sort(key=lambda a: (a["code"] not in lead, -a["impact"], a["severity"] != "critical", str(a["code"])))
    status = _status(score, bool(admin_nomfa or api_open or vendor_risk or ungoverned))
    if (admin_nomfa or api_open) and status != "unknown":
        status = "bad"
    return {"status": status, "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None, "actions": actions, "headline": head}

def exec_zta(payload: dict) -> dict:
    tests = payload.get("tests") or []
    info = payload.get("tenant_info")
    score = payload.get("score")
    hi = [t for t in tests if t.get("status") == "failed" and t.get("risk") == "high"]
    diff = payload.get("diff") or {}
    trend = (diff["score_after"] - diff["score_before"]) if diff.get("score_after") is not None and diff.get("score_before") is not None else None
    kpis = [_kpi("zt", "Zero Trust controls passed", score, "/100", "Pass rate weighted by risk", 80, trend=trend, area="zta", hash_="#/tests?status=failed,investigate")]
    mfa = _flow_share(info, r"camfa", r"^mfa$|multifactor")
    if mfa:
        kpis.append(_kpi("mfa", "Sign-ins protected by MFA", mfa[0], "%", f"Conditional Access enforcing MFA, {int(mfa[2]):,} sign-ins sampled", 100, area="zta", hash_="#/tests?pillar=Identity"))
    pr = _flow_share(info, r"authmethodsallusers", r"phish.?resistant")
    if pr:
        kpis.append(_kpi("pr", "Users with phishing-resistant MFA", pr[0], "%", f"{int(pr[1]):,} of {int(pr[2]):,} users", 100, area="zta", hash_="#/tests?pillar=Identity"))
    dev = _device_compliance(info)
    if dev:
        kpis.append(_kpi("dev", "Compliant devices", dev[0], "%", f"{int(dev[1]):,} of {int(dev[2]):,} devices", 100, area="zta", hash_="#/tests?pillar=Devices"))
    side = [["High-risk controls failing", str(len(hi)), "bad" if hi else "good"]]
    priv = _flow_share(info, r"authmethodsprivileged", r"phish.?resistant")
    if priv:
        side.append(["Admins with phishing-resistant MFA", f"{priv[0]}%", "good" if priv[0] == 100 else "bad"])
    sf = _flow_share(info, r"authmethodsallusers", r"single.?factor", r"^$")
    if sf:
        side.append(["Users with password only", f"{sf[0]}%", "bad" if sf[0] else "good"])
    actions = [{"area": "zta", "code": t.get("id"), "severity": "critical" if t.get("risk") == "high" else "warning", "title": t.get("title"),
                "rec": f"{', '.join(t.get('pillars') or [])}: {t.get('category', '')}, effort {t.get('cost', '')}", "count": 1, "share": None,
                "critical_tier": 0, "impact": t.get("priority", 0), "hash": f"#/tests?d={t.get('id')}"}
               for t in sorted((t for t in tests if t.get("status") in ("failed", "investigate") and t.get("risk") in ("high", "medium")),
                               key=lambda t: -t.get("priority", 0))]
    head = None
    if mfa and mfa[0] < 100:
        head = (100 - mfa[0], f"{100 - mfa[0]}% of sign-ins are not protected by MFA")
    elif hi:
        head = (min(100, 10 * len(hi)), f"{len(hi)} high-risk Zero Trust controls are failing")
    return {"status": _status(score, bool(hi)), "kpis": kpis, "side": side, "trend": trend, "actions": actions, "headline": head}


EXEC = {"email": exec_email, "dns": exec_dns, "waf": exec_waf, "edr": exec_edr, "proofpoint": exec_proofpoint,
        "ias": exec_ias, "pra": exec_pra, "zta": exec_zta}


def parse_date(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M UTC", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def subject_of(kind: str, payload: Optional[dict]) -> str:
    """What a report is about: runs of the same tool on the same subject form a history."""
    if not isinstance(payload, dict):
        return ""
    if kind == "zta":
        t = payload.get("tenant") or {}
        return str(t.get("id") or t.get("domain") or t.get("name") or "")
    if kind == "waf":
        return ",".join(sorted({str(r.get("account_id")) for r in payload.get("results") or [] if r.get("account_id")}))
    return ""


# A run of 'securityhub run' keeps report *data* (<module>.report.json): the pages are rebuilt here, in the portal,
# with the current UI. One HTML file in the end (the portal); history runs cost a few KB of data instead of pages.
REPORT_DATA_SUFFIX = ".report.json"
REPORT_DATA_FORMAT = "securityhub-report/1"


def page_parts(kind: str) -> Tuple[str, str, str]:
    """(template, css, js) of the report application of an area."""
    if kind in DOMAIN_AREAS:
        from .scanners.dns_email import report as m
    elif kind == "waf":
        from .scanners.waf import report as m
    elif kind == "edr":
        from .scanners.edr import report as m
    elif kind == "proofpoint":
        from .scanners.proofpoint import report as m
    elif kind == "ias":
        from .scanners.sap_ias import report as m
    elif kind == "pra":
        from .scanners.pra import report as m
    elif kind == "zta":
        from .scanners import zero_trust as m
    else:
        raise ValueError(f"no report application for '{kind}'")
    return m.REPORT_TEMPLATE, m.REPORT_CSS, m.REPORT_JS


def build_page(kind: str, title: str, payload: dict) -> str:
    """The self-contained report page, exactly as the module writes it."""
    template, css, js = page_parts(kind)
    return (template.replace("__TITLE__", html.escape(title)).replace("__CSS__", css).replace("__JS__", js)
            .replace("__DATA__", json_for_html(payload)))


def extract_report(text: str) -> Tuple[Optional[str], Optional[dict]]:
    """(title, payload) of a report page."""
    m = DATA_RE.search(text)
    payload = None
    if m:
        try:
            payload = json.loads(m.group(1))
        except ValueError:
            payload = None
    tm = TITLE_RE.search(text)
    return (html.unescape(tm.group(1).strip()) if tm else None), payload


def compact_report(html_path: str) -> Optional[str]:
    """Replace a report page with its data (<name>.report.json). Pages that are not Guard reports stay as they are."""
    with open(html_path, "r", encoding="utf-8", errors="replace") as f:
        title, payload = extract_report(f.read())
    if payload is None:
        return None
    out = html_path.rsplit(".", 1)[0] + REPORT_DATA_SUFFIX
    atomic_write(out, json.dumps({"format": REPORT_DATA_FORMAT, "title": title or "", "payload": payload},
                                 ensure_ascii=False, separators=(",", ":")))
    os.remove(html_path)
    return out


def _read_report(path: str, kind: Optional[str] = None) -> Tuple[str, Optional[dict], str]:
    """(page, payload, title). Report data files are turned back into the page only when `kind` is given."""
    if path.endswith(REPORT_DATA_SUFFIX):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        payload, title = data.get("payload"), data.get("title") or os.path.basename(path)
        text = build_page(kind, title, payload) if kind and payload is not None else ""
        return text, payload, title
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    title, payload = extract_report(text)
    return text, payload, title or os.path.basename(path)


STATUS_MAX_SCORE = {"warn": 74, "bad": 49}   # highest score of the grade band of each status (C/D, F)


def _align_score(summary: dict) -> None:
    """Score, grade and status must tell the same story: an area 'needing attention' because of a critical exposure
    (threats delivered, a malicious click allowed, an exposed admin...) cannot show 99/A. Its score is brought down to
    the top of the band of its status, and the reason is kept for the card."""
    ex, score = summary.get("exec") or {}, summary.get("score")
    top = STATUS_MAX_SCORE.get(ex.get("status"))
    if score is None or top is None or score <= top:
        return
    head = ex.get("headline") or [None, None]
    crit = next((a for a in ex.get("actions") or [] if a.get("severity") == "critical"), None)
    reason = head[1] or (crit or {}).get("title") or "critical findings"
    summary["score_uncapped"], summary["score"] = score, top
    summary["score_cap"] = f"Capped at {top} (average {round(score)}): {reason}"


def area_summary(kind: str, payload: dict) -> Optional[dict]:
    """The area figures exactly as the portal shows them (score aligned with the status, grade, cap reason,
    hygiene and exposure): written into each report so the report and the portal never disagree."""
    if kind not in EXEC or kind == "zta":
        return None
    try:
        summary = {"score": area_score(kind, payload), "exec": EXEC[kind](payload)}
    except Exception:
        return None
    raw = summary["score"]
    summary["score"] = round(raw) if raw is not None else None
    _align_score(summary)
    return {"score": summary["score"], "grade": grade(summary["score"]), "status": summary["exec"].get("status"),
            "average": round(raw) if raw is not None else None, "cap": summary.get("score_cap"),
            "split": hygiene_exposure(kind, payload)}


def load_report(path: str, idx: int, keep: bool = True) -> dict:
    """Metadata, summary and executive metrics of a report; with keep=False the page and its parsed data are
    dropped right away (history runs only feed the KPI trends: keeping them would cost hundreds of MB)."""
    text, payload, title = _read_report(path)
    kind = detect(payload, title)
    if keep and path.endswith(REPORT_DATA_SUFFIX) and payload is not None:
        text = build_page(kind, title, payload)
    summary: Dict[str, Any] = {"score": None, "kpis": [], "top": [], "subtitle": "", "generated": "", "delta": None}
    if payload is not None:
        try:
            summary = (summarize_zta(payload) if kind == "zta" else
                       summarize_assets(kind, payload) if kind in ("email", "dns", "waf", "edr", "proofpoint", "ias", "pra") else summary)
        except Exception as e:  # never fail the hub because of one report
            print(f"Warning: summary of {os.path.basename(path)} not available ({type(e).__name__}: {e})", file=sys.stderr)
    summary["exec"] = None
    if payload is not None and kind in ("email", "dns", "waf", "edr", "proofpoint", "ias", "pra", "zta"):
        try:
            summary["exec"] = EXEC[kind](payload)
        except Exception as e:
            print(f"Warning: executive metrics of {os.path.basename(path)} not available ({type(e).__name__}: {e})", file=sys.stderr)
    _align_score(summary)
    if not summary.get("generated"):
        summary["generated"] = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    when = parse_date(summary.get("generated", "")) or datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    name = os.path.basename(path)
    if name.endswith(REPORT_DATA_SUFFIX):  # shown and downloaded as the page it becomes
        name = name[:-len(REPORT_DATA_SUFFIX)] + ".html"
    return {"id": f"r{idx}", "type": kind, "label": TYPE_LABEL[kind], "title": title, "file": name,
            "date": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "subject": subject_of(kind, payload),
            "size": len(text.encode("utf-8")) if text else os.path.getsize(path), "grade": grade(summary["score"]),
            **summary, "path": path,
            **({"html": text, "payload": payload} if keep else {})}


def find_reports(inputs: List[str], include_all: bool) -> List[str]:
    files: List[str] = []
    for p in inputs:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.lower().endswith((".html", ".htm", REPORT_DATA_SUFFIX)):
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)
    out, seen = [], set()
    for f in files:
        real = os.path.realpath(f)
        if real in seen:
            continue
        seen.add(real)
        if not include_all and f not in inputs and not f.endswith(REPORT_DATA_SUFFIX):
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read()
            if not DATA_RE.search(head):
                continue  # inside folders keep only Guard reports unless --all
        out.append(f)
    return out


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj)


HUB_TEMPLATE = ui.asset("portal.html")


def portfolio(reports: List[dict]) -> dict:
    """Headline sentence, area statuses and the cross-report action plan."""
    areas = [r for r in reports if r.get("exec")]
    at_risk = [r for r in areas if r["exec"]["status"] == "bad"]
    attention = [r for r in areas if r["exec"]["status"] == "warn"]
    heads = sorted((r["exec"]["headline"] + (r["label"],) for r in areas if r["exec"].get("headline")), key=lambda h: -(h[0] or 0))
    if not areas:
        sentence = "No executive metrics available: open the reports for details."
    else:
        parts = []
        if at_risk:
            parts.append(f"{len(at_risk)} of {len(areas)} areas at risk")
        if attention:
            parts.append(f"{len(attention)} need{'s' if len(attention) == 1 else ''} attention")
        sentence = (", ".join(parts) or f"All {len(areas)} areas on track") + "."
        if heads:
            sentence += f" Largest exposure: {heads[0][1]}."
    actions = []
    for r in areas:  # round-robin: the most important action of each area comes first
        for k, a in enumerate(r["exec"]["actions"][:3]):
            actions.append({**a, "report": r["id"], "label": r["label"], "round": k})
    actions.sort(key=lambda a: (0 if a["severity"] == "critical" else 1, a["round"], TYPE_ORDER.get(a["area"], 9)))
    return {"sentence": sentence, "actions": actions[:8],
            "counts": {"bad": len(at_risk), "warn": len(attention), "good": sum(r["exec"]["status"] == "good" for r in areas)}}


def split_history(reports: List[dict]) -> Tuple[List[dict], dict]:
    """Latest run of each (tool, subject) is embedded; all runs feed the KPI history."""
    groups: Dict[Tuple[str, str], List[dict]] = {}
    for r in reports:
        groups.setdefault((r["type"], r["subject"]), []).append(r)
    current, series, runs = [], {}, []
    for (kind, subj), runs_ in groups.items():
        runs_.sort(key=lambda r: r["date"])
        latest = runs_[-1]
        latest["history"] = len(runs_)
        current.append(latest)
        if kind == "other":
            continue
        for r in runs_:
            runs.append({"type": kind, "label": r["label"], "date": r["date"], "file": r["file"], "current": r is latest})
            key = f"score|{kind}|{subj}"
            if r.get("score") is not None:
                series.setdefault(key, {"id": key, "key": "score", "label": f"{r['label']} score", "unit": "/100", "area": kind,
                                        "subject": subj, "target": 75, "points": []})["points"].append([r["date"], r["score"]])
            sp = r.get("split") or {}
            for key, label, unit, target, val in (("hygiene", "hygiene", "/100", 75, sp.get("hygiene")),
                                                  ("exposed", "items with an active exposure", "", 0, sp.get("exposed"))):
                if val is not None:
                    sid = f"{key}|{kind}|{subj}"
                    series.setdefault(sid, {"id": sid, "key": key, "label": f"{r['label']} {label}", "unit": unit, "area": kind,
                                            "subject": subj, "target": target, "points": []})["points"].append([r["date"], val])
            for k in (r.get("exec") or {}).get("kpis", []):
                if k.get("value") is None:
                    continue
                sid = f"{k['key']}|{kind}|{subj}"
                series.setdefault(sid, {"id": sid, "key": k["key"], "label": k["label"], "unit": k["unit"], "area": kind,
                                        "subject": subj, "target": k.get("target"), "points": []})["points"].append([r["date"], k["value"]])
    return current, {"series": list(series.values()), "runs": sorted(runs, key=lambda x: x["date"])}


def _links_safe(reports: List[dict]) -> dict:
    """Cross-module risks; never fail the portal because of one unexpected report shape."""
    try:
        return correlations.build(reports)
    except Exception as e:
        print(f"Warning: cross-module risks not available ({type(e).__name__}: {e})", file=sys.stderr)
        return {"links": [], "summary": {"total": 0, "error": str(e)}}


def joins(reports: List[dict]) -> dict:
    """Asset inventory and cross-module risks: computed once, used by the portal and by posture.json."""
    return {"inventory": inventory.build(reports), "links": _links_safe(reports)}


# What the joins (inventory, cross-module risks) read from a report: the rest of a large report (thousands of
# endpoints with their checks) is not kept in memory once its summary and KPIs are computed.
SLIM_TOP = ("results", "people", "tap", "no_mail", "not_managed", "tenant")
SLIM_ROW_DROP = ("remediation", "score_breakdown", "change", "frameworks")
SLIM_ROW_ONLY = {"edr": ("domain", "profile")}


def slim_payload(kind: str, payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    out = {k: payload[k] for k in SLIM_TOP if k in payload}
    only = SLIM_ROW_ONLY.get(kind)
    rows = []
    for x in out.get("results") or []:
        if not isinstance(x, dict):
            continue
        rows.append({k: x.get(k) for k in only} if only else {k: v for k, v in x.items() if k not in SLIM_ROW_DROP})
    if "results" in out:
        out["results"] = rows
    return out


CHUNK = 1 << 20
PAYLOAD_KEY = re.compile(r'^\{\s*"format"\s*:.*?,\s*"payload"\s*:\s*', re.S)


def _enc(text: str) -> str:
    """`text` as the inside of a JSON string safe in a <script> element (concatenation-safe: chunks can be encoded apart)."""
    return json_for_html(text)[1:-1]


def _html_json(text: str) -> str:
    """Raw JSON text made safe to embed in a <script> element, as json_for_html would write it (per character)."""
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _write_page(f, r: dict) -> None:
    """Write the page of report `r` as a JSON string, rebuilding it from its file in chunks: a large report is never
    held in memory as a whole (nor its parsed data), whatever its size."""
    if "html" in r:  # given by the caller
        f.write(json_for_html(r["html"]))
        return
    path = r["path"]
    f.write('"')
    if path.endswith(REPORT_DATA_SUFFIX):
        with open(path, encoding="utf-8") as src:
            head = src.read(CHUNK)
            m = PAYLOAD_KEY.match(head)
            i = head.rfind(",", 0, m.end()) if m else -1
            try:
                title = json.loads(head[:i] + "}").get("title") if i > 0 else None
            except ValueError:
                title, i = None, -1
            if i < 0:  # not the report-data layout (format, title, then payload): parse it
                src.seek(0)
                data = json.load(src)
                page = build_page(r["type"], data.get("title") or r["title"], data.get("payload"))
                f.write(_enc(page))
                f.write('"')
                return
            template, css, js = page_parts(r["type"])
            pre, _, post = (template.replace("__TITLE__", html.escape(title or r["title"])).replace("__CSS__", css)
                            .replace("__JS__", js)).partition("__DATA__")
            f.write(_enc(pre))
            buf = head[m.end():]
            while True:   # the data ends with the closing brace of the file: keep a short tail until the end
                nxt = src.read(CHUNK)
                if not nxt:
                    break
                buf += nxt
                f.write(_enc(_html_json(buf[:-64])))
                buf = buf[-64:]
            buf = buf.rstrip()
            f.write(_enc(_html_json(buf[:-1] if buf.endswith("}") else buf)))
            f.write(_enc(post))
    else:
        with open(path, encoding="utf-8", errors="replace") as src:
            for chunk in iter(lambda: src.read(CHUNK), ""):
                f.write(_enc(chunk))
    f.write('"')


def report_page(r: dict) -> str:
    """The page of a collected report, rebuilt from its file (collect keeps neither pages nor full data in memory)."""
    import io
    buf = io.StringIO()
    _write_page(buf, r)
    return json.loads(buf.getvalue())


HUB_MARKERS = re.compile(r"(__TITLE__|__CSS__|__JS__|__DATA__|__REPORTS__)")


def build_hub(reports: List[dict], out: str, title: str, history: Optional[dict] = None,
              max_age: Optional[Dict[str, float]] = None, failed: Optional[Dict[str, dict]] = None,
              joined: Optional[dict] = None, health: Optional[dict] = None) -> int:
    """failed: area -> {"at", "error"} for the areas whose module failed in the latest run (their data is older).

    The page is written piece by piece (each report in turn), never built as one string: on a small device the
    portal of large portfolios would otherwise need several copies of itself in memory.
    """
    joined = joined or joins(reports)
    meta = {"version": __version__, "title": title, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "failed": failed or {},
            "max_age_days": {**MAX_AGE_DAYS, **(max_age or {})},
            "portfolio": portfolio(reports), "history": history or {"series": [], "runs": []},
            "inventory": joined["inventory"], "links": joined["links"], "health": health or {}}
    index = [{k: v for k, v in r.items() if k not in ("html", "payload", "path")} for r in reports]
    with atomic_open(out) as f:
        for part in HUB_MARKERS.split(HUB_TEMPLATE):
            if part == "__TITLE__":
                f.write(html.escape(title or "GuardHub"))
            elif part == "__CSS__":
                f.write(HUB_CSS)
            elif part == "__JS__":
                f.write(HUB_JS)
            elif part == "__DATA__":
                f.write(_json_for_html({"meta": meta, "reports": index}))
            elif part == "__REPORTS__":
                for k, r in enumerate(reports):
                    f.write(f'{chr(10) if k else ""}<script type="application/json" id="rep-{r["id"]}">')
                    _write_page(f, r)
                    f.write("</script>")
            else:
                f.write(part)
    return os.path.getsize(out)


def build_parser() -> Parser:
    p = Parser(description="Combine MailGuard DNS, WAFGuard and ZTAGuard HTML reports into one navigable portal")
    p.add_argument("inputs", nargs="+", help="HTML report files and/or folders containing them")
    p.add_argument("-o", "--output", default="security_hub.html", help="Output file (default: security_hub.html)")
    p.add_argument("--title", default="", help="Optional portal title, e.g. organization and period")
    p.add_argument("--all", action="store_true", help="In folders, also embed HTML files that are not Guard reports")
    p.add_argument("--max-age", default="", metavar="AREA=DAYS,...",
                   help="Flag data older than this as stale (default: dns=2,waf=2,zta=35)")
    p.add_argument("--summary-json", metavar="FILE", help="Also write a machine-readable posture summary (JSON)")
    p.add_argument("--version", action="version", version=f"GuardHub {__version__}")
    return p


def collect(inputs: List[str], include_all: bool = False, exclude: Optional[List[str]] = None) -> Tuple[List[dict], dict]:
    """Load every report found in `inputs`: returns (latest report per tool/subject, KPI history)."""
    files = find_reports(inputs, include_all)
    skip = {os.path.realpath(x) for x in exclude or []}
    files = [f for f in files if os.path.realpath(f) not in skip]
    loaded = [load_report(f, i, keep=False) for i, f in enumerate(files)]  # one report in memory at a time
    reports, history = split_history(loaded)
    for r in reports:  # only the latest run of each tool is correlated: load its data again, keeping what the joins use
        _, payload, _ = _read_report(r["path"])
        r["payload"] = slim_payload(r["type"], payload)
        del payload
    reports.sort(key=lambda r: (TYPE_ORDER[r["type"]], r["title"]))
    return reports, history


def parse_max_age(text: str) -> Dict[str, float]:
    """'dns=2,waf=2,zta=35' -> {"dns": 2.0, ...} (unknown areas rejected)."""
    out: Dict[str, float] = {}
    for part in filter(None, (p.strip() for p in (text or "").split(","))):
        k, _, v = part.partition("=")
        if k.strip() not in MAX_AGE_DAYS or not v:
            raise ValueError(f"invalid max age '{part}' (expected e.g. email=2,dns=2,waf=2,zta=35)")
        out[k.strip()] = float(v)
    return out


def freshness(r: dict, now: Optional[datetime] = None, limits: Optional[Dict[str, float]] = None) -> dict:
    """Age of the data of a report and whether it exceeds the limit of its area."""
    now = now or datetime.now(timezone.utc)
    limit = {**MAX_AGE_DAYS, **(limits or {})}.get(r.get("type"))
    when = parse_date(r.get("date", ""))
    age = round((now - when).total_seconds() / 86400, 1) if when else None
    return {"age_days": age, "max_age_days": limit, "stale": bool(limit is not None and age is not None and age > limit)}


def overall_status(areas: List[dict]) -> dict:
    """Overall posture without averaging scores that are not comparable across tools.

    status: the worst status among the areas that could be assessed (bad > warn > good);
    'unknown' when none could. 'complete' is false when an area is not verified or its data is stale.
    """
    known = [a for a in areas if a.get("status") in STATUS_RANK]
    status = min((a["status"] for a in known), key=STATUS_RANK.get) if known else "unknown"
    counts = {k: sum(a.get("status") == k for a in areas) for k in ("bad", "warn", "good")}
    counts["unknown"] = len(areas) - sum(counts.values())
    stale = [a["label"] for a in areas if a.get("stale")]
    unverified = [a["label"] for a in areas if a.get("status") not in STATUS_RANK]
    failed = [a["label"] for a in areas if a.get("last_run_failed")]
    return {"status": status, "areas": counts, "stale": stale, "not_verified": unverified, "failed": failed,
            "complete": not stale and not unverified and not failed}


def posture(reports: List[dict], history: Optional[dict] = None, max_age: Optional[Dict[str, float]] = None,
            now: Optional[datetime] = None, failed: Optional[Dict[str, dict]] = None, joined: Optional[dict] = None) -> dict:
    """Machine-readable posture summary (for monitoring, SIEM ingestion or CI gates)."""
    areas = []
    for r in reports:
        ex = r.get("exec") or {}
        areas.append({
            "area": r["type"], "label": r["label"], "title": r["title"], "file": r["file"], "date": r["date"],
            **freshness(r, now, max_age),
            "subject": r.get("subject", ""), "score": r.get("score"), "grade": r.get("grade"),
            "status": ex.get("status"), "headline": (ex.get("headline") or [None, None])[1],
            "kpis": [{k: v for k, v in kpi.items() if k in ("key", "label", "value", "unit", "detail", "target", "trend")}
                     for kpi in ex.get("kpis", [])],
            "actions": ex.get("actions", [])[:5],
            **({"hygiene": r["split"]["hygiene"], "exposure": {k: r["split"][k] for k in ("exposed", "assessed", "exposed_pct", "org_exposures")}}
               if r.get("split") else {}),
            **({"coverage": r["coverage"]} if r.get("coverage") else {}),
            **({"last_run_failed": (failed or {})[r["type"]]} if r["type"] in (failed or {}) else {}),
        })
    pf = portfolio(reports)
    inv = joined["inventory"] if joined else inventory.build(reports, now)
    lk = joined["links"] if joined else _links_safe(reports)
    assets = [{"asset": a["key"], "status": a["status"], "tier": a["tier"], "score": a["score"], "owners": a["owners"],
               "domains": [d["domain"] for d in a["dns"]], "websites": [w["domain"] for w in a["web"]],
               "next_expiry": a["next_expiry"] and {k: a["next_expiry"][k] for k in ("kind", "name", "date", "days")},
               "signals": [{k: s[k] for k in ("severity", "code", "text")} for s in a["signals"]]}
              for a in inv["assets"]]
    return {"schema": 2, "tool": f"GuardHub {__version__}", "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "overall": overall_status(areas), "summary": pf["sentence"], "counts": pf["counts"],
            "areas": areas, "actions": pf["actions"], "assets": {"summary": inv["summary"], "items": assets},
            "links": {"summary": lk["summary"],
                      "items": [dict({k: x[k] for k in ("severity", "code", "title", "subject", "text")}, areas=sorted({r["area"] for r in x["refs"]}))
                                for x in lk["links"]]},
            "runs": (history or {}).get("runs", [])}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        reports, history = collect(args.inputs, args.all, exclude=[args.output])
    except FileNotFoundError as e:
        print(f"Error: not found: {e}", file=sys.stderr)
        return EXIT_USAGE
    if not reports:
        print("Error: no reports found", file=sys.stderr)
        return EXIT_USAGE
    try:
        max_age = parse_max_age(args.max_age)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    size = build_hub(reports, args.output, args.title, history, max_age)
    print(f"Portal generated: {args.output} ({size / 1048576:.1f} MB)")
    for r in reports:
        hist = f", {r['history']} runs in history" if r.get("history", 1) > 1 else ""
        print(f"  {r['label']:<24} {r['grade']:>2} {('' if r['score'] is None else str(r['score'])):>4}  {r['file']}  ({r['subtitle']}{hist})")
    if size > 60 * 1048576:
        print("Note: the portal is large; very big portfolios load faster as separate reports.", file=sys.stderr)
    if args.summary_json:
        atomic_write(args.summary_json, json.dumps(posture(reports, history, max_age), indent=2, ensure_ascii=False))
        print(f"Posture summary: {args.summary_json}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Portal styles and application (same design system as the Guard reports)
# ---------------------------------------------------------------------------

HUB_CSS = ui.asset("portal.css")

HUB_JS = ui.asset("portal.js")


if __name__ == "__main__":
    sys.exit(main())
