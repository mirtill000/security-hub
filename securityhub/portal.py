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

from .common import EXIT_OK, EXIT_USAGE, Parser, atomic_write, grade, json_for_html
from . import inventory, ui

__version__ = "1.2.0"

DATA_RE = re.compile(r'<script type="application/json" id="mg-data">(.*?)</script>', re.S)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S | re.I)
TYPE_ORDER = {"dns": 0, "waf": 1, "zta": 2, "other": 3}
TYPE_LABEL = {"dns": "Email and DNS security", "waf": "Imperva Cloud WAF", "zta": "Microsoft Zero Trust", "other": "Report"}
TIER_W = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Data older than this (days) is flagged as stale: DNS and WAF can be assessed daily, the Zero Trust
# Assessment is a periodic export. Override with --max-age / max_age_days in the configuration.
MAX_AGE_DAYS = {"dns": 2, "waf": 2, "zta": 35}
STATUS_RANK = {"bad": 0, "warn": 1, "good": 2}




def weighted_avg(rows: List[dict], tiers: Dict[str, int]) -> Optional[float]:
    w = sum(tiers.get(r.get("tier", "medium"), 2) for r in rows)
    return sum(r.get("overall_score", 0) * tiers.get(r.get("tier", "medium"), 2) for r in rows) / w if w else None


def detect(payload: Optional[dict], title: str) -> str:
    if isinstance(payload, dict):
        if isinstance(payload.get("tests"), list) and "tenant" in payload:
            return "zta"
        if (payload.get("meta") or {}).get("tool") == "WAFGuard" or "account_issues" in payload:
            return "waf"
        if isinstance(payload.get("results"), list) and "checks" in payload:
            return "dns"
    t = title.lower()
    return "zta" if "zero trust" in t else "waf" if "waf" in t else "dns" if "email security" in t else "other"


def first_issue(r: dict) -> str:
    issues = r.get("issues") or []
    i = next((x for x in issues if x.get("severity") == "critical"), issues[0] if issues else None)
    return (i or {}).get("message", "")


def summarize_assets(kind: str, payload: dict) -> dict:
    rows = payload.get("results") or []
    tiers = payload.get("tiers") or TIER_W
    measured = [r for r in rows if (inventory.dns_measured(r) if kind == "dns" else inventory.waf_measured(r))]
    avg = weighted_avg(measured, tiers)
    sev = Counter(i.get("severity") for r in rows for i in r.get("issues") or [])
    noun = "domains" if kind == "dns" else "websites"
    kpis = [[len(rows), f"{noun} assessed"], *([[len(rows) - len(measured), "not verified (errors)", "warn"]] if len(measured) < len(rows) else []),
            [sum(r.get("overall_score", 0) >= 80 for r in rows), "well protected (80+)", "pass"],
            [sum(r.get("overall_score", 0) < 50 for r in measured), "at critical risk (under 50)", "fail"],
            [sev.get("critical", 0), "critical findings", "fail" if sev.get("critical") else ""]]
    if kind == "waf":
        bypass = sum(r.get("profile") == "bypass" for r in rows)
        if bypass:
            kpis.append([bypass, "in bypass mode", "fail"])
        if payload.get("account_issues"):
            kpis.append([len(payload["account_issues"]), "account findings", "warn"])
    else:
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
    if score is None:
        return "unknown"
    st = "good" if score >= 80 else "warn" if score >= 50 else "bad"
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


def exec_dns(payload: dict) -> dict:
    """E-mail/DNS outcomes. Only measured domains count: not checked or failed lookups are 'not verified', never 'exposed'."""
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
        spoof_kpi = _kpi("spoof", "Domains protected against spoofing", None, "%", "DMARC was not checked in this assessment", 100, area="dns")
    else:
        spoof_kpi = _kpi("spoof", "Domains protected against spoofing", _pct(len(enforced), len(known)), "%",
                         f"{len(enforced)} of {len(known)} verified domains enforce DMARC{note}", 100, area="dns",
                         hash_="#/domains?comp=dmarc_enforcement:fail")
    kpis = [spoof_kpi]
    side = []
    if "dmarc" in checks:
        side.append(["Can be impersonated by email", f"{len(spoofable)} domain{'' if len(spoofable) == 1 else 's'}", "bad" if spoofable else "good"])
    if crit and "dmarc" in checks:
        ok = sum(states[id(r)] == "enforced" for r in crit)
        side.append(["Critical-tier domains protected", f"{ok} of {len(crit)}", "good" if ok == len(crit) else "bad"])
    exposure = False
    if "takeover" in checks:
        tk = [r for r in measured if (r.get("takeover") or {}).get("status") == "error"]
        exposure = bool(tk)
        side.append(["Exposed to takeover of a dependency", f"{len(tk)} domain{'' if len(tk) == 1 else 's'}", "bad" if tk else "good"])
    if "axfr" in checks:
        ax = [r for r in measured if (r.get("axfr") or {}).get("status") == "error"]
        exposure = exposure or bool(ax)
        side.append(["Zone transfer open to anyone", f"{len(ax)} domain{'' if len(ax) == 1 else 's'}", "bad" if ax else "good"])
    if "caa" in checks:
        caa = [r for r in measured if (r.get("caa") or {}).get("status") in ("valid", "warning", "missing")]
        ok = sum((r.get("caa") or {}).get("status") != "missing" for r in caa)
        if caa:
            side.append(["Certificate issuance restricted (CAA)", f"{ok} of {len(caa)}", "good" if ok == len(caa) else "warn"])
    mail = [r for r in measured if r.get("profile") == "mail" and (r.get("dkim") or {}).get("status") not in inventory.UNKNOWN_STATUSES]
    if mail and "dkim" in checks:
        signed = sum((r.get("dkim") or {}).get("status") in ("valid", "partial") for r in mail)
        side.append(["Mail domains signing with DKIM", f"{_pct(signed, len(mail))}%", "good" if signed == len(mail) else "warn"])
    if unverified or len(measured) < len(rows):
        side.append(["Not verified (control not run, DNS errors)", f"{max(unverified, len(rows) - len(measured))} domains", "warn"])
    score = weighted_avg(measured, payload.get("tiers") or TIER_W)
    deltas = [r["change"]["score_delta"] for r in measured if r.get("change") and r["change"].get("score_delta") is not None]
    trend = round(sum(deltas) / len(deltas), 1) if deltas else None
    worst = _pct(len(spoofable), len(known))
    return {"status": _status(score, exposure), "kpis": kpis, "side": side, "trend": trend,
            "actions": _asset_actions("dns", payload, measured),
            "headline": (worst, f"{len(spoofable)} of {len(known)} verified domains ({worst}%) can be impersonated by email")
            if spoofable else None}


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
        side.append(["Not verified (rules not checked, API errors)", f"{unverified} websites", "warn"])
    measured = [r for r in rows if inventory.waf_measured(r)]
    score = weighted_avg(measured, payload.get("tiers") or TIER_W)
    deltas = [r["change"]["score_delta"] for r in measured if r.get("change") and r["change"].get("score_delta") is not None]
    unprot = len(known) - len(protected)
    return {"status": _status(score, bool(bypass)), "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "actions": _asset_actions("waf", payload, measured),
            "headline": (_pct(unprot, len(known)), f"{unprot} of {len(known)} verified websites ({_pct(unprot, len(known))}%) are not "
                         "effectively protected by the WAF") if unprot else None}


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


def _read_report(path: str) -> Tuple[str, Optional[dict]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = DATA_RE.search(text)
    payload = None
    if m:
        try:
            payload = json.loads(m.group(1))
        except ValueError:
            payload = None
    return text, payload


def load_report(path: str, idx: int, keep: bool = True) -> dict:
    """Metadata, summary and executive metrics of a report; with keep=False the page and its parsed data are
    dropped right away (history runs only feed the KPI trends: keeping them would cost hundreds of MB)."""
    text, payload = _read_report(path)
    tm = TITLE_RE.search(text)
    title = html.unescape(tm.group(1).strip()) if tm else os.path.basename(path)
    kind = detect(payload, title)
    summary: Dict[str, Any] = {"score": None, "kpis": [], "top": [], "subtitle": "", "generated": "", "delta": None}
    if payload is not None:
        try:
            summary = summarize_zta(payload) if kind == "zta" else summarize_assets(kind, payload) if kind in ("dns", "waf") else summary
        except Exception as e:  # never fail the hub because of one report
            print(f"Warning: summary of {os.path.basename(path)} not available ({type(e).__name__}: {e})", file=sys.stderr)
    summary["exec"] = None
    if payload is not None and kind in ("dns", "waf", "zta"):
        try:
            summary["exec"] = {"dns": exec_dns, "waf": exec_waf, "zta": exec_zta}[kind](payload)
        except Exception as e:
            print(f"Warning: executive metrics of {os.path.basename(path)} not available ({type(e).__name__}: {e})", file=sys.stderr)
    if not summary.get("generated"):
        summary["generated"] = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    when = parse_date(summary.get("generated", "")) or datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    return {"id": f"r{idx}", "type": kind, "label": TYPE_LABEL[kind], "title": title, "file": os.path.basename(path),
            "date": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "subject": subject_of(kind, payload),
            "size": len(text.encode("utf-8")), "grade": grade(summary["score"]), **summary, "path": path,
            **({"html": text, "payload": payload} if keep else {})}


def find_reports(inputs: List[str], include_all: bool) -> List[str]:
    files: List[str] = []
    for p in inputs:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.lower().endswith((".html", ".htm")):
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
        if not include_all and f not in inputs:
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
                                        "subject": subj, "target": 80, "points": []})["points"].append([r["date"], r["score"]])
            for k in (r.get("exec") or {}).get("kpis", []):
                if k.get("value") is None:
                    continue
                sid = f"{k['key']}|{kind}|{subj}"
                series.setdefault(sid, {"id": sid, "key": k["key"], "label": k["label"], "unit": k["unit"], "area": kind,
                                        "subject": subj, "target": k.get("target"), "points": []})["points"].append([r["date"], k["value"]])
    return current, {"series": list(series.values()), "runs": sorted(runs, key=lambda x: x["date"])}


def build_hub(reports: List[dict], out: str, title: str, history: Optional[dict] = None,
              max_age: Optional[Dict[str, float]] = None) -> int:
    meta = {"version": __version__, "title": title, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "max_age_days": {**MAX_AGE_DAYS, **(max_age or {})},
            "portfolio": portfolio(reports), "history": history or {"series": [], "runs": []},
            "inventory": inventory.build(reports)}
    index = [{k: v for k, v in r.items() if k not in ("html", "payload", "path")} for r in reports]
    blocks = "\n".join(f'<script type="application/json" id="rep-{r["id"]}">{_json_for_html(r["html"])}</script>' for r in reports)
    page = (HUB_TEMPLATE.replace("__TITLE__", html.escape(title or "GuardHub")).replace("__CSS__", HUB_CSS).replace("__JS__", HUB_JS)
            .replace("__DATA__", _json_for_html({"meta": meta, "reports": index}))
            .replace("__REPORTS__", blocks))
    atomic_write(out, page)
    return len(page.encode("utf-8"))


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
    for r in reports:  # only the latest run of each tool is embedded and correlated: load its page again
        r["html"], r["payload"] = _read_report(r["path"])
    reports.sort(key=lambda r: (TYPE_ORDER[r["type"]], r["title"]))
    return reports, history


def parse_max_age(text: str) -> Dict[str, float]:
    """'dns=2,waf=2,zta=35' -> {"dns": 2.0, ...} (unknown areas rejected)."""
    out: Dict[str, float] = {}
    for part in filter(None, (p.strip() for p in (text or "").split(","))):
        k, _, v = part.partition("=")
        if k.strip() not in MAX_AGE_DAYS or not v:
            raise ValueError(f"invalid max age '{part}' (expected e.g. dns=2,waf=2,zta=35)")
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
    return {"status": status, "areas": counts, "stale": stale, "not_verified": unverified,
            "complete": not stale and not unverified}


def posture(reports: List[dict], history: Optional[dict] = None, max_age: Optional[Dict[str, float]] = None,
            now: Optional[datetime] = None) -> dict:
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
        })
    pf = portfolio(reports)
    inv = inventory.build(reports, now)
    assets = [{"asset": a["key"], "status": a["status"], "tier": a["tier"], "score": a["score"], "owners": a["owners"],
               "domains": [d["domain"] for d in a["dns"]], "websites": [w["domain"] for w in a["web"]],
               "next_expiry": a["next_expiry"] and {k: a["next_expiry"][k] for k in ("kind", "name", "date", "days")},
               "signals": [{k: s[k] for k in ("severity", "code", "text")} for s in a["signals"]]}
              for a in inv["assets"]]
    return {"schema": 2, "tool": f"GuardHub {__version__}", "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "overall": overall_status(areas), "summary": pf["sentence"], "counts": pf["counts"],
            "areas": areas, "actions": pf["actions"], "assets": {"summary": inv["summary"], "items": assets},
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
