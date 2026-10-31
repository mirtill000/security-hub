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

from .common import EXIT_OK, EXIT_USAGE, Parser, grade, json_for_html

__version__ = "1.2.0"

DATA_RE = re.compile(r'<script type="application/json" id="mg-data">(.*?)</script>', re.S)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S | re.I)
TYPE_ORDER = {"dns": 0, "waf": 1, "zta": 2, "other": 3}
TYPE_LABEL = {"dns": "Email and DNS security", "waf": "Imperva Cloud WAF", "zta": "Microsoft Zero Trust", "other": "Report"}
TIER_W = {"critical": 4, "high": 3, "medium": 2, "low": 1}




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
    avg = weighted_avg([r for r in rows if r.get("profile") != "nonexistent"], tiers)
    sev = Counter(i.get("severity") for r in rows for i in r.get("issues") or [])
    noun = "domains" if kind == "dns" else "websites"
    kpis = [[len(rows), f"{noun} assessed"],
            [sum(r.get("overall_score", 0) >= 80 for r in rows), "well protected (80+)", "pass"],
            [sum(r.get("overall_score", 0) < 50 for r in rows), "at critical risk (under 50)", "fail"],
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
    rows = [r for r in payload.get("results") or [] if r.get("profile") != "nonexistent"]
    n = len(rows)
    checks = payload.get("checks") or []
    enforced = [r for r in rows if (r.get("dmarc") or {}).get("policy") in ("quarantine", "reject")
                and int((r.get("dmarc") or {}).get("pct") or 100) == 100]
    spoofable = [r for r in rows if (r.get("dmarc") or {}).get("policy") in (None, "", "none")]
    crit = [r for r in rows if r.get("tier") == "critical"]
    kpis = [_kpi("spoof", "Domains protected against spoofing", _pct(len(enforced), n), "%",
                 f"{len(enforced)} of {n} domains enforce DMARC", 100, area="dns", hash_="#/domains?comp=dmarc_enforcement:fail")]
    side = [["Can be impersonated by email", f"{len(spoofable)} domains", "bad" if spoofable else "good"]]
    if crit:
        ok = sum(r in enforced for r in crit)
        side.append(["Critical-tier domains protected", f"{ok} of {len(crit)}", "good" if ok == len(crit) else "bad"])
    exposure = False
    if "takeover" in checks:
        tk = [r for r in rows if (r.get("takeover") or {}).get("status") == "error"]
        exposure = bool(tk)
        side.append(["Exposed to takeover of a dependency", f"{len(tk)} domains", "bad" if tk else "good"])
    mail = [r for r in rows if r.get("profile") == "mail"]
    if mail and "dkim" in checks:
        signed = sum((r.get("dkim") or {}).get("status") in ("valid", "partial") for r in mail)
        side.append(["Mail domains signing with DKIM", f"{_pct(signed, len(mail))}%", "good" if signed == len(mail) else "warn"])
    score = (weighted_avg(rows, payload.get("tiers") or TIER_W))
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    trend = round(sum(deltas) / len(deltas), 1) if deltas else None
    worst = _pct(len(spoofable), n)
    return {"status": _status(score, exposure), "kpis": kpis, "side": side, "trend": trend,
            "actions": _asset_actions("dns", payload, rows),
            "headline": (worst, f"{len(spoofable)} of {n} domains ({worst}%) can be impersonated by email") if spoofable else None}


def exec_waf(payload: dict) -> dict:
    rows = payload.get("results") or []
    n = len(rows)

    def codes(r):
        return {i.get("code") for i in r.get("issues") or []}
    protected = [r for r in rows if r.get("profile") != "bypass" and (r.get("compliance") or {}).get("owasp_block") == "pass"
                 and not codes(r) & {"ORIGIN_EXPOSED", "DNS_NOT_ROUTED", "WAF_POLICY_DISABLED", "ALLOW_BROAD_IP"}]
    kpis = [_kpi("waf", "Websites effectively protected by the WAF", _pct(len(protected), n), "%",
                 f"{len(protected)} of {n} active, blocking attacks, not bypassable", 100, area="waf", hash_="#/domains?comp=owasp_block:fail")]
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
    score = weighted_avg(rows, payload.get("tiers") or TIER_W)
    deltas = [r["change"]["score_delta"] for r in rows if r.get("change") and r["change"].get("score_delta") is not None]
    unprot = n - len(protected)
    return {"status": _status(score, bool(bypass)), "kpis": kpis, "side": side,
            "trend": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "actions": _asset_actions("waf", payload, rows),
            "headline": (_pct(unprot, n), f"{unprot} of {n} websites ({_pct(unprot, n)}%) are not effectively protected by the WAF") if unprot else None}


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


def load_report(path: str, idx: int) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = DATA_RE.search(text)
    payload = None
    if m:
        try:
            payload = json.loads(m.group(1))
        except ValueError:
            payload = None
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
            "size": len(text.encode("utf-8")), "grade": grade(summary["score"]), **summary, "html": text}


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


HUB_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; frame-src blob:">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<div class="app">
  <aside class="side" id="side" aria-label="Reports"></aside>
  <div class="main">
    <header class="topbar" id="topbar"></header>
    <main class="content" id="view" tabindex="-1"></main>
    <div id="frames"></div>
  </div>
</div>
<div id="overlay-root"></div>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<noscript><p style="padding:24px">The portal needs JavaScript.</p></noscript>
<script type="application/json" id="hub-data">__DATA__</script>
__REPORTS__
<script>__JS__</script>
</body>
</html>
"""


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


def build_hub(reports: List[dict], out: str, title: str, history: Optional[dict] = None) -> int:
    meta = {"version": __version__, "title": title, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "portfolio": portfolio(reports), "history": history or {"series": [], "runs": []}}
    index = [{k: v for k, v in r.items() if k != "html"} for r in reports]
    blocks = "\n".join(f'<script type="application/json" id="rep-{r["id"]}">{_json_for_html(r["html"])}</script>' for r in reports)
    page = (HUB_TEMPLATE.replace("__TITLE__", html.escape(title or "GuardHub")).replace("__CSS__", HUB_CSS).replace("__JS__", HUB_JS)
            .replace("__DATA__", _json_for_html({"meta": meta, "reports": index}))
            .replace("__REPORTS__", blocks))
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    return len(page.encode("utf-8"))


def build_parser() -> Parser:
    p = Parser(description="Combine MailGuard DNS, WAFGuard and ZTAGuard HTML reports into one navigable portal")
    p.add_argument("inputs", nargs="+", help="HTML report files and/or folders containing them")
    p.add_argument("-o", "--output", default="security_hub.html", help="Output file (default: security_hub.html)")
    p.add_argument("--title", default="", help="Optional portal title, e.g. organization and period")
    p.add_argument("--all", action="store_true", help="In folders, also embed HTML files that are not Guard reports")
    p.add_argument("--summary-json", metavar="FILE", help="Also write a machine-readable posture summary (JSON)")
    p.add_argument("--version", action="version", version=f"GuardHub {__version__}")
    return p


def collect(inputs: List[str], include_all: bool = False, exclude: Optional[List[str]] = None) -> Tuple[List[dict], dict]:
    """Load every report found in `inputs`: returns (latest report per tool/subject, KPI history)."""
    files = find_reports(inputs, include_all)
    skip = {os.path.realpath(x) for x in exclude or []}
    files = [f for f in files if os.path.realpath(f) not in skip]
    loaded = [load_report(f, i) for i, f in enumerate(files)]
    reports, history = split_history(loaded)
    reports.sort(key=lambda r: (TYPE_ORDER[r["type"]], r["title"]))
    return reports, history


def posture(reports: List[dict], history: Optional[dict] = None) -> dict:
    """Machine-readable posture summary (for monitoring, SIEM ingestion or CI gates)."""
    areas = []
    for r in reports:
        ex = r.get("exec") or {}
        areas.append({
            "area": r["type"], "label": r["label"], "title": r["title"], "file": r["file"], "date": r["date"],
            "subject": r.get("subject", ""), "score": r.get("score"), "grade": r.get("grade"),
            "status": ex.get("status"), "headline": (ex.get("headline") or [None, None])[1],
            "kpis": [{k: v for k, v in kpi.items() if k in ("key", "label", "value", "unit", "detail", "target", "trend")}
                     for kpi in ex.get("kpis", [])],
            "actions": ex.get("actions", [])[:5],
        })
    pf = portfolio(reports)
    scores = [a["score"] for a in areas if a["score"] is not None]
    overall = round(sum(scores) / len(scores)) if scores else None
    return {"tool": f"GuardHub {__version__}", "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "overall_score": overall, "overall_grade": grade(overall), "summary": pf["sentence"], "counts": pf["counts"],
            "areas": areas, "actions": pf["actions"], "runs": (history or {}).get("runs", [])}


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
    size = build_hub(reports, args.output, args.title, history)
    print(f"Portal generated: {args.output} ({size / 1048576:.1f} MB)")
    for r in reports:
        hist = f", {r['history']} runs in history" if r.get("history", 1) > 1 else ""
        print(f"  {r['label']:<24} {r['grade']:>2} {('' if r['score'] is None else str(r['score'])):>4}  {r['file']}  ({r['subtitle']}{hist})")
    if size > 60 * 1048576:
        print("Note: the portal is large; very big portfolios load faster as separate reports.", file=sys.stderr)
    if args.summary_json:
        with open(args.summary_json, "w", encoding="utf-8") as f:
            json.dump(posture(reports, history), f, indent=2, ensure_ascii=False)
        print(f"Posture summary: {args.summary_json}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Portal styles and application (same design system as the Guard reports)
# ---------------------------------------------------------------------------

HUB_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #0e1116; --panel: #151a21; --panel-2: #1a2029; --raised: #1f2632; --hover: #1d2430; --line: #242b36; --line-2: #333c4a;
  --text: #e6e9ef; --muted: #8f99a9; --faint: #687283; --accent: #8b95ff; --accent-strong: #a9b0ff; --accent-ink: #0b0e2a;
  --accent-soft: rgba(139, 149, 255, .14);
  --pass: #009e73; --pass-ink: #ffffff; --pass-text: #3cc79d;
  --warn: #e69f00; --warn-ink: #1d1400; --warn-text: #f0b43a;
  --fail: #d55e00; --fail-ink: #ffffff; --fail-text: #ff8a4c;
  --info: #56b4e9; --info-text: #7cc6ef;
  --null: #0072b2; --null-ink: #ffffff; --null-text: #5aa8d6;
  --dns: #cc79a7; --dns-ink: #1f0b16; --dns-text: #df9cc1;
  --none: #3a4352; --none-ink: #c9d0da; --none-text: #9aa4b2;
  --na: #222934; --na-ink: #6a7484;
  --shadow: 0 18px 48px rgba(0, 0, 0, .45), 0 2px 8px rgba(0, 0, 0, .3);
  --r-lg: 12px; --r: 8px; --r-sm: 5px;
  --font: "Inter", "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, monospace;
  --side-w: 236px; --top-h: 58px;
}
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f4f5f8; --panel: #ffffff; --panel-2: #f8f9fb; --raised: #ffffff; --hover: #f1f3f7; --line: #e3e6ec; --line-2: #ccd3dc;
  --text: #121821; --muted: #566273; --faint: #7d8796; --accent: #4b55d6; --accent-strong: #3640c2; --accent-ink: #ffffff;
  --accent-soft: rgba(75, 85, 214, .10);
  --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --info-text: #1f6f9e; --null-text: #005d91;
  --dns-text: #9b4a77; --none: #ccd3dc; --none-ink: #2d3644; --none-text: #566273; --na: #eceff4; --na-ink: #7d8796;
  --shadow: 0 18px 44px rgba(16, 24, 40, .14), 0 2px 6px rgba(16, 24, 40, .06);
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    color-scheme: light;
    --bg: #f4f5f8; --panel: #ffffff; --panel-2: #f8f9fb; --raised: #ffffff; --hover: #f1f3f7; --line: #e3e6ec; --line-2: #ccd3dc;
    --text: #121821; --muted: #566273; --faint: #7d8796; --accent: #4b55d6; --accent-strong: #3640c2; --accent-ink: #ffffff;
    --accent-soft: rgba(75, 85, 214, .10);
    --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --info-text: #1f6f9e; --null-text: #005d91;
    --dns-text: #9b4a77; --none: #ccd3dc; --none-ink: #2d3644; --none-text: #566273; --na: #eceff4; --na-ink: #7d8796;
    --shadow: 0 18px 44px rgba(16, 24, 40, .14), 0 2px 6px rgba(16, 24, 40, .06);
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 var(--font); font-feature-settings: "cv11", "ss01"; }
body.locked { overflow: hidden; }
a { color: var(--accent); }
code, pre, .mono { font-family: var(--mono); font-size: 12.5px; }
h1, h2, h3, h4 { margin: 0; line-height: 1.25; font-weight: 600; letter-spacing: -.005em; }
p { margin: 0; }
button, input, select { font: inherit; color: inherit; }
button { cursor: pointer; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
.num { font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); } .faint { color: var(--faint); } .nowrap { white-space: nowrap; }
.ico { flex: none; display: block; }
.skip { position: absolute; left: 8px; top: -40px; z-index: 100; background: var(--accent); color: var(--accent-ink); border: 0; padding: 8px 12px; border-radius: var(--r); }
.skip:focus { top: 8px; }

/* ---------- application frame ---------- */
.app { display: grid; grid-template-columns: var(--side-w) minmax(0, 1fr); min-height: 100vh; }
.side { position: sticky; top: 0; height: 100vh; border-right: 1px solid var(--line); background: var(--panel); display: flex; flex-direction: column; overflow-y: auto; }
.brand { display: flex; gap: 10px; align-items: center; padding: 16px 18px 14px; }
.brand-mark { width: 30px; height: 30px; border-radius: 8px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent); }
.brand b { display: block; font-size: 14px; }
.brand small { display: block; color: var(--faint); font-size: 11.5px; }
.posture { margin: 4px 12px 10px; padding: 12px; border: 1px solid var(--line); border-radius: var(--r); display: flex; gap: 12px; align-items: center; background: var(--panel-2); }
.posture .letter { font-size: 30px; font-weight: 700; line-height: 1; width: 34px; text-align: center; }
.posture span { display: block; font-size: 12px; color: var(--muted); line-height: 1.35; }
.posture b { font-size: 13px; }
.nav { display: flex; flex-direction: column; gap: 1px; padding: 6px 10px; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: var(--r); border: 0; background: none; color: var(--muted); text-align: left; width: 100%; }
.nav-item:hover { background: var(--hover); color: var(--text); }
.nav-item[aria-current="page"] { background: var(--accent-soft); color: var(--text); }
.nav-item[aria-current="page"] .ico { color: var(--accent); }
.nav-item .count { margin-left: auto; font-size: 12px; color: var(--faint); font-variant-numeric: tabular-nums; }
.side-foot { margin-top: auto; padding: 10px; border-top: 1px solid var(--line); display: grid; gap: 1px; }
.main { min-width: 0; display: flex; flex-direction: column; }
.topbar { position: sticky; top: 0; z-index: 20; height: var(--top-h); display: flex; align-items: center; gap: 12px; padding: 0 28px;
          border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--bg) 86%, transparent); backdrop-filter: blur(10px); }
.topbar h1 { font-size: 16px; }
.topbar .sub { color: var(--muted); font-size: 13px; }
.topbar .spacer { flex: 1; }
.cmdk { display: flex; align-items: center; gap: 10px; width: 340px; max-width: 40vw; padding: 7px 10px; border: 1px solid var(--line-2); border-radius: var(--r); background: var(--panel); color: var(--faint); }
.cmdk:hover { border-color: var(--accent); color: var(--muted); }
.cmdk .lbl { flex: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kbd { font-family: var(--font); font-size: 11px; border: 1px solid var(--line-2); border-bottom-width: 2px; border-radius: 4px; padding: 0 5px; color: var(--muted); background: var(--panel-2); white-space: nowrap; }
.content { padding: 24px 28px 64px; width: 100%; max-width: 1480px; }
.content:focus { outline: none; }

/* ---------- controls ---------- */
.btn { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--line-2); background: var(--panel); border-radius: var(--r); padding: 6px 12px; line-height: 1.3; white-space: nowrap; }
.btn:hover { background: var(--hover); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.btn.primary:hover { background: var(--accent-strong); }
.btn.ghost { border-color: transparent; background: none; color: var(--muted); }
.btn.ghost:hover { background: var(--hover); color: var(--text); }
.btn.icon { padding: 6px; }
.btn.small { padding: 3px 9px; font-size: 12.5px; }
.btn[aria-pressed="true"] { background: var(--accent-soft); border-color: var(--accent); color: var(--text); }
.btn:disabled { opacity: .4; cursor: default; }
.btn .badge-n { background: var(--accent); color: var(--accent-ink); border-radius: 999px; font-size: 11px; padding: 0 6px; font-weight: 600; }
.seg { display: inline-flex; border: 1px solid var(--line-2); border-radius: var(--r); padding: 2px; background: var(--panel); }
.seg button { border: 0; background: none; padding: 4px 10px; border-radius: 6px; color: var(--muted); }
.seg button[aria-pressed="true"] { background: var(--raised); color: var(--text); box-shadow: 0 0 0 1px var(--line-2); }
input[type="search"], input[type="number"], select { background: var(--panel); border: 1px solid var(--line-2); border-radius: var(--r); padding: 6px 9px; min-width: 0; color: var(--text); }
input[type="number"] { width: 76px; }
input[type="checkbox"] { accent-color: var(--accent); width: 15px; height: 15px; margin: 0; vertical-align: -2px; }
.search-box { position: relative; display: flex; align-items: center; }
.search-box .ico { position: absolute; left: 9px; color: var(--faint); pointer-events: none; }
.search-box input { padding-left: 32px; width: 300px; max-width: 100%; }
label.field { display: grid; gap: 4px; font-size: 12.5px; color: var(--muted); }
label.check { display: inline-flex; gap: 8px; align-items: center; font-size: 13px; color: var(--text); }
.link { background: none; border: 0; padding: 0; color: var(--accent); text-align: left; }
.link:hover { text-decoration: underline; }

/* ---------- cards ---------- */
.card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r-lg); min-width: 0; }
.card > header { display: flex; align-items: baseline; gap: 10px; padding: 14px 18px 0; }
.card > header h2 { font-size: 14px; }
.card > header p { color: var(--faint); font-size: 12.5px; }
.card > header .act { margin-left: auto; }
.card .body { padding: 14px 18px 16px; }
.section-title { display: flex; align-items: baseline; gap: 12px; margin: 0 0 14px; }
.section-title h2 { font-size: 18px; }
.section-title p { color: var(--muted); font-size: 13px; }

/* ---------- overview ---------- */
.ov-top { display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 16px; margin-bottom: 16px; }
.grade-card { padding: 20px 22px; display: grid; grid-template-columns: auto 1fr; gap: 6px 18px; align-items: center; }
.grade-card .letter { font-size: 92px; font-weight: 700; line-height: .85; letter-spacing: -3px; grid-row: span 3; }
.g-A, .g-B { color: var(--pass-text); } .g-C { color: var(--warn-text); } .g-D, .g-F { color: var(--fail-text); }
.grade-card .lbl { color: var(--muted); font-size: 12.5px; }
.grade-card .avg { font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; }
.grade-card .avg small { font-size: 13px; color: var(--muted); font-weight: 400; }
.delta-up { color: var(--pass-text); } .delta-down { color: var(--fail-text); }
.kpi-card { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }
.kpi { border: 0; background: none; text-align: left; padding: 18px 20px; border-right: 1px solid var(--line); color: inherit; }
.kpi:last-child { border-right: 0; }
.kpi:hover { background: var(--hover); }
.kpi b { display: block; font-size: 28px; font-weight: 650; line-height: 1.1; font-variant-numeric: tabular-nums; }
.kpi span { font-size: 12.5px; color: var(--muted); }
.kpi.k-pass b { color: var(--pass-text); } .kpi.k-warn b { color: var(--warn-text); } .kpi.k-fail b { color: var(--fail-text); }
.ov-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.ov-grid .span2 { grid-column: span 2; } .ov-grid .span3 { grid-column: 1 / -1; }
.cov { display: grid; gap: 9px; }
.cov-row { display: grid; grid-template-columns: 92px minmax(0, 1fr) 48px; gap: 12px; align-items: center; font-size: 13px; }
.cov-bar { display: flex; height: 14px; border-radius: 4px; overflow: hidden; gap: 2px; }
.cov-bar button { border: 0; padding: 0; min-width: 4px; height: 100%; }
.cov-bar button:hover { filter: brightness(1.18); }
.cov-num { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 12px; color: var(--muted); margin-top: 12px; }
.legend span { display: inline-flex; gap: 6px; align-items: center; }
.dot { width: 10px; height: 10px; border-radius: 3px; display: inline-block; flex: none; }
.hist { width: 100%; height: auto; display: block; }
.hist rect.hbar { cursor: pointer; }
.hist rect.hbar:hover, .hist rect.hbar:focus { filter: brightness(1.2); outline: none; }
.hist line { stroke: var(--line-2); }
.hist text { fill: var(--faint); font-size: 10px; font-family: var(--font); }
.hist text.v { fill: var(--muted); font-size: 10.5px; }
.rm { display: grid; gap: 4px; font-size: 12.5px; }
.rm-row { display: grid; grid-template-columns: 70px repeat(3, minmax(0, 1fr)); gap: 4px; align-items: center; }
.rm-head { color: var(--faint); text-align: center; }
.rm-cell { border: 0; border-radius: 6px; height: 40px; font-weight: 650; font-size: 14px; font-variant-numeric: tabular-nums; color: var(--text); }
.rm-cell.zero { color: var(--faint); font-weight: 400; }
.rows { list-style: none; margin: 0; padding: 0; }
.rows li + li { border-top: 1px solid var(--line); }
.rows .r-btn { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 2px 12px; width: 100%; text-align: left; border: 0; background: none; padding: 9px 4px; color: inherit; border-radius: 6px; }
.rows .r-btn:hover { background: var(--hover); }
.rows .r-main { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rows .r-sub { grid-column: 1; font-size: 12.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rows .r-val { grid-row: span 2; align-self: center; text-align: right; }
.bar-row { display: grid; grid-template-columns: minmax(110px, 1fr) 1.6fr 4.6em; gap: 10px; align-items: center; font-size: 13px; padding: 4px 0; }
.bar-row > :last-child { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
button.bar-row { border: 0; background: none; width: 100%; text-align: left; color: inherit; border-radius: 6px; }
button.bar-row:hover { background: var(--hover); }
.bar { height: 8px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 5px; overflow: hidden; display: flex; }
.bar i { display: block; height: 100%; }
.b-pass { background: var(--pass); } .b-warn { background: var(--warn); } .b-fail { background: var(--fail); } .b-dns { background: var(--dns); } .b-acc { background: var(--accent); }
.stat-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
.stat { border: 1px solid var(--line); border-radius: var(--r); padding: 10px 12px; background: var(--panel-2); text-align: left; color: inherit; }
button.stat:hover { border-color: var(--line-2); background: var(--hover); }
.stat b { display: block; font-size: 20px; font-variant-numeric: tabular-nums; }
.stat span { font-size: 12px; color: var(--muted); }

/* ---------- status ---------- */
.pill { display: inline-flex; align-items: center; gap: 5px; border-radius: var(--r-sm); padding: 1px 8px; font-size: 12.5px; font-weight: 600; white-space: nowrap; border: 1px solid transparent; line-height: 1.55; }
.pill .sym { font-weight: 700; }
.pill .d { font-weight: 400; opacity: .85; }
.s-pass { background: color-mix(in srgb, var(--pass) 16%, transparent); color: var(--pass-text); border-color: color-mix(in srgb, var(--pass) 38%, transparent); }
.s-warn { background: color-mix(in srgb, var(--warn) 16%, transparent); color: var(--warn-text); border-color: color-mix(in srgb, var(--warn) 38%, transparent); }
.s-fail { background: color-mix(in srgb, var(--fail) 16%, transparent); color: var(--fail-text); border-color: color-mix(in srgb, var(--fail) 38%, transparent); }
.s-null { background: color-mix(in srgb, var(--null) 18%, transparent); color: var(--null-text); border-color: color-mix(in srgb, var(--null) 42%, transparent); }
.s-dns { background: color-mix(in srgb, var(--dns) 16%, transparent); color: var(--dns-text); border-color: color-mix(in srgb, var(--dns) 38%, transparent); }
.s-none { background: color-mix(in srgb, var(--none) 42%, transparent); color: var(--none-text); }
.s-na { background: transparent; color: var(--faint); border-color: var(--line); }
.c-pass { background: var(--pass); color: var(--pass-ink); } .c-warn { background: var(--warn); color: var(--warn-ink); }
.c-fail { background: var(--fail); color: var(--fail-ink); } .c-null { background: var(--null); color: var(--null-ink); }
.c-dns { background: var(--dns); color: var(--dns-ink); } .c-none { background: var(--none); color: var(--none-ink); }
.c-na { background: var(--na); color: var(--na-ink); }
.sq { display: inline-grid; place-items: center; width: 24px; height: 22px; border-radius: 5px; font-weight: 700; font-size: 12px; }
.sev { display: inline-block; width: 8px; height: 8px; border-radius: 2px; flex: none; }
.sev-critical { background: var(--fail); } .sev-warning { background: var(--warn); } .sev-info { background: var(--info); }
.score { font-weight: 700; font-variant-numeric: tabular-nums; }
.score.hi { color: var(--pass-text); } .score.mid { color: var(--warn-text); } .score.lo { color: var(--fail-text); }
.tag { display: inline-block; font-size: 11.5px; border: 1px solid var(--line-2); border-radius: 999px; padding: 0 8px; color: var(--muted); white-space: nowrap; }
.tier-critical { color: var(--fail-text); border-color: color-mix(in srgb, var(--fail) 45%, transparent); }
.tier-high { color: var(--warn-text); border-color: color-mix(in srgb, var(--warn) 45%, transparent); }

/* ---------- domains ---------- */
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.toolbar .spacer { flex: 1; }
.presets { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
.preset { border: 1px solid var(--line-2); background: var(--panel); border-radius: 999px; padding: 3px 12px; font-size: 12.5px; color: var(--muted); }
.preset:hover { color: var(--text); border-color: var(--accent); }
.preset[aria-pressed="true"] { background: var(--accent-soft); border-color: var(--accent); color: var(--text); }
.preset .n { color: var(--faint); margin-left: 4px; font-variant-numeric: tabular-nums; }
.filter-panel { border: 1px solid var(--line); background: var(--panel); border-radius: var(--r-lg); padding: 14px; margin-bottom: 10px;
                display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }
.filter-panel .range { display: flex; gap: 6px; align-items: center; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 10px; min-height: 26px; font-size: 13px; color: var(--muted); }
.chip { display: inline-flex; align-items: center; gap: 4px; border: 1px solid var(--line-2); background: var(--panel); border-radius: 999px; padding: 1px 4px 1px 10px; font-size: 12.5px; color: var(--text); }
.chip button { border: 0; background: none; color: var(--muted); padding: 0 4px; border-radius: 999px; }
.chip button:hover { color: var(--text); background: var(--hover); }
.selbar { display: flex; align-items: center; gap: 10px; padding: 8px 12px; margin-bottom: 10px; border-radius: var(--r); background: var(--accent-soft); border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent); font-size: 13px; }
.menu { position: relative; }
.menu-pop { position: absolute; right: 0; top: calc(100% + 6px); z-index: 30; min-width: 220px; background: var(--raised); border: 1px solid var(--line-2); border-radius: var(--r); box-shadow: var(--shadow); padding: 6px; display: grid; gap: 1px; }
.menu-pop .mi { display: flex; gap: 10px; align-items: center; border: 0; background: none; text-align: left; padding: 7px 10px; border-radius: 6px; color: var(--text); width: 100%; }
.menu-pop .mi:hover { background: var(--hover); }
.menu-pop .mi small { margin-left: auto; color: var(--faint); }
.menu-pop .sep { height: 1px; background: var(--line); margin: 4px 0; }
.menu-pop label.check { padding: 5px 10px; }
.grid-wrap { border: 1px solid var(--line); border-radius: var(--r-lg); background: var(--panel); overflow: auto; max-height: calc(100vh - var(--top-h) - 230px); min-height: 260px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; }
table.grid th, table.grid td { padding: 10px 12px; text-align: left; vertical-align: middle; border-bottom: 1px solid var(--line); background: var(--panel); }
table.grid.compact th, table.grid.compact td { padding: 5px 10px; }
table.grid thead th { position: sticky; top: 0; z-index: 2; font-size: 12px; font-weight: 600; color: var(--muted); background: var(--panel-2); white-space: nowrap; }
table.grid .sticky { position: sticky; left: 0; z-index: 1; }
table.grid thead .sticky { z-index: 3; }
table.grid tbody tr { cursor: pointer; }
table.grid tbody tr:hover td { background: var(--hover); }
table.grid tbody tr.cursor td { box-shadow: inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
table.grid tbody tr.cursor td:first-child { box-shadow: inset 2px 0 0 var(--accent), inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
table.grid tbody tr.active td { background: var(--accent-soft); }
table.grid tbody tr:last-child td { border-bottom: 0; }
th .sort { background: none; border: 0; padding: 0; color: inherit; font-weight: 600; display: inline-flex; gap: 4px; align-items: center; }
th .sort:hover { color: var(--text); }
th[aria-sort="ascending"] .sort::after { content: "\2191"; color: var(--accent); }
th[aria-sort="descending"] .sort::after { content: "\2193"; color: var(--accent); }
th.c, td.c { text-align: center; } th.r, td.r { text-align: right; }
.dom { border: 0; background: none; padding: 0; color: var(--text); font-weight: 600; text-align: left; word-break: break-all; }
.dom:hover { color: var(--accent); }
.dom-sub { font-size: 12px; color: var(--faint); margin-top: 1px; }
.cell-domain { display: flex; gap: 12px; align-items: flex-start; min-width: 220px; }
.scorecell { display: flex; align-items: center; gap: 8px; justify-content: flex-end; }
.mini { width: 42px; height: 4px; border-radius: 2px; background: var(--panel-2); overflow: hidden; border: 1px solid var(--line); }
.mini i { display: block; height: 100%; }
.mini .hi { background: var(--pass); } .mini .mid { background: var(--warn); } .mini .lo { background: var(--fail); }
.counts { display: inline-flex; gap: 6px; }
.cnt { font-size: 12px; font-weight: 600; border-radius: 4px; padding: 0 6px; font-variant-numeric: tabular-nums; }
.cnt.crit { color: var(--fail-text); background: color-mix(in srgb, var(--fail) 16%, transparent); }
.cnt.warn { color: var(--warn-text); background: color-mix(in srgb, var(--warn) 16%, transparent); }
.heat { display: grid; gap: 3px; padding: 12px; min-width: calc(220px + var(--cols) * 40px + 60px); }
.heat-row { display: grid; grid-template-columns: minmax(180px, 260px) repeat(var(--cols), minmax(34px, 1fr)) 52px; gap: 3px; align-items: center; }
.heat-head { position: sticky; top: 0; z-index: 2; background: var(--panel); padding: 4px 0 6px; }
.heat-head div { font-size: 11.5px; color: var(--muted); text-align: center; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.heat-head div:first-child { text-align: left; }
.heat-row .dom { font-weight: 500; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cell { height: 30px; border: 0; border-radius: 4px; font-weight: 700; font-size: 13px; padding: 0; }
.cell:hover { filter: brightness(1.15); }
.heat-row .score { text-align: right; padding-right: 6px; }
.pager { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; padding: 12px 2px; font-size: 13px; color: var(--muted); }
.pager .pages { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
.pager .btn[aria-current="page"] { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.empty { padding: 48px 24px; text-align: center; color: var(--muted); }
.empty b { display: block; color: var(--text); font-size: 15px; margin-bottom: 6px; }

/* ---------- findings ---------- */
.flist { display: grid; gap: 8px; }
.finding { border: 1px solid var(--line); border-radius: var(--r); background: var(--panel); }
.finding > summary { list-style: none; display: grid; grid-template-columns: auto minmax(0, 1fr) 140px 64px auto; gap: 14px; align-items: center; padding: 12px 14px; cursor: pointer; }
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary:hover { background: var(--hover); border-radius: var(--r); }
.finding[open] > summary { border-bottom: 1px solid var(--line); border-radius: var(--r) var(--r) 0 0; }
.finding .ttl b { display: block; }
.finding .ttl span { font-size: 12.5px; color: var(--muted); }
.finding .chev { color: var(--faint); transition: transform .15s; }
.finding[open] .chev { transform: rotate(90deg); }
.finding .fbody { padding: 12px 14px 14px 36px; display: grid; gap: 10px; font-size: 13px; }
.dlist { display: flex; flex-wrap: wrap; gap: 6px; }
.dlist button { border: 1px solid var(--line-2); background: var(--panel-2); border-radius: 6px; padding: 2px 8px; font-size: 12.5px; color: var(--text); }
.dlist button:hover { border-color: var(--accent); }
.fw { display: flex; flex-wrap: wrap; gap: 6px; }

/* ---------- drawer ---------- */
.scrim { position: fixed; inset: 0; background: rgba(4, 7, 12, .55); z-index: 40; }
:root[data-theme="light"] .scrim { background: rgba(16, 24, 40, .28); }
.drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(880px, 100vw); z-index: 41; background: var(--bg); border-left: 1px solid var(--line-2);
          box-shadow: var(--shadow); display: flex; flex-direction: column; }
.dr-head { background: var(--panel); border-bottom: 1px solid var(--line); padding: 10px 24px 0; }
.dr-nav { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12.5px; }
.dr-nav .spacer { flex: 1; }
.dr-id { display: flex; gap: 16px; align-items: center; padding: 12px 0 14px; }
.dr-id h2 { font-size: 22px; word-break: break-all; }
.dr-id .meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; align-items: center; }
.dr-id .meta .t { font-size: 12.5px; color: var(--faint); }
.ring { flex: none; }
.ring .ring-bg { fill: none; stroke: var(--line-2); stroke-width: 6; }
.ring .ring-fg { fill: none; stroke-width: 6; stroke-linecap: round; }
.ring.hi .ring-fg { stroke: var(--pass); } .ring.mid .ring-fg { stroke: var(--warn); } .ring.lo .ring-fg { stroke: var(--fail); }
.ring text { fill: var(--text); font-size: 17px; font-weight: 700; font-family: var(--font); }
.dr-tabs { display: flex; gap: 2px; overflow-x: auto; margin: 0 -6px; }
.dr-tabs button { border: 0; background: none; padding: 9px 12px; color: var(--muted); border-bottom: 2px solid transparent; white-space: nowrap; }
.dr-tabs button:hover { color: var(--text); }
.dr-tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.dr-tabs .n { font-size: 11.5px; color: var(--faint); margin-left: 4px; }
.dr-body { overflow-y: auto; padding: 20px 24px 40px; display: grid; gap: 16px; align-content: start; }
.dr-cols { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }
.dr-sec { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r-lg); padding: 16px 18px; min-width: 0; }
.dr-sec > h3 { font-size: 14px; margin-bottom: 12px; display: flex; gap: 8px; align-items: center; }
.dr-sec > h3 .act { margin-left: auto; }
.dr-sec table th, .dr-sec table td { padding: 7px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
.dr-sec table thead th { color: var(--muted); font-size: 12px; font-weight: 600; }
.dr-sec table tbody tr:last-child td { border-bottom: 0; }
.dr-print-title { display: none; }
.ctl-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(178px, 1fr)); gap: 8px; }
.ctl { display: grid; justify-items: start; gap: 6px; min-width: 0; font-size: 12.5px; color: var(--muted) !important; border: 1px solid var(--line); background: var(--panel-2); border-radius: var(--r); padding: 8px 10px; text-align: left; color: var(--text); }
.ctl:hover { border-color: var(--line-2); background: var(--hover); }
.ctl .pill { max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
.kv { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px 20px; font-size: 13px; }
.kv div span { display: block; color: var(--muted); font-size: 12px; }
.kv div b { font-weight: 600; word-break: break-word; }
pre.record { background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--r); padding: 10px 12px; margin: 0 0 12px; white-space: pre-wrap; word-break: break-all; }
.issue { display: grid; grid-template-columns: 14px minmax(0, 1fr); gap: 2px 10px; padding: 11px 0; border-bottom: 1px solid var(--line); }
.issue:last-child { border-bottom: 0; }
.issue .sev { margin-top: 6px; }
.issue .msg { font-weight: 600; word-break: break-word; }
.issue .proto { font-size: 12px; color: var(--faint); }
.issue .rec { grid-column: 2; font-size: 13px; color: var(--muted); }
.issue .fw { grid-column: 2; margin-top: 4px; }
.fix { padding: 14px 0; border-bottom: 1px solid var(--line); }
.fix:first-child { padding-top: 0; } .fix:last-child { border-bottom: 0; padding-bottom: 0; }
.fix h4 { font-size: 14px; margin-bottom: 6px; }
.fix .where { font-size: 12.5px; color: var(--muted); margin-bottom: 6px; word-break: break-all; }
.fix .rowx { display: flex; gap: 8px; align-items: flex-start; }
.fix pre.record { flex: 1; margin: 0; }
.fix .note { font-size: 12.5px; color: var(--muted); margin-top: 6px; }
.tree { font-family: var(--mono); font-size: 12px; line-height: 1.75; }
details.more > summary { cursor: pointer; color: var(--muted); font-size: 13px; margin-top: 12px; }
.note-box { border-left: 3px solid var(--warn); background: color-mix(in srgb, var(--warn) 9%, transparent); padding: 10px 14px; border-radius: 0 var(--r) var(--r) 0; font-size: 13px; }
.sub { font-size: 12px; color: var(--muted); }

/* ---------- overlays ---------- */
.overlay { position: fixed; inset: 0; z-index: 60; background: rgba(4, 7, 12, .5); display: flex; align-items: flex-start; justify-content: center; padding-top: 12vh; }
:root[data-theme="light"] .overlay { background: rgba(16, 24, 40, .25); }
.dialog { width: min(640px, 92vw); max-height: 72vh; background: var(--raised); border: 1px solid var(--line-2); border-radius: var(--r-lg); box-shadow: var(--shadow); display: flex; flex-direction: column; overflow: hidden; }
.dialog > header { display: flex; align-items: center; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.dialog > header h2 { font-size: 15px; flex: 1; }
.dialog .dbody { padding: 14px 16px 18px; overflow-y: auto; font-size: 13.5px; }
.pal-input { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--line); color: var(--faint); }
.pal-input input { flex: 1; border: 0; background: none; font-size: 15px; color: var(--text); outline: none; padding: 4px 0; }
.pal-list { list-style: none; margin: 0; padding: 6px; overflow-y: auto; }
.pal-group { font-size: 11.5px; color: var(--faint); padding: 8px 10px 4px; }
.pal-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: 6px; cursor: pointer; }
.pal-item[aria-selected="true"] { background: var(--accent-soft); }
.pal-item .ptitle { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pal-item .phint { font-size: 12px; color: var(--faint); }
.pal-foot { display: flex; gap: 14px; padding: 8px 16px; border-top: 1px solid var(--line); font-size: 12px; color: var(--faint); }
.keys { width: 100%; border-collapse: collapse; }
.keys td { padding: 6px 4px; border-bottom: 1px solid var(--line); }
.keys td:first-child { width: 140px; }
.toasts { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); z-index: 80; display: grid; gap: 8px; }
.toast { background: var(--raised); border: 1px solid var(--line-2); box-shadow: var(--shadow); border-radius: var(--r); padding: 9px 14px; font-size: 13px; }

/* ---------- responsive ---------- */
@media (max-width: 1180px) {
  .ov-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-grid .span2 { grid-column: 1 / -1; }
  .cmdk { min-width: 0; }
  .cmdk .lbl { display: none; }
  .cmdk { width: auto; }
}
@media (max-width: 860px) {
  .app { grid-template-columns: 1fr; }
  .side { position: static; height: auto; flex-direction: row; align-items: center; overflow-x: auto; border-right: 0; border-bottom: 1px solid var(--line); }
  .brand { padding: 10px 12px; } .brand small, .posture, .side-foot { display: none; }
  .nav { flex-direction: row; padding: 6px; }
  .nav-item { width: auto; white-space: nowrap; }
  .nav-item .count { display: none; }
  .topbar { padding: 0 14px; position: static; }
  .topbar .sub { display: none; }
  .content { padding: 16px 14px 48px; }
  .ov-top, .ov-grid, .dr-cols { grid-template-columns: 1fr; }
  .kpi { border-right: 0; border-bottom: 1px solid var(--line); }
  .search-box input { width: 100%; }
  .finding > summary { grid-template-columns: auto minmax(0, 1fr) auto; }
  .finding > summary .fbar, .finding > summary .chev { display: none; }
  .drawer { width: 100vw; }
  .dr-head, .dr-body { padding-left: 14px; padding-right: 14px; }
  .grid-wrap { max-height: none; }
}
@media (prefers-reduced-motion: no-preference) {
  .drawer.enter { animation: slide-in .18s ease-out; }
  .scrim.enter, .overlay { animation: fade-in .15s ease-out; }
  .toast { animation: fade-in .15s ease-out; }
  @keyframes slide-in { from { transform: translateX(32px); } to { transform: none; } }
  @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
}

/* ---------- print ---------- */
@media print {
  :root, :root[data-theme] { color-scheme: light; --bg: #fff; --panel: #fff; --panel-2: #f3f5f8; --raised: #fff; --hover: #fff; --line: #d9dee5; --line-2: #c3cad4;
    --text: #111; --muted: #444; --faint: #666; --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --null-text: #005d91;
    --dns-text: #9b4a77; --none: #d4d9e0; --none-ink: #222; --na: #eef1f4; --na-ink: #666; --accent: #3640c2; --accent-soft: #eef0ff; --shadow: none; }
  body { font-size: 11px; }
  .side, .topbar, .toolbar, .presets, .filter-panel, .chips, .selbar, .pager, .no-print, .toasts, #overlay-root, .copy, .dr-nav, .dr-tabs { display: none !important; }
  .app { display: block; }
  .content { padding: 0; max-width: none; }
  .card, .dr-sec, .finding { break-inside: avoid; }
  .grid-wrap { max-height: none; overflow: visible; border: 0; }
  table.grid thead th { position: static; }
  .c-pass, .c-warn, .c-fail, .c-null, .c-dns, .c-none, .c-na, .bar i, .cov-bar button, .rm-cell { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body.print-drawer .app, body.print-drawer .scrim { display: none !important; }
  body.print-drawer .drawer { position: static; width: auto; box-shadow: none; border: 0; }
  body.print-drawer .dr-body { overflow: visible; padding: 0; }
  body.print-drawer .dr-head { padding: 0; border: 0; }
  body.print-drawer .dr-print-title { display: block; font-size: 15px; margin: 6px 0 2px; }
  body.print-exec #drawer-root { display: none !important; }
  body.print-exec .print-head { display: block !important; }
}

.hub-item.on { background: var(--hover); color: var(--text); }
.hub-sub { display: grid; gap: 1px; margin: 2px 0 8px 18px; padding-left: 10px; border-left: 1px solid var(--line-2); }
.hub-subitem { padding: 6px 10px; font-size: 13px; }
.hub-subsep { font-size: 11px; color: var(--faint); padding: 8px 10px 2px; }
.hub-subload { font-size: 12px; padding: 6px 10px; }
.hub-crumb { display: flex; align-items: baseline; gap: 8px; min-width: 0; } .hub-crumb > span { white-space: nowrap; }
.hub-crumb h1 { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.spark { width: 100%; height: 30px; display: block; margin-top: 2px; overflow: visible; }
.spark polyline { fill: none; stroke: var(--muted); stroke-width: 1.6; vector-effect: non-scaling-stroke; stroke-linejoin: round; }
.spark circle { fill: var(--text); }
.t-good .spark polyline { stroke: var(--pass); } .t-warn .spark polyline { stroke: var(--warn); } .t-bad .spark polyline { stroke: var(--fail); }
.area-spark { width: 110px; margin-left: auto; align-self: center; }
.trend-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 460px), 1fr)); gap: 16px; }
.trend-now { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
.trend-now b { font-size: 30px; font-weight: 700; font-variant-numeric: tabular-nums; } .trend-now b small { font-size: 14px; color: var(--muted); font-weight: 500; }
.tchart { width: 100%; height: auto; display: block; }
.tchart .tg { stroke: var(--line); } .tchart .ta { fill: var(--faint); font-size: 10.5px; font-family: var(--font); }
.tchart .tp { fill: none; stroke: var(--accent); stroke-width: 2.2; stroke-linejoin: round; }
.tchart .td { fill: var(--panel); stroke: var(--accent); stroke-width: 2; } .tchart .tl { fill: var(--accent); }
.tchart .tv { fill: var(--text); font-size: 11px; font-weight: 600; font-family: var(--font); }
.tchart .tt { stroke: var(--pass); stroke-width: 1.4; stroke-dasharray: 5 4; } .tchart .ttl { fill: var(--pass-text); font-size: 10.5px; font-family: var(--font); }
.exec-hero { display: flex; gap: 24px; justify-content: space-between; align-items: flex-start; padding: 26px 28px; margin-bottom: 16px;
             background: linear-gradient(135deg, var(--panel) 0%, color-mix(in srgb, var(--accent) 7%, var(--panel)) 100%); }
.exec-kicker { color: var(--muted); font-size: 13px; margin: 0 0 6px; }
.exec-headline { font-size: 24px; line-height: 1.3; font-weight: 650; letter-spacing: -.01em; max-width: 60ch; margin: 0 0 16px; text-wrap: balance; }
.exec-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.exec-chip { display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--line-2); background: var(--panel); border-radius: 999px; padding: 5px 12px; color: var(--text); font-size: 13px; }
.exec-chip span { color: var(--muted); } .exec-chip:hover { border-color: var(--accent); }
.exec-meta { color: var(--faint); font-size: 12.5px; text-align: right; white-space: nowrap; }
.exec-kpis { display: grid; grid-template-columns: repeat(var(--kcols, 3), minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
.exec-actions > header { flex-direction: column; align-items: flex-start; gap: 2px; }
.exec-kpi { display: grid; gap: 6px; align-content: start; text-align: left; padding: 16px 18px; border: 1px solid var(--line); border-radius: var(--r-lg); background: var(--panel); color: inherit; position: relative; }
.exec-kpi:hover { border-color: var(--line-2); background: var(--hover); }
.exec-kpi::before { content: ""; position: absolute; left: 0; top: 14px; bottom: 14px; width: 3px; border-radius: 0 3px 3px 0; background: var(--line-2); }
.exec-kpi.t-good::before { background: var(--pass); } .exec-kpi.t-warn::before { background: var(--warn); } .exec-kpi.t-bad::before { background: var(--fail); }
.exec-kpi-lbl { font-size: 13px; color: var(--muted); line-height: 1.35; min-height: 2.7em; }
.exec-kpi b { font-size: 36px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; letter-spacing: -.02em; }
.exec-kpi.t-good b { color: var(--pass-text); } .exec-kpi.t-warn b { color: var(--warn-text); } .exec-kpi.t-bad b { color: var(--fail-text); }
.exec-kpi b small { font-size: 15px; color: var(--muted); font-weight: 500; margin-left: 2px; }
.exec-bar { position: relative; height: 6px; border-radius: 3px; background: var(--panel-2); border: 1px solid var(--line); margin-top: 4px; }
.exec-bar i { display: block; height: 100%; border-radius: 3px; background: var(--muted); }
.t-good .exec-bar i { background: var(--pass); } .t-warn .exec-bar i { background: var(--warn); } .t-bad .exec-bar i { background: var(--fail); }
.exec-bar em { position: absolute; top: -4px; bottom: -4px; width: 2px; background: var(--text); opacity: .55; transform: translateX(-1px); }
.exec-kpi-det { font-size: 12px; color: var(--faint); }
.exec-trend { font-size: 12px; color: var(--muted); } .exec-trend.up { color: var(--pass-text); } .exec-trend.down { color: var(--fail-text); }
.exec-cols { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 16px; align-items: start; margin-bottom: 16px; }
.exec-areas { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); gap: 16px; margin-bottom: 8px; align-items: stretch; }
.exec-area { display: flex; flex-direction: column; } .exec-area .body { flex: 1; }
.exec-lead { font-size: 18px; font-weight: 600; line-height: 1.4; margin: 2px 0 16px; max-width: 80ch; text-wrap: balance; }
.exec-sec { margin-top: 20px; }
.exec-actions { margin-top: 20px; margin-bottom: 16px; }
.exec-area .body { display: flex; flex-direction: column; gap: 12px; }
.exec-area-head { display: flex; gap: 14px; align-items: center; }
.exec-area-head .letter { font-size: 44px; font-weight: 700; line-height: .9; letter-spacing: -1px; width: 38px; text-align: center; }
.exec-area-head b { font-size: 20px; } .exec-area-head b small { font-size: 12px; color: var(--muted); font-weight: 400; }
.exec-area-head .lbl { color: var(--muted); font-size: 12.5px; }
.exec-side { list-style: none; margin: 0; padding: 0; display: grid; gap: 1px; }
.exec-side li { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; padding: 6px 0; border-bottom: 1px solid var(--line); }
.exec-side li:last-child { border-bottom: 0; } .exec-side li span { color: var(--muted); }
.exec-side li b { white-space: nowrap; text-align: right; }
.tx-good { color: var(--pass-text); } .tx-warn { color: var(--warn-text); } .tx-bad { color: var(--fail-text); }
.exec-actions ul { list-style: none; margin: 0; padding: 0; }
.exec-actions li + li { border-top: 1px solid var(--line); }
.exec-act { display: grid; grid-template-columns: 4px minmax(0, 1fr) auto; gap: 14px; align-items: center; width: 100%; text-align: left; border: 0; background: none; color: inherit; padding: 12px 6px; border-radius: 6px; }
.exec-act:hover { background: var(--hover); }
.sev-bar { align-self: stretch; border-radius: 2px; } .sev-bar.sev-critical { background: var(--fail); } .sev-bar.sev-warning { background: var(--warn); }
.exec-act-main { display: grid; gap: 2px; min-width: 0; } .exec-act-main b { font-size: 14px; }
.exec-act-rec { font-size: 12.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }
.exec-act-meta { display: grid; justify-items: end; gap: 4px; text-align: right; } .exec-act-n { font-size: 12.5px; white-space: nowrap; }
.exec-detail { margin-bottom: 12px; } .exec-detail > summary { cursor: pointer; padding: 14px 18px; }
.exec-note { font-size: 12px; margin-top: 4px; }
@media (max-width: 760px) { .exec-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } .exec-headline { font-size: 20px; } .exec-act { grid-template-columns: 4px minmax(0, 1fr); } .exec-act-meta { grid-column: 2; justify-items: start; text-align: left; } }
@media (max-width: 1100px) { .exec-cols { grid-template-columns: 1fr; } .exec-hero { flex-direction: column; } .exec-meta { text-align: left; } }
.nav-sep { font-size: 11.5px; color: var(--faint); padding: 14px 10px 4px; }
.hub-item { align-items: center; }
.hub-name { display: grid; min-width: 0; text-align: left; } .hub-name > span { color: inherit; }
.hub-name small { color: var(--faint); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hub-grade { margin-left: auto; font-weight: 700; font-size: 15px; width: 22px; text-align: center; }
.hub-grid-legacy { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr)); gap: 16px; }
.hub-card .body { display: flex; flex-direction: column; height: 100%; }
.hub-type { display: inline-flex; align-items: center; gap: 8px; color: var(--muted); font-size: 13px; font-weight: 600; }
.hub-head { display: flex; gap: 18px; align-items: center; margin: 4px 0 14px; }
.hub-head .letter { font-size: 64px; font-weight: 700; line-height: .9; letter-spacing: -2px; }
.hub-head .avg { font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; } .hub-head .avg small { font-size: 13px; color: var(--muted); font-weight: 400; }
.hub-head .lbl { color: var(--muted); font-size: 12.5px; }
.hub-kpis { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; margin-top: auto; }
.hub-kpis > div { border: 1px solid var(--line); border-radius: var(--r); background: var(--panel-2); padding: 8px 10px; }
.hub-kpis b { display: block; font-size: 19px; font-variant-numeric: tabular-nums; } .hub-kpis span { font-size: 12px; color: var(--muted); }
.hub-kpis .k-pass b { color: var(--pass-text); } .hub-kpis .k-fail b { color: var(--fail-text); } .hub-kpis .k-warn b { color: var(--warn-text); }
.hub-card .btn.primary { align-self: flex-start; }
.rep-frame { display: block; width: 100%; height: calc(100vh - var(--top-h)); border: 0; background: var(--bg); }
.rep-frame[hidden] { display: none; }
body.in-report .content { display: none; }
body.in-report { overflow: hidden; }
tr[data-go] { cursor: pointer; }
@media (max-width: 860px) { .rep-frame { height: calc(100vh - 110px); } body.in-report { overflow: auto; } }
@media print { #frames { display: none !important; } }

.print-head { display: none; margin-bottom: 16px; }
.print-head h1 { font-size: 20px; }
"""

HUB_JS = r"""(function () {
'use strict';
const H = JSON.parse(document.getElementById('hub-data').textContent);
const RP = H.reports, M = H.meta;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ESC[c]);
const $ = (s, r) => (r || document).querySelector(s);
const scoreCls = n => n === null || n === undefined ? '' : n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>', shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  dns: '<path d="M3 5h18v14H3zM3 6l9 7 9-7"/>', waf: '<path d="M4 6h16M4 12h16M4 18h16M8 6v6M16 12v6M12 18v-6"/>', zta: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c1.2-3.6 4-5.5 7-5.5s5.8 1.9 7 5.5"/>',
  other: '<path d="M6 3h9l4 4v14H6zM14 3v5h5"/>', ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
  left: '<path d="m15 6-6 6 6 6"/>', sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  trend: '<path d="M3 17l6-6 4 4 8-8M15 7h6v6"/>', search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>', x: '<path d="M6 6l12 12M18 6 6 18"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>'
};
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ICONS.other}</svg>`;

/* ---------- theme ---------- */
let theme = null;
try { theme = localStorage.getItem('guardhub-theme'); } catch (e) { /* storage unavailable */ }
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !matchMedia('(prefers-color-scheme: light)').matches; };
function applyTheme() { if (theme) document.documentElement.dataset.theme = theme; }
function toggleTheme() {
  theme = isDark() ? 'light' : 'dark';
  try { localStorage.setItem('guardhub-theme', theme); } catch (e) { /* ignore */ }
  applyTheme();
  Object.values(frames).forEach(f => { try { f.el.contentWindow.postMessage({mgHubTheme: theme}, '*'); } catch (e) { /* ignore */ } });
  render();
}

/* ---------- embedded reports: one sandboxed frame per report, created on first use ---------- */
const frames = {};
// Inside the portal each report hides its own sidebar and top bar: the portal shows its sections and owns search.
const EMB_CSS = 'html[data-embedded] .app{grid-template-columns:minmax(0,1fr)!important}html[data-embedded] .side,html[data-embedded] .topbar,html[data-embedded] [data-action="copy-link"]{display:none!important}html[data-embedded] .content{padding-top:22px}html[data-embedded] .grid-wrap{max-height:calc(100vh - 200px)}';
const BOOT = (id, hash, th, emb) => `<script>(function(){var ID=${JSON.stringify(id)},D=document.documentElement;try{D.dataset.theme=${JSON.stringify(th)};}catch(e){}
${hash ? `try{history.replaceState(null,'',${JSON.stringify(hash)});}catch(e){location.hash=${JSON.stringify(hash)};}` : ''}
${emb ? `D.dataset.embedded='1';var st=document.createElement('style');st.textContent=${JSON.stringify(EMB_CSS)};(document.head||D).appendChild(st);
var last='',timer=null;function txt(el){return el?el.textContent.replace(/\\s+/g,' ').trim():'';}
function snap(){timer=null;var items=[].slice.call(document.querySelectorAll('#side .nav-item')).map(function(b){var c=b.querySelector('.count'),label='';
[].forEach.call(b.children,function(n){if(!label&&n.tagName==='SPAN'&&!n.classList.contains('count')&&!n.classList.contains('pdot'))label=txt(n);});
return {route:b.getAttribute('data-route'),pillar:b.getAttribute('data-pillar'),action:b.getAttribute('data-action'),label:(label||txt(b)).replace(/\\s+[^\\w\\s]+$/,''),count:c?txt(c):'',current:b.getAttribute('aria-current')==='page'||b.classList.contains('on')};})
.filter(function(x){return x.route||x.pillar||x.action==='about'||x.action==='keys';});
var tb=document.getElementById('topbar'),h1=tb&&tb.querySelector('h1'),sub=tb&&tb.querySelector('.sub');
var msg={mgHub:1,id:ID,hash:location.hash,nav:items,heading:txt(h1),sub:txt(sub),pdf:!!document.querySelector('[data-action="print-exec"]')};
var key=JSON.stringify(msg);if(key!==last){last=key;try{parent.postMessage(msg,'*');}catch(e){}}}
function later(){if(!timer)timer=setTimeout(snap,60);}
new MutationObserver(later).observe(D,{childList:true,subtree:true});addEventListener('hashchange',later);addEventListener('popstate',later);addEventListener('load',later);
addEventListener('keydown',function(e){var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(e.target&&e.target.tagName);
if(((e.ctrlKey||e.metaKey)&&String(e.key).toLowerCase()==='k')||(e.key==='/'&&!typing)){e.preventDefault();e.stopImmediatePropagation();try{parent.postMessage({mgHub:1,id:ID,key:'palette'},'*');}catch(x){}}},true);
addEventListener('message',function(e){if(e.source!==parent||!e.data)return;var d=e.data;if(d.mgHubTheme)D.dataset.theme=d.mgHubTheme;
if(typeof d.mgHubGo==='string')location.hash=d.mgHubGo;
if(d.mgHubClick){var c=d.mgHubClick,sel=c.route?'#side .nav-item[data-route="'+c.route+'"]':c.pillar?'#side .nav-item[data-pillar="'+String(c.pillar).replace(/["\\\\]/g,'')+'"]':c.action?'[data-action="'+c.action+'"]':null;
var el=sel&&document.querySelector(sel);if(el)el.click();}});` : ''}
})();<\/script>`;
const html = id => JSON.parse(document.getElementById('rep-' + id).textContent);
function reportDoc(id, hash, emb) {
  const src = html(id), boot = BOOT(id, hash, isDark() ? 'dark' : 'light', emb !== false);
  return /<head[^>]*>/i.test(src) ? src.replace(/<head[^>]*>/i, m => m + boot) : boot + src;
}
function ensureFrame(id, hash) {
  if (frames[id]) { if (hash && hash !== frames[id].hash) frames[id].el.contentWindow.postMessage({mgHubGo: hash}, '*'); return frames[id]; }
  const el = document.createElement('iframe');
  el.className = 'rep-frame';
  el.title = RP.find(r => r.id === id).title;
  el.setAttribute('sandbox', 'allow-scripts allow-popups allow-downloads allow-modals');
  el.src = URL.createObjectURL(new Blob([reportDoc(id, hash)], {type: 'text/html'}));
  $('#frames').appendChild(el);
  frames[id] = {el, hash: hash || '', nav: [], heading: '', sub: '', pdf: false};
  return frames[id];
}
const tell = (id, msg) => { const f = frames[id]; if (f) f.el.contentWindow.postMessage(msg, '*'); };
window.addEventListener('message', e => {
  const d = e.data;
  if (!d || !d.mgHub) return;
  const f = frames[d.id];
  if (!f || e.source !== f.el.contentWindow) return;  // only trust our own frames
  if (d.key === 'palette') { openPalette(); return; }
  if (typeof d.hash === 'string') f.hash = d.hash;
  if (d.nav) Object.assign(f, {nav: d.nav, heading: d.heading || '', sub: d.sub || '', pdf: !!d.pdf});
  if (S.route === 'r' && S.id === d.id) { const h = toHash(); if (location.hash !== h) history.replaceState(null, '', h); chrome(); }
});

/* ---------- history (trends) ---------- */
const SERIES = (M.history && M.history.series) || [], RUNS = (M.history && M.history.runs) || [];
const seriesFor = (key, r) => SERIES.find(s => s.key === key && s.area === r.type && s.subject === (r.subject || ''));
const hasTrends = () => SERIES.some(s => s.points.length >= 2);
const fmtD = iso => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleDateString(undefined, {year: 'numeric', month: 'short', day: 'numeric'}); };
function spark(s) {
  if (!s || s.points.length < 2) return '';
  const pts = s.points, t0 = Date.parse(pts[0][0]), t1 = Date.parse(pts[pts.length - 1][0]) || t0 + 1;
  const pc = s.unit === '%' || s.unit === '/100', top = pc ? 100 : Math.max(...pts.map(p => p[1])) * 1.1 || 1;
  const xy = pts.map(p => [((Date.parse(p[0]) - t0) / ((t1 - t0) || 1)) * 100, 28 - (p[1] / top) * 26]);
  return `<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true"><polyline points="${xy.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ')}"/>
    <circle cx="${xy[xy.length - 1][0].toFixed(1)}" cy="${xy[xy.length - 1][1].toFixed(1)}" r="2.2"/></svg>`;
}
function histDelta(s) {
  if (!s || s.points.length < 2) return '';
  const a = s.points[s.points.length - 2], b = s.points[s.points.length - 1], d = Math.round((b[1] - a[1]) * 10) / 10;
  const u = s.unit === '/100' ? ' pts' : s.unit === '%' ? ' pts' : '';
  return d === 0 ? `<span class="exec-trend">unchanged since ${esc(fmtD(a[0]))}</span>` : `<span class="exec-trend ${d > 0 ? 'up' : 'down'}">${d > 0 ? '\u25B2 +' : '\u25BC '}${d}${u} since ${esc(fmtD(a[0]))}</span>`;
}
function lineChart(s) {
  const W = 560, H = 200, L = 38, R = 18, T = 16, B = 30, pts = s.points;
  const pc = s.unit === '%' || s.unit === '/100', top = pc ? 100 : Math.max(...pts.map(p => p[1]), s.target || 0) * 1.15 || 1;
  const t0 = Date.parse(pts[0][0]), t1 = Date.parse(pts[pts.length - 1][0]);
  const x = t => L + ((Date.parse(t) - t0) / ((t1 - t0) || 1)) * (W - L - R), y = v => H - B - (v / top) * (H - T - B);
  const path = pts.map((p, i) => `${i ? 'L' : 'M'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join('');
  const grid = [0, 0.5, 1].map(f => `<line x1="${L}" x2="${W - R}" y1="${y(top * f).toFixed(1)}" y2="${y(top * f).toFixed(1)}" class="tg"/><text x="${L - 6}" y="${(y(top * f) + 3).toFixed(1)}" text-anchor="end" class="ta">${Math.round(top * f)}</text>`).join('');
  const tgt = s.target && s.target <= top ? `<line x1="${L}" x2="${W - R}" y1="${y(s.target).toFixed(1)}" y2="${y(s.target).toFixed(1)}" class="tt"/><text x="${W - R}" y="${(y(s.target) - 5).toFixed(1)}" text-anchor="end" class="ttl">Target ${s.target}</text>` : '';
  const dots = pts.map((p, i) => `<circle cx="${x(p[0]).toFixed(1)}" cy="${y(p[1]).toFixed(1)}" r="${i === pts.length - 1 ? 4 : 3}" class="${i === pts.length - 1 ? 'tl' : 'td'}"><title>${esc(fmtD(p[0]))}: ${p[1]}${esc(s.unit)}</title></circle>`).join('');
  const lbls = pts.map((p, i) => (i === 0 || i === pts.length - 1 || pts.length <= 6) ? `<text x="${x(p[0]).toFixed(1)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === pts.length - 1 ? 'end' : 'middle'}" class="ta">${esc(fmtD(p[0]))}</text>` : '').join('');
  const vlab = pts.map((p, i) => `<text x="${x(p[0]).toFixed(1)}" y="${(y(p[1]) - 9).toFixed(1)}" text-anchor="${i === 0 ? 'start' : i === pts.length - 1 ? 'end' : 'middle'}" class="tv">${p[1]}</text>`).join('');
  return `<svg class="tchart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(s.label)} over time: ${esc(pts.map(p => fmtD(p[0]) + ' ' + p[1] + s.unit).join(', '))}">${grid}${tgt}<path d="${path}" class="tp"/>${dots}${vlab}${lbls}</svg>`;
}
const KORDER = ['score', 'spoof', 'waf', 'zt', 'mfa', 'pr', 'dev'];
function trends() {
  const dup = s => s.key === 'zt' && SERIES.some(o => o.key === 'score' && o.area === s.area && o.subject === s.subject);
  const ss = SERIES.filter(s => s.points.length >= 2 && !dup(s)).sort((a, b) => KORDER.indexOf(a.key) - KORDER.indexOf(b.key) || a.area.localeCompare(b.area));
  if (!ss.length) return '<div class="card empty"><b>No history yet</b>Generate the portal with reports from two or more assessments (for example one folder per quarter) to see trends.</div>';
  const first = RUNS[0], last = RUNS[RUNS.length - 1];
  const lab = {dns: 'Email and DNS security', waf: 'Imperva Cloud WAF', zta: 'Microsoft Zero Trust'};
  return `<div class="section-title"><h2>Trends</h2><p>${RUNS.length} assessments from ${esc(fmtD(first.date))} to ${esc(fmtD(last.date))}</p></div>
    <div class="trend-grid">${ss.map(s => { const a = s.points[0], b = s.points[s.points.length - 1], d = Math.round((b[1] - a[1]) * 10) / 10;
      return `<section class="card"><header><h2>${esc(s.label)}</h2><span class="act"><span class="hub-type">${icon(s.area, 14)}${esc(lab[s.area] || s.area)}</span></span></header>
        <div class="body"><div class="trend-now"><b>${esc(b[1])}<small>${esc(s.unit)}</small></b>${histDelta(s)}<span class="exec-trend ${d > 0 ? 'up' : d < 0 ? 'down' : ''}">${d > 0 ? '+' : ''}${d} since ${esc(fmtD(a[0]))}</span></div>${lineChart(s)}</div></section>`; }).join('')}</div>
    <details class="card exec-detail" style="margin-top:16px"><summary><b>Assessments included</b> <span class="faint">${RUNS.length}</span></summary><div class="body"><table class="keys">
      ${RUNS.map(r => `<tr><td>${esc(fmtD(r.date))}</td><td>${esc(r.label)}</td><td class="mono">${esc(r.file)}</td><td>${r.current ? '<span class="pill s-pass">current, embedded</span>' : '<span class="faint">history</span>'}</td></tr>`).join('')}</table></div></details>`;
}

/* ---------- state & routing: #/overview, #/trends or #/r/<id>?h=<report hash> ---------- */
const S = {route: 'overview', id: null};
function toHash() { if (S.route === 'trends') return '#/trends'; if (S.route !== 'r') return '#/overview'; const f = frames[S.id]; return `#/r/${S.id}${f && f.hash ? '?h=' + encodeURIComponent(f.hash) : ''}`; }
function fromHash() {
  if (location.hash === '#/trends' && hasTrends()) return {route: 'trends', id: null, inner: ''};
  const m = location.hash.match(/^#\/r\/([^?]+)(?:\?h=(.*))?$/);
  if (m && RP.some(r => r.id === m[1])) return {route: 'r', id: m[1], inner: m[2] ? decodeURIComponent(m[2]) : ''};
  return {route: 'overview', id: null, inner: ''};
}
function open(id, inner, push) {
  S.route = 'r'; S.id = id;
  ensureFrame(id, inner);
  const h = `#/r/${id}${inner ? '?h=' + encodeURIComponent(inner) : (frames[id].hash ? '?h=' + encodeURIComponent(frames[id].hash) : '')}`;
  if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h);
  render();
  frames[id].el.focus();
}
function page(route, push) { S.route = route; S.id = null; const h = route === 'trends' ? '#/trends' : '#/overview'; if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h); render(); window.scrollTo(0, 0); }
const home = push => page('overview', push);
window.addEventListener('popstate', () => { const r = fromHash(); r.route === 'r' ? open(r.id, r.inner, false) : page(r.route, false); });

/* ---------- chrome ---------- */
function subNav(r) {
  const f = frames[r.id];
  if (!f || !f.nav.length) return '<div class="hub-sub"><span class="faint hub-subload">Loading sections\u2026</span></div>';
  const item = (x, attr) => `<button class="nav-item hub-subitem" ${attr}${x.current ? ' aria-current="page"' : ''}><span>${esc(x.label)}</span>${x.count ? `<span class="count">${esc(x.count)}</span>` : ''}</button>`;
  const routes = f.nav.filter(x => x.route), pillars = f.nav.filter(x => x.pillar);
  return `<div class="hub-sub">${routes.map(x => item(x, `data-sub-route="${esc(x.route)}"`)).join('')}
    ${pillars.length ? `<div class="hub-subsep">Pillars</div>${pillars.map(x => item(x, `data-sub-pillar="${esc(x.pillar)}"`)).join('')}` : ''}</div>`;
}
function side() {
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>GuardHub</b>${M.title ? `<small>${esc(M.title)}</small>` : ''}</div></div>
    <nav class="nav" aria-label="Portal"><button class="nav-item" data-home${S.route === 'overview' ? ' aria-current="page"' : ''}>${icon('grid')}<span>Overview</span></button>
      ${hasTrends() ? `<button class="nav-item" data-trends${S.route === 'trends' ? ' aria-current="page"' : ''}>${icon('trend')}<span>Trends</span><span class="count">${RUNS.length}</span></button>` : ''}
      <div class="nav-sep">Reports</div>
      ${RP.map(r => { const on = S.route === 'r' && S.id === r.id;
        return `<button class="nav-item hub-item${on ? ' on' : ''}" data-open="${r.id}"${on && !(frames[r.id] && frames[r.id].nav.some(x => x.current)) ? ' aria-current="page"' : ''} title="${esc(r.title)}">${icon(r.type)}
          <span class="hub-name"><span>${esc(r.label)}</span><small>${esc(r.subtitle || r.file)}</small></span><span class="hub-grade g-${esc(r.grade)}">${esc(r.grade)}</span></button>${on ? subNav(r) : ''}`; }).join('')}</nav>
    <div class="side-foot">${S.route === 'r' && frames[S.id] && frames[S.id].nav.some(x => x.action === 'keys') ? `<button class="nav-item" data-sub-action="keys">${icon('info')}<span>Report shortcuts</span></button>` : ''}
      <button class="nav-item" data-action="about">${icon('info')}<span>About this portal</span></button>
      <button class="nav-item" data-action="theme">${icon(isDark() ? 'sun' : 'moon')}<span>${isDark() ? 'Light theme' : 'Dark theme'}</span></button></div>`;
}
const searchBtn = `<button class="cmdk" data-action="palette" aria-label="Search all reports">${icon('search')}<span class="lbl">Search all reports</span><span class="kbd">Ctrl K</span></button>`;
function topbar() {
  if (S.route === 'trends') return `<h1>Trends</h1><span class="sub">${RUNS.length} assessments</span><span class="spacer"></span>${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print</span></button>`;
  if (S.route !== 'r') return `<h1>${esc(M.title || 'Overview')}</h1><span class="sub">${RP.length} report${RP.length === 1 ? '' : 's'}, portal generated ${esc(M.generated)}</span><span class="spacer"></span>
    ${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print overview</span></button>`;
  const r = RP.find(x => x.id === S.id), f = frames[S.id] || {};
  return `<button class="btn icon ghost" data-home aria-label="Back to the overview" title="Overview">${icon('left')}</button>
    <div class="hub-crumb"><span class="faint">${esc(r.label)}</span>${f.heading ? `<span class="faint">/</span><h1>${esc(f.heading)}</h1>` : `<h1 class="sr-only">${esc(r.label)}</h1>`}</div><span class="sub">${esc(f.sub || r.subtitle)}</span><span class="spacer"></span>
    ${searchBtn}${f.pdf ? `<button class="btn" data-action="report-pdf">${icon('print')}<span>Executive PDF</span></button>` : ''}
    <button class="btn icon ghost" data-action="copy-link" title="Copy link to this view" aria-label="Copy link to this view">${icon('link')}</button>
    <button class="btn icon ghost" data-action="newtab" title="Open in a new tab" aria-label="Open in a new tab">${icon('ext')}</button>
    <button class="btn icon ghost" data-action="download" title="Download the report" aria-label="Download the report">${icon('download')}</button>`;
}
function chrome() { $('#side').innerHTML = side(); $('#topbar').innerHTML = topbar(); }

/* ---------- overview ---------- */
const deltaTxt = d => !d || (d.improved === null && d.worsened === null) ? '' :
  `<span class="delta-up">${d.improved || 0} better</span>, <span class="delta-down">${d.worsened || 0} worse</span> since the baseline`;
const AREA_ST = {good: ['On track', 'pass'], warn: ['Needs attention', 'warn'], bad: ['At risk', 'fail'], unknown: ['No data', 'na']};
const NOUN = {dns: ['domain', 'domains'], waf: ['website', 'websites']};
function tone(k) {
  if (k.value === null || k.value === undefined) return 'na';
  const v = k.unit === '/100' || k.unit === '%' ? k.value : null;
  if (v === null) return k.hib ? 'good' : (k.value ? 'bad' : 'good');
  return k.hib ? (v >= 90 ? 'good' : v >= 70 ? 'warn' : 'bad') : (v <= 10 ? 'good' : v <= 30 ? 'warn' : 'bad');
}
const trendChip = (t, unit) => t === null || t === undefined ? '' : t === 0 ? '<span class="exec-trend">no change since baseline</span>'
  : `<span class="exec-trend ${t > 0 ? 'up' : 'down'}">${t > 0 ? '\u25B2 +' : '\u25BC '}${t}${unit || ''} since baseline</span>`;
function overview() {
  const PF = M.portfolio || {}, areas = RP.filter(r => r.exec);
  const order = ['spoof', 'waf', 'zt', 'mfa', 'pr', 'dev'];
  const kpis = areas.flatMap(r => r.exec.kpis.map(k => ({...k, r}))).sort((a, b) => order.indexOf(a.key) - order.indexOf(b.key)).slice(0, 6);
  const hero = `<section class="card exec-hero"><div><p class="exec-kicker">${esc(M.title)}</p><h2 class="exec-headline">${esc(PF.sentence || '')}</h2>
      <div class="exec-chips">${RP.map(r => { const st = AREA_ST[(r.exec || {}).status || 'unknown']; return `<button class="exec-chip" data-open="${r.id}"><i class="dot c-${st[1]}"></i>${esc(r.label)}<span>${esc(st[0])}</span></button>`; }).join('')}</div></div>
    <div class="exec-meta">${RP.length} report${RP.length === 1 ? '' : 's'}<br>Portal generated ${esc(M.generated)}</div></section>`;
  const kpiHtml = kpis.length ? `<div class="exec-kpis" style="--kcols:${kpis.length <= 4 ? kpis.length : 3}">${kpis.map(k => { const t = tone(k), v = k.value === null || k.value === undefined ? null : k.value;
    return `<button class="exec-kpi t-${t}" data-go="${k.r.id}" data-h="${esc(k.hash)}" title="Open in ${esc(k.r.label)}">
      <span class="exec-kpi-lbl">${esc(k.label)}</span><b>${v === null ? '-' : esc(v)}<small>${esc(k.unit)}</small></b>
      ${v !== null && (k.unit === '%' || k.unit === '/100') ? `<span class="exec-bar"><i style="width:${Math.max(0, Math.min(100, v))}%"></i>${k.target ? `<em style="left:${k.target}%" title="Target ${k.target}"></em>` : ''}</span>` : ''}
      <span class="exec-kpi-det">${esc(k.detail)}</span>${spark(seriesFor(k.key, k.r))}${histDelta(seriesFor(k.key, k.r)) || trendChip(k.trend, k.unit === '/100' ? ' pts' : '')}</button>`; }).join('')}</div>` : '';
  const areaHtml = `<div class="exec-areas">${RP.map(r => { const x = r.exec, st = AREA_ST[(x || {}).status || 'unknown'];
    return `<section class="card exec-area"><header><span class="hub-type">${icon(r.type)}${esc(r.label)}</span><span class="act"><span class="pill s-${st[1]}">${esc(st[0])}</span></span></header>
      <div class="body"><div class="exec-area-head"><span class="letter g-${esc(r.grade)}">${esc(r.grade)}</span><div><b class="num">${r.score === null || r.score === undefined ? '-' : esc(r.score)}<small>/100</small></b>
        <div class="lbl">${esc(r.subtitle || r.title)}</div>${histDelta(seriesFor('score', r)) || (x ? trendChip(x.trend, r.type === 'zta' ? ' pts' : ' pts avg') : '')}</div>${spark(seriesFor('score', r)) ? `<div class="area-spark">${spark(seriesFor('score', r))}</div>` : ''}</div>
      ${x ? `<ul class="exec-side">${x.side.map(([l, v, tn]) => `<li><span>${esc(l)}</span><b class="tx-${esc(tn)}">${esc(v)}</b></li>`).join('')}</ul>` : '<p class="muted">Not a Guard report: open it to view the content.</p>'}
      <button class="btn" data-open="${r.id}" style="margin-top:auto;align-self:flex-start">Open report</button></div></section>`; }).join('')}</div>`;
  const acts = PF.actions || [];
  const actHtml = acts.length ? `<section class="card exec-actions"><header><h2>Priority actions</h2><p>The few changes that remove the most risk, grouped by problem across assets</p></header><div class="body"><ul>
    ${acts.map(a => `<li><button class="exec-act" data-go="${esc(a.report)}" data-h="${esc(a.hash)}"><span class="sev-bar sev-${esc(a.severity)}"></span>
      <span class="exec-act-main"><b>${esc(a.title)}</b><span class="exec-act-rec">${esc(a.rec)}</span></span>
      <span class="exec-act-meta"><span class="hub-type">${icon(a.area, 14)}${esc(a.label)}</span>
        <span class="exec-act-n">${a.area === 'zta' ? 'single control' : `${esc(a.count)} ${(NOUN[a.area] || ['asset', 'assets'])[a.count === 1 ? 0 : 1]}${a.share !== null && a.share !== undefined ? ` <span class="faint">(${esc(a.share)}%)</span>` : ''}`}${a.critical_tier ? `, <span class="tx-bad">${esc(a.critical_tier)} critical tier</span>` : ''}</span></span></button></li>`).join('')}</ul></div></section>` : '';
  const risks = RP.flatMap(r => (r.top || []).map((t, k) => ({...t, r, k}))).sort((a, b) => (a.severity === 'critical' ? 0 : 1) - (b.severity === 'critical' ? 0 : 1) || a.k - b.k).slice(0, 20);
  const riskCell = t => t.score !== null && t.score !== undefined ? `<span class="score ${scoreCls(t.score)}">${esc(t.score)}</span>` : `<span class="pill ${({high: 's-fail', medium: 's-warn', low: 's-null'})[t.risk] || 's-na'}">${esc(t.risk || '')}</span>`;
  const detail = risks.length ? `<details class="card exec-detail"><summary><b>Most exposed assets and controls</b> <span class="faint">${risks.length} items, for analysts</span></summary>
    <div class="grid-wrap" style="max-height:none;border:0;border-radius:0"><table class="grid"><thead><tr><th>Source</th><th class="sticky">Item</th><th>Score or risk</th><th>Main finding</th></tr></thead><tbody>
    ${risks.map(t => `<tr data-go="${t.r.id}" data-h="${esc(t.hash)}"><td class="nowrap"><span class="hub-type">${icon(t.r.type, 14)}${esc(t.r.label)}</span></td><td class="sticky"><button class="dom" style="word-break:normal" data-go="${t.r.id}" data-h="${esc(t.hash)}">${esc(t.item)}</button></td>
      <td>${riskCell(t)}</td><td class="sub">${esc(t.detail)}</td></tr>`).join('')}</tbody></table></div></details>` : '';
  return `<div class="print-head"><h1>${esc(M.title || 'GuardHub')}</h1><p class="muted">Generated ${esc(M.generated)}</p></div>
    ${areaHtml}
    ${kpiHtml ? `<div class="section-title exec-sec"><h2>Key indicators</h2><p>Outcomes measured across all reports. Select one to see the affected items.</p></div>${kpiHtml}` : ''}
    ${actHtml}${detail}
    <p class="faint exec-note">Each tool scores on its own scale: grades are not comparable across areas. Targets on the bars mark the expected end state.</p>`;
}
function render() {
  applyTheme();
  chrome();
  const inReport = S.route === 'r';
  document.body.classList.toggle('in-report', inReport);
  $('#view').innerHTML = inReport ? '' : S.route === 'trends' ? trends() : overview();
  Object.entries(frames).forEach(([id, f]) => { f.el.hidden = !(inReport && id === S.id); });
  const r = inReport ? RP.find(x => x.id === S.id) : null;
  document.title = (r ? r.label + ' - ' : S.route === 'trends' ? 'Trends - ' : '') + (M.title || 'GuardHub');
}

/* ---------- search across all reports ---------- */
let INDEX = null, pal = null;
function payloadOf(id) {
  const m = html(id).match(/<script type="application\/json" id="mg-data">([\s\S]*?)<\/script>/);
  try { return m ? JSON.parse(m[1]) : null; } catch (e) { return null; }
}
function buildIndex() {
  INDEX = [];
  RP.forEach(r => {
    const p = payloadOf(r.id);
    if (!p) return;
    const enc = encodeURIComponent;
    if (r.type === 'zta') {
      (p.tests || []).forEach(t => INDEX.push({r, t: t.title, h: `${t.status}, ${t.risk} risk`, go: '#/tests?d=' + enc(t.id), s: `${t.title} ${t.id} ${t.category}`.toLowerCase()}));
      [...new Set((p.tests || []).map(t => t.category))].forEach(c => INDEX.push({r, t: c, h: 'category', go: '#/tests?category=' + enc(c), s: String(c).toLowerCase(), kind: 'f'}));
    } else {
      (p.results || []).forEach(x => INDEX.push({r, t: x.domain, h: `score ${x.overall_score}${x.owner ? ', ' + x.owner : ''}`, go: '#/domains?d=' + enc(x.domain), s: `${x.domain} ${x.owner || ''} ${x.bu || ''} ${x.site_id || ''}`.toLowerCase()}));
      const n = {};
      (p.results || []).forEach(x => new Set((x.issues || []).map(i => i.code)).forEach(c => { n[c] = (n[c] || 0) + 1; }));
      Object.entries(n).forEach(([c, k]) => { const f = (p.findings || {})[c]; if (f) INDEX.push({r, t: f[2], h: `${k} affected`, go: '#/domains?finding=' + enc(c), s: `${f[2]} ${f[1]} ${c}`.toLowerCase(), kind: 'f'}); });
    }
  });
}
function paletteItems(q) {
  q = q.trim().toLowerCase();
  const out = [], add = (g, t, h, run) => out.push({g, t, h, run});
  [['Overview', () => home()], ...(hasTrends() ? [['Trends', () => page('trends')]] : [])].forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) add('Go to', t, '', fn); });
  RP.forEach(r => { if (!q || r.label.toLowerCase().includes(q) || (r.subtitle || '').toLowerCase().includes(q)) add('Reports', r.label, r.subtitle, () => open(r.id, '')); });
  if (S.route === 'r' && frames[S.id]) frames[S.id].nav.filter(x => x.route || x.pillar).forEach(x => { if (!q || x.label.toLowerCase().includes(q)) add('In this report', x.label, x.count, () => tell(S.id, {mgHubClick: x.route ? {route: x.route} : {pillar: x.pillar}})); });
  if (q) {
    if (!INDEX) buildIndex();
    const per = {};
    INDEX.filter(e => e.s.includes(q)).forEach(e => { const k = e.r.id + (e.kind || ''); per[k] = (per[k] || 0) + 1;
      if (per[k] <= (e.kind ? 4 : 6)) add(e.r.label + (e.kind ? ', findings' : ''), e.t, e.h, () => open(e.r.id, e.go)); });
  }
  [['Toggle light or dark theme', toggleTheme], ['Print this page', () => window.print()]].forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) add('Actions', t, '', fn); });
  return out;
}
function openPalette() {
  pal = {idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Search all reports"><div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search domains, websites, tests, findings across all reports" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul><div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette();
  $('#pal-q').focus();
}
function renderPalette() {
  let g = '', h = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; h += `<li class="pal-group" role="presentation">${esc(g)}</li>`; }
    h += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h || '')}</span></li>`; });
  $('#pal-list').innerHTML = h || '<li class="pal-group">No results</li>';
  const c = $('#pal-' + pal.idx); if (c) c.scrollIntoView({block: 'nearest'});
}
function closeOverlay() { $('#overlay-root').innerHTML = ''; pal = null; }
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }

/* ---------- actions ---------- */
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2400); }
function copyText(text, ok) { const done = () => toast(ok);
  const fb = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fb); else fb(); }
function about() {
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t"><header><h2 id="dlg-t">About this portal</h2><button class="btn icon ghost" data-action="close" aria-label="Close">${icon('x')}</button></header>
    <div class="dbody"><p style="margin-bottom:10px">Generated ${esc(M.generated)} with GuardHub ${esc(M.version)}.</p>
    <table class="keys">${RP.map(r => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.file)}</td><td class="r">${(r.size / 1048576).toFixed(1)} MB</td>${r.history > 1 ? `<td class="faint">${r.history} runs</td>` : '<td></td>'}</tr>`).join('')}</table>
    <p class="muted" style="margin-top:12px">Grades are computed by each tool on its own scale and are not comparable across tools. Each report runs in an isolated frame: it cannot read the portal or the other reports. Search covers every domain, website, test and finding in the embedded reports.</p>
    <p class="muted" style="margin-top:8px">Shortcuts: <span class="kbd">Ctrl K</span> search, <span class="kbd">0</span> overview, <span class="kbd">1</span>-<span class="kbd">${RP.length}</span> reports${hasTrends() ? ', <span class="kbd">t</span> trends' : ''}.</p></div></div></div>`;
}
document.addEventListener('click', e => {
  const t = e.target.closest('button, tr[data-go], [data-overlay], [data-pal]');
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.home !== undefined) { home(); return; }
  if (ds.trends !== undefined) { page('trends'); return; }
  if (ds.open) { if (S.route === 'r' && S.id === ds.open && frames[ds.open]) tell(ds.open, {mgHubClick: {route: 'overview'}}); else open(ds.open, ''); return; }
  if (ds.subRoute) { tell(S.id, {mgHubClick: {route: ds.subRoute}}); frames[S.id].el.focus(); return; }
  if (ds.subPillar) { tell(S.id, {mgHubClick: {pillar: ds.subPillar}}); frames[S.id].el.focus(); return; }
  if (ds.subAction) { tell(S.id, {mgHubClick: {action: ds.subAction}}); return; }
  if (ds.go) { open(ds.go, ds.h || ''); return; }
  const r = RP.find(x => x.id === S.id);
  const acts = {
    theme: toggleTheme, about, close: closeOverlay, print: () => window.print(), palette: openPalette,
    'report-pdf': () => tell(S.id, {mgHubClick: {action: 'print-exec'}}),
    'copy-link': () => copyText(location.href, 'Link to this view copied'),
    newtab: () => { const f = frames[S.id]; const w = window.open(URL.createObjectURL(new Blob([reportDoc(S.id, f ? f.hash : '', false)], {type: 'text/html'})), '_blank', 'noopener'); if (!w) toast('Allow pop-ups to open the report in a new tab'); },
    download: () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([html(S.id)], {type: 'text/html'})); a.download = r ? r.file : 'report.html'; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  };
  if (acts[ds.action]) acts[ds.action]();
});
document.addEventListener('input', e => { if (e.target.id === 'pal-q' && pal) { pal.items = paletteItems(e.target.value); pal.idx = 0; renderPalette(); } });
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); }
    else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape' && $('#overlay-root').innerHTML) { closeOverlay(); return; }
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  const n = parseInt(e.key, 10);
  if (e.key === '0') home(); else if (e.key === 't' && hasTrends()) page('trends'); else if (n >= 1 && n <= RP.length) open(RP[n - 1].id, '');
});

applyTheme();
const start = fromHash();
if (start.route === 'r') open(start.id, start.inner, false); else page(start.route, false);
})();
"""


if __name__ == "__main__":
    sys.exit(main())
