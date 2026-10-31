"""
ZTAGuard - viewer for Microsoft Zero Trust Assessment results

Turns the JSON produced by the Microsoft Zero Trust Assessment PowerShell module
(ZeroTrustAssessmentReport.json, in <report folder>\\zt-export) into a self-contained
HTML report with the same look and workflow as MailGuard DNS and WAFGuard:
overview with grade and pillar coverage, filterable list of tests, prioritized
fixes and quick wins, categories, comparison with a previous run, tenant summary.

The loader is tolerant: field names are matched case-insensitively and with
aliases, so reports from different module versions (including multi-pillar
tests) are accepted. Nothing is sent anywhere: the HTML works offline.

Usage:
    securityhub zta .\\ZeroTrustReport                       # report folder
    securityhub zta ZeroTrustAssessmentReport.json -o zta.html
    securityhub zta current.json --baseline previous.json --csv --json
    securityhub zta report.json --title "Contoso - Q4 assessment"

Requires Python 3.9+ (standard library only).
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE, Parser, csv_safe, json_for_html

__version__ = "1.2.0"

STATUS_ALIASES = {
    "passed": "passed", "pass": "passed", "success": "passed", "true": "passed",
    "failed": "failed", "fail": "failed", "false": "failed",
    "investigate": "investigate", "warning": "investigate", "review": "investigate",
    "skipped": "skipped", "skip": "skipped", "notapplicable": "skipped", "not applicable": "skipped", "na": "skipped",
    "planned": "planned", "preview": "planned", "comingsoon": "planned",
    "error": "error", "failedtorun": "error",
}
LEVEL_ALIASES = {"high": "high", "h": "high", "3": "high", "medium": "medium", "med": "medium", "m": "medium", "2": "medium",
                 "low": "low", "l": "low", "1": "low", "none": "low"}
RISK_WEIGHT = {"high": 5, "medium": 3, "low": 1, "unknown": 2}
COST_WEIGHT = {"low": 1.0, "medium": 1.6, "high": 2.4, "unknown": 1.6}
IMPACT_WEIGHT = {"low": 1.0, "medium": 1.2, "high": 1.5, "unknown": 1.2}
STATUS_CREDIT = {"passed": 1.0, "investigate": 0.5, "failed": 0.0}


# ---------------------------------------------------------------------------
# Loading (JSON file, report folder, or the original HTML report)
# ---------------------------------------------------------------------------

def _ci(d: Any, *names: str, default: Any = None) -> Any:
    """Case-insensitive lookup with aliases."""
    if not isinstance(d, dict):
        return default
    lower = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        v = lower.get(n.lower())
        if v is not None:
            return v
    return default


def _extract_json_from_html(text: str) -> Optional[dict]:
    """Best effort: the original HTML report embeds the report data as a JSON object."""
    for marker in ("reportData", "ReportData", "report_data"):
        idx = text.find(marker)
        while idx != -1:
            start = text.find("{", idx)
            if start == -1:
                break
            try:
                obj, _ = json.JSONDecoder().raw_decode(text[start:])
                if isinstance(obj, dict) and _ci(obj, "Tests") is not None:
                    return obj
            except ValueError:
                pass
            idx = text.find(marker, idx + 1)
    return None


def load_input(path: str) -> Tuple[dict, str]:
    if os.path.isdir(path):
        candidates = []
        for root, _, files in os.walk(path):
            for f in files:
                if f.lower() == "zerotrustassessmentreport.json":
                    candidates.append(os.path.join(root, f))
        if not candidates:
            raise ValueError("ZeroTrustAssessmentReport.json not found in the folder (look in zt-export)")
        path = max(candidates, key=os.path.getmtime)
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8-sig", errors="replace")
    if path.lower().endswith((".html", ".htm")):
        data = _extract_json_from_html(text)
        if data is None:
            raise ValueError("no report data found in the HTML file: use zt-export\\ZeroTrustAssessmentReport.json")
        return data, path
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"invalid JSON: {e}")
    if isinstance(data, list):  # a bare list of tests
        data = {"Tests": data}
    if isinstance(data, dict) and _ci(data, "Tests") is None and isinstance(_ci(data, "results"), list):
        data = {"Tests": _ci(data, "results"), **{k: v for k, v in data.items() if k.lower() != "results"}}
    if not isinstance(data, dict) or not isinstance(_ci(data, "Tests"), list):
        raise ValueError("the file does not contain a 'Tests' list (is it ZeroTrustAssessmentReport.json?)")
    return data, path


def _as_list(v: Any) -> List[str]:
    if v is None or v == "":
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [s.strip() for s in re.split(r"[,;|]", str(v)) if s.strip()]


def _level(v: Any) -> str:
    return LEVEL_ALIASES.get(str(v or "").strip().lower(), "unknown") if v not in (None, "") else "unknown"


def _status(v: Any) -> Tuple[str, str]:
    raw = str(v if v is not None else "").strip()
    key = raw.lower().replace(" ", "").replace("_", "")
    return STATUS_ALIASES.get(key, STATUS_ALIASES.get(raw.lower(), "other" if raw else "skipped")), raw


def normalize(data: dict) -> dict:
    tests: List[dict] = []
    seen = Counter()
    for t in _ci(data, "Tests", default=[]) or []:
        if not isinstance(t, dict):
            continue
        tid = str(_ci(t, "TestId", "Id", "TestID", default="") or "").strip() or f"test-{len(tests) + 1}"
        seen[tid] += 1
        if seen[tid] > 1:
            tid = f"{tid}#{seen[tid]}"
        status, raw_status = _status(_ci(t, "TestStatus", "Status", "Result"))
        pillars = _as_list(_ci(t, "TestPillar", "Pillar", "TestPillars", "Pillars"))
        tests.append({
            "id": tid,
            "title": str(_ci(t, "TestTitle", "Title", "Name", default=tid)),
            "status": status, "status_raw": raw_status,
            "risk": _level(_ci(t, "TestRisk", "Risk")),
            "impact": _level(_ci(t, "TestImpact", "UserImpact", "Impact")),
            "cost": _level(_ci(t, "TestImplementationCost", "ImplementationCost", "Effort", "Cost")),
            "pillars": pillars or ["Other"],
            "sfi": str(_ci(t, "TestSfiPillar", "SfiPillar", "Sfi", default="") or ""),
            "category": str(_ci(t, "TestCategory", "Category", default="") or "Uncategorized"),
            "applies_to": _as_list(_ci(t, "TestAppliesTo", "AppliesTo")),
            "tags": _as_list(_ci(t, "TestTags", "Tags")),
            "license": ", ".join(_as_list(_ci(t, "TestMinimumLicense", "MinimumLicense", "License"))),
            "skipped_reason": str(_ci(t, "TestSkippedReason", "SkippedReason", default="") or ""),
            "description": str(_ci(t, "TestDescription", "Description", default="") or ""),
            "result": str(_ci(t, "TestResult", "ResultDetail", "Details", default="") or ""),
        })
    for t in tests:
        crit = STATUS_CREDIT.get(t["status"])
        t["priority"] = 0 if crit is None or crit == 1.0 else round(
            RISK_WEIGHT[t["risk"]] * (1 - crit) * 20 / COST_WEIGHT[t["cost"]] / IMPACT_WEIGHT[t["impact"]])
        t["quick_win"] = t["status"] in ("failed", "investigate") and t["risk"] in ("high", "medium") \
            and t["cost"] == "low" and t["impact"] in ("low", "unknown")
    tenant = {
        "name": str(_ci(data, "TenantName", default="") or ""),
        "id": str(_ci(data, "TenantId", default="") or ""),
        "domain": str(_ci(data, "Domain", "TenantDomain", default="") or ""),
        "account": str(_ci(data, "Account", default="") or ""),
        "executed_at": str(_ci(data, "ExecutedAt", "Timestamp", "Date", default="") or ""),
        "version": str(_ci(data, "CurrentVersion", "Version", default="") or ""),
        "latest_version": str(_ci(data, "LatestVersion", default="") or ""),
    }
    info = _ci(data, "TenantInfo", default=None)
    return {"tenant": tenant, "tests": tests, "summary": _ci(data, "TestResultSummary", default=None),
            "tenant_info": info if isinstance(info, dict) else None}


# ---------------------------------------------------------------------------
# Scoring and comparison
# ---------------------------------------------------------------------------

def score_of(tests: List[dict]) -> Optional[int]:
    """Risk-weighted pass rate over evaluated tests (passed, failed, investigate = half)."""
    num = den = 0.0
    for t in tests:
        credit = STATUS_CREDIT.get(t["status"])
        if credit is None:
            continue
        w = RISK_WEIGHT[t["risk"]]
        num += w * credit
        den += w
    return int(round(100 * num / den)) if den else None


def pillar_stats(tests: List[dict]) -> List[dict]:
    pillars: Dict[str, List[dict]] = {}
    for t in tests:
        for p in t["pillars"]:
            pillars.setdefault(p, []).append(t)
    order = ["Identity", "Devices", "Network", "Data", "Infrastructure", "SecOps", "AI"]
    rows = []
    for name, ts in sorted(pillars.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else 99, kv[0])):
        c = Counter(t["status"] for t in ts)
        rows.append({"pillar": name, "total": len(ts), "score": score_of(ts), **{k: c.get(k, 0) for k in
                     ("passed", "failed", "investigate", "skipped", "planned", "error", "other")}})
    return rows


def compute_diff(current: dict, baseline_path: str) -> dict:
    data, _ = load_input(baseline_path)
    base = normalize(data)  # raw ZTA JSON or a previous ZTAGuard --json export
    if not base["tenant"]["executed_at"]:
        base["tenant"]["executed_at"] = str(_ci(_ci(data, "tenant", default={}), "executed_at", default="") or "")
    old = {t["id"]: t for t in base["tests"]}
    summary = {"baseline": os.path.basename(baseline_path), "baseline_date": base["tenant"].get("executed_at", ""),
               "fixed": 0, "regressed": 0, "changed": 0, "new_tests": 0, "removed_tests": [],
               "score_before": score_of(base["tests"]), "score_after": score_of(current["tests"])}
    rank = {"passed": 3, "investigate": 2, "failed": 1}
    for t in current["tests"]:
        b = old.get(t["id"])
        if b is None:
            t["change"] = {"new": True, "from": None}
            summary["new_tests"] += 1
            continue
        if b["status"] != t["status"]:
            before, after = rank.get(b["status"]), rank.get(t["status"])
            kind = "fixed" if before and after and after > before else "regressed" if before and after and after < before else "changed"
            t["change"] = {"new": False, "from": b["status"], "kind": kind}
            summary[kind] += 1
        else:
            t["change"] = None
    current_ids = {t["id"] for t in current["tests"]}
    summary["removed_tests"] = sorted(f"{i} {old[i]['title']}" for i in set(old) - current_ids)[:50]
    return summary


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------



def write_csv(norm: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["test_id", "title", "status", "risk", "user_impact", "implementation_cost", "pillars", "sfi_pillar",
                    "category", "license", "priority", "quick_win", "change"])
        for t in sorted(norm["tests"], key=lambda t: -t["priority"]):
            ch = t.get("change") or {}
            w.writerow([csv_safe(v) for v in (t["id"], t["title"], t["status"], t["risk"], t["impact"], t["cost"],
                                              "|".join(t["pillars"]), t["sfi"], t["category"], t["license"], t["priority"],
                                              "yes" if t["quick_win"] else "", ch.get("kind") or ("new" if ch.get("new") else ""))])


def write_json(norm: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": f"ZTAGuard {__version__}", "tenant": norm["tenant"], "score": score_of(norm["tests"]),
                   "pillars": pillar_stats(norm["tests"]), "tests": norm["tests"]}, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<button class="skip" type="button" onclick="document.getElementById('view').focus()">Skip to content</button>
<div class="app">
  <aside class="side" id="side" aria-label="Navigation"></aside>
  <div class="main">
    <header class="topbar" id="topbar"></header>
    <main class="content" id="view" tabindex="-1"></main>
  </div>
</div>
<div id="drawer-root"></div>
<div id="overlay-root"></div>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<noscript><p style="padding:24px">This report needs JavaScript to display the results.</p></noscript>
<script type="application/json" id="mg-data">__DATA__</script>
<script>__JS__</script>
</body>
</html>
"""


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=str)


def generate_html(norm: dict, out: str, title: Optional[str], diff: Optional[dict], source: str) -> None:
    tenant = norm["tenant"]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "source": source, "title": title or tenant.get("name") or tenant.get("domain") or "Zero Trust Assessment"},
        "tenant": tenant, "summary": norm["summary"], "tenant_info": norm["tenant_info"],
        "tests": norm["tests"], "pillars": pillar_stats(norm["tests"]), "score": score_of(norm["tests"]), "diff": diff,
        "weights": {"risk": RISK_WEIGHT, "cost": COST_WEIGHT, "impact": IMPACT_WEIGHT},
    }
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"Zero Trust posture - {payload['meta']['title']}"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)


def build_parser() -> Parser:
    p = Parser(description="HTML viewer for Microsoft Zero Trust Assessment results",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Input: the report folder (searched for zt-export\\ZeroTrustAssessmentReport.json), the JSON file itself,
or the original HTML report (best effort).
Exit codes: 0 ok, 1 input error, 2 score below --fail-under.
""")
    p.add_argument("input", help="Report folder, ZeroTrustAssessmentReport.json or the original HTML report")
    p.add_argument("-o", "--output", default="zta_report.html", help="Output HTML file (default: zta_report.html)")
    p.add_argument("--baseline", help="Previous assessment (folder or JSON) to compare with")
    p.add_argument("--title", help="Title shown in the report (default: tenant name)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV of the tests, ordered by priority")
    p.add_argument("--json", action="store_true", help="Also write the normalized JSON")
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if the overall score is below this value")
    p.add_argument("--version", action="version", version=f"ZTAGuard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data, source = load_input(args.input)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    norm = normalize(data)
    if not norm["tests"]:
        print("Error: no tests found in the input", file=sys.stderr)
        return EXIT_USAGE
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(norm, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    generate_html(norm, args.output, args.title, diff, os.path.basename(source))
    base = args.output.rsplit(".", 1)[0]
    if args.csv:
        write_csv(norm, base + ".csv")
    if args.json:
        write_json(norm, base + ".json")
    score = score_of(norm["tests"])
    c = Counter(t["status"] for t in norm["tests"])
    print(f"Report generated: {args.output}" + (f" (+ {base}.csv)" if args.csv else "") + (f" (+ {base}.json)" if args.json else ""))
    print(f"Tenant: {norm['tenant'].get('name') or '-'} {norm['tenant'].get('domain') or ''}".rstrip())
    print(f"Tests: {len(norm['tests'])}  passed {c['passed']}  failed {c['failed']}  investigate {c['investigate']}  "
          f"skipped {c['skipped']}  planned {c['planned']}")
    print(f"Risk-weighted score: {score if score is not None else 'n/a'}")
    for row in pillar_stats(norm["tests"]):
        print(f"  {row['pillar']:<15} {row['passed']:>3}/{row['total']:<3} passed   score {row['score'] if row['score'] is not None else '-'}")
    if diff:
        print(f"Since {diff['baseline']}: {diff['fixed']} fixed, {diff['regressed']} regressed, {diff['new_tests']} new tests")
    if args.fail_under is not None and score is not None and score < args.fail_under:
        return EXIT_FAIL_UNDER
    return EXIT_OK


# ---------------------------------------------------------------------------
# Report styles and application (shared design with MailGuard DNS and WAFGuard)
# ---------------------------------------------------------------------------

REPORT_CSS = r"""
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

.viz-panel { border: 1px solid var(--line); border-radius: var(--r-lg); background: var(--panel-2); padding: 10px 14px; margin-bottom: 14px; }
.viz-panel > summary { cursor: pointer; padding: 4px 0; } .viz-panel .card.viz { background: var(--panel); }
.viz-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 430px), 1fr)); gap: 16px; margin-bottom: 24px; }
.card.viz { display: flex; flex-direction: column; }
.card.viz .body { flex: 1; display: flex; flex-direction: column; justify-content: space-between; }
.viz-sub { color: var(--muted); font-size: 12.5px; padding: 4px 18px 0; margin: 0; }
.sankey { width: 100%; height: auto; display: block; }
.sankey .sk-link { opacity: .55; transition: opacity .15s; } .sankey .sk-link:hover { opacity: .9; }
.sankey .sk-lbl { font-size: 11.5px; fill: var(--text); font-family: var(--font); paint-order: stroke; stroke: var(--panel); stroke-width: 3px; stroke-linejoin: round; }
.sankey .sk-pct { fill: var(--muted); font-size: 10.5px; }
.viz-foot { display: flex; flex-wrap: wrap; gap: 8px 0; border-top: 1px solid var(--line); margin-top: 12px; padding-top: 10px; }
.viz-foot > div { flex: 1 1 90px; display: grid; gap: 1px; padding-right: 10px; }
.viz-foot > div + div { border-left: 1px solid var(--line); padding-left: 12px; }
.viz-foot span { font-size: 12px; color: var(--muted); display: inline-flex; gap: 6px; align-items: center; }
.viz-foot b { font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; line-height: 1.2; } .viz-foot b small { font-size: 12px; color: var(--muted); font-weight: 400; margin-left: 2px; }
.donut-wrap { display: grid; place-items: center; padding: 6px 0 14px; } .donut { width: 190px; height: 190px; }
.donut .dn-v { fill: var(--text); font-size: 26px; font-weight: 700; font-family: var(--font); } .donut .dn-l { fill: var(--muted); font-size: 12px; font-family: var(--font); }
.osb { display: grid; gap: 14px; padding: 6px 0 14px; } .osb-row { display: grid; grid-template-columns: 70px 1fr 120px; gap: 10px; align-items: center; font-size: 12.5px; }
.osb-row > span:first-child { color: var(--muted); text-align: right; } .osb-track { height: 22px; }
.osb-tot { height: 100%; min-width: 2px; border-radius: 4px; background: color-mix(in srgb, var(--accent) 35%, transparent); overflow: hidden; }
.osb-tot i { display: block; height: 100%; background: var(--accent); }
.nav-sep { font-size: 11.5px; color: var(--faint); padding: 14px 10px 4px; }
.nav-item.on { background: var(--hover); color: var(--text); }
.pdot { width: 9px; height: 9px; border-radius: 50%; background: var(--none); flex: none; margin: 0 3px; }
.pdot.hi { background: var(--pass); } .pdot.mid { background: var(--warn); } .pdot.lo { background: var(--fail); }
.st-badge { width: 56px; height: 56px; border-radius: 14px; display: grid; place-items: center; font-size: 26px; font-weight: 700; flex: none; }
.lvl { font-size: 12.5px; white-space: nowrap; } .lvl-high { color: var(--fail-text); font-weight: 600; } .lvl-medium { color: var(--warn-text); } .lvl-low { color: var(--muted); } .lvl-unknown { color: var(--faint); }
tr.grp td { background: var(--panel-2) !important; cursor: default; font-size: 13px; }
.chg-up { color: var(--pass-text); border-color: color-mix(in srgb, var(--pass) 45%, transparent); }
.chg-down { color: var(--fail-text); border-color: color-mix(in srgb, var(--fail) 45%, transparent); }
.md { font-size: 13.5px; line-height: 1.6; overflow-wrap: anywhere; }
.md p { margin: 0 0 10px; } .md .md-h { margin: 16px 0 8px; font-size: 14px; } .md h3.md-h { font-size: 15px; }
.md code { background: var(--panel-2); border: 1px solid var(--line); border-radius: 4px; padding: 0 4px; }
.md-list { margin: 0 0 10px; padding-left: 20px; } .md-list li { margin: 2px 0; }
.md-table { overflow-x: auto; margin: 8px 0 12px; border: 1px solid var(--line); border-radius: var(--r); }
.md-table table { border-collapse: collapse; width: 100%; } .md-table th, .md-table td { padding: 6px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 12.5px; }
.md-table th { background: var(--panel-2); color: var(--muted); font-weight: 600; } .md-table tr:last-child td { border-bottom: 0; }
.md-hr { border: 0; border-top: 1px solid var(--line); margin: 14px 0; }
.kvtree { display: grid; gap: 4px; font-size: 13px; } .kvtree details > summary { cursor: pointer; padding: 3px 0; }
.kvtree-in { padding-left: 16px; border-left: 1px solid var(--line); margin: 4px 0 6px 4px; }
.kvrow { display: grid; grid-template-columns: minmax(140px, 260px) 1fr; gap: 12px; padding: 2px 0; } .kvrow > span:first-child { color: var(--muted); }

.print-head { display: none; margin-bottom: 16px; }
.print-head h1 { font-size: 20px; }
"""

REPORT_JS = r"""(function () {
'use strict';
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const T = D.tests, M = D.meta || {}, TEN = D.tenant || {}, diff = D.diff;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ESC[c]);
const $ = (s, r) => (r || document).querySelector(s);
const pct = (n, t) => t ? Math.round(100 * n / t) : 0;
const uniq = a => [...new Set(a.filter(Boolean))].sort();
const scoreCls = n => n === null || n === undefined ? '' : n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const gradeOf = n => n === null || n === undefined ? '-' : n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 65 ? 'C' : n >= 50 ? 'D' : 'F';
const ST = {passed: ['pass', '\u2713', 'Passed'], failed: ['fail', '\u2715', 'Failed'], investigate: ['warn', '?', 'Investigate'],
  skipped: ['na', '\u00B7', 'Skipped'], planned: ['none', '\u2013', 'Planned'], error: ['dns', '!', 'Error'], other: ['none', '\u2013', 'Other']};
const ST_ORDER = ['failed', 'investigate', 'passed', 'error', 'skipped', 'planned', 'other'];
const LV = {high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown'};
const LV_ORDER = ['high', 'medium', 'low', 'unknown'];
const st = s => ST[s] || ST.other;
const pill = (s, extra) => { const m = st(s); return `<span class="pill s-${m[0]}"><span class="sym" aria-hidden="true">${m[1]}</span>${esc(m[2])}${extra ? ` <span class="d">${esc(extra)}</span>` : ''}</span>`; };
const riskPill = r => `<span class="pill ${({high: 's-fail', medium: 's-warn', low: 's-null'})[r] || 's-na'}">${esc(LV[r] || r)}</span>`;
const lvl = v => `<span class="lvl lvl-${esc(v)}">${esc(LV[v] || v)}</span>`;
T.forEach((t, i) => { t._i = i; t._text = (t.id + ' ' + t.title + ' ' + t.category + ' ' + t.sfi + ' ' + t.tags.join(' ')).toLowerCase(); });
const PILLARS = D.pillars.map(p => p.pillar);
function score(ts) { let n = 0, d = 0; ts.forEach(t => { const c = {passed: 1, investigate: 0.5, failed: 0}[t.status]; if (c === undefined) return;
  const w = D.weights.risk[t.risk] || 2; n += w * c; d += w; }); return d ? Math.round(100 * n / d) : null; }

/* ================= icons ================= */
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>', list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>', diff: '<path d="M7 4v16M3.5 7.5 7 4l3.5 3.5M17 20V4M13.5 16.5 17 20l3.5-3.5"/>',
  building: '<path d="M4 21V4h11v17M15 9h5v12M8 8h3M8 12h3M8 16h3"/>', search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', x: '<path d="M6 6l12 12M18 6 6 18"/>', left: '<path d="m15 6-6 6 6 6"/>', right: '<path d="m9 6 6 6-6 6"/>',
  link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>', filter: '<path d="M3 5h18l-7 8.5V19l-4 2v-7.5L3 5z"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', key: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>', bolt: '<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/>'
};
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
function ring(v) { const r = 26, c = 2 * Math.PI * r, off = c * (1 - (v || 0) / 100);
  return `<svg class="ring ${scoreCls(v)}" width="64" height="64" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="${r}" class="ring-bg"/><circle cx="32" cy="32" r="${r}" class="ring-fg" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 32 32)"/></svg>`; }
function statusRing(t) { const m = st(t.status); return `<div class="st-badge c-${m[0]}" aria-hidden="true">${m[1]}</div>`; }

/* ================= safe markdown (TestResult / TestDescription) ================= */
function inline(s) {
  let h = esc(s).replace(/&lt;br\s*\/?&gt;/gi, '<br>');
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  h = h.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, txt, url) => /^(https?:|mailto:)/i.test(url) ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${txt}</a>` : txt);
  h = h.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/__([^_]+)__/g, '<b>$1</b>');
  h = h.replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:!?]|$)/g, '$1<i>$2</i>');
  h = h.replace(/(https?:\/\/[^\s<"]+)(?![^<]*<\/a>)(?![^<]*">)/g, m => `<a href="${m}" target="_blank" rel="noopener noreferrer">${m}</a>`);
  return h;
}
function md(src) {
  if (!src) return '';
  const lines = String(src).replace(/\r\n?/g, '\n').split('\n'), out = [];
  let i = 0;
  const cells = l => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
  while (i < lines.length) {
    const l = lines[i];
    if (!l.trim()) { i++; continue; }
    if (/^\s*```/.test(l)) { const b = []; i++; while (i < lines.length && !/^\s*```/.test(lines[i])) b.push(lines[i++]); i++; out.push(`<pre class="record">${esc(b.join('\n'))}</pre>`); continue; }
    const h = l.match(/^\s*(#{1,6})\s+(.*)$/);
    if (h) { const lv = Math.min(6, h[1].length + 2); out.push(`<h${lv} class="md-h">${inline(h[2])}</h${lv}>`); i++; continue; }
    if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const head = cells(l); i += 2; const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(`<div class="md-table"><table><thead><tr>${head.map(c => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l), items = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, '')); i++;
        while (i < lines.length && lines[i].trim() && !/^\s*([-*+]|\d+\.)\s+/.test(lines[i]) && /^\s{2,}/.test(lines[i])) items[items.length - 1] += ' ' + lines[i++].trim(); }
      out.push(`<${ordered ? 'ol' : 'ul'} class="md-list">${items.map(x => `<li>${inline(x)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`);
      continue;
    }
    if (/^\s*>/.test(l)) { const b = []; while (i < lines.length && /^\s*>/.test(lines[i])) b.push(lines[i++].replace(/^\s*>\s?/, '')); out.push(`<blockquote class="note-box">${inline(b.join(' '))}</blockquote>`); continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(l)) { out.push('<hr class="md-hr">'); i++; continue; }
    const p = [];
    while (i < lines.length && lines[i].trim() && !/^\s*(#{1,6}\s|```|\||([-*+]|\d+\.)\s|>)/.test(lines[i])) p.push(lines[i++]);
    if (!p.length) { out.push(`<p>${inline(lines[i++])}</p>`); continue; }
    out.push(`<p>${p.map(inline).join('<br>')}</p>`);
  }
  return `<div class="md">${out.join('')}</div>`;
}

/* ================= preferences & state ================= */
const PREF_KEY = 'ztaguard-prefs-v1';
const P = {density: 'comfortable', size: 50, theme: null, group: 'none'};
try { Object.assign(P, JSON.parse(localStorage.getItem(PREF_KEY) || '{}')); } catch (e) { /* storage unavailable */ }
const savePrefs = () => { try { localStorage.setItem(PREF_KEY, JSON.stringify(P)); } catch (e) { /* ignore */ } };
const FKEYS = ['q', 'status', 'pillar', 'risk', 'impact', 'cost', 'category', 'sfi', 'license', 'tag', 'changed', 'quick'];
const blank = () => Object.fromEntries(FKEYS.map(k => [k, '']));
const S = Object.assign({route: 'overview', sort: {k: 'priority', d: -1}, page: 1, open: null, dtab: 'result', cursor: -1, filtersOpen: false}, blank());
const ROUTES = [
  {id: 'overview', label: 'Overview', icon: 'grid', show: () => true},
  {id: 'tests', label: 'Tests', icon: 'list', show: () => true, count: () => T.length},
  {id: 'categories', label: 'Categories', icon: 'layers', show: () => true, count: () => uniq(T.map(t => t.category)).length},
  {id: 'changes', label: 'Changes', icon: 'diff', show: () => !!diff, count: () => T.filter(t => t.change && (t.change.new || t.change.from)).length},
  {id: 'tenant', label: 'Tenant', icon: 'building', show: () => !!(D.tenant_info || TEN.id)}
];
function toHash() {
  const p = new URLSearchParams();
  FKEYS.forEach(k => { if (S[k]) p.set(k, S[k]); });
  if (S.sort.k !== 'priority' || S.sort.d !== -1) p.set('sort', (S.sort.d < 0 ? '-' : '') + S.sort.k);
  if (S.page > 1) p.set('page', S.page);
  if (S.open !== null) { p.set('d', T[S.open].id); if (S.dtab !== 'result') p.set('t', S.dtab); }
  const qs = p.toString();
  return '#/' + S.route + (qs ? '?' + qs : '');
}
function fromHash() {
  const h = location.hash.replace(/^#\/?/, ''), qi = h.indexOf('?');
  const route = qi >= 0 ? h.slice(0, qi) : h, p = new URLSearchParams(qi >= 0 ? h.slice(qi + 1) : '');
  Object.assign(S, blank());
  S.route = ROUTES.some(r => r.id === route && r.show()) ? route : 'overview';
  FKEYS.forEach(k => { if (p.has(k)) S[k] = p.get(k); });
  const so = p.get('sort'); S.sort = so ? {k: so.replace(/^-/, ''), d: so.startsWith('-') ? -1 : 1} : {k: 'priority', d: -1};
  S.page = Math.max(1, +p.get('page') || 1);
  const d = p.get('d'), t = d ? T.find(x => x.id === d) : null;
  S.open = t ? t._i : null; S.dtab = p.get('t') || 'result';
}
function go(ch, push) { Object.assign(S, ch); const h = toHash(); if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h); render(); }
window.addEventListener('popstate', () => { fromHash(); render(); });
const filterTo = extra => go(Object.assign(blank(), {route: 'tests', open: null, page: 1, cursor: -1}, extra));

/* ================= filtering ================= */
function matches(t) {
  const q = S.q.trim().toLowerCase();
  if (q && !t._text.includes(q)) return false;
  if (S.status && !S.status.split(',').includes(t.status)) return false;
  if (S.pillar && !t.pillars.includes(S.pillar)) return false;
  if (S.risk && t.risk !== S.risk) return false;
  if (S.impact && t.impact !== S.impact) return false;
  if (S.cost && t.cost !== S.cost) return false;
  if (S.category && t.category !== S.category) return false;
  if (S.sfi && t.sfi !== S.sfi) return false;
  if (S.license && t.license !== S.license) return false;
  if (S.tag && !t.tags.includes(S.tag)) return false;
  if (S.quick && !t.quick_win) return false;
  if (S.changed) { const c = t.change; if (!c || !(c.new || c.from)) return false; if (S.changed !== '1' && c.kind !== S.changed && !(S.changed === 'new' && c.new)) return false; }
  return true;
}
const RANK = {high: 3, medium: 2, low: 1, unknown: 0};
const SORTERS = {priority: t => t.priority, title: t => t.title.toLowerCase(), id: t => t.id, status: t => ST_ORDER.indexOf(t.status),
  risk: t => RANK[t.risk], impact: t => RANK[t.impact], cost: t => RANK[t.cost], category: t => t.category.toLowerCase(), pillar: t => t.pillars.join(',')};
function list() {
  const a = T.filter(matches), fn = SORTERS[S.sort.k] || SORTERS.priority, d = S.sort.d;
  return a.sort((x, y) => { const p = fn(x), q = fn(y); return (p < q ? -1 : p > q ? 1 : 0) * d || RANK[y.risk] - RANK[x.risk] || x.title.localeCompare(y.title); });
}
const CHIP_LABEL = {q: v => `Search "${v}"`, status: v => 'Status: ' + v.split(',').map(s => st(s)[2]).join(' or '), pillar: v => `Pillar ${v}`,
  risk: v => `Risk ${LV[v]}`, impact: v => `User impact ${LV[v]}`, cost: v => `Effort ${LV[v]}`, category: v => v, sfi: v => `SFI: ${v}`,
  license: v => `License ${v}`, tag: v => `#${v}`, changed: v => v === '1' ? 'Changed since baseline' : `Change: ${v}`, quick: () => 'Quick wins'};

/* ================= frame ================= */
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !matchMedia('(prefers-color-scheme: light)').matches; };
function side() {
  const sc = D.score, g = gradeOf(sc);
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>ZTAGuard</b><small>Zero Trust posture</small></div></div>
    <button class="posture" data-route="overview" title="Tenant grade"><span class="letter g-${g}">${g}</span><span><b class="num">${sc === null ? '-' : sc + '/100'}</b><br>${esc(TEN.name || TEN.domain || 'Tenant')}</span></button>
    <nav class="nav" aria-label="Sections">${ROUTES.filter(r => r.show()).map((r, k) => { const c = r.count ? r.count() : null;
      return `<button class="nav-item" data-route="${r.id}"${S.route === r.id ? ' aria-current="page"' : ''} title="${esc(r.label)} (${k + 1})">${icon(r.icon)}<span>${esc(r.label)}</span>${c !== null ? `<span class="count">${c}</span>` : ''}</button>`; }).join('')}
      <div class="nav-sep">Pillars</div>
      ${D.pillars.map(p => `<button class="nav-item${S.route === 'tests' && S.pillar === p.pillar ? ' on' : ''}" data-pillar="${esc(p.pillar)}"><span class="pdot ${scoreCls(p.score)}"></span><span>${esc(p.pillar)}${pillarSankeys(p.pillar).length ? ' <span class="faint" title="Includes charts">\u25D4</span>' : ''}</span><span class="count">${p.passed}/${p.total}</span></button>`).join('')}</nav>
    <div class="side-foot">
      <button class="nav-item" data-action="about">${icon('info')}<span>About this report</span></button>
      <button class="nav-item" data-action="keys">${icon('key')}<span>Keyboard shortcuts</span><span class="count"><span class="kbd">?</span></span></button>
      <button class="nav-item" data-action="theme">${icon(isDark() ? 'sun' : 'moon')}<span>${isDark() ? 'Light theme' : 'Dark theme'}</span></button></div>`;
}
function topbar() {
  const r = ROUTES.find(x => x.id === S.route) || ROUTES[0];
  const n = S.route === 'tests' ? list().length : null;
  const sub = S.route === 'tests' ? (n === T.length ? `${T.length} tests` : `${n} of ${T.length} tests`) : S.route === 'overview' ? `${esc(TEN.name || '')} ${TEN.executed_at ? 'assessed ' + esc(fmtDate(TEN.executed_at)) : ''}` : '';
  return `<h1>${esc(S.route === 'tests' && S.pillar ? S.pillar : r.label)}</h1><span class="sub">${sub}</span><span class="spacer"></span>
    <button class="cmdk" data-action="palette" aria-label="Search tests and actions">${icon('search')}<span class="lbl">Search tests, categories, actions</span><span class="kbd">Ctrl K</span></button>
    <button class="btn" data-action="print-exec">${icon('print')}<span>Executive PDF</span></button>`;
}
function fmtDate(s) { const d = new Date(s); return isNaN(d) ? s : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'; }

/* ================= overview ================= */
function overview() {
  const c = s => T.filter(t => t.status === s).length;
  const sc = D.score, g = gradeOf(sc), outdated = TEN.latest_version && TEN.version && TEN.latest_version !== TEN.version;
  const kpi = (v, l, cls, attrs) => `<button class="kpi ${cls || ''}" ${attrs}><b>${v}</b><span>${esc(l)}</span></button>`;
  let h = `<div class="print-head"><h1>Zero Trust posture: ${esc(M.title)}</h1><p class="muted">${esc(TEN.domain || '')} ${TEN.executed_at ? ', assessed ' + esc(fmtDate(TEN.executed_at)) : ''}</p></div>
  <div class="ov-top"><section class="card grade-card"><div class="letter g-${g}">${g}</div><div class="lbl">Tenant grade</div>
    <div class="avg">${sc === null ? '-' : sc}<small>/100</small></div>
    <div class="lbl">Risk-weighted pass rate${diff && diff.score_before !== null ? `, <span class="${sc >= diff.score_before ? 'delta-up' : 'delta-down'}">${sc - diff.score_before >= 0 ? '+' : ''}${sc - diff.score_before} since baseline</span>` : ''}</div></section>
  <section class="card kpi-card">${kpi(T.length, 'tests', '', 'data-route="tests"')}${kpi(c('passed'), 'passed', 'k-pass', 'data-status="passed"')}
    ${kpi(c('failed'), 'failed', 'k-fail', 'data-status="failed"')}${kpi(c('investigate'), 'to investigate', 'k-warn', 'data-status="investigate"')}
    ${kpi(c('skipped') + c('planned') + c('error') + c('other'), 'skipped, planned or error', '', 'data-status="skipped,planned,error,other"')}</section></div>`;
  if (outdated) h += `<p class="note-box" style="margin-bottom:16px">Assessment run with module version ${esc(TEN.version)}; version ${esc(TEN.latest_version)} is available and may include more tests.</p>`;
  const viz = vizCards();
  const flows = uniq(VIZ().sankeys.map(s => s.pillar)).filter(Boolean);
  if (viz.length || flows.length) h += `<div class="section-title" style="margin-top:8px"><h2>Tenant posture</h2><p>From the tenant data collected by the assessment${flows.length ? `. Authentication and device flows are in ${flows.map(p => `<button class="link" data-pillar="${esc(p)}">${esc(p)}</button>`).join(' and ')}` : ''}</p></div>${viz.length ? `<div class="viz-grid">${viz.join('')}</div>` : ''}<div class="section-title"><h2>Assessment results</h2></div>`;
  h += '<div class="ov-grid">';
  const present = new Set();
  h += `<section class="card span2"><header><h2>Pillars</h2><p>Test results per Zero Trust pillar. Select a segment to list those tests.</p></header><div class="body"><div class="cov">${D.pillars.map(p => {
    const segs = ST_ORDER.filter(s => p[s]).map(s => { present.add(s); return `<button class="c-${st(s)[0]}" style="flex:${p[s]}" data-pillar="${esc(p.pillar)}" data-pst="${s}" title="${esc(p.pillar + ': ' + p[s] + ' ' + st(s)[2].toLowerCase())}" aria-label="${esc(p.pillar + ': ' + p[s] + ' ' + st(s)[2].toLowerCase())}"></button>`; }).join('');
    return `<div class="cov-row" style="grid-template-columns:110px minmax(0,1fr) 92px"><button class="link" data-pillar="${esc(p.pillar)}" style="color:var(--text)">${esc(p.pillar)}</button><div class="cov-bar">${segs}</div><span class="cov-num"><span class="score ${scoreCls(p.score)}">${p.score === null ? '-' : p.score}</span> <span class="faint">${p.passed}/${p.total}</span></span></div>`; }).join('')}</div>
    <div class="legend">${ST_ORDER.filter(s => present.has(s)).map(s => `<span><i class="dot c-${st(s)[0]}"></i>${st(s)[2]}</span>`).join('')}<span class="faint">Score = pass rate weighted by risk</span></div></div></section>`;
  // risk x status
  const rs = ['high', 'medium', 'low'], cols = [['failed', 'var(--fail)'], ['investigate', 'var(--warn)'], ['passed', 'var(--pass)']];
  const cnt = (r, s) => T.filter(t => t.risk === r && t.status === s).length, mx = Math.max(1, ...rs.flatMap(r => cols.map(c => cnt(r, c[0]))));
  h += `<section class="card"><header><h2>Risk and result</h2></header><div class="body"><div class="rm"><div class="rm-row" style="grid-template-columns:70px repeat(3,minmax(0,1fr))"><span></span>${cols.map(c => `<span class="rm-head">${st(c[0])[2]}</span>`).join('')}</div>
    ${rs.map(r => `<div class="rm-row" style="grid-template-columns:70px repeat(3,minmax(0,1fr))">${riskPill(r)}${cols.map(([s, col]) => { const v = cnt(r, s);
      return `<button class="rm-cell${v ? '' : ' zero'}" style="background:color-mix(in srgb, ${col} ${v ? 12 + Math.round(48 * v / mx) : 4}%, transparent)" data-risk="${r}" data-rst="${s}" aria-label="${v} ${r} risk tests ${s}">${v}</button>`; }).join('')}</div>`).join('')}</div></div></section>`;
  const fix = T.filter(t => t.priority > 0).sort((a, b) => b.priority - a.priority).slice(0, 7);
  h += `<section class="card"><header><h2>Fix first</h2><p>Risk, effort and user impact</p></header><div class="body"><ul class="rows">${fix.map(t => `<li><button class="r-btn" data-open="${t._i}"><span class="r-main">${esc(t.title)}</span><span class="r-val">${riskPill(t.risk)}</span>
    <span class="r-sub">${esc(t.pillars.join(', '))}, ${st(t.status)[2].toLowerCase()}, effort ${esc((LV[t.cost] || '').toLowerCase())}</span></button></li>`).join('') || '<li class="muted">Nothing to fix.</li>'}</ul></div></section>`;
  const quick = T.filter(t => t.quick_win).sort((a, b) => b.priority - a.priority);
  h += `<section class="card"><header><h2>Quick wins</h2><p>Low effort, low user impact</p><span class="act"><button class="link" data-quick="1">All ${quick.length}</button></span></header><div class="body"><ul class="rows">${quick.slice(0, 6).map(t => `<li><button class="r-btn" data-open="${t._i}"><span class="r-main">${esc(t.title)}</span><span class="r-val">${riskPill(t.risk)}</span>
    <span class="r-sub">${esc(t.category)}</span></button></li>`).join('') || '<li class="muted">No quick wins left.</li>'}</ul></div></section>`;
  const sfi = uniq(T.map(t => t.sfi));
  if (sfi.length) h += `<section class="card"><header><h2>Secure Future Initiative</h2><p>Pass rate per SFI pillar</p></header><div class="body">${sfi.map(s => { const ts = T.filter(t => t.sfi === s), ev = ts.filter(t => ['passed', 'failed', 'investigate'].includes(t.status)), ok = ts.filter(t => t.status === 'passed').length;
    return `<button class="bar-row" data-sfi="${esc(s)}"><span>${esc(s)}</span><span class="bar"><i class="b-pass" style="width:${pct(ok, ev.length)}%"></i></span><span>${ok}/${ev.length}</span></button>`; }).join('')}</div></section>`;
  const ov = (D.tenant_info || {}).TenantOverview || (D.tenant_info || {}).tenantOverview;
  if (ov && typeof ov === 'object') { const nums = Object.entries(ov).filter(([, v]) => typeof v === 'number').slice(0, 8);
    if (nums.length) h += `<section class="card"><header><h2>Tenant</h2><p>${esc(TEN.domain || '')}</p></header><div class="body"><div class="stat-strip">${nums.map(([k, v]) => `<div class="stat"><b>${v.toLocaleString()}</b><span>${esc(k.replace(/([a-z])([A-Z])/g, '$1 $2'))}</span></div>`).join('')}</div></div></section>`; }
  if (diff) h += `<section class="card"><header><h2>Since the baseline</h2><p>${esc(diff.baseline_date ? fmtDate(diff.baseline_date) : diff.baseline)}</p></header><div class="body"><div class="stat-strip">
    <button class="stat" data-changed="fixed"><b class="delta-up">${diff.fixed}</b><span>fixed</span></button><button class="stat" data-changed="regressed"><b class="delta-down">${diff.regressed}</b><span>regressed</span></button>
    <button class="stat" data-changed="new"><b>${diff.new_tests}</b><span>new tests</span></button><button class="stat" data-route="changes"><b>${diff.removed_tests.length}</b><span>removed</span></button></div></div></section>`;
  return h + '</div>';
}

/* ================= tests ================= */
const PRESETS = () => [['All tests', {}], ['Failed, high risk', {status: 'failed', risk: 'high'}], ['Failed or investigate', {status: 'failed,investigate'}],
  ['Quick wins', {quick: '1'}], ...(diff ? [['Regressed', {changed: 'regressed'}], ['Fixed', {changed: 'fixed'}]] : []), ['Skipped', {status: 'skipped'}]];
function presetActive(p) { const t = Object.assign(blank(), p[1]); return FKEYS.every(k => (S[k] || '') === (t[k] || '')); }
function tests() {
  const all = list(), pages = Math.max(1, Math.ceil(all.length / P.size));
  if (S.page > pages) S.page = pages;
  const items = all.slice((S.page - 1) * P.size, S.page * P.size);
  const chips = FKEYS.filter(k => S[k]).map(k => [k, CHIP_LABEL[k](S[k])]);
  const counts = PRESETS().map(p => { const keep = {}; FKEYS.forEach(k => keep[k] = S[k]); Object.assign(S, blank(), p[1]); const n = T.filter(matches).length; Object.assign(S, keep); return n; });
  let h = pillarPanel() + `<div class="presets" role="group" aria-label="Saved views">${PRESETS().map((p, k) => `<button class="preset" data-preset="${k}" aria-pressed="${presetActive(p)}">${esc(p[0])}<span class="n">${counts[k]}</span></button>`).join('')}</div>
  <div class="toolbar"><div class="search-box">${icon('search')}<input type="search" id="q" placeholder="Filter by title, ID, category or tag" value="${esc(S.q)}" aria-label="Filter tests"></div>
    <button class="btn" data-action="filters" aria-expanded="${S.filtersOpen}">${icon('filter')}Filters${chips.length ? `<span class="badge-n">${chips.length}</span>` : ''}</button><span class="spacer"></span>
    <label class="field" style="flex-direction:row;align-items:center;gap:8px;display:flex">Group<select data-k="group" aria-label="Group by">${[['none', 'None'], ['category', 'Category'], ['pillar', 'Pillar'], ['risk', 'Risk']].map(([v, l]) => `<option value="${v}"${P.group === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
    <div class="seg" role="group" aria-label="Density"><button data-density="comfortable" aria-pressed="${P.density === 'comfortable'}">Comfortable</button><button data-density="compact" aria-pressed="${P.density === 'compact'}">Compact</button></div>
    <button class="btn" data-action="csv">${icon('download')}CSV</button></div>`;
  if (S.filtersOpen) h += filterPanel();
  h += `<div class="chips">${chips.length ? chips.map(([k, l]) => `<span class="chip">${esc(l)}<button data-chip="${k}" aria-label="Remove filter ${esc(l)}">${icon('x', 12)}</button></span>`).join('') + '<button class="link" data-action="clear">Clear all</button>' : `<span>${all.length} tests</span>`}</div>`;
  if (!all.length) return h + `<div class="grid-wrap"><div class="empty"><b>No test matches these filters</b><button class="btn" data-action="clear">Clear filters</button></div></div>`;
  return h + `<div class="grid-wrap" id="grid">${table(P.group === 'none' ? items : all)}</div>` + (P.group === 'none' ? pager(all.length, pages) : '');
}
function filterPanel() {
  const sel = (k, label, opts, fmt) => `<label class="field">${esc(label)}<select data-k="${k}"><option value="">All</option>${opts.map(o => `<option value="${esc(o)}"${S[k] === o ? ' selected' : ''}>${esc(fmt ? fmt(o) : o)}</option>`).join('')}</select></label>`;
  return `<div class="filter-panel">${sel('status', 'Status', ST_ORDER.filter(s => T.some(t => t.status === s)), s => st(s)[2])}${sel('pillar', 'Pillar', PILLARS)}
    ${sel('risk', 'Risk', LV_ORDER.filter(v => T.some(t => t.risk === v)), v => LV[v])}${sel('impact', 'User impact', LV_ORDER.filter(v => T.some(t => t.impact === v)), v => LV[v])}
    ${sel('cost', 'Implementation effort', LV_ORDER.filter(v => T.some(t => t.cost === v)), v => LV[v])}${sel('category', 'Category', uniq(T.map(t => t.category)))}
    ${uniq(T.map(t => t.sfi)).length ? sel('sfi', 'SFI pillar', uniq(T.map(t => t.sfi))) : ''}${uniq(T.map(t => t.license)).length ? sel('license', 'Minimum license', uniq(T.map(t => t.license))) : ''}
    ${uniq(T.flatMap(t => t.tags)).length ? sel('tag', 'Tag', uniq(T.flatMap(t => t.tags))) : ''}
    ${diff ? sel('changed', 'Change', ['1', 'fixed', 'regressed', 'changed', 'new'], v => ({'1': 'Any change', fixed: 'Fixed', regressed: 'Regressed', changed: 'Other change', new: 'New test'})[v]) : ''}</div>`;
}
function th(k, label, cls) { const cur = S.sort.k === k ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<th class="${cls || ''}" aria-sort="${cur}"><button class="sort" data-sort="${k}">${esc(label)}</button></th>`; }
function row(t, k) {
  const ch = t.change, chHtml = !ch ? '' : ch.new ? '<span class="tag">new</span>' : ch.from ? `<span class="tag ${ch.kind === 'fixed' ? 'chg-up' : ch.kind === 'regressed' ? 'chg-down' : ''}">${esc(ch.kind)}: was ${esc(st(ch.from)[2].toLowerCase())}</span>` : '';
  return `<tr data-row="${t._i}" class="${k === S.cursor ? 'cursor ' : ''}${S.open === t._i ? 'active' : ''}"><td>${pill(t.status)}</td>
    <td class="sticky"><button class="dom" data-open="${t._i}" style="word-break:normal">${esc(t.title)}</button>${P.density !== 'compact' ? `<div class="dom-sub">${esc(t.id)}, ${esc(t.category)}${t.license ? ', ' + esc(t.license) : ''}</div>` : ''}${chHtml ? '<div style="margin-top:3px">' + chHtml + '</div>' : ''}</td>
    <td class="nowrap">${esc(t.pillars.join(', '))}</td><td>${riskPill(t.risk)}</td><td>${lvl(t.impact)}</td><td>${lvl(t.cost)}</td><td class="r num">${t.priority || '<span class="faint">0</span>'}</td></tr>`;
}
function table(items) {
  const head = `<thead><tr>${th('status', 'Status')}${th('title', 'Test', 'sticky')}${th('pillar', 'Pillar')}${th('risk', 'Risk')}${th('impact', 'User impact')}${th('cost', 'Effort')}${th('priority', 'Priority', 'r')}</tr></thead>`;
  if (P.group === 'none') return `<table class="grid${P.density === 'compact' ? ' compact' : ''}">${head}<tbody>${items.map(row).join('')}</tbody></table>`;
  const key = {category: t => [t.category], pillar: t => t.pillars, risk: t => [LV[t.risk]]}[P.group];
  const groups = {};
  items.forEach(t => key(t).forEach(g => (groups[g] = groups[g] || []).push(t)));
  const names = Object.keys(groups).sort((a, b) => P.group === 'risk' ? LV_ORDER.indexOf(a.toLowerCase()) - LV_ORDER.indexOf(b.toLowerCase()) : a.localeCompare(b));
  return `<table class="grid${P.density === 'compact' ? ' compact' : ''}">${head}<tbody>${names.map(g => { const ts = groups[g], sc = score(ts), f = ts.filter(t => t.status === 'failed').length;
    return `<tr class="grp"><td colspan="7"><b>${esc(g)}</b> <span class="faint">${ts.length} tests, ${f} failed</span> ${sc === null ? '' : `<span class="score ${scoreCls(sc)}">${sc}</span>`}</td></tr>${ts.map(row).join('')}`; }).join('')}</tbody></table>`;
}
function pager(total, pages) {
  const cur = S.page, nums = [];
  for (let p = 1; p <= pages; p++) if (p === 1 || p === pages || Math.abs(p - cur) <= 2) nums.push(p);
  let prev = 0, out = '';
  nums.forEach(p => { if (p - prev > 1) out += '<span class="faint">\u2026</span>'; out += `<button class="btn small" data-page="${p}"${p === cur ? ' aria-current="page"' : ''}>${p}</button>`; prev = p; });
  return `<nav class="pager" aria-label="Pagination"><span>Rows ${total ? (cur - 1) * P.size + 1 : 0} to ${Math.min(cur * P.size, total)} of ${total}
    <select data-k="size" aria-label="Rows per page" style="margin-left:8px">${[25, 50, 100, 250].map(s => `<option value="${s}"${s === P.size ? ' selected' : ''}>${s} per page</option>`).join('')}</select></span>
    ${pages > 1 ? `<div class="pages"><button class="btn small" data-page="${cur - 1}"${cur <= 1 ? ' disabled' : ''}>${icon('left', 14)}Previous</button>${out}<button class="btn small" data-page="${cur + 1}"${cur >= pages ? ' disabled' : ''}>Next${icon('right', 14)}</button></div>` : ''}
    <span class="faint">Keys: <span class="kbd">j</span> <span class="kbd">k</span> move, <span class="kbd">Enter</span> open</span></nav>`;
}

/* ================= tenant visuals (TenantInfo): sankey, donut, splits, OS bars ================= */
const VIZ_TITLES = {
  overviewauthmethodsprivilegedusers: ['Privileged users auth methods', 'Strongest authentication method registered by privileged users.', 'Identity'],
  overviewauthmethodsallusers: ['All users auth methods', 'Strongest authentication method registered by all users.', 'Identity'],
  overviewcamfaallusers: ['User authentication', 'Sign-ins protected by Conditional Access policies enforcing multifactor authentication.', 'Identity'],
  overviewcadevicesallusers: ['Device sign-ins', 'Sign-ins by device management and compliance state.', 'Devices'],
  desktopdevicessummary: ['Desktop devices', 'Join type and compliance of desktop devices.', 'Devices'],
  mobilesummary: ['Mobile devices', 'Platform and compliance of mobile devices.', 'Devices']
};
const VIZ_ORDER = Object.keys(VIZ_TITLES);
const normKey = k => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
const human = k => String(k).replace(/^Overview/, '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
const num = v => { const n = typeof v === 'number' ? v : parseFloat(v); return isFinite(n) ? n : 0; };
const fmtK = n => n >= 1e6 ? (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K' : String(Math.round(n));
function ciGet(o, ...names) { if (!o || typeof o !== 'object') return undefined; const m = {}; Object.keys(o).forEach(k => { m[normKey(k)] = o[k]; }); for (const n of names) { const v = m[normKey(n)]; if (v !== undefined && v !== null) return v; } return undefined; }
function asLinks(arr) {
  if (!Array.isArray(arr) || !arr.length) return null;
  const ok = arr.filter(x => x && typeof x === 'object' && ciGet(x, 'source') !== undefined && ciGet(x, 'target') !== undefined);
  if (ok.length < Math.max(1, arr.length / 2)) return null;
  return ok.map(x => ({source: String(ciGet(x, 'source')), target: String(ciGet(x, 'target')), value: num(ciGet(x, 'value'))}));
}
function nodeClass(name) {
  const n = name.toLowerCase();
  if (/single ?factor|no ca|non.?compliant|unmanaged|unprotected|not covered|no mfa|password only|^none$|disabled/.test(n)) return 'bad';
  if (/phish.?resistant|passkey|whfb|windows hello|fido|certificate|^mfa$|multifactor|^compliant|^protected|ca applied|sensor installed|covered/.test(n)) return 'good';
  if (/phishable|phone|sms|voice|authenticator|email|otp|software|registered/.test(n)) return 'warn';
  if (/managed|joined/.test(n)) return 'mid';
  if (/^(ios|ipados|android|windows|macos|linux)$/.test(n)) return 'plat';
  return 'root';
}
const VIZ_COLOR = {good: 'var(--pass)', bad: 'var(--fail)', warn: 'var(--warn)', mid: '#e8735a', plat: 'var(--null)', root: '#f08a24', purple: '#9b6fd6'};
function discoverVisuals(info) {
  const out = {sankeys: [], splits: [], osbars: []};
  if (!info || typeof info !== 'object') return out;
  const seen = new Set();
  (function walk(o, key, depth) {
    if (!o || typeof o !== 'object' || depth > 6 || seen.has(o)) return;
    seen.add(o);
    const links = Array.isArray(o) ? asLinks(o) : asLinks(ciGet(o, 'nodes', 'links', 'data'));
    if (links && links.some(l => l.value > 0)) {
      const meta = VIZ_TITLES[normKey(key)] || [human(key), '', /device|desktop|mobile/i.test(key) ? 'Devices' : /auth|mfa|ca|sign/i.test(key) ? 'Identity' : ''];
      out.sankeys.push({key, title: meta[0], sub: (!Array.isArray(o) && ciGet(o, 'description')) || meta[1], pillar: meta[2], links});
      return;
    }
    if (!Array.isArray(o)) {
      const nums = Object.entries(o).filter(([, v]) => typeof v === 'number' || (typeof v === 'string' && v.trim() !== '' && isFinite(+v)));
      const pick = (re, not) => nums.filter(([k]) => re.test(normKey(k)) && !(not && not.test(normKey(k))));
      const pairs = [
        [pick(/^compliant|compliantcount|compliantdevice/, /non/), pick(/noncompliant/), 'Device compliance', ['Compliant', 'Non-compliant'], ['good', 'bad']],
        [pick(/corporate/), pick(/personal/), 'Device ownership', ['Corporate', 'Personal'], ['plat', 'purple']],
        [pick(/^protected|protectedcount/, /un/), pick(/unprotected/), human(key) || 'Protection', ['Protected', 'Unprotected'], ['good', 'bad']]];
      pairs.forEach(([a, b, title, labels, cls]) => { if (a.length && b.length) out.splits.push({key, title: /^(\d+|data|value)?$/.test(String(key)) ? title : (VIZ_TITLES[normKey(key)] ? title : title), parts: [[labels[0], num(a[0][1]), cls[0]], [labels[1], num(b[0][1]), cls[1]]]}); });
      const OS = ['windows', 'macos', 'ios', 'android', 'linux', 'ipados', 'chromeos'];
      const osKeys = Object.keys(o).filter(k => OS.some(os => normKey(k) === os || normKey(k) === os + 'count'));
      if (osKeys.length >= 2) {
        const OSL = {windows: 'Windows', macos: 'macOS', ios: 'iOS', android: 'Android', linux: 'Linux', ipados: 'iPadOS', chromeos: 'ChromeOS'};
        const rows = osKeys.map(k => { const v = o[k], label = OSL[normKey(k).replace(/count$/, '')] || human(k);
          if (v && typeof v === 'object') { const e = Object.entries(v).filter(([, x]) => isFinite(+x));
            const isTot = kk => /total/.test(normKey(kk)) || ['all', 'count'].includes(normKey(kk)); const tot = e.find(([kk]) => isTot(kk)), cov = e.find(([kk]) => !isTot(kk));
            return cov ? {label, covered: num(cov[1]), total: tot ? num(tot[1]) : num(cov[1]), metric: human(cov[0])} : null; }
          return isFinite(+v) ? {label, covered: num(v), total: null, metric: ''} : null; }).filter(Boolean);
        if (rows.length >= 2) out.osbars.push({key, title: rows.some(r => r.total !== null) ? 'Device summary' : 'Devices by operating system', rows});
      }
    }
    (Array.isArray(o) ? o.map((v, i) => [i, v]) : Object.entries(o)).forEach(([k, v]) => { if (v && typeof v === 'object') walk(v, Array.isArray(o) ? key : k, depth + 1); });
  })(info, 'TenantInfo', 0);
  out.sankeys.sort((a, b) => { const ia = VIZ_ORDER.indexOf(normKey(a.key)), ib = VIZ_ORDER.indexOf(normKey(b.key)); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  if (!out.splits.some(s => s.title === 'Device compliance')) {  // derive it from the device sankeys
    let ok = 0, bad = 0;
    out.sankeys.filter(s => /desktop|mobile/i.test(s.key)).forEach(s => s.links.forEach(l => { const c = nodeClass(l.target); if (/^compliant/i.test(l.target)) ok += l.value; else if (c === 'bad' && /compliant/i.test(l.target)) bad += l.value; }));
    if (ok + bad) out.splits.unshift({key: 'derived', title: 'Device compliance', parts: [['Compliant', ok, 'good'], ['Non-compliant', bad, 'bad']], derived: true});
  }
  return out;
}
let vizUid = 0;
function sankeySvg(rawLinks) {
  const links0 = rawLinks.filter(l => l.value > 0 && l.source !== l.target);
  if (!links0.length) return '<p class="muted">No data.</p>';
  const W = 640, H = 300, NW = 10, PAD = 14, uid = 'sk' + (++vizUid);
  const nodes = [], idx = {};
  const node = n => { if (!(n in idx)) { idx[n] = nodes.length; nodes.push({name: n, ins: [], outs: [], depth: 0}); } return nodes[idx[n]]; };
  const L = links0.map(l => { const s = node(l.source), t = node(l.target), o = {s, t, v: l.value}; s.outs.push(o); t.ins.push(o); return o; });
  for (let it = 0; it < nodes.length; it++) { let ch = false; L.forEach(l => { if (l.t.depth < l.s.depth + 1) { l.t.depth = l.s.depth + 1; ch = true; } }); if (!ch) break; }
  nodes.forEach(n => { n.d0 = n.depth; });
  const maxD = Math.max(1, ...nodes.map(n => n.depth));
  nodes.forEach(n => { if (!n.outs.length) n.depth = maxD; n.value = Math.max(n.ins.reduce((a, l) => a + l.v, 0), n.outs.reduce((a, l) => a + l.v, 0)); });
  const cols = Array.from({length: maxD + 1}, (_, d) => nodes.filter(n => n.depth === d));
  const ky = Math.min(...cols.filter(c => c.length).map(c => (H - PAD * (c.length - 1)) / (c.reduce((a, n) => a + n.value, 0) || 1)));
  const minH = 2;
  cols.forEach((c, d) => {
    if (d > 0) c.sort((a, b) => { const bc = n => { const w = n.ins.reduce((s, l) => s + l.v, 0) || 1; return n.ins.reduce((s, l) => s + (l.s.y0 + l.s.h / 2) * l.v, 0) / w; }; return bc(a) - bc(b); });
    const tot = c.reduce((a, n) => a + Math.max(minH, n.value * ky), 0) + PAD * (c.length - 1);
    let y = Math.max(0, (H - tot) / 2);
    c.forEach(n => { n.x = d * (W - NW) / maxD; n.h = Math.max(minH, n.value * ky); n.y0 = y; y += n.h + PAD; });
  });
  nodes.forEach(n => { let sy = n.y0; n.outs.sort((a, b) => a.t.y0 - b.t.y0).forEach(l => { l.sy = sy; l.h = Math.max(1, l.v * ky); sy += l.v * ky; });
    let ty = n.y0; n.ins.sort((a, b) => a.s.y0 - b.s.y0).forEach(l => { l.ty = ty; ty += l.v * ky; }); });
  const total = nodes.filter(n => !n.ins.length).reduce((a, n) => a + n.value, 0) || 1;
  const col = n => VIZ_COLOR[nodeClass(n.name)] || VIZ_COLOR.root;
  let defs = '', paths = '';
  L.forEach((l, i) => { const x0 = l.s.x + NW, x1 = l.t.x, xm = (x0 + x1) / 2, y0 = l.sy, y1 = l.ty, h = l.h;
    defs += `<linearGradient id="${uid}g${i}" gradientUnits="userSpaceOnUse" x1="${x0}" x2="${x1}" y1="0" y2="0"><stop offset="0" stop-color="${col(l.s)}"/><stop offset="1" stop-color="${col(l.t)}"/></linearGradient>`;
    paths += `<path class="sk-link" d="M${x0},${y0}C${xm},${y0} ${xm},${y1} ${x1},${y1}L${x1},${y1 + h}C${xm},${y1 + h} ${xm},${y0 + h} ${x0},${y0 + h}Z" fill="url(#${uid}g${i})"><title>${esc(l.s.name)} to ${esc(l.t.name)}: ${l.v.toLocaleString()} (${pct(l.v, total)}%)</title></path>`; });
  const rects = nodes.map(n => { const last = n.depth === maxD, tx = last ? n.x - 6 : n.x + NW + 6, ty = n.y0 + n.h / 2;
    return `<rect x="${n.x}" y="${n.y0}" width="${NW}" height="${n.h}" rx="2" fill="${col(n)}"><title>${esc(n.name)}: ${n.value.toLocaleString()} (${pct(n.value, total)}%)</title></rect>
      <text x="${tx}" y="${ty}" dy="0.35em" text-anchor="${last ? 'end' : 'start'}" class="sk-lbl">${esc(n.name)} <tspan class="sk-pct">${pct(n.value, total)}%</tspan></text>`; }).join('');
  let split = nodes.filter(n => !n.ins.length);
  if (split.length === 1) { let cur = split[0]; while (cur.outs.length === 1) cur = cur.outs[0].t; split = cur.outs.map(l => l.t); }
  const foot = split.length > 1 ? `<div class="viz-foot">${split.slice(0, 4).map(n => `<div><span><i class="dot" style="background:${col(n)}"></i>${esc(n.name)}</span><b>${pct(n.value, total)}<small>%</small></b></div>`).join('')}<div><span>Total</span><b>${fmtK(total)}</b></div></div>` : '';
  return `<svg class="sankey" viewBox="-2 -4 ${W + 4} ${H + 8}" role="img" aria-label="Flow diagram"><defs>${defs}</defs>${paths}${rects}</svg>${foot}`;
}
function donutSvg(parts) {
  const total = parts.reduce((a, p) => a + p[1], 0) || 1, r = 70, c = 2 * Math.PI * r;
  let off = 0;
  const arcs = parts.map(([lbl, v, cls]) => { const len = c * v / total, gap = parts.filter(p => p[1] > 0).length > 1 ? 3 : 0;
    const s = `<circle cx="100" cy="100" r="${r}" fill="none" stroke="${VIZ_COLOR[cls] || 'var(--accent)'}" stroke-width="30" stroke-dasharray="${Math.max(0, len - gap).toFixed(2)} ${c.toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 100 100)"><title>${esc(lbl)}: ${v.toLocaleString()} (${pct(v, total)}%)</title></circle>`; off += len; return s; }).join('');
  return `<svg class="donut" viewBox="0 0 200 200" role="img" aria-label="${esc(parts.map(p => p[0] + ' ' + pct(p[1], total) + '%').join(', '))}">${arcs}<text x="100" y="98" text-anchor="middle" class="dn-v">${fmtK(total)}</text><text x="100" y="118" text-anchor="middle" class="dn-l">total</text></svg>`;
}
function splitBar(parts) {
  const total = parts.reduce((a, p) => a + p[1], 0) || 1;
  return `<div class="bar" style="height:12px">${parts.map(([l, v, cls]) => `<i style="width:${pct(v, total)}%;background:${cls === 'purple' ? '#9b6fd6' : VIZ_COLOR[cls]}" title="${esc(l)}"></i>`).join('')}</div>
    <div class="viz-foot" style="border:0;padding:12px 0 0">${parts.map(([l, v, cls]) => `<div><span><i class="dot" style="background:${cls === 'purple' ? '#9b6fd6' : VIZ_COLOR[cls]}"></i>${esc(l)}</span><b>${pct(v, total)}<small>%</small></b><span class="faint">${fmtK(v)}</span></div>`).join('')}</div>`;
}
function osBars(rows) {
  const max = Math.max(1, ...rows.map(r => r.total !== null ? r.total : r.covered));
  const metric = (rows.find(r => r.metric) || {}).metric;
  return `<div class="osb">${rows.map(r => { const tot = r.total !== null ? r.total : r.covered;
    return `<div class="osb-row"><span>${esc(r.label)}</span><div class="osb-track"><div class="osb-tot" style="width:${(100 * tot / max).toFixed(1)}%">${r.total !== null ? `<i style="width:${pct(r.covered, tot)}%"></i>` : ''}</div></div>
      <span class="num">${r.total !== null ? `${fmtK(r.covered)}/${fmtK(r.total)} <span class="faint">${pct(r.covered, r.total)}%</span>` : fmtK(r.covered)}</span></div>`; }).join('')}</div>
    ${metric ? `<div class="legend"><span><i class="dot" style="background:var(--accent)"></i>${esc(metric)}</span><span><i class="dot" style="background:color-mix(in srgb, var(--accent) 35%, transparent)"></i>Not covered</span></div>` : ''}`;
}
let _viz = null;
const VIZ = () => _viz || (_viz = discoverVisuals(D.tenant_info));
const pillarSankeys = p => VIZ().sankeys.filter(s => s.pillar === p);
function sankeyCards(list) {
  return list.map(s => `<section class="card viz"><header><h2>${esc(s.title)}</h2></header>${s.sub ? `<p class="viz-sub">${esc(s.sub)}</p>` : ''}<div class="body">${sankeySvg(s.links)}</div></section>`);
}
function pillarPanel() {
  const list = S.pillar ? pillarSankeys(S.pillar) : [];
  if (!list.length) return '';
  return `<details class="viz-panel" id="viz-panel"${P.vizOpen === false ? '' : ' open'}><summary><b>${esc(S.pillar)} posture</b> <span class="faint">${list.length} chart${list.length === 1 ? '' : 's'} from the tenant data</span></summary>
    <div class="viz-grid" style="margin:12px 0 4px">${sankeyCards(list).join('')}</div></details>`;
}
function vizCards(onlyUnmapped) {
  const v = VIZ();
  const cards = [];
  const link = p => p ? `<span class="act"><button class="link" data-pillar="${esc(p)}">${esc(p)} tests</button></span>` : '';
  if (onlyUnmapped) return sankeyCards(v.sankeys.filter(s => !s.pillar));
  if (false) v.sankeys.forEach(s => cards.push(`<section class="card viz"><header><h2>${esc(s.title)}</h2>${link(s.pillar)}</header>${s.sub ? `<p class="viz-sub">${esc(s.sub)}</p>` : ''}<div class="body">${sankeySvg(s.links)}</div></section>`));
  v.osbars.sort((a, b) => (b.title === 'Device summary') - (a.title === 'Device summary'));
  v.osbars.forEach((o, k) => {
    const dsk = v.sankeys.find(s => /desktop/i.test(s.key)), mob = v.sankeys.find(s => /mobile/i.test(s.key));
    const sum = s => s.links.filter(l => !s.links.some(x => x.target === l.source)).reduce((a, l) => a + l.value, 0);
    cards.push(`<section class="card viz"><header><h2>${esc(o.title)}</h2>${link('Devices')}</header><p class="viz-sub">${o.title === 'Device summary' ? 'Devices by operating system and coverage.' : 'Managed devices by operating system.'}</p><div class="body">${osBars(o.rows)}
      ${k === 0 && dsk && mob ? splitBar([['Desktops', sum(dsk), 'plat'], ['Mobiles', sum(mob), 'purple']]) : ''}</div></section>`); });
  v.splits.forEach(s => cards.push(`<section class="card viz"><header><h2>${esc(s.title)}</h2>${s.title === 'Device compliance' ? link('Devices') : ''}</header>${s.derived ? '<p class="viz-sub">Derived from the desktop and mobile device flows.</p>' : ''}<div class="body">
    <div class="donut-wrap">${donutSvg(s.parts.map(p => [p[0], p[1], p[2] === 'purple' ? 'purple' : p[2]]))}</div>${splitBar(s.parts)}</div></section>`));
  return cards;
}

/* ================= categories, changes, tenant ================= */
function categories() {
  const g = {};
  T.forEach(t => (g[t.category] = g[t.category] || []).push(t));
  const rows = Object.entries(g).map(([k, ts]) => ({k, ts, sc: score(ts), f: ts.filter(t => t.status === 'failed').length, inv: ts.filter(t => t.status === 'investigate').length,
    hi: ts.filter(t => t.status === 'failed' && t.risk === 'high').length, pil: uniq(ts.flatMap(t => t.pillars)).join(', ')}))
    .sort((a, b) => (a.sc === null) - (b.sc === null) || a.sc - b.sc || b.f - a.f);
  return `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Category</th><th>Pillar</th><th class="r">Tests</th><th>Score</th><th class="r">Failed</th><th class="r">High-risk failed</th><th class="r">Investigate</th></tr></thead><tbody>
    ${rows.map(x => `<tr><td class="sticky"><button class="dom" data-category="${esc(x.k)}" style="word-break:normal">${esc(x.k)}</button></td><td class="sub">${esc(x.pil)}</td><td class="r num">${x.ts.length}</td>
      <td>${x.sc === null ? '<span class="faint">not evaluated</span>' : `<div class="scorecell" style="justify-content:flex-start"><span class="score ${scoreCls(x.sc)}">${x.sc}</span><span class="mini" style="width:110px"><i class="${scoreCls(x.sc)}" style="width:${x.sc}%"></i></span></div>`}</td>
      <td class="r num">${x.f}</td><td class="r num">${x.hi ? `<span class="cnt crit">${x.hi}</span>` : 0}</td><td class="r num">${x.inv}</td></tr>`).join('')}</tbody></table></div>`;
}
function changes() {
  const ch = T.filter(t => t.change && (t.change.new || t.change.from)).sort((a, b) => ({regressed: 0, changed: 1, fixed: 2})[a.change.kind] - ({regressed: 0, changed: 1, fixed: 2})[b.change.kind] || b.priority - a.priority);
  return `<div class="stat-strip" style="margin-bottom:16px"><div class="stat"><b class="delta-up">${diff.fixed}</b><span>fixed</span></div><div class="stat"><b class="delta-down">${diff.regressed}</b><span>regressed</span></div>
    <div class="stat"><b>${diff.changed}</b><span>other changes</span></div><div class="stat"><b>${diff.new_tests}</b><span>new tests</span></div>
    <div class="stat"><b>${diff.score_before === null ? '-' : diff.score_before} \u2192 ${diff.score_after === null ? '-' : diff.score_after}</b><span>score</span></div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th>Change</th><th class="sticky">Test</th><th>Before</th><th>Now</th><th>Risk</th></tr></thead><tbody>
    ${ch.map(t => `<tr data-row="${t._i}"><td>${t.change.new ? '<span class="tag">new test</span>' : `<span class="tag ${t.change.kind === 'fixed' ? 'chg-up' : t.change.kind === 'regressed' ? 'chg-down' : ''}">${esc(t.change.kind)}</span>`}</td>
      <td class="sticky"><button class="dom" data-open="${t._i}" style="word-break:normal">${esc(t.title)}</button><div class="dom-sub">${esc(t.id)}</div></td>
      <td>${t.change.from ? pill(t.change.from) : '<span class="faint">-</span>'}</td><td>${pill(t.status)}</td><td>${riskPill(t.risk)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No changes.</td></tr>'}</tbody></table></div>
    ${diff.removed_tests.length ? `<p class="muted" style="margin-top:12px">No longer in the assessment: ${diff.removed_tests.map(esc).join(', ')}</p>` : ''}`;
}
function tree(v, depth) {
  if (v === null || v === undefined) return '<span class="faint">null</span>';
  if (typeof v !== 'object') return `<span class="mono">${esc(v)}</span>`;
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  if (!entries.length) return '<span class="faint">empty</span>';
  if (Array.isArray(v) && v.every(x => x && typeof x === 'object' && !Array.isArray(x)) && v.length <= 200) {
    const cols = uniq(v.flatMap(x => Object.keys(x))).slice(0, 8);
    if (cols.every(c => v.every(x => x[c] === undefined || x[c] === null || typeof x[c] !== 'object')))
      return `<div class="md-table"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${v.map(x => `<tr>${cols.map(c => `<td class="mono">${esc(x[c] === undefined ? '' : x[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  }
  return `<div class="kvtree">${entries.slice(0, 300).map(([k, x]) => typeof x === 'object' && x !== null
    ? `<details${depth < 1 ? ' open' : ''}><summary><b>${esc(k)}</b> <span class="faint">${Array.isArray(x) ? x.length + ' items' : Object.keys(x).length + ' fields'}</span></summary><div class="kvtree-in">${tree(x, depth + 1)}</div></details>`
    : `<div class="kvrow"><span>${esc(k)}</span>${tree(x, depth + 1)}</div>`).join('')}</div>`;
}
function tenant() {
  const kv = (l, v) => `<div><span>${esc(l)}</span><b>${v ? esc(v) : '<span class="faint">none</span>'}</b></div>`;
  let h = `<section class="card" style="margin-bottom:16px"><header><h2>Assessment</h2></header><div class="body"><div class="kv">${kv('Tenant', TEN.name)}${kv('Domain', TEN.domain)}${kv('Tenant ID', TEN.id)}${kv('Run by', TEN.account)}
    ${kv('Executed', TEN.executed_at ? fmtDate(TEN.executed_at) : '')}${kv('Module version', TEN.version)}${kv('Latest version', TEN.latest_version)}${kv('Source file', M.source)}</div></div></section>`;
  const viz = vizCards(true);
  if (viz.length) h += `<div class="viz-grid">${viz.join('')}</div>`;
  if (D.summary) h += `<section class="card" style="margin-bottom:16px"><header><h2>Summary from the module</h2><p>TestResultSummary as produced by the assessment</p></header><div class="body">${tree(D.summary, 0)}</div></section>`;
  if (D.tenant_info) h += `<section class="card"><header><h2>Tenant information</h2><p>Raw TenantInfo collected by the assessment</p></header><div class="body">${tree(D.tenant_info, 0)}</div></section>`;
  return h;
}

/* ================= test drawer ================= */
const DTABS = [{id: 'result', label: 'Result', show: t => !!t.result}, {id: 'guidance', label: 'Guidance', show: t => !!t.description},
  {id: 'details', label: 'Details', show: () => true}];
function drawerBody(t, tab) {
  if (tab === 'result') return `<section class="dr-sec">${md(t.result)}</section>`;
  if (tab === 'guidance') return `<section class="dr-sec">${md(t.description)}</section>`;
  const kv = (l, v) => `<div><span>${esc(l)}</span><b>${v ? v : '<span class="faint">none</span>'}</b></div>`;
  return `<section class="dr-sec"><div class="kv">${kv('Test ID', esc(t.id))}${kv('Status', pill(t.status) + (t.status_raw && t.status_raw.toLowerCase() !== t.status ? ' <span class="faint">' + esc(t.status_raw) + '</span>' : ''))}
    ${kv('Risk', riskPill(t.risk))}${kv('User impact', lvl(t.impact))}${kv('Implementation effort', lvl(t.cost))}${kv('Priority', String(t.priority))}
    ${kv('Pillar', esc(t.pillars.join(', ')))}${kv('Category', esc(t.category))}${kv('SFI pillar', esc(t.sfi))}${kv('Minimum license', esc(t.license))}
    ${kv('Applies to', esc(t.applies_to.join(', ')))}${kv('Tags', esc(t.tags.join(', ')))}${t.skipped_reason ? kv('Skipped because', esc(t.skipped_reason)) : ''}
    ${t.change ? kv('Since baseline', t.change.new ? 'new test' : t.change.from ? esc(t.change.kind + ', was ' + st(t.change.from)[2].toLowerCase()) : 'unchanged') : ''}</div></section>`;
}
let lastOpen = null;
function drawer() {
  const root = $('#drawer-root');
  if (S.open === null) { if (lastOpen !== null) { root.innerHTML = ''; document.body.classList.remove('locked'); const b = document.querySelector(`[data-open="${lastOpen}"]`); if (b) b.focus({preventScroll: true}); } lastOpen = null; return; }
  const t = T[S.open], lst = list(), pos = lst.findIndex(x => x._i === t._i);
  const prev = pos > 0 ? lst[pos - 1]._i : null, next = pos >= 0 && pos < lst.length - 1 ? lst[pos + 1]._i : null;
  const tabs = DTABS.filter(x => x.show(t));
  if (S.dtab !== 'all' && !tabs.some(x => x.id === S.dtab)) S.dtab = tabs[0].id;
  const body = S.dtab === 'all' ? tabs.map(x => `<h2 class="dr-print-title">${esc(x.label)}</h2>` + drawerBody(t, x.id)).join('') : drawerBody(t, S.dtab);
  const fresh = lastOpen === null;
  root.innerHTML = `<div class="scrim${fresh ? ' enter' : ''}" data-action="close"></div><aside class="drawer${fresh ? ' enter' : ''}" role="dialog" aria-modal="true" aria-labelledby="dr-title">
    <header class="dr-head"><div class="dr-nav"><button class="btn icon ghost" data-open="${prev}" ${prev === null ? 'disabled' : ''} aria-label="Previous test" title="Previous (k)">${icon('left')}</button>
      <button class="btn icon ghost" data-open="${next}" ${next === null ? 'disabled' : ''} aria-label="Next test" title="Next (j)">${icon('right')}</button><span>${pos >= 0 ? `${pos + 1} of ${lst.length}` : ''}</span><span class="spacer"></span>
      <button class="btn ghost small" data-action="copy-link">${icon('link', 14)}Copy link</button><button class="btn ghost small" data-action="print-test">${icon('print', 14)}Print</button>
      <button class="btn icon ghost" data-action="close" id="dr-close" aria-label="Close" title="Close (Esc)">${icon('x')}</button></div>
      <div class="dr-id">${statusRing(t)}<div style="min-width:0"><h2 id="dr-title" style="word-break:normal">${esc(t.title)}</h2>
        <div class="meta">${pill(t.status)}${riskPill(t.risk)}<span class="tag">${esc(t.id)}</span>${t.pillars.map(p => `<span class="tag">${esc(p)}</span>`).join('')}<span class="tag">${esc(t.category)}</span>
        <span class="t">User impact ${esc((LV[t.impact] || '').toLowerCase())}, effort ${esc((LV[t.cost] || '').toLowerCase())}${t.license ? ', ' + esc(t.license) : ''}</span></div></div></div>
      <nav class="dr-tabs" role="tablist">${tabs.map(x => `<button role="tab" data-dtab="${x.id}" aria-selected="${S.dtab === x.id}">${esc(x.label)}</button>`).join('')}</nav></header>
    <div class="dr-body" id="dr-body">${body}</div></aside>`;
  document.body.classList.add('locked');
  if (fresh) { const c = $('#dr-close'); if (c) c.focus({preventScroll: true}); }
  lastOpen = S.open;
}

/* ================= overlays ================= */
let pal = null;
function paletteItems(q) {
  q = q.trim().toLowerCase(); const items = [];
  ROUTES.filter(r => r.show()).forEach(r => { if (!q || r.label.toLowerCase().includes(q)) items.push({g: 'Go to', t: r.label, h: '', run: () => go({route: r.id, open: null})}); });
  PILLARS.forEach(p => { if (!q || p.toLowerCase().includes(q)) items.push({g: 'Pillars', t: p, h: '', run: () => filterTo({pillar: p})}); });
  (q ? T.filter(t => t._text.includes(q)) : T.filter(t => t.priority > 0).sort((a, b) => b.priority - a.priority)).slice(0, q ? 10 : 5)
    .forEach(t => items.push({g: 'Tests', t: t.title, h: st(t.status)[2], run: () => go({open: t._i, dtab: 'result'})}));
  if (q) uniq(T.map(t => t.category)).filter(c => c.toLowerCase().includes(q)).slice(0, 5).forEach(c => items.push({g: 'Categories', t: c, h: '', run: () => filterTo({category: c})}));
  [['Toggle light or dark theme', toggleTheme], ['Executive summary as PDF', printExec], ['Export filtered tests as CSV', () => exportCsv(list())], ['Clear all filters', () => filterTo({})], ['Keyboard shortcuts', showKeys]]
    .forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) items.push({g: 'Actions', t, h: '', run: fn}); });
  return items;
}
function openPalette() {
  pal = {q: '', idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Command palette"><div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search tests, pillars, categories and actions" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul><div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette(); $('#pal-q').focus();
}
function renderPalette() {
  let g = '', h = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; h += `<li class="pal-group" role="presentation">${esc(g)}</li>`; } h += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h)}</span></li>`; });
  $('#pal-list').innerHTML = h || '<li class="pal-group">No results</li>';
  const c = $('#pal-' + pal.idx); if (c) c.scrollIntoView({block: 'nearest'});
}
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }
function dialog(title, body) { $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t"><header><h2 id="dlg-t">${esc(title)}</h2><button class="btn icon ghost" data-action="overlay-close" aria-label="Close">${icon('x')}</button></header><div class="dbody">${body}</div></div></div>`;
  const b = $('#overlay-root [data-action="overlay-close"]'); if (b) b.focus(); }
function closeOverlay() { $('#overlay-root').innerHTML = ''; pal = null; }
function showKeys() { const k = [['Ctrl K or /', 'Search tests, pillars and actions'], ['1 to 5', 'Switch section'], ['j / k', 'Next or previous test'], ['Enter', 'Open the highlighted test'], ['f', 'Show or hide filters'], ['Esc', 'Close the detail or dialog'], ['?', 'This help']];
  dialog('Keyboard shortcuts', `<table class="keys">${k.map(([a, b]) => `<tr><td><span class="kbd">${esc(a)}</span></td><td>${esc(b)}</td></tr>`).join('')}</table>`); }
function showAbout() {
  dialog('About this report', `<div class="kv" style="margin-bottom:14px"><div><span>Generated</span><b>${esc(M.generated)}</b></div><div><span>Tool</span><b>ZTAGuard ${esc(M.version)}</b></div><div><span>Source</span><b>${esc(M.source)}</b></div><div><span>Tests</span><b>${T.length}</b></div></div>
    <ul style="margin:0;padding-left:18px;color:var(--muted)"><li>Results come from the Microsoft Zero Trust Assessment module; this report only re-presents them.</li>
    <li>Score: pass rate weighted by risk (High ${D.weights.risk.high}, Medium ${D.weights.risk.medium}, Low ${D.weights.risk.low}); Investigate counts half; skipped, planned and errors are excluded.</li>
    <li>Priority: risk weight on failed or investigate tests, divided by implementation effort and user impact.</li><li>Quick wins: failed or investigate, high or medium risk, low effort, low user impact.</li>
    <li>Skipped tests often depend on licenses or permissions: they are not evidence that the tenant meets the recommendation.</li></ul>`);
}
function toggleTheme() { P.theme = isDark() ? 'light' : 'dark'; savePrefs(); applyTheme(); render(); }
function applyTheme() { if (P.theme) document.documentElement.dataset.theme = P.theme; }
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2600); }
function copyText(text, ok) { const done = () => toast(ok || 'Copied');
  const fb = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fb); else fb(); }
const csvCell = v => { let s = String(v === null || v === undefined ? '' : v); if (/^[=+\-@\t\r|%]/.test(s)) s = "'" + s; return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function exportCsv(rows) {
  const head = ['test_id', 'title', 'status', 'risk', 'user_impact', 'effort', 'pillars', 'category', 'sfi_pillar', 'license', 'priority', 'quick_win'];
  const body = rows.map(t => [t.id, t.title, t.status, t.risk, t.impact, t.cost, t.pillars.join('|'), t.category, t.sfi, t.license, t.priority, t.quick_win ? 'yes' : '']);
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['\ufeff' + [head, ...body].map(r => r.map(csvCell).join(';')).join('\r\n')], {type: 'text/csv;charset=utf-8'}));
  a.download = 'zta-tests.csv'; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); toast('Downloaded zta-tests.csv');
}
function printExec() { if (S.route !== 'overview' || S.open !== null) go({route: 'overview', open: null}); document.body.classList.add('print-exec'); setTimeout(() => window.print(), 60); }
function printTest() { const prev = S.dtab; S.dtab = 'all'; drawer(); document.body.classList.add('print-drawer'); window.__restore = prev; setTimeout(() => window.print(), 60); }
window.addEventListener('afterprint', () => { document.body.classList.remove('print-exec', 'print-drawer'); if (window.__restore) { S.dtab = window.__restore; window.__restore = null; drawer(); } });

/* ================= render & events ================= */
const VIEWS = {overview, tests, categories, changes, tenant};
function render() {
  applyTheme();
  $('#side').innerHTML = side(); $('#topbar').innerHTML = topbar(); $('#view').innerHTML = (VIEWS[S.route] || overview)();
  drawer();
  document.title = (S.open !== null ? T[S.open].title + ' - ' : '') + 'Zero Trust posture - ' + (M.title || '');
}
function keepFocus(id) { const el = document.getElementById(id), pos = el ? el.selectionStart : null; render(); const n = document.getElementById(id); if (n) { n.focus(); if (pos !== null) n.setSelectionRange(pos, pos); } }
document.addEventListener('click', e => {
  const t = e.target.closest('button, [data-open], tr[data-row], [data-pal], [data-overlay], .scrim');
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.open !== undefined && ds.open !== 'null') { go({open: +ds.open, dtab: S.open === +ds.open ? S.dtab : 'result'}); return; }
  if (ds.route) { go({route: ds.route, open: null, page: 1, cursor: -1}); window.scrollTo(0, 0); return; }
  if (ds.pillar !== undefined) { filterTo(ds.pst ? {pillar: ds.pillar, status: ds.pst} : {pillar: ds.pillar}); return; }
  if (ds.status) { filterTo({status: ds.status}); return; }
  if (ds.risk) { filterTo({risk: ds.risk, status: ds.rst}); return; }
  if (ds.sfi) { filterTo({sfi: ds.sfi}); return; }
  if (ds.quick) { filterTo({quick: '1'}); return; }
  if (ds.changed) { filterTo({changed: ds.changed}); return; }
  if (ds.category) { filterTo({category: ds.category}); return; }
  if (ds.preset !== undefined) { filterTo(Object.assign({}, PRESETS()[+ds.preset][1])); return; }
  if (ds.chip) { S[ds.chip] = ''; go({page: 1}, false); return; }
  if (ds.sort) { const k = ds.sort; go({sort: {k, d: S.sort.k === k ? -S.sort.d : (['title', 'category', 'id', 'pillar', 'status'].includes(k) ? 1 : -1)}, page: 1}, false); return; }
  if (ds.page) { go({page: +ds.page, cursor: -1}, false); const g = $('#grid'); if (g) g.scrollTop = 0; return; }
  if (ds.density) { P.density = ds.density; savePrefs(); render(); return; }
  if (ds.dtab) { go({dtab: ds.dtab}, false); const b = $('#dr-body'); if (b) b.scrollTop = 0; return; }
  if (t.tagName === 'TR' && ds.row !== undefined && !e.target.closest('a, button, input')) { go({open: +ds.row, dtab: 'result'}); return; }
  const acts = {close: () => go({open: null}), palette: openPalette, about: showAbout, keys: showKeys, theme: toggleTheme, 'overlay-close': closeOverlay,
    'print-exec': printExec, 'print-test': printTest, 'copy-link': () => copyText(location.href, 'Link copied'), filters: () => { S.filtersOpen = !S.filtersOpen; render(); },
    clear: () => filterTo({}), csv: () => exportCsv(list())};
  if (acts[ds.action]) acts[ds.action]();
});
document.addEventListener('toggle', e => { if (e.target.id === 'viz-panel') { P.vizOpen = e.target.open; savePrefs(); } }, true);
document.addEventListener('change', e => {
  const t = e.target, k = t.dataset.k;
  if (k === 'size') { P.size = +t.value; savePrefs(); go({page: 1}, false); }
  else if (k === 'group') { P.group = t.value; savePrefs(); render(); }
  else if (k) go({[k]: t.value, page: 1, cursor: -1}, false);
});
let qt = null;
document.addEventListener('input', e => {
  if (e.target.id === 'pal-q') { pal.q = e.target.value; pal.items = paletteItems(pal.q); pal.idx = 0; renderPalette(); return; }
  if (e.target.id !== 'q') return;
  clearTimeout(qt); const v = e.target.value;
  qt = setTimeout(() => { Object.assign(S, {q: v, page: 1, cursor: -1}); history.replaceState(null, '', toHash()); keepFocus('q'); }, 160);
});
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); } else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape') { if ($('#overlay-root').innerHTML) closeOverlay(); else if (S.open !== null) go({open: null}); else if (typing) e.target.blur(); return; }
  if ($('#overlay-root').innerHTML) { if (e.key === 'Tab') { const f = [...$('#overlay-root').querySelectorAll('button, input')]; if (f.length) { e.preventDefault(); const i = f.indexOf(document.activeElement); f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus(); } } return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  if (e.key === '?') { showKeys(); return; }
  if (S.open !== null) { const l = list(), p = l.findIndex(x => x._i === S.open);
    if ((e.key === 'j' || e.key === ']') && p < l.length - 1) go({open: l[p + 1]._i}, false); else if ((e.key === 'k' || e.key === '[') && p > 0) go({open: l[p - 1]._i}, false); return; }
  const n = parseInt(e.key, 10), vis = ROUTES.filter(r => r.show());
  if (n >= 1 && n <= vis.length) { go({route: vis[n - 1].id, open: null, page: 1, cursor: -1}); return; }
  if (S.route === 'tests') {
    const items = P.group === 'none' ? list().slice((S.page - 1) * P.size, S.page * P.size) : list();
    if (e.key === 'f') { S.filtersOpen = !S.filtersOpen; render(); return; }
    if (!items.length || P.group !== 'none') return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); S.cursor = Math.min(items.length - 1, S.cursor + 1); render(); const r = $('tr.cursor'); if (r) r.scrollIntoView({block: 'nearest'}); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); S.cursor = Math.max(0, S.cursor - 1); render(); const r = $('tr.cursor'); if (r) r.scrollIntoView({block: 'nearest'}); }
    else if (e.key === 'Enter' && S.cursor >= 0) { e.preventDefault(); go({open: items[S.cursor]._i, dtab: 'result'}); }
  }
});
applyTheme(); fromHash(); history.replaceState(null, '', toHash()); render();
})();
"""


if __name__ == "__main__":
    sys.exit(main())
