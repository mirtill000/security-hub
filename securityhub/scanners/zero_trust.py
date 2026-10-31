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
from .. import ui

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

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results.</p></noscript>\n')


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

REPORT_CSS = ui.asset("zta.css")

REPORT_JS = ui.asset("zta.js")


if __name__ == "__main__":
    sys.exit(main())
