"""Self-contained HTML report (UI assets in securityhub/ui: edr.js shares the asset-report application with WAF)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List

from ... import ui
from ...common import json_for_html
from .constants import CHECKS, CHECK_LABELS, COMPLIANCE_PROFILES, FINDINGS, FRAMEWORK_MAP, TIER_WEIGHTS, __version__
from .models import EndpointResult, Issue

REPORT_CSS = ui.asset("edr.css")

REPORT_JS = ui.asset("edr.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[EndpointResult], account_issues: List[Issue], policies: List[dict], extra: dict,
                         output_file: str, meta: dict) -> None:
    checks = meta["checks"]
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (normalized over the checks that could be evaluated: a policy that could not be read is not counted as failed).",
        "Active unmitigated threats, disabled or stale agents, Detect mode and anti-tamper off cap the score. "
        "Priority = tier weight x (100 - score + 15 x critical findings).",
        f"Stale = not seen for more than {meta.get('stale_days')} days; threat triage SLA = {meta.get('sla_days')} days. "
        "Decommissioned and uninstalled agents are not assessed.",
        "The policy of an endpoint is its group's policy when the group does not inherit, otherwise its site's policy.",
        "Read-only: the tool only lists agents, sites, groups, policies, open threats, exclusions and GA packages.",
        "Compliance and framework references are indicative.",
    ] + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "EDRGuard", "vendor": "SentinelOne"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": policies,
        "exclusions": extra.get("exclusions") or [], "coverage": extra.get("coverage"),
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"SentinelOne EDR posture - {len(results)} endpoints"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
