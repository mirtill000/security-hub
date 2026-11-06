"""Self-contained HTML report (UI assets in securityhub/ui: ias.js shares the asset-report application)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List

from ... import ui
from ...common import json_for_html
from .constants import CHECKS, CHECK_LABELS, COMPLIANCE_PROFILES, FINDINGS, FRAMEWORK_MAP, TIER_WEIGHTS, __version__
from .models import Issue, UserResult

REPORT_CSS = ui.asset("ias.css")

REPORT_JS = ui.asset("ias.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[UserResult], account_issues: List[Issue], extra: dict, output_file: str,
                         meta: dict) -> None:
    checks = meta["checks"]
    tot = extra.get("totals") or {}
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (normalized over the checks that could be evaluated: a value the tenant does not expose is not counted as failed).",
        "A local IAS password lets the user sign in without the corporate identity provider, so without its MFA and "
        "conditional access. Users of the types given with --password-types are expected to use it (only its hygiene "
        "is evaluated); members of the --privileged-groups must never have one.",
        f"Inactive = no sign-in for {meta.get('inactive_days')} days; old password = not changed for "
        f"{meta.get('password_max_days')} days. Deactivated accounts are counted but not assessed.",
        "Read-only: SCIM 2.0 users and groups. Phone numbers, addresses and passwords are not read or stored.",
        "Compliance and framework references are indicative.",
    ] + (["Very large directory: only the users that need action are listed; the totals cover every user."]
         if tot.get("limited") else []) + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "IASGuard", "vendor": "SAP"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": [],
        "totals": tot, "tenant": meta.get("tenant", ""),
        "results": [asdict(r) for r in results],
    }
    from ...portal import area_summary   # same area score, grade and cap as the portal
    payload["area"] = area_summary("ias", payload) if "ias" else None
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"SAP Cloud Identity posture - {tot.get('active', len(results))} users"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
