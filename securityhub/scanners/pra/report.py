"""Self-contained HTML report (UI assets in securityhub/ui: pra.js shares the asset-report application)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List

from ... import ui
from ...common import json_for_html
from .constants import CHECKS, CHECK_LABELS, COMPLIANCE_PROFILES, FINDINGS, FRAMEWORK_MAP, TIER_WEIGHTS, __version__
from .models import Issue, ObjectResult

REPORT_CSS = ui.asset("pra.css")

REPORT_JS = ui.asset("pra.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[ObjectResult], account_issues: List[Issue], extra: dict, output_file: str,
                         meta: dict) -> None:
    checks = meta["checks"]
    tot = extra.get("totals") or {}
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (each object is scored on the checks that apply to its kind: users and vendor users on authentication, "
          "privileges and lifecycle; assets on access policy and exposure; gateways on exposure; API accounts on "
          "authentication and privileges; vault accounts on rotation and checkout).",
        "MFA is evaluated only for local and LDAP users: the API exposes it only for them. Users of SAML or SCIM "
        "providers (e.g. PRA on Pathfinder with SSO), Kerberos or RADIUS get MFA from their identity provider, so it is "
        "not reported as missing here: verify it in the IdP (conditional access) and that local sign-in is restricted.",
        f"Inactive = no sign-in for {meta.get('inactive_days')} days. Disabled users are counted but not assessed.",
        "Read-only: Configuration API (GET only) and the session listing of the Reporting API. Users' e-mail addresses "
        "are kept to join the person with the other modules; IP addresses, passwords and recordings are not stored.",
        "Compliance and framework references are indicative.",
    ] + (["Very large site: only the objects that need action are listed; the totals cover every object."]
         if tot.get("limited") else []) + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "PRAGuard", "vendor": "BeyondTrust"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": [],
        "totals": tot, "site": meta.get("site", ""),
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"BeyondTrust PRA posture - {len(results)} objects"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
