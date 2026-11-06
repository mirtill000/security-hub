"""Self-contained HTML report (UI assets in securityhub/ui)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List

from ... import ui
from ...common import json_for_html
from .constants import (CHECKS, CHECK_LABELS, COMPLIANCE_PROFILES, DDOS_FACTOR, DDOS_FLOOR, FINDINGS, FRAMEWORK_MAP,
                        TIER_WEIGHTS, __version__)
from .models import Issue, SiteResult

REPORT_CSS = ui.asset("waf.css")


REPORT_JS = ui.asset("waf.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[SiteResult], account_issues: List[Issue], policies: List[dict],
                         output_file: str, meta: dict) -> None:
    checks = meta["checks"]
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (normalized over the checks that could be evaluated).",
        "Bypass mode, DNS not routed, missing or disabled WAF policy, exposed origin, broad allow-lists and expired "
        "certificates cap the score. Priority = tier weight x (100 - score + 15 x critical findings).",
        "WAF rules are read from the WAF Rules policy applied to each website; legacy per-site rules are used only when no policy is applied.",
        "Origin exposure, DNS routing, HSTS, redirects and TLS versions are tested only with --probe.",
        f"DDoS threshold: recommended = {meta.get('ddos_factor', DDOS_FACTOR):g} x peak legitimate requests/s "
        f"(minimum {meta.get('ddos_floor', DDOS_FLOOR)}), rounded up to an accepted value. Peaks are averages per time "
        "bucket, so short bursts are higher than shown.",
        "Compliance and framework references are indicative.",
    ] + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "WAFGuard"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": policies,
        "results": [asdict(r) for r in results],
    }
    from ...portal import area_summary   # same area score, grade and cap as the portal
    payload["area"] = area_summary("waf", payload) if "waf" else None
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"Imperva WAF posture - {len(results)} websites"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
