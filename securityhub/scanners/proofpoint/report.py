"""Self-contained HTML report (UI assets in securityhub/ui: proofpoint.js shares the asset-report application)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List

from ... import ui
from ...common import json_for_html
from .constants import CHECKS, CHECK_LABELS, COMPLIANCE_PROFILES, FINDINGS, FRAMEWORK_MAP, TIER_WEIGHTS, __version__
from .models import Issue, MailDomainResult

REPORT_CSS = ui.asset("proofpoint.css")

REPORT_JS = ui.asset("proofpoint.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[MailDomainResult], account_issues: List[Issue], extra: dict, output_file: str,
                         meta: dict) -> None:
    checks = meta["checks"]
    weighted = [c for c in checks if CHECKS[c]]
    win = extra.get("window") or {}
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (normalized over the checks that could be evaluated: a check that could not be measured is not counted as failed).",
        "Inbound mail that does not go through Proofpoint, preferred bypass MX, permitted malicious clicks, threats "
        "delivered through a safelist and delivered threats cap the score. Priority = tier weight x (100 - score + 15 x critical findings).",
        "Routing is read from public DNS: an MX host is Proofpoint by name (pphosted.com), CNAME or reverse DNS. "
        "Direct delivery: the Microsoft 365 endpoint of the domain resolves; whether it rejects mail not coming from "
        "Proofpoint (connector restriction) cannot be seen from outside and must be verified.",
        (f"TAP window: {str(win.get('start', ''))[:16]} - {str(win.get('end', ''))[:16]} UTC ({win.get('hours')} hours); "
         f"Very Attacked People and top clickers over {(extra.get('people') or {}).get('window_days')} days."
         if extra.get("tap") else "TAP data not available: only the DNS routing checks were evaluated."),
        "Read-only: SIEM and People APIs of TAP, Threat Protection reports (GET only), PoD log streams (read for a past "
        "window and counted as they arrive), public DNS. Subjects, bodies, addresses of the PoD logs, click IPs and "
        "malicious URLs are not stored.",
        "Compliance and framework references are indicative.",
    ] + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "PPGuard", "vendor": "Proofpoint"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": [],
        "people": extra.get("people"), "threats": extra.get("threats") or [], "totals": extra.get("totals"),
        "window": win, "no_mail": extra.get("no_mail") or [], "tap": bool(extra.get("tap")),
        "tp": extra.get("tp") or {}, "pod": extra.get("pod") or {},
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"Proofpoint email protection posture - {len(results)} domains"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
