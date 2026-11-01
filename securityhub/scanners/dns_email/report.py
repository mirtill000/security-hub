"""Self-contained HTML report (UI assets in securityhub/ui)."""

from __future__ import annotations

import html
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, List, Optional

from ... import ui
from ...common import json_for_html
from .constants import (CHECKS, CHECK_ATTRS, CHECK_LABELS, COMPLIANCE_PROFILES, DEFAULT_CHECKS, FINDINGS,
                        FRAMEWORK_MAP, TIER_WEIGHTS, __version__)
from .models import DomainResult

REPORT_CSS = ui.asset("dns.css")

REPORT_JS = ui.asset("dns.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[DomainResult], output_file: str, meta: Optional[dict] = None) -> None:
    """Self-contained single-file application: CSS and JS inline, results embedded as JSON."""
    from .views import COMBINED_TITLE, DNS_WEIGHTS, VIEWS
    meta = meta or {}
    view = meta.get("view")
    checks = [c for c in CHECKS if c in (meta.get("checks") or DEFAULT_CHECKS)]
    weights = {c: (DNS_WEIGHTS.get(c, 0) if view == "dns" else CHECKS[c]) for c in checks}
    weighted = [c for c in checks if weights[c]]
    title = VIEWS[view]["title"] if view in VIEWS else COMBINED_TITLE
    notes = [
        ("Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {weights[c]}" for c in weighted)
         + (" (normalized to 100 over the selected checks)." if sum(weights[c] for c in weighted) != 100 else ".")
         + (" Controls that could not be measured are left out of the maximum." if view == "dns" else "")
         if weighted else "Score derived from findings: 100 minus 40 per critical and 15 per warning finding."),
        ("Takeover exposure, broken DNSSEC and expired registrations cap the score. " if view != "email" else "")
        + "Priority = tier weight x (100 - score + 15 x critical findings).",
    ]
    if view != "dns":
        notes += ["DKIM is detected by probing the selectors of the mail provider, common selectors and the selectors "
                  "seen in DMARC reports: not found does not prove it is absent.",
                  "Compliance and framework references are indicative: they cover what DNS can show."]
    notes += [n for n in meta.get("notes", []) if n]
    if meta.get("stats"):
        notes.append(meta["stats"])
    payload = {
        "meta": {
            "version": __version__,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "resolver": meta.get("resolver", ""),
            "notes": notes,
            "view": view or "combined",
            "title": title,
        },
        "checks": checks,
        "labels": CHECK_LABELS,
        "attrs": CHECK_ATTRS,
        "weights": weights,
        "findings": {k: list(v) for k, v in FINDINGS.items()},
        "frameworks": FRAMEWORK_MAP,
        "compliance": {} if view == "dns" else {k: list(v) for k, v in COMPLIANCE_PROFILES.items()},
        "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"),
        "unscanned_report_domains": [] if view == "dns" else meta.get("unscanned_report_domains", []),
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE
            .replace("__TITLE__", html.escape(f"{title} - {len(results)} domains"))
            .replace("__CSS__", REPORT_CSS)
            .replace("__JS__", REPORT_JS)
            .replace("__DATA__", _json_for_html(payload)))  # data last: placeholders inside data stay inert
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)
