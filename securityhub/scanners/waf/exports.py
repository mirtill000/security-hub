"""JSON and CSV exports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from typing import List

from ...common import csv_safe
from .constants import __version__
from .models import Issue, SiteResult


def write_json(results: List[SiteResult], account_issues: List[Issue], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": f"WAFGuard {__version__}", "account_issues": [asdict(i) for i in account_issues],
                   "results": [asdict(r) for r in results]}, f, indent=2, ensure_ascii=False, default=list)


def write_csv(results: List[SiteResult], checks: List[str], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["site_id", "domain", "account_id", "score", "priority", "tier", "owner", "bu", "tags", "status", "active",
                    *checks, "waf_policy", "pci_642", "critical", "warning", "info", "issue_codes"])
        for r in results:
            sev = Counter(i.severity for i in r.issues)
            waf = r.checks.get("waf")
            row = [r.site_id, r.domain, r.account_id, r.overall_score, r.priority, r.tier, r.owner, r.bu, "|".join(r.tags),
                   r.status_text, r.active, *[r.checks[c].status if c in r.checks else "" for c in checks],
                   ((waf.data.get("policy") or {}).get("name") if waf else "") or "", r.compliance.get("pci_642", ""),
                   sev["critical"], sev["warning"], sev["info"], "|".join(i.code for i in r.issues)]
            w.writerow([csv_safe(v) for v in row])
