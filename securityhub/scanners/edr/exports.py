"""JSON and CSV exports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from typing import List

from ...common import csv_safe
from .constants import CHECK_LABELS, __version__
from .models import EndpointResult, Issue


def write_json(results: List[EndpointResult], account_issues: List[Issue], extra: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": f"EDRGuard {__version__}", "results": [asdict(r) for r in results],
                   "account_issues": [asdict(i) for i in account_issues], "coverage": extra.get("coverage"),
                   "exclusions": extra.get("exclusions") or []}, f, indent=2, ensure_ascii=False)


def write_csv(results: List[EndpointResult], checks: List[str], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["hostname", "agent_id", "site", "group", "os", "agent_version", "profile", "score", "priority", "tier",
                    "owner", "bu", "tags"] + [CHECK_LABELS[c] for c in checks] + ["critical", "warning", "issue_codes"])
        for r in results:
            sev = Counter(i.severity for i in r.issues)
            row = [r.domain, r.site_id, r.account_name, r.group_name, r.os, r.agent_version, r.profile, r.overall_score,
                   r.priority, r.tier, r.owner, r.bu, "|".join(r.tags)] + [r.checks[c].status if c in r.checks else "" for c in checks] \
                + [sev["critical"], sev["warning"], "|".join(i.code for i in r.issues)]
            w.writerow([csv_safe(v) for v in row])
