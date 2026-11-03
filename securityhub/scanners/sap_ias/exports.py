"""JSON and CSV exports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from typing import List

from ...common import csv_safe
from .constants import CHECK_LABELS, __version__
from .models import Issue, UserResult


def write_json(results: List[UserResult], account_issues: List[Issue], extra: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": f"IASGuard {__version__}", "results": [asdict(r) for r in results],
                   "account_issues": [asdict(i) for i in account_issues], "totals": extra.get("totals")},
                  f, indent=2, ensure_ascii=False)


def write_csv(results: List[UserResult], checks: List[str], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["user_name", "user_id", "display_name", "email", "user_type", "password", "groups", "profile", "score",
                    "priority"] + [CHECK_LABELS[c] for c in checks] + ["critical", "warning", "issue_codes"])
        for r in results:
            sev = Counter(i.severity for i in r.issues)
            row = [r.domain, r.user_id, r.display_name, r.email, r.account_name, r.password, "|".join(r.groups), r.profile,
                   r.overall_score, r.priority] + [r.checks[c].status if c in r.checks else "" for c in checks] \
                + [sev["critical"], sev["warning"], "|".join(i.code for i in r.issues)]
            w.writerow([csv_safe(v) for v in row])
