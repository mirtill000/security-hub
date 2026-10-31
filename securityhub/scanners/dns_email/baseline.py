"""Comparison with a previous JSON export."""

from __future__ import annotations

import json
import os
from typing import List, Set

from .constants import CHECK_ATTRS
from .models import DomainResult


def compute_diff(results: List[DomainResult], baseline_path: str) -> dict:
    with open(baseline_path, encoding="utf-8") as f:
        raw = json.load(f)
    items = raw.get("results", raw) if isinstance(raw, dict) else raw
    base = {str(d.get("domain", "")).lower(): d for d in items if isinstance(d, dict)}
    base_date = max((str(d.get("scan_date", "")) for d in base.values()), default="")

    def codes(issues) -> Set[str]:
        return {(i.get("code") or i.get("message", "")) for i in issues or []}

    summary = {"baseline": os.path.basename(baseline_path), "baseline_date": base_date, "improved": 0,
               "worsened": 0, "unchanged": 0, "new_domains": [], "removed_domains": [], "new_critical": 0}
    current = set()
    for r in results:
        current.add(r.domain)
        b = base.get(r.domain)
        if b is None:
            r.change = {"new": True, "changed": True, "score_delta": None, "status_changes": [],
                        "new_issues": [], "resolved_issues": []}
            summary["new_domains"].append(r.domain)
            continue
        delta = r.overall_score - int(b.get("overall_score") or 0)
        status_changes = []
        for check, attr in CHECK_ATTRS.items():
            before = (b.get(attr) or {}).get("status")
            after = getattr(r, attr).status
            if before and before != after and "skipped" not in (before, after):
                status_changes.append({"check": check, "from": before, "to": after})
        now_codes = {i.code or i.message for i in r.issues}
        old_codes = codes(b.get("issues"))
        new_issues = sorted(now_codes - old_codes)
        resolved = sorted(old_codes - now_codes)
        crit_codes = {i.code for i in r.issues if i.severity == "critical"}
        summary["new_critical"] += len(crit_codes & set(new_issues))
        changed = bool(delta or status_changes or new_issues or resolved)
        r.change = {"new": False, "changed": changed, "score_delta": delta, "previous_score": b.get("overall_score"),
                    "status_changes": status_changes, "new_issues": new_issues, "resolved_issues": resolved}
        key = "improved" if delta > 0 else "worsened" if delta < 0 else "unchanged"
        summary[key] += 1
    summary["removed_domains"] = sorted(set(base) - current)
    return summary
