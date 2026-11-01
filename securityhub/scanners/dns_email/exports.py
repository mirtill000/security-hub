"""JSON and CSV exports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from typing import Any, List, Optional

from ...common import csv_safe
from .models import DomainResult


def write_json(results: List[DomainResult], path: str, view: Optional[str] = None) -> None:
    """A list of domain objects (combined report, as in v1-v3) or {"view": ..., "results": [...]} for a view."""
    data: Any = [asdict(r) for r in results]
    if view:
        data = {"view": view, "results": data}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


CSV_EXPORT_COLUMNS = [
    "domain", "score", "priority", "tier", "owner", "bu", "tags", "profile", "mx_status", "mx_providers",
    "spf_status", "spf_all", "spf_lookups", "spf_void_lookups", "dkim_status", "dkim_selectors", "dmarc_status",
    "dmarc_policy", "dmarc_sp", "dmarc_pct", "dmarc_rua", "mta_sts_mode", "tls_rpt", "bimi", "dnssec",
    "caa", "caa_issuers", "takeover", "axfr", "lookalikes_with_mx", "gmail_yahoo", "microsoft", "dmarc_enforcement", "score_delta",
    "critical", "warning", "info", "issue_codes",
]


# Columns that belong to only one view (the others are common: domain, score, tier, findings...)
EMAIL_COLUMNS = {"mx_status", "mx_providers", "spf_status", "spf_all", "spf_lookups", "spf_void_lookups", "dkim_status",
                 "dkim_selectors", "dmarc_status", "dmarc_policy", "dmarc_sp", "dmarc_pct", "dmarc_rua", "mta_sts_mode",
                 "tls_rpt", "bimi", "gmail_yahoo", "microsoft", "dmarc_enforcement"}
DNS_COLUMNS = {"dnssec", "caa", "caa_issuers", "takeover", "axfr", "lookalikes_with_mx"}


def write_csv(results: List[DomainResult], path: str, view: Optional[str] = None) -> None:
    drop = DNS_COLUMNS if view == "email" else EMAIL_COLUMNS if view == "dns" else set()
    keep = [i for i, c in enumerate(CSV_EXPORT_COLUMNS) if c not in drop]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel opens it as UTF-8
        w = csv.writer(f, delimiter=";")
        w.writerow([CSV_EXPORT_COLUMNS[i] for i in keep])
        for r in results:
            sev = Counter(i.severity for i in r.issues)
            row = [
                r.domain, r.overall_score, r.priority, r.tier, r.owner, r.bu, "|".join(r.tags), r.profile,
                r.mx.status, ", ".join(r.mx.providers), r.spf.status, r.spf.mechanism or "", r.spf.lookups,
                r.spf.void_lookups, r.dkim.status,
                ", ".join(f"{s.name}:{s.key_size or s.status}" for s in r.dkim.selectors), r.dmarc.status,
                r.dmarc.policy or "", r.dmarc.subdomain_policy or "", r.dmarc.pct, ", ".join(r.dmarc.rua_destinations),
                r.mta_sts.mode or r.mta_sts.status, r.tls_rpt.status, r.bimi.status, r.dnssec.status,
                r.caa.status, ", ".join(r.caa.issuers), r.takeover.status, r.axfr.status, sum(1 for e in r.lookalikes.registered if e.get("mx")),
                r.compliance.get("gmail_yahoo", ""), r.compliance.get("microsoft", ""),
                r.compliance.get("dmarc_enforcement", ""),
                "" if not r.change or r.change.get("score_delta") is None else r.change["score_delta"],
                sev["critical"], sev["warning"], sev["info"], "|".join(i.code for i in r.issues),
            ]
            w.writerow([csv_safe(row[i]) for i in keep])
