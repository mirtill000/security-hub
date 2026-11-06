"""Result data classes and findings (same shape as the other asset modules: the report applications share code)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .constants import FINDINGS


@dataclass
class Issue:
    severity: str
    protocol: str
    message: str
    recommendation: str = ""
    code: str = ""


def make_issue(code: str, detail: Optional[str] = None, severity: Optional[str] = None) -> Issue:
    sev, area, title, rec = FINDINGS[code]
    return Issue(severity=severity or sev, protocol=area, message=f"{title}: {detail}" if detail else title,
                 recommendation=rec, code=code)


@dataclass
class CheckResult:
    status: str = "skipped"   # valid, warning, error, na, unknown, skipped
    got: float = 0.0
    max: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    issues: List[Issue] = field(default_factory=list)


@dataclass
class ObjectResult:
    site_id: str                 # "<kind>:<id>" (the report applications call the asset id 'site_id')
    domain: str                  # object name (user name, asset name, gateway...)
    account_id: Optional[str] = None   # kind code: user, vendor_user, asset, gateway, api_account, vault_account
    account_name: str = ""             # kind label
    kind: str = ""
    detail: str = ""             # one-line description (asset type and host, user display name, vendor group...)
    groups: List[str] = field(default_factory=list)
    profile: str = "ok"
    tier: str = "medium"
    owner: str = ""
    bu: str = ""
    tags: List[str] = field(default_factory=list)
    checks: Dict[str, CheckResult] = field(default_factory=dict)
    policies: List[dict] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    overall_score: int = 0
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, str] = field(default_factory=dict)
    remediation: List[dict] = field(default_factory=list)
    priority: int = 0
    change: Optional[dict] = None
    scan_date: str = ""
    error: Optional[str] = None
