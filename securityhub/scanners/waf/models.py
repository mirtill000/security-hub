"""Result data classes and findings."""

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
    status: str = "skipped"   # valid, warning, partial, error, missing, na, unknown, skipped
    got: float = 0.0
    max: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    issues: List[Issue] = field(default_factory=list)


@dataclass
class SiteResult:
    site_id: int
    domain: str
    account_id: Optional[int] = None
    account_name: str = ""
    status_text: str = ""
    active: str = ""
    profile: str = "protected"   # protected, bypass, onboarding, error
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
    probed: bool = False
    scan_date: str = ""
    error: Optional[str] = None
