"""Result data classes (one per control) and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .constants import FINDINGS


@dataclass
class Issue:
    severity: str  # critical, warning, info
    protocol: str
    message: str
    recommendation: str = ""
    code: str = ""


def make_issue(code: str, detail: Optional[str] = None, severity: Optional[str] = None) -> Issue:
    sev, proto, title, rec = FINDINGS[code]
    msg = f"{title}: {detail}" if detail else title
    return Issue(severity=severity or sev, protocol=proto, message=msg, recommendation=rec, code=code)


@dataclass
class MXRecord:
    priority: int
    host: str
    is_protected: bool = False
    provider: Optional[str] = None
    resolves: Optional[bool] = None
    is_cname: bool = False


@dataclass
class MXResult:
    status: str = "missing"  # valid, partial, warning, missing, null, dns_error, skipped
    records: List[MXRecord] = field(default_factory=list)
    protected_count: int = 0
    total_count: int = 0
    providers: List[str] = field(default_factory=list)
    null_mx: bool = False
    implicit: bool = False
    issues: List[Issue] = field(default_factory=list)


@dataclass
class SPFResult:
    status: str = "missing"  # valid, warning, error, missing, dns_error, skipped
    record: Optional[str] = None
    records: List[str] = field(default_factory=list)
    lookups: int = 0
    max_lookups: int = 10
    void_lookups: int = 0
    mechanism: Optional[str] = None
    includes: List[str] = field(default_factory=list)
    include_tree: List[dict] = field(default_factory=list)
    permerror: bool = False
    issues: List[Issue] = field(default_factory=list)


@dataclass
class DKIMSelector:
    name: str
    status: str = "missing"  # valid, weak, revoked, invalid
    key_size: Optional[int] = None
    algorithm: Optional[str] = None
    testing: bool = False
    hash_algorithms: Optional[str] = None
    cname: Optional[str] = None      # CNAME target when the selector is delegated
    source: str = "probe"            # probe | report (seen in DMARC aggregate reports) | declared (dkim.csv)
    key_id: Optional[str] = None     # fingerprint of the published p= key (compared with dkim.csv)


@dataclass
class DKIMResult:
    status: str = "missing"  # valid, partial, error, missing, na, dns_error, skipped
    selectors: List[DKIMSelector] = field(default_factory=list)
    valid_selectors: int = 0
    total_selectors: int = 0
    weak_keys: int = 0
    probed: int = 0
    stopped_early: bool = False  # a valid key was found in the first round (or the domain sends no mail)
    full_search: Optional[str] = None  # when the full selector search was last run, if this run reused it
    dangling: List[dict] = field(default_factory=list)  # {"name", "target"}
    declared: List[str] = field(default_factory=list)   # selectors listed for the domain in dkim.csv
    issues: List[Issue] = field(default_factory=list)


@dataclass
class DMARCResult:
    status: str = "missing"  # valid, warning, misconfigured, missing, dns_error, skipped
    record: Optional[str] = None
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    nonexistent_policy: Optional[str] = None
    pct: int = 100
    rua: Optional[str] = None
    ruf: Optional[str] = None
    rua_destinations: List[str] = field(default_factory=list)
    aspf: str = "relaxed"
    adkim: str = "relaxed"
    inherited_from: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)


@dataclass
class MTASTSResult:
    status: str = "missing"  # valid, warning, partial, error, missing, na, dns_error, skipped
    txt_record: Optional[str] = None
    policy_id: Optional[str] = None
    mode: Optional[str] = None
    mx_patterns: List[str] = field(default_factory=list)
    max_age: Optional[int] = None
    policy_error: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    status: str = "missing"  # valid, error, missing, na, dns_error, skipped
    record: Optional[str] = None
    rua: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)


@dataclass
class BIMIResult:
    status: str = "missing"  # valid, warning, missing, dns_error, skipped
    record: Optional[str] = None
    logo_url: Optional[str] = None
    vmc_url: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)


@dataclass
class DNSSECResult:
    status: str = "unknown"  # valid, missing, bogus, unknown, skipped
    issues: List[Issue] = field(default_factory=list)


@dataclass
class TakeoverResult:
    status: str = "missing"  # valid, warning, error, unknown, skipped
    dependencies: List[dict] = field(default_factory=list)  # domain, used_by, state, expires
    dangling: List[dict] = field(default_factory=list)      # name, target, used_by
    ns_hosts: List[str] = field(default_factory=list)
    domain_expires: Optional[str] = None
    rdap: bool = False
    issues: List[Issue] = field(default_factory=list)


@dataclass
class CAAResult:
    status: str = "missing"  # valid, warning, missing, dns_error, skipped
    records: List[dict] = field(default_factory=list)   # flags, tag, value
    issuers: List[str] = field(default_factory=list)    # CAs allowed to issue (";" = none)
    wildcard_issuers: Optional[List[str]] = None        # issuewild, when present
    iodef: List[str] = field(default_factory=list)
    inherited_from: Optional[str] = None                # parent name the CAA set was found at (RFC 8659 climbing)
    issues: List[Issue] = field(default_factory=list)


@dataclass
class AXFRResult:
    status: str = "unknown"  # valid (all refuse), error (a server allows it), unknown, skipped
    servers: List[dict] = field(default_factory=list)   # ns, ip, result (refused, open, unreachable), records
    issues: List[Issue] = field(default_factory=list)


@dataclass
class ConsistencyResult:
    status: str = "missing"  # valid, warning, unknown, skipped
    sources: List[str] = field(default_factory=list)
    differences: List[dict] = field(default_factory=list)   # name, type, kind, answers{source: [..]}
    issues: List[Issue] = field(default_factory=list)


@dataclass
class LookalikeResult:
    status: str = "missing"  # valid, warning, error, unknown, skipped
    base: Optional[str] = None
    generated: int = 0
    registered: List[dict] = field(default_factory=list)    # domain, kind, mx, a, created
    issues: List[Issue] = field(default_factory=list)


@dataclass
class DMARCReportResult:
    status: str = "missing"  # valid, warning, unknown (insufficient data), missing
    reports: int = 0
    messages: int = 0
    passed: int = 0
    pass_rate: float = 0.0
    unaligned: int = 0
    spoofed: int = 0
    period: List[str] = field(default_factory=list)
    reporters: List[str] = field(default_factory=list)
    selectors: List[str] = field(default_factory=list)
    sources: List[dict] = field(default_factory=list)
    verdict: str = ""
    issues: List[Issue] = field(default_factory=list)


@dataclass
class DomainResult:
    domain: str
    scan_date: str = ""
    overall_score: int = 0
    exists: bool = True
    profile: str = "mail"  # mail, non-mail, nonexistent, unreachable
    tier: str = "medium"
    owner: str = ""
    bu: str = ""
    tags: List[str] = field(default_factory=list)
    mx: MXResult = field(default_factory=MXResult)
    spf: SPFResult = field(default_factory=SPFResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    mta_sts: MTASTSResult = field(default_factory=MTASTSResult)
    tls_rpt: TLSRPTResult = field(default_factory=TLSRPTResult)
    bimi: BIMIResult = field(default_factory=BIMIResult)
    dnssec: DNSSECResult = field(default_factory=DNSSECResult)
    caa: CAAResult = field(default_factory=CAAResult)
    takeover: TakeoverResult = field(default_factory=TakeoverResult)
    axfr: AXFRResult = field(default_factory=AXFRResult)
    consistency: ConsistencyResult = field(default_factory=ConsistencyResult)
    lookalikes: LookalikeResult = field(default_factory=LookalikeResult)
    dmarc_reports: DMARCReportResult = field(default_factory=DMARCReportResult)
    issues: List[Issue] = field(default_factory=list)
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, str] = field(default_factory=dict)
    remediation: List[dict] = field(default_factory=list)
    priority: int = 0
    change: Optional[dict] = None
    error: Optional[str] = None
    duration_ms: int = 0
    timings: Dict[str, int] = field(default_factory=dict)  # ms per check


@dataclass
class DomainInput:
    domain: str
    tier: str = "medium"
    owner: str = ""
    bu: str = ""
    tags: List[str] = field(default_factory=list)
