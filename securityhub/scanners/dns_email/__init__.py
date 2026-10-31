"""MailGuard DNS v3 - Email Security Analyzer (Live DNS)

Assesses the e-mail security posture of a domain portfolio via live DNS:
MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, dependency takeover risk
(RDAP), resolver/authoritative consistency and lookalike domains. Optionally
ingests DMARC aggregate reports and compares the run with a previous baseline.
Produces a self-contained HTML report (works offline) plus JSON / CSV exports.

What's new in v3
  - Takeover risk: SPF includes, MX, NS, DKIM CNAMEs and rua domains checked for
    unregistered / expired / expiring registrations (RDAP) and dangling CNAMEs
  - DMARC aggregate report ingestion (.xml/.gz/.zip/.eml): real DKIM selectors,
    failing senders, spoofing volume, p=reject readiness
  - Lookalike / typosquatting discovery (opt-in) with MX detection
  - Resolver vs authoritative consistency checks (opt-in), optional query rate limit
  - Compliance view (Gmail/Yahoo & Microsoft sender requirements, DMARC enforcement,
    inbound TLS) with indicative NIS2 / ISO 27001 mapping; tier-weighted priorities
  - CSV input with tier / owner / business unit / tags, baseline diff (--baseline)
  - New report: offline, light/dark, accessible heatmap, sortable table, score
    breakdown, copy-ready remediation records, executive PDF, filtered exports
  - Fixes: transient DNS errors no longer cached for the whole run, DNSSEC-bogus
    zones detected, resolver preflight, Public Suffix List, SSRF-safe MTA-STS fetch,
    CSV formula injection, IDNA 2008, consistent exit codes

Usage:
    securityhub dns domains.txt
    securityhub dns portfolio.csv -o report.html --json --csv
    securityhub dns domains.txt --checks spf,dmarc,takeover
    securityhub dns domains.txt --checks all,lookalikes,consistency
    securityhub dns domains.txt --dmarc-reports ./rua/ --baseline last.json
    securityhub dns domains.txt --config mailguard.yaml --profile weekly

Requires: dnspython. Optional: idna (IDNA 2008), PyYAML (YAML config),
defusedxml (extra XML hardening), tldextract (offline PSL fallback).
"""

from __future__ import annotations

from .constants import (
    DKIM_FIRST_ROUND,
    DKIM_PROVIDER_SELECTORS,
    CHECKS,
    CHECK_ALIASES,
    CHECK_ATTRS,
    CHECK_DEPENDENCIES,
    CHECK_LABELS,
    COMPLIANCE_PROFILES,
    DEFAULT_CHECKS,
    DEFAULT_DKIM_SELECTORS,
    DMARC_RE,
    DOMAIN_RE,
    FINDINGS,
    FRAMEWORK_MAP,
    PROTECTED_MX_PROVIDERS,
    SCORE_CAP_CODES,
    SEVERITY_RANK,
    SPF_MECHANISMS,
    SPF_RE,
    SPF_TERM_RE,
    TIER_ALIASES,
    TIER_WEIGHTS,
    USER_AGENT,
    parse_checks,
)
from .checks_dns import (
    DNSHygieneChecks,
)
from .models import (
    AXFRResult,
    CAAResult,
    BIMIResult,
    ConsistencyResult,
    DKIMResult,
    DKIMSelector,
    DMARCReportResult,
    DMARCResult,
    DNSSECResult,
    DomainInput,
    DomainResult,
    Issue,
    LookalikeResult,
    MTASTSResult,
    MXRecord,
    MXResult,
    SPFResult,
    TLSRPTResult,
    TakeoverResult,
    make_issue,
)
from .util import (
    cache_dir,
    http_get,
    issues_from_problems,
    match_provider,
    parse_tags,
    rsa_key_bits,
)
from .domains import (
    PSL_URLS,
    PublicSuffixList,
    normalize_domain,
    org_domain,
    set_psl,
    tier_weight,
    to_ascii,
)
from .dnsclient import (
    DNSAnswer,
    DNSClient,
    preflight,
)
from .rdap import (
    RDAPClient,
)
from .fetch import (
    is_public_ip,
)
from .checks_auth import (
    AuthChecks,
)
from .lookalikes import (
    ASCII_HOMOGLYPHS,
    COMBO_WORDS,
    IDN_HOMOGLYPHS,
    KEYBOARD_NEIGHBOURS,
    LOOKALIKE_PRIORITY,
    LOOKALIKE_TLDS,
    MULTI_HOMOGLYPHS,
    generate_lookalikes,
)
from .checks_exposure import (
    ExposureChecks,
    WELL_KNOWN_PROVIDERS,
)
from .checks_transport import (
    TransportChecks,
)
from .scoring import (
    Scoring,
)
from .remediation import (
    SPF_PROVIDER_INCLUDES,
    suggest_remediation,
)
from .analyzer import (
    EmailSecurityAnalyzer,
)
from .dmarc_reports import (
    MAX_REPORT_BYTES,
    load_dmarc_reports,
)
from .baseline import (
    compute_diff,
)
from .inputs import (
    CSV_COLUMNS,
    load_config,
    load_domains,
)
from .exports import (
    CSV_EXPORT_COLUMNS,
    write_csv,
    write_json,
)
from .report import (
    REPORT_CSS,
    REPORT_JS,
    REPORT_TEMPLATE,
    generate_html_report,
)
from .cli import (
    Progress,
    build_parser,
    main,
    parse_arguments,
    print_timing_summary,
)

__all__ = [
    'DKIM_FIRST_ROUND',
    'DKIM_PROVIDER_SELECTORS',
    'AXFRResult',
    'CAAResult',
    'DNSHygieneChecks',
    'ASCII_HOMOGLYPHS',
    'AuthChecks',
    'BIMIResult',
    'CHECKS',
    'CHECK_ALIASES',
    'CHECK_ATTRS',
    'CHECK_DEPENDENCIES',
    'CHECK_LABELS',
    'COMBO_WORDS',
    'COMPLIANCE_PROFILES',
    'CSV_COLUMNS',
    'CSV_EXPORT_COLUMNS',
    'ConsistencyResult',
    'DEFAULT_CHECKS',
    'DEFAULT_DKIM_SELECTORS',
    'DKIMResult',
    'DKIMSelector',
    'DMARCReportResult',
    'DMARCResult',
    'DMARC_RE',
    'DNSAnswer',
    'DNSClient',
    'DNSSECResult',
    'DOMAIN_RE',
    'DomainInput',
    'DomainResult',
    'EmailSecurityAnalyzer',
    'ExposureChecks',
    'FINDINGS',
    'FRAMEWORK_MAP',
    'IDN_HOMOGLYPHS',
    'Issue',
    'KEYBOARD_NEIGHBOURS',
    'LOOKALIKE_PRIORITY',
    'LOOKALIKE_TLDS',
    'LookalikeResult',
    'MAX_REPORT_BYTES',
    'MTASTSResult',
    'MULTI_HOMOGLYPHS',
    'MXRecord',
    'MXResult',
    'PROTECTED_MX_PROVIDERS',
    'PSL_URLS',
    'Progress',
    'PublicSuffixList',
    'RDAPClient',
    'REPORT_CSS',
    'REPORT_JS',
    'REPORT_TEMPLATE',
    'SCORE_CAP_CODES',
    'SEVERITY_RANK',
    'SPFResult',
    'SPF_MECHANISMS',
    'SPF_PROVIDER_INCLUDES',
    'SPF_RE',
    'SPF_TERM_RE',
    'Scoring',
    'TIER_ALIASES',
    'TIER_WEIGHTS',
    'TLSRPTResult',
    'TakeoverResult',
    'TransportChecks',
    'USER_AGENT',
    'WELL_KNOWN_PROVIDERS',
    'build_parser',
    'cache_dir',
    'compute_diff',
    'generate_html_report',
    'generate_lookalikes',
    'http_get',
    'is_public_ip',
    'issues_from_problems',
    'load_config',
    'load_dmarc_reports',
    'load_domains',
    'main',
    'make_issue',
    'match_provider',
    'normalize_domain',
    'org_domain',
    'parse_arguments',
    'parse_checks',
    'parse_tags',
    'preflight',
    'print_timing_summary',
    'rsa_key_bits',
    'set_psl',
    'suggest_remediation',
    'tier_weight',
    'to_ascii',
    'write_csv',
    'write_json',
]
