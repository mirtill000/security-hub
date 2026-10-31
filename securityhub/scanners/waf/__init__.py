"""WAFGuard for Imperva - Cloud WAF security posture & configuration assessment

Reads the configuration of every website protected by Imperva Cloud WAF (and,
optionally, of its sub-accounts) through the Imperva APIs, validates it against
security best practices and produces a self-contained HTML report (offline,
single file) plus JSON / CSV exports.

What is assessed, per website
  - Onboarding: active vs bypass mode, onboarding status, DNS really routed
    through Imperva (with --probe)
  - WAF rules: WAF Rules policy applied and enabled, SQLi / XSS / RFI / illegal
    resource access in blocking mode, broad or undocumented exceptions,
    backdoor protection (legacy rules are evaluated when no policy is applied)
  - Allow-lists: WHITELIST policies and legacy whitelists that bypass the WAF
  - Bot access control, DDoS protection mode and threshold
  - TLS: certificate expiry and errors, TLS between Imperva and the origin,
    HSTS / HTTP->HTTPS redirect / legacy TLS versions (with --probe)
  - Origin exposure: origin servers answering directly from the Internet,
    bypassing the WAF (with --probe)
Account level: default WAF policy, disabled or unused policies.

The tool is read-only: it only calls list/status/get endpoints.

Usage:
    export IMPERVA_API_ID=12345 IMPERVA_API_KEY=xxxxxxxx
    securityhub waf --account-id 1234567
    securityhub waf --account-id 1234567 --include-subaccounts --probe --json --csv
    securityhub waf --account-id 1234567 --save-raw snapshot.json
    securityhub waf --from-json snapshot.json --baseline last.json
    securityhub waf --account-id 1234567 --metadata sites.csv --fail-under 70

Requires Python 3.9+ (standard library only; dnspython optional for CNAME checks).
"""

from __future__ import annotations

from .constants import (
    ACTION_LABELS,
    BLOCKING_ACTIONS,
    CHECKS,
    CHECK_ALIASES,
    CHECK_LABELS,
    COMPLIANCE_PROFILES,
    CORE_RULES,
    DDOS_DEFAULT_THRESHOLD,
    DDOS_FACTOR,
    DDOS_FLOOR,
    DDOS_HIGH_RATIO,
    DDOS_LOW_RATIO,
    DDOS_THRESHOLDS,
    FINDINGS,
    FRAMEWORK_MAP,
    IMPERVA_DNS_SUFFIXES,
    SCORE_CAPS,
    SEVERITY_RANK,
    TIER_ALIASES,
    TIER_WEIGHTS,
    USER_AGENT,
    V1_ACTIONS,
    V1_RULE_IDS,
    parse_checks,
)
from .models import (
    CheckResult,
    Issue,
    SiteResult,
    make_issue,
)
from .api import (
    APIError,
    ImpervaAPI,
    TRAFFIC_GRANULARITY_MS,
    collect,
    fetch_traffic,
)
from .probe import (
    probe_site,
)
from .checks import (
    check_allowlist,
    check_bots,
    check_ddos,
    check_onboarding,
    check_origin,
    check_tls,
    check_waf,
    recommend_threshold,
    traffic_profile,
)
from .scoring import (
    evaluate_compliance,
    score_site,
)
from .remediation import (
    suggest_remediation,
    tf_name,
)
from .analysis import (
    analyze_snapshot,
    compute_diff,
    load_metadata,
)
from .exports import (
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
    build_parser,
    main,
)

__all__ = [
    'ACTION_LABELS',
    'APIError',
    'BLOCKING_ACTIONS',
    'CHECKS',
    'CHECK_ALIASES',
    'CHECK_LABELS',
    'COMPLIANCE_PROFILES',
    'CORE_RULES',
    'CheckResult',
    'DDOS_DEFAULT_THRESHOLD',
    'DDOS_FACTOR',
    'DDOS_FLOOR',
    'DDOS_HIGH_RATIO',
    'DDOS_LOW_RATIO',
    'DDOS_THRESHOLDS',
    'FINDINGS',
    'FRAMEWORK_MAP',
    'IMPERVA_DNS_SUFFIXES',
    'ImpervaAPI',
    'Issue',
    'REPORT_CSS',
    'REPORT_JS',
    'REPORT_TEMPLATE',
    'SCORE_CAPS',
    'SEVERITY_RANK',
    'SiteResult',
    'TIER_ALIASES',
    'TIER_WEIGHTS',
    'TRAFFIC_GRANULARITY_MS',
    'USER_AGENT',
    'V1_ACTIONS',
    'V1_RULE_IDS',
    'analyze_snapshot',
    'build_parser',
    'check_allowlist',
    'check_bots',
    'check_ddos',
    'check_onboarding',
    'check_origin',
    'check_tls',
    'check_waf',
    'collect',
    'compute_diff',
    'evaluate_compliance',
    'fetch_traffic',
    'generate_html_report',
    'load_metadata',
    'main',
    'make_issue',
    'parse_checks',
    'probe_site',
    'recommend_threshold',
    'score_site',
    'suggest_remediation',
    'tf_name',
    'traffic_profile',
    'write_csv',
    'write_json',
]
