"""
WAFGuard for Imperva - Cloud WAF security posture & configuration assessment

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

import argparse
import csv
import html
import io
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..common import (EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, Parser, RateLimiter,
                      csv_safe, json_for_html)

try:  # optional: CNAME resolution for the DNS routing check
    import dns.resolver as _dns_resolver
except ImportError:  # pragma: no cover
    _dns_resolver = None

__version__ = "1.1.0"
USER_AGENT = f"WAFGuard/{__version__} (read-only assessment)"

# ---------------------------------------------------------------------------
# Findings catalogue: code -> (severity, area, title, recommendation)
# ---------------------------------------------------------------------------

FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # Onboarding / routing
    "SITE_BYPASS": ("critical", "Onboarding", "Website in bypass mode: traffic is not inspected",
                    "Set the website back to Active (Websites > Settings > General, or 'active' in Terraform incapsula_site)"),
    "SITE_NOT_CONFIGURED": ("warning", "Onboarding", "Website onboarding not completed",
                            "Complete the DNS / SSL onboarding steps until the status is 'Fully configured'"),
    "SITE_WARNINGS": ("info", "Onboarding", "Imperva reports configuration warnings for this website",
                      "Review the warnings in the Cloud Security Console"),
    "DNS_NOT_ROUTED": ("critical", "Onboarding", "Public DNS does not route traffic through Imperva",
                       "Point the DNS record to the Imperva CNAME/IPs shown in the website settings"),
    "DNS_UNRESOLVED": ("warning", "Onboarding", "Website hostname does not resolve",
                       "Check the DNS record or remove the website from Imperva"),
    # WAF rules
    "WAF_NO_POLICY": ("critical", "WAF", "No WAF rules policy protects this website",
                      "Apply a WAF Rules policy (or the account default) to the website"),
    "WAF_POLICY_DISABLED": ("critical", "WAF", "Applied WAF rules policy is disabled",
                            "Enable the policy - while disabled the core WAF rules are not enforced"),
    "WAF_RULE_MISSING": ("critical", "WAF", "Core WAF rule not configured",
                         "Add the rule to the WAF Rules policy with action Block Request"),
    "WAF_RULE_IGNORED": ("critical", "WAF", "Core WAF rule set to Ignore / disabled",
                         "Set the rule to Block Request (or Block User / Block IP)"),
    "WAF_RULE_ALERT": ("warning", "WAF", "Core WAF rule in Alert Only mode",
                       "Switch to Block Request once false positives are tuned; alert-only is acceptable for PCI DSS 6.4.2 only if alerts are investigated"),
    "WAF_LEGACY_RULES": ("info", "WAF", "WAF rules come from legacy per-site settings, not from a policy",
                         "Migrate to a WAF Rules policy for consistent, auditable configuration"),
    "WAF_MULTIPLE_POLICIES": ("info", "WAF", "More than one WAF rules policy applied",
                              "Keep a single WAF Rules policy per website to avoid ambiguity"),
    "WAF_BROAD_EXCEPTION": ("warning", "WAF", "Broad WAF exception weakens protection",
                            "Narrow the exception to specific URLs/parameters/IPs and document why it exists"),
    "WAF_EXCEPTION_NO_COMMENT": ("info", "WAF", "WAF exceptions without a justification comment",
                                 "Add a comment with owner, ticket and expiry to every exception"),
    "WAF_MANY_EXCEPTIONS": ("info", "WAF", "Large number of WAF exceptions",
                            "Review exceptions periodically and remove the ones no longer needed"),
    "WAF_DATA_LEAK_OFF": ("info", "WAF", "Sensitive data leakage protection not blocking",
                          "Consider enabling response data leak protection if included in your plan"),
    "WAF_BACKDOOR_WEAK": ("warning", "WAF", "Backdoor protection not in quarantine/block mode",
                          "Set Backdoor Protect to Auto-Quarantine"),
    # Allow-lists
    "ALLOW_BROAD_IP": ("critical", "Allow-list", "Very broad IP range allow-listed (WAF bypass)",
                       "Allow-listed IPs skip WAF inspection: restrict entries to specific trusted hosts"),
    "ALLOW_BROAD_URL": ("warning", "Allow-list", "Broad URL allow-list (WAF bypass)",
                        "Restrict allow-listed URLs to the exact paths that need it"),
    "ALLOW_MANY_IPS": ("info", "Allow-list", "Many allow-listed IP addresses",
                       "Review allow-list entries: each one bypasses WAF inspection"),
    # Bots / DDoS
    "BOT_BAD_NOT_BLOCKED": ("warning", "Bots", "Known bad bots are not blocked",
                            "Enable 'Block bad bots' in Bot Access Control"),
    "BOT_SUSPECTED_NOT_CHALLENGED": ("info", "Bots", "Suspected bots are not challenged",
                                     "Enable 'Challenge suspected bots' (or deploy Advanced Bot Protection)"),
    "BOT_RULE_MISSING": ("warning", "Bots", "Bot access control settings not found",
                         "Configure Bot Access Control for the website"),
    "DDOS_OFF": ("critical", "DDoS", "DDoS protection is off",
                 "Set DDoS activation mode to Automatic (or Always on)"),
    "DDOS_HIGH_THRESHOLD": ("info", "DDoS", "High DDoS activation threshold",
                            "Align the threshold with the site's normal peak traffic"),
    "DDOS_RULE_MISSING": ("warning", "DDoS", "DDoS settings not found",
                          "Verify the DDoS protection settings of the website"),
    "DDOS_THRESHOLD_LOW": ("warning", "DDoS", "DDoS threshold too close to real traffic",
                           "Raise the threshold: at peak, legitimate visitors are challenged as if under attack"),
    "DDOS_THRESHOLD_HIGH": ("warning", "DDoS", "DDoS threshold far above real traffic",
                            "Lower the threshold: an attack below it does not trigger DDoS mitigation"),
    "DDOS_ABOVE_ORIGIN": ("warning", "DDoS", "DDoS threshold above the origin capacity",
                          "Set the threshold below what the origin can serve, or scale the origin"),
    "DDOS_DEFAULT_THRESHOLD": ("info", "DDoS", "DDoS threshold left at the default value",
                               "Tune the threshold to the site's own traffic profile"),
    "DDOS_ACTIVATIONS": ("info", "DDoS", "DDoS mitigation was triggered in the analysis window",
                         "Check whether the activations were real attacks or legitimate peaks"),
    "DDOS_TRAFFIC_UNAVAILABLE": ("info", "DDoS", "Traffic statistics not available: threshold not validated",
                                 "Give the API key access to traffic statistics (or check that the plan includes them)"),
    # TLS
    "CERT_EXPIRED": ("critical", "TLS", "Custom certificate expired",
                     "Upload a renewed certificate (or switch to the Imperva-generated certificate)"),
    "CERT_EXPIRING": ("warning", "TLS", "Custom certificate expires within 30 days",
                      "Renew and upload the certificate before it expires"),
    "CERT_ERROR": ("warning", "TLS", "Certificate problems reported by Imperva",
                   "Fix the certificate chain, hostname or revocation issues"),
    "CERT_VALIDATION_PENDING": ("warning", "TLS", "Imperva-generated certificate not validated",
                                "Complete domain validation so the certificate can be issued/renewed"),
    "ORIGIN_NO_TLS": ("warning", "TLS", "TLS not detected between Imperva and the origin",
                      "Enable HTTPS on the origin so traffic from Imperva to the origin is encrypted"),
    "TLS_NO_HSTS": ("warning", "TLS", "HSTS header not served",
                    "Enable HSTS (incapsula_site_ssl_settings hsts block, max-age >= 1 year)"),
    "TLS_NO_REDIRECT": ("warning", "TLS", "HTTP is not redirected to HTTPS",
                        "Add a redirect rule from HTTP to HTTPS"),
    "TLS_LEGACY": ("warning", "TLS", "Legacy TLS versions accepted (TLS 1.0/1.1)",
                   "Restrict the inbound TLS configuration to TLS 1.2 and 1.3"),
    "TLS_LIVE_CERT_EXPIRING": ("warning", "TLS", "Certificate served to visitors expires soon",
                               "Renew the certificate served by Imperva"),
    # Origin
    "ORIGIN_EXPOSED": ("critical", "Origin", "Origin server answers directly from the Internet (WAF bypass)",
                       "Restrict the origin firewall to Imperva IP ranges only (or use a private connection)"),
    "ORIGIN_REACHABLE": ("info", "Origin", "Origin port reachable from the Internet",
                         "Confirm the origin only accepts traffic from Imperva IP ranges"),
    # Collection
    "API_ERROR": ("warning", "Collection", "Some configuration could not be read from the API",
                  "Check the API key permissions and re-run the assessment"),
    # Account level
    "ACCOUNT_NO_DEFAULT_WAF": ("warning", "Account", "No default WAF Rules policy in the account",
                               "Mark a WAF Rules policy as default so new websites are protected from day one"),
    "ACCOUNT_DISABLED_POLICIES": ("info", "Account", "Disabled policies exist in the account",
                                  "Delete or re-enable disabled policies to keep the configuration auditable"),
    "ACCOUNT_UNUSED_POLICIES": ("info", "Account", "Policies not applied to any asset",
                                "Remove unused policies or apply them where intended"),
    "ACCOUNT_SITES_WITHOUT_POLICY": ("warning", "Account", "Websites without any policy",
                                     "Apply the standard WAF and ACL policies to every website"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

FRAMEWORK_MAP: Dict[str, List[str]] = {
    "Onboarding": ["PCI DSS 6.4.2", "NIS2 Art.21(2)(e)", "ISO 27001 A.8.20"],
    "WAF": ["PCI DSS 6.4.2", "OWASP Top 10 A03", "NIS2 Art.21(2)(e)", "ISO 27001 A.8.26"],
    "Allow-list": ["PCI DSS 6.4.2", "ISO 27001 A.8.20"],
    "Bots": ["OWASP Automated Threats", "ISO 27001 A.8.20"],
    "DDoS": ["NIS2 Art.21(2)(c)", "ISO 27001 A.8.6"],
    "TLS": ["PCI DSS 4.2.1", "NIS2 Art.21(2)(h)", "ISO 27001 A.8.24"],
    "Origin": ["PCI DSS 1.4.1", "NIS2 Art.21(2)(e)", "ISO 27001 A.8.20"],
    "Account": ["ISO 27001 A.8.9"],
    "Collection": [],
}

COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "pci_642": ("PCI DSS 6.4.2 (WAF in front of public web apps)",
                "Website active, core WAF rules blocking or alerting, traffic routed through Imperva."),
    "owasp_block": ("Injection attacks blocked",
                    "SQL injection, XSS, remote file inclusion and illegal resource access set to block."),
    "ddos": ("DDoS protection enabled", "DDoS activation mode automatic or always on."),
    "transport": ("Transport security", "Valid certificate, TLS to origin; with --probe also HSTS, redirect and no TLS 1.0/1.1."),
    "origin_lockdown": ("Origin locked down", "Origin does not answer directly (requires --probe)."),
}

TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Values accepted by Imperva for the DDoS activity threshold (requests per second)
DDOS_THRESHOLDS = [10, 20, 50, 100, 200, 500, 750, 1000, 2000, 3000, 4000, 5000]
DDOS_DEFAULT_THRESHOLD = 1000
DDOS_FACTOR = 3.5        # recommended threshold = factor x peak (Imperva guidance)
DDOS_FLOOR = 150         # ... but never below this value
DDOS_LOW_RATIO = 0.9     # peak above 90% of the threshold: too low
DDOS_HIGH_RATIO = 2.0    # threshold above 2x the recommended value: too high
TIER_ALIASES = {"critical": "critical", "critica": "critical", "1": "critical", "c": "critical",
                "high": "high", "alta": "high", "alto": "high", "2": "high", "h": "high",
                "medium": "medium", "media": "medium", "medio": "medium", "3": "medium", "m": "medium", "": "medium",
                "low": "low", "bassa": "low", "basso": "low", "4": "low", "l": "low"}

CHECKS: Dict[str, int] = {"onboarding": 20, "waf": 40, "allowlist": 0, "bots": 10, "ddos": 15, "tls": 15, "origin": 0}
CHECK_LABELS = {"onboarding": "Onboarding", "waf": "WAF rules", "allowlist": "Allow-lists", "bots": "Bots",
                "ddos": "DDoS", "tls": "TLS", "origin": "Origin"}
CHECK_ALIASES = {"rules": "waf", "whitelist": "allowlist", "allow": "allowlist", "bot": "bots", "ssl": "tls",
                 "onboard": "onboarding", "routing": "onboarding"}
SCORE_CAPS = {"SITE_BYPASS": 20, "DNS_NOT_ROUTED": 30, "WAF_NO_POLICY": 30, "WAF_POLICY_DISABLED": 30,
              "ORIGIN_EXPOSED": 40, "ALLOW_BROAD_IP": 40, "CERT_EXPIRED": 40}

CORE_RULES = {
    "SQL_INJECTION": "SQL injection",
    "CROSS_SITE_SCRIPTING": "Cross-site scripting",
    "ILLEGAL_RESOURCE_ACCESS": "Illegal resource access",
    "REMOTE_FILE_INCLUSION": "Remote file inclusion",
}
V1_RULE_IDS = {
    "api.threats.sql_injection": "SQL_INJECTION",
    "api.threats.cross_site_scripting": "CROSS_SITE_SCRIPTING",
    "api.threats.illegal_resource_access": "ILLEGAL_RESOURCE_ACCESS",
    "api.threats.remote_file_inclusion": "REMOTE_FILE_INCLUSION",
}
V1_ACTIONS = {
    "api.threats.action.block_request": "BLOCK", "api.threats.action.block_user": "BLOCK_USER",
    "api.threats.action.block_ip": "BLOCK_IP", "api.threats.action.alert": "ALERT",
    "api.threats.action.disabled": "IGNORE", "api.threats.action.quarantine_url": "QUARANTINE",
}
BLOCKING_ACTIONS = {"BLOCK", "BLOCK_REQUEST", "BLOCK_USER", "BLOCK_IP", "QUARANTINE"}
ACTION_LABELS = {"BLOCK": "Block request", "BLOCK_REQUEST": "Block request", "BLOCK_USER": "Block user",
                 "BLOCK_IP": "Block IP", "ALERT": "Alert only", "IGNORE": "Ignore", "QUARANTINE": "Auto-quarantine",
                 "ALLOW": "Allow", None: "Not set"}
IMPERVA_DNS_SUFFIXES = (".incapdns.net", ".impervadns.net", ".incapsula.net", ".imperva.net")


def parse_checks(spec: str = "all", skip: str = "") -> List[str]:
    def names(text: str) -> List[str]:
        out = []
        for raw in re.split(r"[,\s]+", (text or "").strip().lower()):
            if not raw:
                continue
            n = CHECK_ALIASES.get(raw, raw)
            if n != "all" and n not in CHECKS:
                raise ValueError(f"unknown check '{raw}' (valid: {', '.join(CHECKS)}, all)")
            out.append(n)
        return out
    wanted = names(spec) or ["all"]
    sel = set(CHECKS) if "all" in wanted else set(wanted)
    sel -= set(names(skip))
    if not sel:
        raise ValueError("no checks left to run")
    return [c for c in CHECKS if c in sel]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Imperva API client (read-only)
# ---------------------------------------------------------------------------

class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status




class ImpervaAPI:
    """Minimal read-only client. Credentials travel only in headers (never in URLs or logs)."""

    def __init__(self, api_id: str, api_key: str, v1_base: str = "https://my.imperva.com",
                 api_base: str = "https://api.imperva.com", timeout: float = 30.0, qps: float = 8.0,
                 retries: int = 4, verify_tls: bool = True):
        self._headers = {"x-API-Id": str(api_id), "x-API-Key": str(api_key), "Accept": "application/json",
                         "User-Agent": USER_AGENT}
        self.v1_base = v1_base.rstrip("/")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.stats = Counter()
        self._lock = threading.Lock()

    def _request(self, method: str, url: str, form: Optional[dict] = None) -> Tuple[int, Any]:
        data = None
        headers = dict(self._headers)
        if form is not None:
            data = urllib.parse.urlencode({k: v for k, v in form.items() if v is not None}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        last = None
        for attempt in range(self.retries + 1):
            self.rate.wait()
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    body = resp.read()
                    with self._lock:
                        self.stats["requests"] += 1
                    return resp.status, json.loads(body or b"null")
            except urllib.error.HTTPError as e:
                with self._lock:
                    self.stats["requests"] += 1
                    self.stats[f"http_{e.code}"] += 1
                if e.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    delay = float(retry_after) if retry_after and retry_after.isdigit() else 1.5 * 2 ** attempt
                    time.sleep(min(delay, 30) + random.random() * 0.5)
                    continue
                try:
                    payload = json.loads(e.read() or b"null")
                except ValueError:
                    payload = None
                return e.code, payload
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                last = e
                if attempt < self.retries:
                    time.sleep(1.5 * 2 ** attempt + random.random() * 0.5)
                    continue
        raise APIError(f"network error: {getattr(last, 'reason', last)}")

    @staticmethod
    def _explain(status: int, payload: Any) -> str:
        if status == 401:
            return "authentication failed (check API ID / API key)"
        if status == 403:
            return "permission denied for this API (check the API key role)"
        msg = ""
        if isinstance(payload, dict):
            msg = payload.get("res_message") or payload.get("message") or payload.get("error") or ""
        return f"HTTP {status}{': ' + str(msg) if msg else ''}"

    def v1(self, path: str, **params) -> dict:
        """POST to a v1 provisioning endpoint; v1 reports errors with a non-zero 'res'."""
        status, payload = self._request("POST", f"{self.v1_base}{path}", form=params)
        if status != 200 or not isinstance(payload, dict):
            raise APIError(self._explain(status, payload), status)
        res = payload.get("res", 0)
        if str(res) not in ("0", "None"):
            raise APIError(f"API error {res}: {payload.get('res_message', 'unknown')}", status)
        return payload

    def get(self, path: str, **params) -> Any:
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        status, payload = self._request("GET", f"{self.api_base}{path}{'?' + qs if qs else ''}")
        if status == 404:
            return None
        if status != 200:
            raise APIError(self._explain(status, payload), status)
        if isinstance(payload, dict) and payload.get("isError"):
            raise APIError(str(payload.get("value") or "API returned isError"), status)
        return payload


# ---------------------------------------------------------------------------
# Collection: builds a raw snapshot (also saved with --save-raw, re-analyzed with --from-json)
# ---------------------------------------------------------------------------

def _unwrap(payload: Any) -> list:
    if isinstance(payload, dict):
        value = payload.get("value", payload.get("data"))
        if isinstance(value, list):
            return value
    return payload if isinstance(payload, list) else []


TRAFFIC_GRANULARITY_MS = 3600000  # hourly buckets: finer data gives more realistic peaks


def fetch_traffic(api: ImpervaAPI, site_id: Any, days: int) -> dict:
    """hits_timeseries (+ threats) for one site. Falls back to the default granularity when the
    requested one is rejected (error 13002)."""
    if days in (7, 30, 90):
        window = {"time_range": f"last_{days}_days"}
    else:
        end = int(time.time() * 1000)
        window = {"time_range": "custom", "start": end - days * 86400000, "end": end}
    for granularity in (TRAFFIC_GRANULARITY_MS, None):
        try:
            resp = api.v1("/api/stats/v1", site_id=site_id, stats="hits_timeseries,threats",
                          granularity=granularity, **window)
            return {"days": days, "granularity": granularity, "hits_timeseries": resp.get("hits_timeseries") or [],
                    "threats": resp.get("threats") or []}
        except APIError as e:
            if granularity and "13002" in str(e):
                continue
            raise
    return {}


def collect(api: ImpervaAPI, account_id: Optional[int], include_subaccounts: bool, site_filter: Set[str],
            workers: int, log, traffic_days: int = 90) -> dict:
    snap = {"tool": f"WAFGuard {__version__}", "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "accounts": [], "errors": []}

    def err(where: str, e: Exception) -> None:
        snap["errors"].append({"where": where, "error": str(e)})
        log(f"  ! {where}: {e}")

    accounts: List[dict] = []
    try:
        info = api.v1("/api/prov/v1/account", account_id=account_id).get("account", {}) or {}
        accounts.append({"account_id": info.get("account_id", account_id), "name": info.get("account_name", ""),
                         "plan": info.get("plan_name", ""), "parent": True})
    except APIError as e:
        err("account info", e)
        accounts.append({"account_id": account_id, "name": "", "plan": "", "parent": True})
    if include_subaccounts:
        page = 0
        while True:
            try:
                resp = api.v1("/api/prov/v1/accounts/listSubAccounts", account_id=account_id, page_size=100, page_num=page)
            except APIError as e:
                err("sub-accounts", e)
                break
            items = resp.get("resultList") or resp.get("accounts") or []
            for s in items:
                accounts.append({"account_id": s.get("sub_account_id") or s.get("account_id"),
                                 "name": s.get("sub_account_name") or s.get("account_name", ""), "plan": "",
                                 "parent": False})
            if len(items) < 100:
                break
            page += 1

    for acc in accounts:
        aid = acc["account_id"]
        caid = None if acc["parent"] else aid
        log(f"Account {aid} {acc['name']}".rstrip())
        sites: List[dict] = []
        page = 0
        while True:
            try:
                resp = api.v1("/api/prov/v1/sites/list", account_id=aid, page_size=100, page_num=page)
            except APIError as e:
                err(f"sites list (account {aid})", e)
                break
            batch = resp.get("sites") or []
            sites.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        if site_filter:
            sites = [s for s in sites if str(s.get("site_id")) in site_filter or
                     str(s.get("domain", "")).lower() in site_filter]
        log(f"  {len(sites)} website(s)")
        try:
            policies = _unwrap(api.get("/policies/v2/policies", extended="true", caid=caid))
        except APIError as e:
            err(f"policies (account {aid})", e)
            policies = []

        def detail(site: dict) -> Tuple[dict, list, Optional[str], Optional[dict]]:
            sid = site.get("site_id")
            problem = None
            full = site
            try:
                full = api.v1("/api/prov/v1/sites/status", site_id=sid) or site
            except APIError as e:
                problem = f"site status: {e}"
            try:
                applied = _unwrap(api.get(f"/policies/v2/assets/WEBSITE/{sid}/policies", extended="true", caid=caid))
            except APIError as e:
                applied = None
                problem = (problem + "; " if problem else "") + f"applied policies: {e}"
            traffic = None
            if traffic_days:
                try:
                    traffic = fetch_traffic(api, sid, traffic_days)
                except APIError as e:
                    traffic = {"error": str(e)}
            return full, applied, problem, traffic

        acc_sites, applied_map, problems, traffic_map = [], {}, {}, {}
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futures = {ex.submit(detail, s): s for s in sites}
            for k, fut in enumerate(as_completed(futures), 1):
                full, applied, problem, traffic = fut.result()
                sid = str(full.get("site_id", futures[fut].get("site_id")))
                acc_sites.append(full)
                applied_map[sid] = applied
                if traffic is not None:
                    traffic_map[sid] = traffic
                if problem:
                    problems[sid] = problem
                if k % 25 == 0 or k == len(sites):
                    log(f"  read {k}/{len(sites)} websites")
        snap["accounts"].append({**acc, "sites": acc_sites, "policies": policies, "asset_policies": applied_map,
                                 "site_errors": problems, "traffic": traffic_map})
    snap["api_stats"] = dict(api.stats)
    return snap


# ---------------------------------------------------------------------------
# External probes (opt-in): DNS routing, HTTPS behaviour, legacy TLS, origin exposure
# ---------------------------------------------------------------------------

def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _resolve(host: str) -> Tuple[List[str], List[str]]:
    """(cname chain, addresses)."""
    cnames: List[str] = []
    if _dns_resolver is not None:
        try:
            ans = _dns_resolver.resolve(host, "A", raise_on_no_answer=False)
            canon = str(ans.canonical_name).rstrip(".").lower()
            if canon != host.lower():
                cnames.append(canon)
        except Exception:
            pass
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        addrs = []
    return cnames, addrs


def _http_head(host: str, ip: Optional[str], port: int, use_tls: bool, timeout: float, verify: bool) -> dict:
    """Minimal HTTP/1.1 request; returns status, headers and certificate info."""
    out: Dict[str, Any] = {"ok": False}
    target = ip or host
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
    except OSError as e:
        out["error"] = f"connect: {e.strerror or e}"
        return out
    try:
        if use_tls:
            ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            cert = sock.getpeercert() if verify else None
            if cert and cert.get("notAfter"):
                exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                out["cert_days"] = (exp - datetime.now(timezone.utc)).days
            out["tls_version"] = sock.version()
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace").split("\r\n")
        m = re.match(r"HTTP/\d\.\d (\d{3})", head[0] if head else "")
        out["status"] = int(m.group(1)) if m else None
        out["headers"] = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:]) if k}
        out["ok"] = out["status"] is not None
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"certificate: {e.verify_message}"
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _accepts_tls(host: str, version: ssl.TLSVersion, timeout: float) -> Optional[bool]:
    ctx = ssl._create_unverified_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None  # local OpenSSL cannot test this version
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return None


def probe_site(site: dict, timeout: float = 6.0) -> dict:
    """Read-only checks from the Internet. Origin probes only send one GET / per origin address."""
    host = str(site.get("domain", "")).lower()
    res: Dict[str, Any] = {"host": host, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    cnames, addrs = _resolve(host)
    res["cnames"], res["addresses"] = cnames, addrs
    expected = set()
    for rec in site.get("dns") or []:
        for v in rec.get("set_data_to") or []:
            expected.add(str(v).lower().rstrip("."))
    res["expected"] = sorted(expected)
    routed = None
    if addrs:
        routed = any(c.endswith(IMPERVA_DNS_SUFFIXES) or c in expected for c in cnames) or \
                 any(a in expected for a in addrs)
        if not routed and not cnames and _dns_resolver is None and not expected & set(addrs):
            routed = None if not expected else False
    res["routed"] = routed
    if addrs:
        https = _http_head(host, None, 443, True, timeout, True)
        res["https"] = {k: v for k, v in https.items() if k != "headers"}
        hdrs = https.get("headers") or {}
        res["hsts"] = hdrs.get("strict-transport-security")
        res["imperva_edge"] = bool(hdrs.get("x-iinfo") or "imperva" in hdrs.get("x-cdn", "").lower())
        http = _http_head(host, None, 80, False, timeout, False)
        loc = (http.get("headers") or {}).get("location", "")
        res["http_status"] = http.get("status")
        res["redirects_https"] = bool(http.get("status") in (301, 302, 307, 308) and loc.lower().startswith("https://"))
        res["tls10"] = _accepts_tls(host, ssl.TLSVersion.TLSv1, timeout)
        res["tls11"] = _accepts_tls(host, ssl.TLSVersion.TLSv1_1, timeout)
    origins = []
    for origin in (site.get("ips") or [])[:6]:
        origin = str(origin).strip()
        ips = [origin] if re.fullmatch(r"[0-9a-fA-F:.]+", origin) else _resolve(origin)[1][:2]
        for ip in ips:
            if not _is_public(ip):
                origins.append({"origin": origin, "ip": ip, "result": "private"})
                continue
            entry = {"origin": origin, "ip": ip, "result": "closed"}
            for port, tls in ((443, True), (80, False)):
                r = _http_head(host, ip, port, tls, timeout, False)
                if r.get("ok"):
                    entry.update({"result": "serves" if (r["status"] or 0) < 400 else "reachable",
                                  "port": port, "status": r["status"]})
                    break
                if r.get("error", "").startswith("connect") is False and "error" in r:
                    entry.update({"result": "reachable", "port": port})
            origins.append(entry)
    res["origins"] = origins
    return res


FINDINGS["TLS_NOT_ENABLED"] = ("critical", "TLS", "HTTPS not enabled on the website",
                               "Enable SSL support with an Imperva-generated or a custom certificate")

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "on")


def _broad_cidr(value: str, v4_prefix: int, v6_prefix: int) -> bool:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return net.prefixlen <= (v4_prefix if net.version == 4 else v6_prefix)


def _status_from(issues: List[Issue], default: str = "valid") -> str:
    sev = {i.severity for i in issues}
    return "error" if "critical" in sev else "warning" if "warning" in sev else default


def _legacy_rules(site: dict) -> Dict[str, dict]:
    rules = ((site.get("security") or {}).get("waf") or {}).get("rules") or []
    return {str(r.get("id")): r for r in rules if isinstance(r, dict)}


def _legacy_acls(site: dict) -> Dict[str, dict]:
    rules = ((site.get("security") or {}).get("acls") or {}).get("rules") or []
    return {str(r.get("id")): r for r in rules if isinstance(r, dict)}


def _enrich_policies(applied: Optional[list], account_policies: Dict[Any, dict]) -> List[dict]:
    out = []
    for p in applied or []:
        full = dict(account_policies.get(p.get("id"), {}))
        full.update({k: v for k, v in p.items() if v not in (None, [], "")})
        out.append(full)
    return out


def check_onboarding(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=20)
    active = str(site.get("active", "")).lower()
    status = str(site.get("status", "")).lower()
    if active == "bypass":
        c.issues.append(make_issue("SITE_BYPASS"))
    else:
        c.got += 12
    if status.replace("-", "_") == "fully_configured":
        c.got += 8
    else:
        c.issues.append(make_issue("SITE_NOT_CONFIGURED", status or "unknown status"))
    warnings = site.get("warnings") or []
    if warnings:
        first = warnings[0] if isinstance(warnings[0], str) else json.dumps(warnings[0])[:120]
        c.issues.append(make_issue("SITE_WARNINGS", f"{len(warnings)}: {first}"))
    c.data = {"status": site.get("status"), "active": site.get("active"), "display_name": site.get("display_name"),
              "dns": [{"name": d.get("dns_record_name"), "type": d.get("set_type_to"), "value": d.get("set_data_to")}
                      for d in site.get("dns") or []]}
    if probe:
        c.data["probe"] = {k: probe.get(k) for k in ("cnames", "addresses", "expected", "routed", "imperva_edge")}
        if not probe.get("addresses"):
            c.issues.append(make_issue("DNS_UNRESOLVED", probe.get("host")))
        elif probe.get("routed") is False:
            c.issues.append(make_issue("DNS_NOT_ROUTED", ", ".join((probe.get("cnames") or []) + probe["addresses"][:3])))
    c.status = _status_from(c.issues)
    return c


def check_waf(site: dict, policies: List[dict]) -> CheckResult:
    c = CheckResult(max=36)
    waf = [p for p in policies if p.get("policyType") == "WAF_RULES"]
    legacy = _legacy_rules(site)
    rules: Dict[str, dict] = {}
    exceptions: List[dict] = []
    data_leak = None
    policy_info = None
    if waf:
        if len(waf) > 1:
            c.issues.append(make_issue("WAF_MULTIPLE_POLICIES", ", ".join(str(p.get("name")) for p in waf)))
        enabled = [p for p in waf if p.get("enabled") is not False]
        p = enabled[0] if enabled else waf[0]
        policy_info = {"id": p.get("id"), "name": p.get("name"), "enabled": p.get("enabled") is not False}
        if not enabled:
            c.issues.append(make_issue("WAF_POLICY_DISABLED", str(p.get("name"))))
        for s in p.get("policySettings") or []:
            t = s.get("policySettingType")
            act = str(s.get("settingsAction") or "").upper() or None
            excs = s.get("policyDataExceptions") or []
            if t in CORE_RULES:
                rules[t] = {"action": act if policy_info["enabled"] else "IGNORE", "source": f"policy '{p.get('name')}'",
                            "exceptions": len(excs)}
            elif t == "RESP_DATA_LEAK":
                data_leak = act
            for exc in excs:
                for d in exc.get("data") or []:
                    etype = str(d.get("exceptionType") or "").upper()
                    values = [str(v) for v in d.get("values") or []]
                    broad = (etype == "URL" and any(v.strip() in ("", "/", "*", "/*") for v in values)) or \
                            (etype == "IP" and any(_broad_cidr(v, 16, 32) for v in values)) or etype == "GEO"
                    exceptions.append({"rule": CORE_RULES.get(t, t), "type": etype, "values": values[:20],
                                       "comment": exc.get("comment") or "", "broad": broad})
    else:
        for rid, core in V1_RULE_IDS.items():
            r = legacy.get(rid)
            if r:
                rules[core] = {"action": V1_ACTIONS.get(r.get("action"), str(r.get("action") or "").upper() or None),
                               "source": "legacy site settings", "exceptions": len(r.get("exceptions") or [])}
        if rules:
            c.issues.append(make_issue("WAF_LEGACY_RULES"))
        else:
            c.issues.append(make_issue("WAF_NO_POLICY"))

    no_policy = any(i.code == "WAF_NO_POLICY" for i in c.issues)
    disabled = any(i.code == "WAF_POLICY_DISABLED" for i in c.issues)
    if not no_policy:
        missing, ignored, alert = [], [], []
        for core, name in CORE_RULES.items():
            act = (rules.get(core) or {}).get("action")
            if not act:
                missing.append(name)
            elif act in BLOCKING_ACTIONS:
                c.got += 0 if disabled else 8
            elif act == "ALERT":
                alert.append(name)
                c.got += 4
            else:
                ignored.append(name)
        if missing:
            c.issues.append(make_issue("WAF_RULE_MISSING", ", ".join(missing)))
        if ignored and not disabled:
            c.issues.append(make_issue("WAF_RULE_IGNORED", ", ".join(ignored)))
        if alert:
            c.issues.append(make_issue("WAF_RULE_ALERT", ", ".join(alert)))

    backdoor = legacy.get("api.threats.backdoor")
    backdoor_action = None
    if backdoor:
        c.max += 4
        backdoor_action = V1_ACTIONS.get(backdoor.get("action"), str(backdoor.get("action") or "").upper())
        if backdoor_action in BLOCKING_ACTIONS:
            c.got += 4
        else:
            c.got += 2 if backdoor_action == "ALERT" else 0
            c.issues.append(make_issue("WAF_BACKDOOR_WEAK", ACTION_LABELS.get(backdoor_action, backdoor_action)))

    if not no_policy:
        broad = [e for e in exceptions if e["broad"]]
        c.max += 4
        c.got += max(0, 4 - 2 * len(broad))
        if broad:
            c.issues.append(make_issue("WAF_BROAD_EXCEPTION", ", ".join(
                f"{e['rule']} {e['type']} {','.join(e['values'][:2]) or '(any)'}" for e in broad[:3])))
        undocumented = [e for e in exceptions if not e["comment"]]
        if undocumented:
            c.issues.append(make_issue("WAF_EXCEPTION_NO_COMMENT", f"{len(undocumented)} of {len(exceptions)}"))
        if len(exceptions) > 20:
            c.issues.append(make_issue("WAF_MANY_EXCEPTIONS", str(len(exceptions))))
    if data_leak and data_leak not in BLOCKING_ACTIONS:
        c.issues.append(make_issue("WAF_DATA_LEAK_OFF", ACTION_LABELS.get(data_leak, data_leak)))

    c.data = {"policy": policy_info, "legacy": not waf and bool(rules),
              "rules": [{"rule": name, "action": (rules.get(core) or {}).get("action"),
                         "label": ACTION_LABELS.get((rules.get(core) or {}).get("action"), "Not set"),
                         "source": (rules.get(core) or {}).get("source", ""),
                         "exceptions": (rules.get(core) or {}).get("exceptions", 0)} for core, name in CORE_RULES.items()],
              "backdoor": ACTION_LABELS.get(backdoor_action, backdoor_action) if backdoor else None,
              "data_leak": ACTION_LABELS.get(data_leak, data_leak) if data_leak else None,
              "exceptions": exceptions[:60], "exception_count": len(exceptions)}
    c.status = _status_from(c.issues)
    return c


def check_allowlist(site: dict, policies: List[dict]) -> CheckResult:
    c = CheckResult(max=0)
    ips: List[Tuple[str, str]] = []
    urls: List[Tuple[str, str]] = []
    blocked = {"countries": set(), "continents": set(), "ips": 0, "urls": 0}
    for p in policies:
        ptype = p.get("policyType")
        if p.get("enabled") is False:
            continue
        for s in p.get("policySettings") or []:
            data = s.get("data") or {}
            act = str(s.get("settingsAction") or "").upper()
            if ptype == "WHITELIST" or act == "ALLOW":
                for ip in data.get("ips") or []:
                    ips.append((str(ip), f"policy '{p.get('name')}'"))
                for u in data.get("urls") or []:
                    urls.append((f"{u.get('pattern', '')} {u.get('url', '')}".strip() if isinstance(u, dict) else str(u),
                                 f"policy '{p.get('name')}'"))
            elif ptype == "ACL" and act == "BLOCK":
                geo = data.get("geo") or {}
                blocked["countries"] |= set(geo.get("countries") or [])
                blocked["continents"] |= set(geo.get("continents") or [])
                blocked["ips"] += len(data.get("ips") or [])
                blocked["urls"] += len(data.get("urls") or [])
    acls = _legacy_acls(site)
    for ip in (acls.get("api.acl.whitelisted_ips") or {}).get("ips") or []:
        ips.append((str(ip), "legacy whitelist"))
    for rid, key in (("api.acl.blacklisted_countries", "countries"),):
        geo = (acls.get(rid) or {}).get("geo") or {}
        blocked["countries"] |= set(geo.get("countries") or [])
        blocked["continents"] |= set(geo.get("continents") or [])
    blocked["ips"] += len((acls.get("api.acl.blacklisted_ips") or {}).get("ips") or [])
    broad_ips = [f"{ip} ({src})" for ip, src in ips if _broad_cidr(ip.split("-")[0], 16, 32)]
    if broad_ips:
        c.issues.append(make_issue("ALLOW_BROAD_IP", ", ".join(broad_ips[:4])))
    broad_urls = [f"{u} ({src})" for u, src in urls if re.fullmatch(r"(PREFIX|CONTAINS)?\s*/?\*?", u.strip(), re.I)
                  or u.strip().upper().endswith(" /")]
    if broad_urls:
        c.issues.append(make_issue("ALLOW_BROAD_URL", ", ".join(broad_urls[:4])))
    if len(ips) > 50:
        c.issues.append(make_issue("ALLOW_MANY_IPS", str(len(ips))))
    c.data = {"allowed_ips": [f"{ip} ({src})" for ip, src in ips[:80]], "allowed_ip_count": len(ips),
              "allowed_urls": [f"{u} ({src})" for u, src in urls[:40]],
              "blocked_countries": sorted(blocked["countries"]), "blocked_continents": sorted(blocked["continents"]),
              "blocked_ips": blocked["ips"], "blocked_urls": blocked["urls"]}
    c.status = _status_from(c.issues)
    return c


def check_bots(site: dict) -> CheckResult:
    c = CheckResult(max=10)
    r = _legacy_rules(site).get("api.threats.bot_access_control")
    if not r:
        c.issues.append(make_issue("BOT_RULE_MISSING"))
        c.status = "missing"
        return c
    bad, suspected = _truthy(r.get("block_bad_bots")), _truthy(r.get("challenge_suspected_bots"))
    c.got = (6 if bad else 0) + (4 if suspected else 0)
    if not bad:
        c.issues.append(make_issue("BOT_BAD_NOT_BLOCKED"))
    if not suspected:
        c.issues.append(make_issue("BOT_SUSPECTED_NOT_CHALLENGED"))
    c.data = {"block_bad_bots": bad, "challenge_suspected_bots": suspected}
    c.status = _status_from(c.issues) if bad else "warning"
    return c


def traffic_profile(traffic: Optional[dict]) -> Optional[dict]:
    """Peak / p95 / average requests per second from hits_timeseries (human + bot = legitimate,
    blocked counted separately). Values are bucket averages, so short bursts are smoothed."""
    if not traffic or traffic.get("error") or not traffic.get("hits_timeseries"):
        return None
    gran_s = (traffic.get("granularity") or 0) / 1000 or None
    if not gran_s:  # default granularity: infer the bucket size from the timestamps
        for s in traffic["hits_timeseries"]:
            ts = sorted(int(p[0]) for p in s.get("data") or [] if isinstance(p, (list, tuple)) and p)
            if len(ts) > 1:
                gaps = sorted(b - a for a, b in zip(ts, ts[1:]) if b > a)
                gran_s = gaps[len(gaps) // 2] / 1000 if gaps else None
                break

    def series(kind: str, per_second: bool) -> Optional[Dict[int, float]]:
        for s in traffic["hits_timeseries"]:
            label = f"{s.get('id', '')} {s.get('name', '')}".lower()
            ps = "_ps" in label or "per second" in label or "per_second" in label
            if kind in label and ps == per_second:
                return {int(p[0]): float(p[1] or 0) for p in s.get("data") or [] if isinstance(p, (list, tuple)) and len(p) >= 2}
        return None

    parts = {}
    for kind in ("human", "bot", "blocked"):
        data = series(kind, True)
        if data is None and gran_s:
            counts = series(kind, False)
            data = {t: v / gran_s for t, v in counts.items()} if counts else None
        parts[kind] = data or {}
    stamps = sorted(set(parts["human"]) | set(parts["bot"]) | set(parts["blocked"]))
    if not stamps:
        return None
    legit = [(t, parts["human"].get(t, 0.0) + parts["bot"].get(t, 0.0)) for t in stamps]
    blocked = [parts["blocked"].get(t, 0.0) for t in stamps]
    values = sorted(v for _, v in legit)
    peak_t, peak = max(legit, key=lambda x: x[1])
    p95 = values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))]
    step = max(1, -(-len(legit) // 120))  # at most ~120 points for the chart (bucket maximum)
    chart = [[legit[i][0], round(max(v for _, v in legit[i:i + step]), 2), round(max(blocked[i:i + step]), 2)]
             for i in range(0, len(legit), step)]
    ddos_incidents = sum(int(t.get("incidents") or 0) for t in traffic.get("threats") or []
                         if "ddos" in str(t.get("id", "")).lower())
    return {"peak": round(peak, 2), "peak_at": datetime.fromtimestamp(peak_t / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "p95": round(p95, 2), "avg": round(sum(values) / len(values), 2), "blocked_peak": round(max(blocked), 2),
            "days": traffic.get("days"), "granularity_s": int(gran_s) if gran_s else None, "points": len(legit),
            "ddos_incidents": ddos_incidents, "chart": chart}


def recommend_threshold(peak: float, factor: float, floor: int, origin_max: Optional[float]) -> Tuple[int, str]:
    target = max(floor, factor * peak)
    rec = next((v for v in DDOS_THRESHOLDS if v >= target), DDOS_THRESHOLDS[-1])
    why = f"{factor:g} x peak {peak:g} rps, minimum {floor}" + (", capped at the highest value Imperva accepts" if target > DDOS_THRESHOLDS[-1] else "")
    if origin_max and rec > origin_max:
        below = [v for v in DDOS_THRESHOLDS if v <= origin_max]
        if below:
            rec = below[-1]
            why += f", limited by origin capacity {origin_max:g} rps"
    return rec, why


def check_ddos(site: dict, traffic: Optional[dict] = None, origin_max: Optional[float] = None,
               factor: float = DDOS_FACTOR, floor: int = DDOS_FLOOR) -> CheckResult:
    c = CheckResult(max=10)
    r = _legacy_rules(site).get("api.threats.ddos")
    if not r:
        c.issues.append(make_issue("DDOS_RULE_MISSING"))
        c.status = "missing"
        return c
    mode = str(r.get("activation_mode") or "").lower()
    label = r.get("activation_mode_text") or mode.rsplit(".", 1)[-1]
    try:
        threshold = int(r.get("ddos_traffic_threshold") or 0)
    except (TypeError, ValueError):
        threshold = 0
    mode_off = mode.endswith(".off") or mode == "off"
    if mode_off:
        c.issues.append(make_issue("DDOS_OFF"))
    else:
        c.got = 10
    c.data = {"mode": label, "threshold": threshold or None, "origin_max_rps": origin_max}
    profile = traffic_profile(traffic)
    if profile is None:
        if traffic is not None:
            c.issues.append(make_issue("DDOS_TRAFFIC_UNAVAILABLE", (traffic or {}).get("error")))
        elif threshold > 2000:
            c.issues.append(make_issue("DDOS_HIGH_THRESHOLD", f"{threshold} requests/s"))
    else:
        rec, why = recommend_threshold(profile["peak"], factor, floor, origin_max)
        c.data.update({"traffic": profile, "recommended": rec, "recommended_why": why})
        c.max += 5
        tuning = 5
        # Coarse buckets (a day or more) average peaks away: be stricter when comparing with the threshold.
        coarse = not profile["granularity_s"] or profile["granularity_s"] >= 86400
        low_ratio = 0.5 if coarse else DDOS_LOW_RATIO
        c.data["coarse"] = coarse
        if threshold:
            ratio = profile["peak"] / threshold
            c.data["peak_ratio"] = round(ratio * 100)
            if ratio >= low_ratio:
                tuning = 0
                c.issues.append(make_issue("DDOS_THRESHOLD_LOW", f"peak {profile['peak']:g} rps on {profile['peak_at']} UTC "
                                                                f"is {ratio:.0%} of the threshold {threshold}"
                                                                + (" (multi-day averages: real peaks are higher)" if coarse else "")
                                                                + f"; recommended {rec}"))
            elif threshold > DDOS_HIGH_RATIO * rec:
                tuning = 2
                c.issues.append(make_issue("DDOS_THRESHOLD_HIGH", f"threshold {threshold}, peak {profile['peak']:g} rps, recommended {rec}"))
            elif threshold == DDOS_DEFAULT_THRESHOLD and rec != DDOS_DEFAULT_THRESHOLD:
                tuning = 4
                c.issues.append(make_issue("DDOS_DEFAULT_THRESHOLD", f"recommended {rec} for a peak of {profile['peak']:g} rps"))
            if origin_max and threshold > origin_max:
                tuning = min(tuning, 1)
                c.issues.append(make_issue("DDOS_ABOVE_ORIGIN", f"threshold {threshold}, origin capacity {origin_max:g} rps"))
        c.got += 0 if mode_off else tuning
        if profile["ddos_incidents"]:
            c.issues.append(make_issue("DDOS_ACTIVATIONS", f"{profile['ddos_incidents']} incident(s) in {profile['days']} days"))
    c.status = _status_from(c.issues)
    return c


def check_tls(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=12)
    ssl_info = site.get("ssl") or {}
    custom = ssl_info.get("custom_certificate") or {}
    generated = ssl_info.get("generated_certificate") or {}
    origin = ssl_info.get("origin_server") or {}
    data: Dict[str, Any] = {}
    has_cert = False
    if custom and _truthy(custom.get("active", True)) and custom.get("expirationDate"):
        has_cert = True
        try:
            exp = datetime.fromtimestamp(int(custom["expirationDate"]) / 1000, timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            data.update({"certificate": "custom", "expires": exp.strftime("%Y-%m-%d"), "days_left": days})
            if days < 0:
                c.issues.append(make_issue("CERT_EXPIRED", exp.strftime("%Y-%m-%d")))
            elif days <= 30:
                c.issues.append(make_issue("CERT_EXPIRING", f"{days} days, {exp:%Y-%m-%d}"))
                c.got += 3
            else:
                c.got += 6
        except (TypeError, ValueError, OSError):
            data["certificate"] = "custom (expiry unreadable)"
        errors = [k for k in ("validityError", "chainError", "hostnameMismatchError", "revocationError") if _truthy(custom.get(k))]
        if errors:
            c.issues.append(make_issue("CERT_ERROR", ", ".join(errors)))
        else:
            c.got += 3
    elif generated:
        has_cert = True
        vstatus = str(generated.get("validation_status") or "").lower()
        data.update({"certificate": f"Imperva-generated ({generated.get('ca', 'CA')})", "validation": vstatus,
                     "san": generated.get("san")})
        if vstatus in ("done", "valid", "completed"):
            c.got += 9
        else:
            c.got += 3
            c.issues.append(make_issue("CERT_VALIDATION_PENDING", vstatus or "unknown"))
    if not has_cert:
        c.issues.append(make_issue("TLS_NOT_ENABLED"))
    if origin:
        detected = _truthy(origin.get("detected"))
        data["origin_tls"] = detected
        if detected:
            c.got += 3
        elif has_cert:
            c.issues.append(make_issue("ORIGIN_NO_TLS", origin.get("detectionStatus")))
    else:
        c.max -= 3
    if probe and probe.get("addresses"):
        c.max += 3
        data.update({"hsts": probe.get("hsts"), "redirects_https": probe.get("redirects_https"),
                     "tls10": probe.get("tls10"), "tls11": probe.get("tls11"),
                     "served_tls": (probe.get("https") or {}).get("tls_version"),
                     "served_cert_days": (probe.get("https") or {}).get("cert_days")})
        if probe.get("hsts"):
            c.got += 1
        elif has_cert:
            c.issues.append(make_issue("TLS_NO_HSTS"))
        if probe.get("redirects_https"):
            c.got += 1
        elif probe.get("http_status") is not None and has_cert:
            c.issues.append(make_issue("TLS_NO_REDIRECT", f"HTTP {probe.get('http_status')}"))
        if probe.get("tls10") or probe.get("tls11"):
            c.issues.append(make_issue("TLS_LEGACY", ", ".join(v for v, k in (("TLS 1.0", "tls10"), ("TLS 1.1", "tls11")) if probe.get(k))))
        else:
            c.got += 1
        days = (probe.get("https") or {}).get("cert_days")
        if days is not None and days <= 14:
            c.issues.append(make_issue("TLS_LIVE_CERT_EXPIRING", f"{days} days"))
    c.data = data
    c.status = _status_from(c.issues)
    return c


def check_origin(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=0)
    c.data = {"origins": site.get("ips") or []}
    if not probe:
        c.status = "na"
        c.data["note"] = "Run with --probe to test direct access to the origin"
        return c
    c.data["results"] = probe.get("origins") or []
    serves = [o for o in c.data["results"] if o.get("result") == "serves"]
    reach = [o for o in c.data["results"] if o.get("result") == "reachable"]
    if serves:
        c.issues.append(make_issue("ORIGIN_EXPOSED", ", ".join(f"{o['ip']}:{o.get('port')} HTTP {o.get('status')}" for o in serves[:3])))
    if reach:
        c.issues.append(make_issue("ORIGIN_REACHABLE", ", ".join(f"{o['ip']}:{o.get('port')}" for o in reach[:3])))
    c.status = _status_from(c.issues) if c.data["results"] else "unknown"
    return c


def score_site(r: SiteResult, checks: List[str]) -> None:
    weighted = [(cname, CHECKS[cname]) for cname in checks if CHECKS[cname] and r.checks.get(cname) and r.checks[cname].max > 0]
    total_w = sum(w for _, w in weighted)
    comps = {}
    score = 0.0
    for cname, w in weighted:
        ch = r.checks[cname]
        frac = max(0.0, min(1.0, ch.got / ch.max))
        comps[cname] = {"got": round(frac * w, 1), "max": w}
        score += frac * w
    score = 100 * score / total_w if total_w else max(0, 100 - 40 * sum(i.severity == "critical" for i in r.issues)
                                                      - 15 * sum(i.severity == "warning" for i in r.issues))
    score = int(round(score))
    cap = None
    for i in r.issues:
        limit = SCORE_CAPS.get(i.code)
        if limit is not None and score > limit and (cap is None or limit < cap[0]):
            cap = (limit, FINDINGS[i.code][2])
    if cap:
        score = cap[0]
    r.overall_score = score
    r.score_breakdown = {"components": comps, "max": total_w, "normalized": total_w != 100,
                         "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}


def evaluate_compliance(r: SiteResult, checks: List[str]) -> Dict[str, str]:
    def st(name: str):
        ch = r.checks.get(name)
        return ch.status if ch else "skipped"
    codes = {i.code for i in r.issues}
    out = {}
    waf = r.checks.get("waf")
    rules = {x["rule"]: x["action"] for x in (waf.data.get("rules") if waf else [])}
    if {"onboarding", "waf"} <= set(checks):
        ok = ("SITE_BYPASS" not in codes and "DNS_NOT_ROUTED" not in codes and "WAF_POLICY_DISABLED" not in codes
              and "WAF_NO_POLICY" not in codes and all(a in BLOCKING_ACTIONS | {"ALERT"} for a in rules.values()) and len(rules) == 4)
        out["pci_642"] = "pass" if ok else "fail"
    if "waf" in checks:
        out["owasp_block"] = "pass" if (len(rules) == 4 and all(a in BLOCKING_ACTIONS for a in rules.values())
                                        and "WAF_POLICY_DISABLED" not in codes) else "fail"
    if "ddos" in checks:
        out["ddos"] = "pass" if st("ddos") == "valid" or (st("ddos") == "warning" and "DDOS_OFF" not in codes) else "fail"
    if "tls" in checks:
        tls = r.checks.get("tls")
        out["transport"] = "pass" if tls and not any(i.severity != "info" for i in tls.issues) else "fail"
    if "origin" in checks:
        out["origin_lockdown"] = "n/a" if st("origin") in ("na", "skipped") else \
            "unknown" if st("origin") == "unknown" else ("pass" if "ORIGIN_EXPOSED" not in codes and "DNS_NOT_ROUTED" not in codes else "fail")
    if r.error:
        out = {k: ("unknown" if v == "fail" else v) for k, v in out.items()}
    return out


def tf_name(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", text).strip("_").lower()[:40] or "site"


def suggest_remediation(r: SiteResult) -> List[dict]:
    out: List[dict] = []
    sid = str(r.site_id)
    key = tf_name(r.domain)
    codes = {i.code for i in r.issues}

    def rec(title, kind, value, note=""):
        out.append({"title": title, "name": kind, "type": "Terraform" if value and value.lstrip().startswith(("resource", "#")) else "Action",
                    "value": value, "note": note})

    waf = r.checks.get("waf")
    if waf and codes & {"WAF_NO_POLICY", "WAF_RULE_MISSING", "WAF_RULE_IGNORED", "WAF_RULE_ALERT", "WAF_POLICY_DISABLED", "WAF_LEGACY_RULES"}:
        existing = (waf.data.get("policy") or {}).get("name")
        rec("Enforce the core WAF rules in blocking mode", "incapsula_policy / incapsula_policy_asset_association",
            'resource "incapsula_policy" "waf_block" {\n'
            '  name        = "WAF rules - block"\n'
            '  enabled     = true\n'
            '  policy_type = "WAF_RULES"\n'
            '  policy_settings = jsonencode([\n'
            '    { policySettingType = "SQL_INJECTION",           settingsAction = "BLOCK" },\n'
            '    { policySettingType = "CROSS_SITE_SCRIPTING",    settingsAction = "BLOCK" },\n'
            '    { policySettingType = "ILLEGAL_RESOURCE_ACCESS", settingsAction = "BLOCK" },\n'
            '    { policySettingType = "REMOTE_FILE_INCLUSION",   settingsAction = "BLOCK" },\n'
            '  ])\n}\n\n'
            f'resource "incapsula_policy_asset_association" "waf_{key}" {{\n'
            '  policy_id  = incapsula_policy.waf_block.id\n'
            f'  asset_id   = "{sid}"\n'
            '  asset_type = "WEBSITE"\n}',
            (f"Or change policy '{existing}' in place. " if existing else "") +
            "Move from Alert to Block after reviewing Security Events for false positives.")
    ddos = r.checks.get("ddos")
    if ddos and codes & {"DDOS_OFF", "DDOS_THRESHOLD_LOW", "DDOS_THRESHOLD_HIGH", "DDOS_ABOVE_ORIGIN", "DDOS_DEFAULT_THRESHOLD"}:
        recommended = ddos.data.get("recommended")
        value = recommended or ddos.data.get("threshold") or DDOS_DEFAULT_THRESHOLD
        title = "Turn DDoS protection on" if "DDOS_OFF" in codes else f"Set the DDoS threshold to {value} requests/s"
        note = (f"Recommended {recommended}: {ddos.data.get('recommended_why')}. " if recommended else
                "No traffic data: pick a threshold just above normal peak traffic. ") + \
               "Re-check after seasonal peaks (sales, campaigns) and keep it below what the origin can serve."
        rec(title, "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "ddos_{key}" {{\n  site_id                = "{sid}"\n'
            '  rule_id                = "api.threats.ddos"\n'
            '  activation_mode        = "api.threats.ddos.activation_mode.auto"\n'
            f'  ddos_traffic_threshold = "{value}"\n}}', note)
    if codes & {"BOT_BAD_NOT_BLOCKED", "BOT_SUSPECTED_NOT_CHALLENGED", "BOT_RULE_MISSING"}:
        rec("Block bad bots and challenge suspected ones", "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "bots_{key}" {{\n  site_id                   = "{sid}"\n'
            '  rule_id                   = "api.threats.bot_access_control"\n'
            '  block_bad_bots            = "true"\n'
            '  challenge_suspicious_bots = "true"\n}')
    if "WAF_BACKDOOR_WEAK" in codes:
        rec("Quarantine backdoor uploads", "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "backdoor_{key}" {{\n  site_id              = "{sid}"\n'
            '  rule_id              = "api.threats.backdoor"\n'
            '  security_rule_action = "api.threats.action.quarantine_url"\n}')
    if "SITE_BYPASS" in codes:
        rec("Take the website out of bypass", "incapsula_site",
            f'# in the incapsula_site resource of {r.domain}\nactive = "active"',
            "Bypass is often left on after an incident or a migration: confirm with the site owner first.")
    if "TLS_NO_HSTS" in codes:
        rec("Enable HSTS", "incapsula_site_ssl_settings",
            f'resource "incapsula_site_ssl_settings" "ssl_{key}" {{\n  site_id = "{sid}"\n  hsts {{\n'
            '    is_enabled           = true\n    max_age              = 31536000\n'
            '    sub_domains_included = true\n    pre_loaded           = false\n  }\n}',
            "Enable includeSubDomains only if every subdomain is served over HTTPS.")
    if "TLS_LEGACY" in codes:
        rec("Disable TLS 1.0 and 1.1", "incapsula_site_ssl_settings", "",
            "Set the inbound TLS configuration of the website to TLS 1.2 and 1.3 only (inbound_tls_settings).")
    if "ORIGIN_EXPOSED" in codes or "ORIGIN_REACHABLE" in codes:
        rec("Lock the origin to Imperva", "Origin firewall", "",
            "Allow inbound 80/443 on the origin only from the Imperva IP ranges (published by Imperva and retrievable "
            "via its IP ranges integration API), then re-run with --probe.")
    if "ALLOW_BROAD_IP" in codes or "ALLOW_BROAD_URL" in codes:
        rec("Shrink the allow-lists", "WHITELIST policy", "",
            "Every allow-listed IP or URL skips WAF inspection: replace wide ranges with the specific hosts that need it.")
    if "WAF_BROAD_EXCEPTION" in codes:
        rec("Narrow the broad WAF exceptions", "WAF Rules policy exceptions", "",
            "Scope exceptions to the exact URL and parameter, add a comment with owner and expiry date.")
    if "CERT_EXPIRED" in codes or "CERT_EXPIRING" in codes:
        rec("Renew the certificate", "incapsula_custom_certificate", "",
            "Upload the renewed certificate, or move the website to an Imperva-generated certificate with automatic renewal.")
    return out


def analyze_snapshot(snap: dict, checks: List[str], probes: Dict[str, dict], metadata: Dict[str, dict],
                     ddos_factor: float = DDOS_FACTOR, ddos_floor: int = DDOS_FLOOR
                     ) -> Tuple[List[SiteResult], List[Issue], List[dict]]:
    results: List[SiteResult] = []
    account_issues: List[Issue] = []
    policy_rows: List[dict] = []
    scan_date = snap.get("collected", "")
    for acc in snap.get("accounts", []):
        acc_policies = {p.get("id"): p for p in acc.get("policies") or []}
        usage = Counter()
        sites_without_policy = []
        for site in acc.get("sites") or []:
            sid = str(site.get("site_id"))
            applied_raw = (acc.get("asset_policies") or {}).get(sid)
            policies = _enrich_policies(applied_raw, acc_policies)
            for p in policies:
                usage[p.get("id")] += 1
            r = SiteResult(site_id=int(site.get("site_id") or 0), domain=str(site.get("domain") or site.get("display_name") or sid).lower(),
                           account_id=acc.get("account_id"), account_name=acc.get("name") or "",
                           status_text=str(site.get("status") or ""), active=str(site.get("active") or ""), scan_date=scan_date)
            meta = metadata.get(sid) or metadata.get(r.domain) or {}
            r.tier, r.owner, r.bu, r.tags = meta.get("tier", "medium"), meta.get("owner", ""), meta.get("bu", ""), list(meta.get("tags", []))
            r.policies = [{"id": p.get("id"), "name": p.get("name"), "type": p.get("policyType"),
                           "enabled": p.get("enabled") is not False} for p in policies]
            if applied_raw == [] or (applied_raw is not None and not policies):
                sites_without_policy.append(r.domain)
            probe = probes.get(sid)
            r.probed = probe is not None
            builders = {"onboarding": lambda: check_onboarding(site, probe), "waf": lambda: check_waf(site, policies),
                        "allowlist": lambda: check_allowlist(site, policies), "bots": lambda: check_bots(site),
                        "ddos": lambda: check_ddos(site, (acc.get("traffic") or {}).get(sid), meta.get("max_rps"),
                                                   ddos_factor, ddos_floor),
                        "tls": lambda: check_tls(site, probe),
                        "origin": lambda: check_origin(site, probe)}
            for cname in checks:
                try:
                    r.checks[cname] = builders[cname]()
                except Exception as e:  # never lose a site because of unexpected data
                    r.checks[cname] = CheckResult(status="unknown", issues=[make_issue("API_ERROR", f"{cname}: {type(e).__name__}: {e}")])
            problem = (acc.get("site_errors") or {}).get(sid)
            r.issues = [i for cname in checks for i in r.checks[cname].issues]
            if problem:
                r.error = problem
                r.issues.append(make_issue("API_ERROR", problem))
            r.issues.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
            r.profile = ("bypass" if r.active.lower() == "bypass" else
                         "error" if r.error else
                         "onboarding" if r.status_text.lower().replace("-", "_") != "fully_configured" else "protected")
            score_site(r, checks)
            r.compliance = evaluate_compliance(r, checks)
            r.remediation = suggest_remediation(r)
            crit = sum(1 for i in r.issues if i.severity == "critical")
            r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
            results.append(r)

        # account-level hygiene
        waf_policies = [p for p in acc_policies.values() if p.get("policyType") == "WAF_RULES"]
        if waf_policies and not any(p.get("isMarkedAsDefault") or p.get("defaultPolicyConfig") for p in waf_policies):
            account_issues.append(make_issue("ACCOUNT_NO_DEFAULT_WAF", f"account {acc.get('account_id')}"))
        disabled = [str(p.get("name")) for p in acc_policies.values() if p.get("enabled") is False]
        if disabled:
            account_issues.append(make_issue("ACCOUNT_DISABLED_POLICIES", ", ".join(disabled[:5]) + (" ..." if len(disabled) > 5 else "")))
        unused = [str(p.get("name")) for p in acc_policies.values()
                  if (p.get("numberOfAssets") == 0 if p.get("numberOfAssets") is not None else usage[p.get("id")] == 0)]
        if unused:
            account_issues.append(make_issue("ACCOUNT_UNUSED_POLICIES", f"{len(unused)}: " + ", ".join(unused[:5])))
        if sites_without_policy:
            account_issues.append(make_issue("ACCOUNT_SITES_WITHOUT_POLICY", f"{len(sites_without_policy)}: " + ", ".join(sites_without_policy[:5])))
        for p in acc_policies.values():
            settings = p.get("policySettings") or []
            summary = ", ".join(f"{CORE_RULES.get(s.get('policySettingType'), s.get('policySettingType'))} "
                                f"{ACTION_LABELS.get(str(s.get('settingsAction') or '').upper(), s.get('settingsAction'))}"
                                for s in settings[:6])
            policy_rows.append({"id": p.get("id"), "name": p.get("name"), "type": p.get("policyType"),
                                "enabled": p.get("enabled") is not False,
                                "default": bool(p.get("isMarkedAsDefault") or p.get("defaultPolicyConfig")),
                                "assets": p.get("numberOfAssets") if p.get("numberOfAssets") is not None else usage[p.get("id")],
                                "in_scan": usage[p.get("id")], "settings": summary,
                                "exceptions": sum(len(s.get("policyDataExceptions") or []) for s in settings),
                                "modified": str(p.get("lastModified") or "")[:10], "modified_by": p.get("lastUserModified") or "",
                                "account": acc.get("account_id")})
    for e in snap.get("errors") or []:
        account_issues.append(make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}"))
    seen, unique = set(), []
    for i in account_issues:  # sub-accounts that inherit the parent's policies report the same items
        if (i.code, i.message) not in seen:
            seen.add((i.code, i.message))
            unique.append(i)
    account_issues = sorted(unique, key=lambda i: SEVERITY_RANK.get(i.severity, 9))
    seen_p, rows = set(), []
    for p in policy_rows:
        if p["id"] not in seen_p:
            seen_p.add(p["id"])
            rows.append(p)
    policy_rows = rows
    return results, account_issues, policy_rows


# ---------------------------------------------------------------------------
# Baseline, metadata, exports
# ---------------------------------------------------------------------------

def compute_diff(results: List[SiteResult], baseline_path: str) -> dict:
    with open(baseline_path, encoding="utf-8") as f:
        raw = json.load(f)
    items = raw.get("results", raw) if isinstance(raw, dict) else raw
    base = {str(d.get("site_id") or d.get("domain")): d for d in items if isinstance(d, dict)}
    summary = {"baseline": os.path.basename(baseline_path), "baseline_date": max((str(d.get("scan_date", "")) for d in base.values()), default=""),
               "improved": 0, "worsened": 0, "unchanged": 0, "new_domains": [], "removed_domains": [], "new_critical": 0}
    seen = set()
    for r in results:
        key = str(r.site_id)
        seen.add(key)
        b = base.get(key)
        if b is None:
            r.change = {"new": True, "changed": True, "score_delta": None, "status_changes": [], "new_issues": [], "resolved_issues": []}
            summary["new_domains"].append(r.domain)
            continue
        delta = r.overall_score - int(b.get("overall_score") or 0)
        changes = []
        for cname, ch in r.checks.items():
            before = ((b.get("checks") or {}).get(cname) or {}).get("status")
            if before and before != ch.status and "skipped" not in (before, ch.status):
                changes.append({"check": cname, "from": before, "to": ch.status})
        now = {i.code for i in r.issues}
        old = {i.get("code") for i in b.get("issues") or []}
        new_i, res_i = sorted(now - old), sorted(old - now)
        summary["new_critical"] += len({i.code for i in r.issues if i.severity == "critical"} & set(new_i))
        r.change = {"new": False, "changed": bool(delta or changes or new_i or res_i), "score_delta": delta,
                    "previous_score": b.get("overall_score"), "status_changes": changes, "new_issues": new_i, "resolved_issues": res_i}
        summary["improved" if delta > 0 else "worsened" if delta < 0 else "unchanged"] += 1
    summary["removed_domains"] = sorted(str(base[k].get("domain", k)) for k in set(base) - seen)
    return summary


def load_metadata(path: str) -> Dict[str, dict]:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0], delimiters=",;\t")
    except (csv.Error, IndexError):
        dialect = csv.excel
    out: Dict[str, dict] = {}
    for row in csv.DictReader(io.StringIO(text), dialect=dialect):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        key = row.get("site_id") or row.get("domain") or row.get("dominio") or ""
        if not key:
            continue
        try:
            max_rps = float(row.get("max_rps") or row.get("origin_max_rps") or 0) or None
        except ValueError:
            max_rps = None
        out[key.lower()] = {"max_rps": max_rps,
                            "tier": TIER_ALIASES.get(row.get("tier", row.get("criticality", "")).lower(), "medium"),
                            "owner": row.get("owner", row.get("referente", "")), "bu": row.get("bu", row.get("business_unit", "")),
                            "tags": [t.strip() for t in re.split(r"[|,;]", row.get("tags", "")) if t.strip()]}
    return out




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



# ---------------------------------------------------------------------------
# HTML report: self-contained application (no CDN, no web fonts, no network) - shared with MailGuard DNS
# ---------------------------------------------------------------------------

REPORT_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #0e1116; --panel: #151a21; --panel-2: #1a2029; --raised: #1f2632; --hover: #1d2430; --line: #242b36; --line-2: #333c4a;
  --text: #e6e9ef; --muted: #8f99a9; --faint: #687283; --accent: #8b95ff; --accent-strong: #a9b0ff; --accent-ink: #0b0e2a;
  --accent-soft: rgba(139, 149, 255, .14);
  --pass: #009e73; --pass-ink: #ffffff; --pass-text: #3cc79d;
  --warn: #e69f00; --warn-ink: #1d1400; --warn-text: #f0b43a;
  --fail: #d55e00; --fail-ink: #ffffff; --fail-text: #ff8a4c;
  --info: #56b4e9; --info-text: #7cc6ef;
  --null: #0072b2; --null-ink: #ffffff; --null-text: #5aa8d6;
  --dns: #cc79a7; --dns-ink: #1f0b16; --dns-text: #df9cc1;
  --none: #3a4352; --none-ink: #c9d0da; --none-text: #9aa4b2;
  --na: #222934; --na-ink: #6a7484;
  --shadow: 0 18px 48px rgba(0, 0, 0, .45), 0 2px 8px rgba(0, 0, 0, .3);
  --r-lg: 12px; --r: 8px; --r-sm: 5px;
  --font: "Inter", "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, monospace;
  --side-w: 236px; --top-h: 58px;
}
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f4f5f8; --panel: #ffffff; --panel-2: #f8f9fb; --raised: #ffffff; --hover: #f1f3f7; --line: #e3e6ec; --line-2: #ccd3dc;
  --text: #121821; --muted: #566273; --faint: #7d8796; --accent: #4b55d6; --accent-strong: #3640c2; --accent-ink: #ffffff;
  --accent-soft: rgba(75, 85, 214, .10);
  --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --info-text: #1f6f9e; --null-text: #005d91;
  --dns-text: #9b4a77; --none: #ccd3dc; --none-ink: #2d3644; --none-text: #566273; --na: #eceff4; --na-ink: #7d8796;
  --shadow: 0 18px 44px rgba(16, 24, 40, .14), 0 2px 6px rgba(16, 24, 40, .06);
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    color-scheme: light;
    --bg: #f4f5f8; --panel: #ffffff; --panel-2: #f8f9fb; --raised: #ffffff; --hover: #f1f3f7; --line: #e3e6ec; --line-2: #ccd3dc;
    --text: #121821; --muted: #566273; --faint: #7d8796; --accent: #4b55d6; --accent-strong: #3640c2; --accent-ink: #ffffff;
    --accent-soft: rgba(75, 85, 214, .10);
    --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --info-text: #1f6f9e; --null-text: #005d91;
    --dns-text: #9b4a77; --none: #ccd3dc; --none-ink: #2d3644; --none-text: #566273; --na: #eceff4; --na-ink: #7d8796;
    --shadow: 0 18px 44px rgba(16, 24, 40, .14), 0 2px 6px rgba(16, 24, 40, .06);
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 var(--font); font-feature-settings: "cv11", "ss01"; }
body.locked { overflow: hidden; }
a { color: var(--accent); }
code, pre, .mono { font-family: var(--mono); font-size: 12.5px; }
h1, h2, h3, h4 { margin: 0; line-height: 1.25; font-weight: 600; letter-spacing: -.005em; }
p { margin: 0; }
button, input, select { font: inherit; color: inherit; }
button { cursor: pointer; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
.num { font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); } .faint { color: var(--faint); } .nowrap { white-space: nowrap; }
.ico { flex: none; display: block; }
.skip { position: absolute; left: 8px; top: -40px; z-index: 100; background: var(--accent); color: var(--accent-ink); border: 0; padding: 8px 12px; border-radius: var(--r); }
.skip:focus { top: 8px; }

/* ---------- application frame ---------- */
.app { display: grid; grid-template-columns: var(--side-w) minmax(0, 1fr); min-height: 100vh; }
.side { position: sticky; top: 0; height: 100vh; border-right: 1px solid var(--line); background: var(--panel); display: flex; flex-direction: column; overflow-y: auto; }
.brand { display: flex; gap: 10px; align-items: center; padding: 16px 18px 14px; }
.brand-mark { width: 30px; height: 30px; border-radius: 8px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent); }
.brand b { display: block; font-size: 14px; }
.brand small { display: block; color: var(--faint); font-size: 11.5px; }
.posture { margin: 4px 12px 10px; padding: 12px; border: 1px solid var(--line); border-radius: var(--r); display: flex; gap: 12px; align-items: center; background: var(--panel-2); }
.posture .letter { font-size: 30px; font-weight: 700; line-height: 1; width: 34px; text-align: center; }
.posture span { display: block; font-size: 12px; color: var(--muted); line-height: 1.35; }
.posture b { font-size: 13px; }
.nav { display: flex; flex-direction: column; gap: 1px; padding: 6px 10px; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: var(--r); border: 0; background: none; color: var(--muted); text-align: left; width: 100%; }
.nav-item:hover { background: var(--hover); color: var(--text); }
.nav-item[aria-current="page"] { background: var(--accent-soft); color: var(--text); }
.nav-item[aria-current="page"] .ico { color: var(--accent); }
.nav-item .count { margin-left: auto; font-size: 12px; color: var(--faint); font-variant-numeric: tabular-nums; }
.side-foot { margin-top: auto; padding: 10px; border-top: 1px solid var(--line); display: grid; gap: 1px; }
.main { min-width: 0; display: flex; flex-direction: column; }
.topbar { position: sticky; top: 0; z-index: 20; height: var(--top-h); display: flex; align-items: center; gap: 12px; padding: 0 28px;
          border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--bg) 86%, transparent); backdrop-filter: blur(10px); }
.topbar h1 { font-size: 16px; }
.topbar .sub { color: var(--muted); font-size: 13px; }
.topbar .spacer { flex: 1; }
.cmdk { display: flex; align-items: center; gap: 10px; width: 340px; max-width: 40vw; padding: 7px 10px; border: 1px solid var(--line-2); border-radius: var(--r); background: var(--panel); color: var(--faint); }
.cmdk:hover { border-color: var(--accent); color: var(--muted); }
.cmdk .lbl { flex: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kbd { font-family: var(--font); font-size: 11px; border: 1px solid var(--line-2); border-bottom-width: 2px; border-radius: 4px; padding: 0 5px; color: var(--muted); background: var(--panel-2); white-space: nowrap; }
.content { padding: 24px 28px 64px; width: 100%; max-width: 1480px; }
.content:focus { outline: none; }

/* ---------- controls ---------- */
.btn { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--line-2); background: var(--panel); border-radius: var(--r); padding: 6px 12px; line-height: 1.3; white-space: nowrap; }
.btn:hover { background: var(--hover); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.btn.primary:hover { background: var(--accent-strong); }
.btn.ghost { border-color: transparent; background: none; color: var(--muted); }
.btn.ghost:hover { background: var(--hover); color: var(--text); }
.btn.icon { padding: 6px; }
.btn.small { padding: 3px 9px; font-size: 12.5px; }
.btn[aria-pressed="true"] { background: var(--accent-soft); border-color: var(--accent); color: var(--text); }
.btn:disabled { opacity: .4; cursor: default; }
.btn .badge-n { background: var(--accent); color: var(--accent-ink); border-radius: 999px; font-size: 11px; padding: 0 6px; font-weight: 600; }
.seg { display: inline-flex; border: 1px solid var(--line-2); border-radius: var(--r); padding: 2px; background: var(--panel); }
.seg button { border: 0; background: none; padding: 4px 10px; border-radius: 6px; color: var(--muted); }
.seg button[aria-pressed="true"] { background: var(--raised); color: var(--text); box-shadow: 0 0 0 1px var(--line-2); }
input[type="search"], input[type="number"], select { background: var(--panel); border: 1px solid var(--line-2); border-radius: var(--r); padding: 6px 9px; min-width: 0; color: var(--text); }
input[type="number"] { width: 76px; }
input[type="checkbox"] { accent-color: var(--accent); width: 15px; height: 15px; margin: 0; vertical-align: -2px; }
.search-box { position: relative; display: flex; align-items: center; }
.search-box .ico { position: absolute; left: 9px; color: var(--faint); pointer-events: none; }
.search-box input { padding-left: 32px; width: 300px; max-width: 100%; }
label.field { display: grid; gap: 4px; font-size: 12.5px; color: var(--muted); }
label.check { display: inline-flex; gap: 8px; align-items: center; font-size: 13px; color: var(--text); }
.link { background: none; border: 0; padding: 0; color: var(--accent); text-align: left; }
.link:hover { text-decoration: underline; }

/* ---------- cards ---------- */
.card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r-lg); min-width: 0; }
.card > header { display: flex; align-items: baseline; gap: 10px; padding: 14px 18px 0; }
.card > header h2 { font-size: 14px; }
.card > header p { color: var(--faint); font-size: 12.5px; }
.card > header .act { margin-left: auto; }
.card .body { padding: 14px 18px 16px; }
.section-title { display: flex; align-items: baseline; gap: 12px; margin: 0 0 14px; }
.section-title h2 { font-size: 18px; }
.section-title p { color: var(--muted); font-size: 13px; }

/* ---------- overview ---------- */
.ov-top { display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 16px; margin-bottom: 16px; }
.grade-card { padding: 20px 22px; display: grid; grid-template-columns: auto 1fr; gap: 6px 18px; align-items: center; }
.grade-card .letter { font-size: 92px; font-weight: 700; line-height: .85; letter-spacing: -3px; grid-row: span 3; }
.g-A, .g-B { color: var(--pass-text); } .g-C { color: var(--warn-text); } .g-D, .g-F { color: var(--fail-text); }
.grade-card .lbl { color: var(--muted); font-size: 12.5px; }
.grade-card .avg { font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; }
.grade-card .avg small { font-size: 13px; color: var(--muted); font-weight: 400; }
.delta-up { color: var(--pass-text); } .delta-down { color: var(--fail-text); }
.kpi-card { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }
.kpi { border: 0; background: none; text-align: left; padding: 18px 20px; border-right: 1px solid var(--line); color: inherit; }
.kpi:last-child { border-right: 0; }
.kpi:hover { background: var(--hover); }
.kpi b { display: block; font-size: 28px; font-weight: 650; line-height: 1.1; font-variant-numeric: tabular-nums; }
.kpi span { font-size: 12.5px; color: var(--muted); }
.kpi.k-pass b { color: var(--pass-text); } .kpi.k-warn b { color: var(--warn-text); } .kpi.k-fail b { color: var(--fail-text); }
.ov-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.ov-grid .span2 { grid-column: span 2; } .ov-grid .span3 { grid-column: 1 / -1; }
.cov { display: grid; gap: 9px; }
.cov-row { display: grid; grid-template-columns: 92px minmax(0, 1fr) 48px; gap: 12px; align-items: center; font-size: 13px; }
.cov-bar { display: flex; height: 14px; border-radius: 4px; overflow: hidden; gap: 2px; }
.cov-bar button { border: 0; padding: 0; min-width: 4px; height: 100%; }
.cov-bar button:hover { filter: brightness(1.18); }
.cov-num { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 12px; color: var(--muted); margin-top: 12px; }
.legend span { display: inline-flex; gap: 6px; align-items: center; }
.dot { width: 10px; height: 10px; border-radius: 3px; display: inline-block; flex: none; }
.hist { width: 100%; height: auto; display: block; }
.hist rect.hbar { cursor: pointer; }
.hist rect.hbar:hover, .hist rect.hbar:focus { filter: brightness(1.2); outline: none; }
.hist line { stroke: var(--line-2); }
.hist text { fill: var(--faint); font-size: 10px; font-family: var(--font); }
.hist text.v { fill: var(--muted); font-size: 10.5px; }
.rm { display: grid; gap: 4px; font-size: 12.5px; }
.rm-row { display: grid; grid-template-columns: 70px repeat(3, minmax(0, 1fr)); gap: 4px; align-items: center; }
.rm-head { color: var(--faint); text-align: center; }
.rm-cell { border: 0; border-radius: 6px; height: 40px; font-weight: 650; font-size: 14px; font-variant-numeric: tabular-nums; color: var(--text); }
.rm-cell.zero { color: var(--faint); font-weight: 400; }
.rows { list-style: none; margin: 0; padding: 0; }
.rows li + li { border-top: 1px solid var(--line); }
.rows .r-btn { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 2px 12px; width: 100%; text-align: left; border: 0; background: none; padding: 9px 4px; color: inherit; border-radius: 6px; }
.rows .r-btn:hover { background: var(--hover); }
.rows .r-main { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rows .r-sub { grid-column: 1; font-size: 12.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rows .r-val { grid-row: span 2; align-self: center; text-align: right; }
.bar-row { display: grid; grid-template-columns: minmax(110px, 1fr) 1.6fr 4.6em; gap: 10px; align-items: center; font-size: 13px; padding: 4px 0; }
.bar-row > :last-child { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
button.bar-row { border: 0; background: none; width: 100%; text-align: left; color: inherit; border-radius: 6px; }
button.bar-row:hover { background: var(--hover); }
.bar { height: 8px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 5px; overflow: hidden; display: flex; }
.bar i { display: block; height: 100%; }
.b-pass { background: var(--pass); } .b-warn { background: var(--warn); } .b-fail { background: var(--fail); } .b-dns { background: var(--dns); } .b-acc { background: var(--accent); }
.stat-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
.stat { border: 1px solid var(--line); border-radius: var(--r); padding: 10px 12px; background: var(--panel-2); text-align: left; color: inherit; }
button.stat:hover { border-color: var(--line-2); background: var(--hover); }
.stat b { display: block; font-size: 20px; font-variant-numeric: tabular-nums; }
.stat span { font-size: 12px; color: var(--muted); }

/* ---------- status ---------- */
.pill { display: inline-flex; align-items: center; gap: 5px; border-radius: var(--r-sm); padding: 1px 8px; font-size: 12.5px; font-weight: 600; white-space: nowrap; border: 1px solid transparent; line-height: 1.55; }
.pill .sym { font-weight: 700; }
.pill .d { font-weight: 400; opacity: .85; }
.s-pass { background: color-mix(in srgb, var(--pass) 16%, transparent); color: var(--pass-text); border-color: color-mix(in srgb, var(--pass) 38%, transparent); }
.s-warn { background: color-mix(in srgb, var(--warn) 16%, transparent); color: var(--warn-text); border-color: color-mix(in srgb, var(--warn) 38%, transparent); }
.s-fail { background: color-mix(in srgb, var(--fail) 16%, transparent); color: var(--fail-text); border-color: color-mix(in srgb, var(--fail) 38%, transparent); }
.s-null { background: color-mix(in srgb, var(--null) 18%, transparent); color: var(--null-text); border-color: color-mix(in srgb, var(--null) 42%, transparent); }
.s-dns { background: color-mix(in srgb, var(--dns) 16%, transparent); color: var(--dns-text); border-color: color-mix(in srgb, var(--dns) 38%, transparent); }
.s-none { background: color-mix(in srgb, var(--none) 42%, transparent); color: var(--none-text); }
.s-na { background: transparent; color: var(--faint); border-color: var(--line); }
.c-pass { background: var(--pass); color: var(--pass-ink); } .c-warn { background: var(--warn); color: var(--warn-ink); }
.c-fail { background: var(--fail); color: var(--fail-ink); } .c-null { background: var(--null); color: var(--null-ink); }
.c-dns { background: var(--dns); color: var(--dns-ink); } .c-none { background: var(--none); color: var(--none-ink); }
.c-na { background: var(--na); color: var(--na-ink); }
.sq { display: inline-grid; place-items: center; width: 24px; height: 22px; border-radius: 5px; font-weight: 700; font-size: 12px; }
.sev { display: inline-block; width: 8px; height: 8px; border-radius: 2px; flex: none; }
.sev-critical { background: var(--fail); } .sev-warning { background: var(--warn); } .sev-info { background: var(--info); }
.score { font-weight: 700; font-variant-numeric: tabular-nums; }
.score.hi { color: var(--pass-text); } .score.mid { color: var(--warn-text); } .score.lo { color: var(--fail-text); }
.tag { display: inline-block; font-size: 11.5px; border: 1px solid var(--line-2); border-radius: 999px; padding: 0 8px; color: var(--muted); white-space: nowrap; }
.tier-critical { color: var(--fail-text); border-color: color-mix(in srgb, var(--fail) 45%, transparent); }
.tier-high { color: var(--warn-text); border-color: color-mix(in srgb, var(--warn) 45%, transparent); }

/* ---------- domains ---------- */
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.toolbar .spacer { flex: 1; }
.presets { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
.preset { border: 1px solid var(--line-2); background: var(--panel); border-radius: 999px; padding: 3px 12px; font-size: 12.5px; color: var(--muted); }
.preset:hover { color: var(--text); border-color: var(--accent); }
.preset[aria-pressed="true"] { background: var(--accent-soft); border-color: var(--accent); color: var(--text); }
.preset .n { color: var(--faint); margin-left: 4px; font-variant-numeric: tabular-nums; }
.filter-panel { border: 1px solid var(--line); background: var(--panel); border-radius: var(--r-lg); padding: 14px; margin-bottom: 10px;
                display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }
.filter-panel .range { display: flex; gap: 6px; align-items: center; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 10px; min-height: 26px; font-size: 13px; color: var(--muted); }
.chip { display: inline-flex; align-items: center; gap: 4px; border: 1px solid var(--line-2); background: var(--panel); border-radius: 999px; padding: 1px 4px 1px 10px; font-size: 12.5px; color: var(--text); }
.chip button { border: 0; background: none; color: var(--muted); padding: 0 4px; border-radius: 999px; }
.chip button:hover { color: var(--text); background: var(--hover); }
.selbar { display: flex; align-items: center; gap: 10px; padding: 8px 12px; margin-bottom: 10px; border-radius: var(--r); background: var(--accent-soft); border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent); font-size: 13px; }
.menu { position: relative; }
.menu-pop { position: absolute; right: 0; top: calc(100% + 6px); z-index: 30; min-width: 220px; background: var(--raised); border: 1px solid var(--line-2); border-radius: var(--r); box-shadow: var(--shadow); padding: 6px; display: grid; gap: 1px; }
.menu-pop .mi { display: flex; gap: 10px; align-items: center; border: 0; background: none; text-align: left; padding: 7px 10px; border-radius: 6px; color: var(--text); width: 100%; }
.menu-pop .mi:hover { background: var(--hover); }
.menu-pop .mi small { margin-left: auto; color: var(--faint); }
.menu-pop .sep { height: 1px; background: var(--line); margin: 4px 0; }
.menu-pop label.check { padding: 5px 10px; }
.grid-wrap { border: 1px solid var(--line); border-radius: var(--r-lg); background: var(--panel); overflow: auto; max-height: calc(100vh - var(--top-h) - 230px); min-height: 260px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; }
table.grid th, table.grid td { padding: 10px 12px; text-align: left; vertical-align: middle; border-bottom: 1px solid var(--line); background: var(--panel); }
table.grid.compact th, table.grid.compact td { padding: 5px 10px; }
table.grid thead th { position: sticky; top: 0; z-index: 2; font-size: 12px; font-weight: 600; color: var(--muted); background: var(--panel-2); white-space: nowrap; }
table.grid .sticky { position: sticky; left: 0; z-index: 1; }
table.grid thead .sticky { z-index: 3; }
table.grid tbody tr { cursor: pointer; }
table.grid tbody tr:hover td { background: var(--hover); }
table.grid tbody tr.cursor td { box-shadow: inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
table.grid tbody tr.cursor td:first-child { box-shadow: inset 2px 0 0 var(--accent), inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
table.grid tbody tr.active td { background: var(--accent-soft); }
table.grid tbody tr:last-child td { border-bottom: 0; }
th .sort { background: none; border: 0; padding: 0; color: inherit; font-weight: 600; display: inline-flex; gap: 4px; align-items: center; }
th .sort:hover { color: var(--text); }
th[aria-sort="ascending"] .sort::after { content: "\2191"; color: var(--accent); }
th[aria-sort="descending"] .sort::after { content: "\2193"; color: var(--accent); }
th.c, td.c { text-align: center; } th.r, td.r { text-align: right; }
.dom { border: 0; background: none; padding: 0; color: var(--text); font-weight: 600; text-align: left; word-break: break-all; }
.dom:hover { color: var(--accent); }
.dom-sub { font-size: 12px; color: var(--faint); margin-top: 1px; }
.cell-domain { display: flex; gap: 12px; align-items: flex-start; min-width: 220px; }
.scorecell { display: flex; align-items: center; gap: 8px; justify-content: flex-end; }
.mini { width: 42px; height: 4px; border-radius: 2px; background: var(--panel-2); overflow: hidden; border: 1px solid var(--line); }
.mini i { display: block; height: 100%; }
.mini .hi { background: var(--pass); } .mini .mid { background: var(--warn); } .mini .lo { background: var(--fail); }
.counts { display: inline-flex; gap: 6px; }
.cnt { font-size: 12px; font-weight: 600; border-radius: 4px; padding: 0 6px; font-variant-numeric: tabular-nums; }
.cnt.crit { color: var(--fail-text); background: color-mix(in srgb, var(--fail) 16%, transparent); }
.cnt.warn { color: var(--warn-text); background: color-mix(in srgb, var(--warn) 16%, transparent); }
.heat { display: grid; gap: 3px; padding: 12px; min-width: calc(220px + var(--cols) * 40px + 60px); }
.heat-row { display: grid; grid-template-columns: minmax(180px, 260px) repeat(var(--cols), minmax(34px, 1fr)) 52px; gap: 3px; align-items: center; }
.heat-head { position: sticky; top: 0; z-index: 2; background: var(--panel); padding: 4px 0 6px; }
.heat-head div { font-size: 11.5px; color: var(--muted); text-align: center; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.heat-head div:first-child { text-align: left; }
.heat-row .dom { font-weight: 500; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cell { height: 30px; border: 0; border-radius: 4px; font-weight: 700; font-size: 13px; padding: 0; }
.cell:hover { filter: brightness(1.15); }
.heat-row .score { text-align: right; padding-right: 6px; }
.pager { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; padding: 12px 2px; font-size: 13px; color: var(--muted); }
.pager .pages { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
.pager .btn[aria-current="page"] { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.empty { padding: 48px 24px; text-align: center; color: var(--muted); }
.empty b { display: block; color: var(--text); font-size: 15px; margin-bottom: 6px; }

/* ---------- findings ---------- */
.flist { display: grid; gap: 8px; }
.finding { border: 1px solid var(--line); border-radius: var(--r); background: var(--panel); }
.finding > summary { list-style: none; display: grid; grid-template-columns: auto minmax(0, 1fr) 140px 64px auto; gap: 14px; align-items: center; padding: 12px 14px; cursor: pointer; }
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary:hover { background: var(--hover); border-radius: var(--r); }
.finding[open] > summary { border-bottom: 1px solid var(--line); border-radius: var(--r) var(--r) 0 0; }
.finding .ttl b { display: block; }
.finding .ttl span { font-size: 12.5px; color: var(--muted); }
.finding .chev { color: var(--faint); transition: transform .15s; }
.finding[open] .chev { transform: rotate(90deg); }
.finding .fbody { padding: 12px 14px 14px 36px; display: grid; gap: 10px; font-size: 13px; }
.dlist { display: flex; flex-wrap: wrap; gap: 6px; }
.dlist button { border: 1px solid var(--line-2); background: var(--panel-2); border-radius: 6px; padding: 2px 8px; font-size: 12.5px; color: var(--text); }
.dlist button:hover { border-color: var(--accent); }
.fw { display: flex; flex-wrap: wrap; gap: 6px; }

/* ---------- drawer ---------- */
.scrim { position: fixed; inset: 0; background: rgba(4, 7, 12, .55); z-index: 40; }
:root[data-theme="light"] .scrim { background: rgba(16, 24, 40, .28); }
.drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(880px, 100vw); z-index: 41; background: var(--bg); border-left: 1px solid var(--line-2);
          box-shadow: var(--shadow); display: flex; flex-direction: column; }
.dr-head { background: var(--panel); border-bottom: 1px solid var(--line); padding: 10px 24px 0; }
.dr-nav { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12.5px; }
.dr-nav .spacer { flex: 1; }
.dr-id { display: flex; gap: 16px; align-items: center; padding: 12px 0 14px; }
.dr-id h2 { font-size: 22px; word-break: break-all; }
.dr-id .meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; align-items: center; }
.dr-id .meta .t { font-size: 12.5px; color: var(--faint); }
.ring { flex: none; }
.ring .ring-bg { fill: none; stroke: var(--line-2); stroke-width: 6; }
.ring .ring-fg { fill: none; stroke-width: 6; stroke-linecap: round; }
.ring.hi .ring-fg { stroke: var(--pass); } .ring.mid .ring-fg { stroke: var(--warn); } .ring.lo .ring-fg { stroke: var(--fail); }
.ring text { fill: var(--text); font-size: 17px; font-weight: 700; font-family: var(--font); }
.dr-tabs { display: flex; gap: 2px; overflow-x: auto; margin: 0 -6px; }
.dr-tabs button { border: 0; background: none; padding: 9px 12px; color: var(--muted); border-bottom: 2px solid transparent; white-space: nowrap; }
.dr-tabs button:hover { color: var(--text); }
.dr-tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.dr-tabs .n { font-size: 11.5px; color: var(--faint); margin-left: 4px; }
.dr-body { overflow-y: auto; padding: 20px 24px 40px; display: grid; gap: 16px; align-content: start; }
.dr-cols { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }
.dr-sec { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r-lg); padding: 16px 18px; min-width: 0; }
.dr-sec > h3 { font-size: 14px; margin-bottom: 12px; display: flex; gap: 8px; align-items: center; }
.dr-sec > h3 .act { margin-left: auto; }
.dr-sec table th, .dr-sec table td { padding: 7px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
.dr-sec table thead th { color: var(--muted); font-size: 12px; font-weight: 600; }
.dr-sec table tbody tr:last-child td { border-bottom: 0; }
.dr-print-title { display: none; }
.ctl-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(178px, 1fr)); gap: 8px; }
.ctl { display: grid; justify-items: start; gap: 6px; min-width: 0; font-size: 12.5px; color: var(--muted) !important; border: 1px solid var(--line); background: var(--panel-2); border-radius: var(--r); padding: 8px 10px; text-align: left; color: var(--text); }
.ctl:hover { border-color: var(--line-2); background: var(--hover); }
.ctl .pill { max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
.kv { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px 20px; font-size: 13px; }
.kv div span { display: block; color: var(--muted); font-size: 12px; }
.kv div b { font-weight: 600; word-break: break-word; }
pre.record { background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--r); padding: 10px 12px; margin: 0 0 12px; white-space: pre-wrap; word-break: break-all; }
.issue { display: grid; grid-template-columns: 14px minmax(0, 1fr); gap: 2px 10px; padding: 11px 0; border-bottom: 1px solid var(--line); }
.issue:last-child { border-bottom: 0; }
.issue .sev { margin-top: 6px; }
.issue .msg { font-weight: 600; word-break: break-word; }
.issue .proto { font-size: 12px; color: var(--faint); }
.issue .rec { grid-column: 2; font-size: 13px; color: var(--muted); }
.issue .fw { grid-column: 2; margin-top: 4px; }
.fix { padding: 14px 0; border-bottom: 1px solid var(--line); }
.fix:first-child { padding-top: 0; } .fix:last-child { border-bottom: 0; padding-bottom: 0; }
.fix h4 { font-size: 14px; margin-bottom: 6px; }
.fix .where { font-size: 12.5px; color: var(--muted); margin-bottom: 6px; word-break: break-all; }
.fix .rowx { display: flex; gap: 8px; align-items: flex-start; }
.fix pre.record { flex: 1; margin: 0; }
.fix .note { font-size: 12.5px; color: var(--muted); margin-top: 6px; }
.tree { font-family: var(--mono); font-size: 12px; line-height: 1.75; }
details.more > summary { cursor: pointer; color: var(--muted); font-size: 13px; margin-top: 12px; }
.note-box { border-left: 3px solid var(--warn); background: color-mix(in srgb, var(--warn) 9%, transparent); padding: 10px 14px; border-radius: 0 var(--r) var(--r) 0; font-size: 13px; }
.sub { font-size: 12px; color: var(--muted); }

/* ---------- overlays ---------- */
.overlay { position: fixed; inset: 0; z-index: 60; background: rgba(4, 7, 12, .5); display: flex; align-items: flex-start; justify-content: center; padding-top: 12vh; }
:root[data-theme="light"] .overlay { background: rgba(16, 24, 40, .25); }
.dialog { width: min(640px, 92vw); max-height: 72vh; background: var(--raised); border: 1px solid var(--line-2); border-radius: var(--r-lg); box-shadow: var(--shadow); display: flex; flex-direction: column; overflow: hidden; }
.dialog > header { display: flex; align-items: center; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.dialog > header h2 { font-size: 15px; flex: 1; }
.dialog .dbody { padding: 14px 16px 18px; overflow-y: auto; font-size: 13.5px; }
.pal-input { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--line); color: var(--faint); }
.pal-input input { flex: 1; border: 0; background: none; font-size: 15px; color: var(--text); outline: none; padding: 4px 0; }
.pal-list { list-style: none; margin: 0; padding: 6px; overflow-y: auto; }
.pal-group { font-size: 11.5px; color: var(--faint); padding: 8px 10px 4px; }
.pal-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: 6px; cursor: pointer; }
.pal-item[aria-selected="true"] { background: var(--accent-soft); }
.pal-item .ptitle { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pal-item .phint { font-size: 12px; color: var(--faint); }
.pal-foot { display: flex; gap: 14px; padding: 8px 16px; border-top: 1px solid var(--line); font-size: 12px; color: var(--faint); }
.keys { width: 100%; border-collapse: collapse; }
.keys td { padding: 6px 4px; border-bottom: 1px solid var(--line); }
.keys td:first-child { width: 140px; }
.toasts { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); z-index: 80; display: grid; gap: 8px; }
.toast { background: var(--raised); border: 1px solid var(--line-2); box-shadow: var(--shadow); border-radius: var(--r); padding: 9px 14px; font-size: 13px; }

/* ---------- responsive ---------- */
@media (max-width: 1180px) {
  .ov-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-grid .span2 { grid-column: 1 / -1; }
  .cmdk { min-width: 0; }
  .cmdk .lbl { display: none; }
  .cmdk { width: auto; }
}
@media (max-width: 860px) {
  .app { grid-template-columns: 1fr; }
  .side { position: static; height: auto; flex-direction: row; align-items: center; overflow-x: auto; border-right: 0; border-bottom: 1px solid var(--line); }
  .brand { padding: 10px 12px; } .brand small, .posture, .side-foot { display: none; }
  .nav { flex-direction: row; padding: 6px; }
  .nav-item { width: auto; white-space: nowrap; }
  .nav-item .count { display: none; }
  .topbar { padding: 0 14px; position: static; }
  .topbar .sub { display: none; }
  .content { padding: 16px 14px 48px; }
  .ov-top, .ov-grid, .dr-cols { grid-template-columns: 1fr; }
  .kpi { border-right: 0; border-bottom: 1px solid var(--line); }
  .search-box input { width: 100%; }
  .finding > summary { grid-template-columns: auto minmax(0, 1fr) auto; }
  .finding > summary .fbar, .finding > summary .chev { display: none; }
  .drawer { width: 100vw; }
  .dr-head, .dr-body { padding-left: 14px; padding-right: 14px; }
  .grid-wrap { max-height: none; }
}
@media (prefers-reduced-motion: no-preference) {
  .drawer.enter { animation: slide-in .18s ease-out; }
  .scrim.enter, .overlay { animation: fade-in .15s ease-out; }
  .toast { animation: fade-in .15s ease-out; }
  @keyframes slide-in { from { transform: translateX(32px); } to { transform: none; } }
  @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
}

/* ---------- print ---------- */
@media print {
  :root, :root[data-theme] { color-scheme: light; --bg: #fff; --panel: #fff; --panel-2: #f3f5f8; --raised: #fff; --hover: #fff; --line: #d9dee5; --line-2: #c3cad4;
    --text: #111; --muted: #444; --faint: #666; --pass-text: #00785a; --warn-text: #8f6100; --fail-text: #b34700; --null-text: #005d91;
    --dns-text: #9b4a77; --none: #d4d9e0; --none-ink: #222; --na: #eef1f4; --na-ink: #666; --accent: #3640c2; --accent-soft: #eef0ff; --shadow: none; }
  body { font-size: 11px; }
  .side, .topbar, .toolbar, .presets, .filter-panel, .chips, .selbar, .pager, .no-print, .toasts, #overlay-root, .copy, .dr-nav, .dr-tabs { display: none !important; }
  .app { display: block; }
  .content { padding: 0; max-width: none; }
  .card, .dr-sec, .finding { break-inside: avoid; }
  .grid-wrap { max-height: none; overflow: visible; border: 0; }
  table.grid thead th { position: static; }
  .c-pass, .c-warn, .c-fail, .c-null, .c-dns, .c-none, .c-na, .bar i, .cov-bar button, .rm-cell { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body.print-drawer .app, body.print-drawer .scrim { display: none !important; }
  body.print-drawer .drawer { position: static; width: auto; box-shadow: none; border: 0; }
  body.print-drawer .dr-body { overflow: visible; padding: 0; }
  body.print-drawer .dr-head { padding: 0; border: 0; }
  body.print-drawer .dr-print-title { display: block; font-size: 15px; margin: 6px 0 2px; }
  body.print-exec #drawer-root { display: none !important; }
  body.print-exec .print-head { display: block !important; }
}
.ddos-chart { width: 100%; height: auto; display: block; margin-top: 14px; }
.ddos-chart .grid { stroke: var(--line); } .ddos-chart .ax { fill: var(--faint); font-size: 10px; font-family: var(--font); }
.ddos-chart .area { fill: color-mix(in srgb, var(--accent) 16%, transparent); } .ddos-chart .ln { fill: none; stroke: var(--accent); stroke-width: 1.6; }
.ddos-chart .blk { fill: none; stroke: var(--dns); stroke-width: 1; stroke-dasharray: 3 3; }
.ddos-chart .thr { stroke: var(--fail); stroke-width: 1.5; stroke-dasharray: 6 4; } .ddos-chart .thr-t { fill: var(--fail-text); font-size: 11px; font-weight: 600; font-family: var(--font); }
.ddos-chart .rec { stroke: var(--pass); stroke-width: 1.5; stroke-dasharray: 2 3; } .ddos-chart .rec-t { fill: var(--pass-text); font-size: 11px; font-weight: 600; font-family: var(--font); }
.print-head { display: none; margin-bottom: 16px; }
.print-head h1 { font-size: 20px; }
"""


REPORT_JS = r"""
(function () {
'use strict';
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const R = D.results, CHECKS = D.checks, L = D.labels, M = D.meta || {};
const FIND = D.findings, FW = D.frameworks, COMP = D.compliance;
const ACC = D.account_issues || [], POL = D.policies || [];
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ESC[c]);
const $ = (s, r) => (r || document).querySelector(s);
const SEV = {critical: 0, warning: 1, info: 2};
const ST = {
  valid: ['pass', '\u2713', 'Pass'], warning: ['warn', '!', 'Warning'], partial: ['warn', '\u25D0', 'Partial'],
  error: ['fail', '\u2715', 'Fail'], misconfigured: ['fail', '\u2715', 'Misconfigured'], bogus: ['fail', '\u2715', 'Bogus'],
  missing: ['none', '\u2013', 'Missing'], null: ['null', '\u2205', 'Null'], na: ['na', '\u00B7', 'Not tested'],
  dns_error: ['dns', '?', 'Read error'], unknown: ['dns', '?', 'Unknown'], skipped: ['na', '\u00B7', 'Skipped']
};
const ST_ORDER = ['valid', 'partial', 'warning', 'misconfigured', 'error', 'bogus', 'missing', 'null', 'na', 'dns_error', 'unknown', 'skipped'];
const st = s => ST[s] || ST.missing;
const scoreCls = n => n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const gradeOf = n => n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 65 ? 'C' : n >= 50 ? 'D' : 'F';
const pct = (n, t) => t ? Math.round(100 * n / t) : 0;
const TIER_ORDER = ['critical', 'high', 'medium', 'low'];
const tierW = t => D.tiers[t] || 2;
const BLOCKING = ['BLOCK', 'BLOCK_REQUEST', 'BLOCK_USER', 'BLOCK_IP', 'QUARANTINE'];
const SHORT = {onboarding: 'Onboard', allowlist: 'Allow'};
const cd = (r, c) => ((r.checks || {})[c] || {}).data || {};
const DETAIL = {
  onboarding: r => r.active === 'bypass' ? 'bypass' : '',
  waf: r => { const rs = cd(r, 'waf').rules || []; return rs.length ? `${rs.filter(x => BLOCKING.includes(x.action)).length}/4 blocking` : ''; },
  allowlist: r => { const n = cd(r, 'allowlist').allowed_ip_count; return n ? `${n} IPs` : ''; },
  ddos: r => { const d = cd(r, 'ddos'); return d.recommended && d.threshold && d.recommended !== d.threshold ? `${d.threshold} \u2192 ${d.recommended} rps` : d.threshold ? `${d.mode || ''} ${d.threshold} rps`.trim() : (d.mode || ''); },
  tls: r => { const d = cd(r, 'tls'); return d.days_left !== undefined && d.days_left !== null ? `${d.days_left} days` : ''; }
};
R.forEach((r, i) => {
  r._i = i;
  r._crit = r.issues.filter(x => x.severity === 'critical').length;
  r._warn = r.issues.filter(x => x.severity === 'warning').length;
  r._codes = new Set(r.issues.map(x => x.code));
  r._st = c => ((r.checks || {})[c] || {}).status || 'skipped';
  r._acc = r.account_name || String(r.account_id || '');
});
const hasMeta = R.some(r => r.owner || r.bu || (r.tags && r.tags.length)) || new Set(R.map(r => r.tier)).size > 1 || new Set(R.map(r => r.account_id)).size > 1;
const diff = D.diff;
const hasReports = false, hasLook = false, hasAuth = CHECKS.includes('waf');
const vis = (r, c) => CHECKS.includes(c) && r._st(c) !== 'skipped';
const uniq = a => [...new Set(a.filter(Boolean))].sort();
const domSub = r => esc([`#${r.site_id}`, r._acc, r.owner, r.bu].filter(Boolean).join(', '));

/* ================= icons ================= */
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  alert: '<path d="M12 3.5 2.5 20h19L12 3.5zM12 10v4.5M12 17.2h.01"/>',
  diff: '<path d="M7 4v16M3.5 7.5 7 4l3.5 3.5M17 20V4M13.5 16.5 17 20l3.5-3.5"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
  copy: '<path d="M9 9h11v11H9zM5 15H4V4h11v1"/>',
  mail: '<path d="M3 5h18v14H3zM3 6l9 7 9-7"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>', left: '<path d="m15 6-6 6 6 6"/>', right: '<path d="m9 6 6 6-6 6"/>',
  link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
  filter: '<path d="M3 5h18l-7 8.5V19l-4 2v-7.5L3 5z"/>', columns: '<path d="M3 4h18v16H3zM9 4v16M15 4v16"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', key: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  chev: '<path d="m9 6 6 6-6 6"/>', arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>'
};
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;

/* ================= small renderers ================= */
const pill = (s, extra) => { const m = st(s); return `<span class="pill s-${m[0]}"><span class="sym" aria-hidden="true">${m[1]}</span>${esc(m[2])}${extra ? ` <span class="d">${esc(extra)}</span>` : ''}</span>`; };
const sq = (s, label) => { const m = st(s); return `<span class="sq c-${m[0]}" title="${esc(label + ': ' + m[2])}" aria-label="${esc(label + ': ' + m[2])}">${m[1]}</span>`; };
const tierTag = t => `<span class="tag tier-${esc(t)}">${esc(t)}</span>`;
const scoreHtml = n => `<span class="score ${scoreCls(n)}">${n}</span>`;
function deltaHtml(r) {
  if (!r.change) return '<span class="faint">\u2013</span>';
  if (r.change.new) return '<span class="tag">new</span>';
  const d = r.change.score_delta;
  return d > 0 ? `<span class="delta-up num">+${d}</span>` : d < 0 ? `<span class="delta-down num">${d}</span>` : '<span class="faint num">0</span>';
}
function ring(score, size) {
  const rad = 26, c = 2 * Math.PI * rad, off = c * (1 - score / 100);
  return `<svg class="ring ${scoreCls(score)}" width="${size || 64}" height="${size || 64}" viewBox="0 0 64 64" aria-label="Score ${score}"><circle cx="32" cy="32" r="${rad}" class="ring-bg"/><circle cx="32" cy="32" r="${rad}" class="ring-fg" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 32 32)"/><text x="32" y="38" text-anchor="middle">${score}</text></svg>`;
}
function weighted(rows, fn) {
  const w = rows.reduce((a, r) => a + tierW(r.tier), 0);
  return w ? rows.reduce((a, r) => a + fn(r) * tierW(r.tier), 0) / w : 0;
}
const findingTitle = c => (FIND[c] || [0, 0, c])[2];

/* ================= preferences & state ================= */
const PREF_KEY = 'wafguard-prefs-v1';
const P = {density: 'comfortable', view: 'table', size: 50, hidden: [], theme: null};
try { Object.assign(P, JSON.parse(localStorage.getItem(PREF_KEY) || '{}')); } catch (e) { /* storage unavailable */ }
const savePrefs = () => { try { localStorage.setItem(PREF_KEY, JSON.stringify(P)); } catch (e) { /* ignore */ } };
const FKEYS = ['q', 'score', 'smin', 'smax', 'tier', 'owner', 'bu', 'tag', 'finding', 'changed', 'comp', 'profile', 'account', 'policy'];
const blank = () => ({q: '', f: {}, score: '', smin: '', smax: '', tier: '', owner: '', bu: '', tag: '', finding: '', changed: '', comp: '', profile: '', account: '', policy: ''});
const S = Object.assign({route: 'overview', sort: {k: 'priority', d: -1}, page: 1, open: null, dtab: 'overview', sel: new Set(),
  groupBy: new Set(R.map(r => r.account_id)).size > 1 ? 'account' : hasMeta ? 'owner' : 'tier', cursor: -1, menu: null, filtersOpen: false, fsev: '', fq: '', lmx: false, overlay: null}, blank());

/* ================= routing (state in the URL hash: shareable views) ================= */
const ROUTES = [
  {id: 'overview', label: 'Overview', icon: 'grid', show: () => true},
  {id: 'domains', label: 'Websites', icon: 'list', show: () => true, count: () => R.length},
  {id: 'findings', label: 'Findings', icon: 'alert', show: () => true, count: () => findingCounts().length},
  {id: 'policies', label: 'Policies', icon: 'shield', show: () => POL.length > 0, count: () => POL.length},
  {id: 'changes', label: 'Changes', icon: 'diff', show: () => !!diff, count: () => R.filter(r => r.change && r.change.changed).length},
  {id: 'groups', label: 'Groups', icon: 'layers', show: () => hasMeta}
];
function toHash() {
  const p = new URLSearchParams();
  FKEYS.forEach(k => { if (S[k]) p.set(k, S[k]); });
  Object.keys(S.f).forEach(c => { if (S.f[c]) p.set('c.' + c, S.f[c]); });
  if (S.sort.k !== 'priority' || S.sort.d !== -1) p.set('sort', (S.sort.d < 0 ? '-' : '') + S.sort.k);
  if (S.page > 1) p.set('page', S.page);
  if (S.open !== null) { p.set('d', R[S.open].domain); if (S.dtab !== 'overview') p.set('t', S.dtab); }
  const qs = p.toString();
  return '#/' + S.route + (qs ? '?' + qs : '');
}
function fromHash() {
  const raw = decodeURIComponent(location.hash.replace(/^#\/?/, ''));
  if (raw.startsWith('domain=')) {  // links from v3.0 reports
    const r0 = R.find(x => x.domain === raw.slice(7));
    Object.assign(S, blank(), {route: 'domains', open: r0 ? r0._i : null, dtab: 'overview'});
    return;
  }
  const qi = location.hash.indexOf('?');
  const route = location.hash.replace(/^#\/?/, '').split('?')[0];
  const p = new URLSearchParams(qi >= 0 ? location.hash.slice(qi + 1) : '');
  Object.assign(S, blank());
  S.route = ROUTES.some(x => x.id === route && x.show()) ? route : 'overview';
  FKEYS.forEach(k => { if (p.has(k)) S[k] = p.get(k); });
  p.forEach((v, k) => { if (k.startsWith('c.') && CHECKS.includes(k.slice(2))) S.f[k.slice(2)] = v; });
  const so = p.get('sort');
  S.sort = so ? {k: so.replace(/^-/, ''), d: so.startsWith('-') ? -1 : 1} : {k: 'priority', d: -1};
  S.page = Math.max(1, +p.get('page') || 1);
  const d = p.get('d'), r = d ? R.find(x => x.domain === d) : null;
  S.open = r ? r._i : null;
  S.dtab = p.get('t') || 'overview';
}
function go(changes, push) {
  Object.assign(S, changes);
  const h = toHash();
  if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h);
  render();
}
window.addEventListener('popstate', () => { fromHash(); render(); });

/* ================= filtering ================= */
function matches(r) {
  const q = S.q.trim().toLowerCase();
  if (q && !(r.domain.includes(q) || String(r.site_id).includes(q) || r._acc.toLowerCase().includes(q) || (r.owner || '').toLowerCase().includes(q) || (r.bu || '').toLowerCase().includes(q)
      || (r.tags || []).some(t => t.toLowerCase().includes(q)))) return false;
  for (const c of CHECKS) if (S.f[c] && r._st(c) !== S.f[c]) return false;
  const sc = r.overall_score;
  if (S.score && !({hi: sc >= 80, mid: sc >= 50 && sc < 80, lo: sc < 50})[S.score]) return false;
  if (S.smin !== '' && sc < +S.smin) return false;
  if (S.smax !== '' && sc > +S.smax) return false;
  if (S.tier && r.tier !== S.tier) return false;
  if (S.owner && r.owner !== S.owner) return false;
  if (S.bu && r.bu !== S.bu) return false;
  if (S.tag && !(r.tags || []).includes(S.tag)) return false;
  if (S.finding && !r._codes.has(S.finding)) return false;
  if (S.changed && !(r.change && r.change.changed)) return false;
  if (S.profile && r.profile !== S.profile) return false;
  if (S.account && r._acc !== S.account) return false;
  if (S.policy && !(r.policies || []).some(p => String(p.id) === String(S.policy))) return false;
  if (S.comp) { const [k, v] = S.comp.split(':'); if ((r.compliance || {})[k] !== v) return false; }
  return true;
}
const SORTERS = {
  domain: r => r.domain, score: r => r.overall_score, priority: r => r.priority, tier: r => tierW(r.tier),
  findings: r => r._crit * 1000 + r._warn, delta: r => (r.change && r.change.score_delta) || 0
};
let _cache = {key: null, list: null};
function list() {
  const key = toHash().replace(/[?&](d|t|page)=[^&]*/g, '');
  if (_cache.key === key) return _cache.list;
  const a = R.filter(matches);
  const fn = SORTERS[S.sort.k] || SORTERS.priority, d = S.sort.d;
  a.sort((x, y) => { const p = fn(x), q = fn(y); return (p < q ? -1 : p > q ? 1 : 0) * d || x.domain.localeCompare(y.domain); });
  _cache = {key, list: a};
  return a;
}
function chips() {
  const out = [];
  if (S.q) out.push(['q', `Search "${S.q}"`]);
  CHECKS.forEach(c => { if (S.f[c]) out.push(['c.' + c, `${L[c]}: ${st(S.f[c])[2]}`]); });
  if (S.score) out.push(['score', {hi: 'Score 80 and above', mid: 'Score 50 to 79', lo: 'Score under 50'}[S.score]]);
  if (S.smin !== '' || S.smax !== '') out.push(['range', `Score ${S.smin || 0} to ${S.smax || 100}`]);
  if (S.tier) out.push(['tier', `Tier ${S.tier}`]);
  if (S.owner) out.push(['owner', `Owner ${S.owner}`]);
  if (S.bu) out.push(['bu', `Unit ${S.bu}`]);
  if (S.tag) out.push(['tag', `Tag ${S.tag}`]);
  if (S.finding) out.push(['finding', findingTitle(S.finding)]);
  if (S.changed) out.push(['changed', 'Changed since baseline']);
  if (S.profile) out.push(['profile', {bypass: 'Bypass mode', onboarding: 'Onboarding incomplete', error: 'Partially read', protected: 'Protected'}[S.profile] || S.profile]);
  if (S.account) out.push(['account', `Account ${S.account}`]);
  if (S.policy) { const p = POL.find(x => String(x.id) === String(S.policy)); out.push(['policy', `Policy ${p ? p.name : S.policy}`]); }
  if (S.comp) { const [k, v] = S.comp.split(':'); out.push(['comp', `${(COMP[k] || [k])[0]}: ${v}`]); }
  return out;
}
function clearChip(key) {
  if (key.startsWith('c.')) delete S.f[key.slice(2)];
  else if (key === 'range') { S.smin = ''; S.smax = ''; }
  else S[key] = '';
}
const filterTo = extra => go(Object.assign(blank(), {route: 'domains', open: null, page: 1, cursor: -1}, extra));

/* ================= sidebar & top bar ================= */
function side() {
  const live = R.filter(r => r.profile !== 'nonexistent');
  const avg = weighted(live, r => r.overall_score), g = gradeOf(avg);
  const visible = ROUTES.filter(x => x.show());
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>WAFGuard</b><small>Imperva WAF posture</small></div></div>
    <button class="posture" data-route="overview" title="Portfolio grade"><span class="letter g-${g}">${g}</span>
      <span><b class="num">${avg.toFixed(0)}/100</b><br>${R.length} websites</span></button>
    <nav class="nav" aria-label="Sections">${visible.map((x, k) => {
      const c = x.count ? x.count() : null;
      return `<button class="nav-item" data-route="${x.id}"${S.route === x.id ? ' aria-current="page"' : ''} title="${esc(x.label)} (${k + 1})">
        ${icon(x.icon)}<span>${esc(x.label)}</span>${c !== null ? `<span class="count">${c}</span>` : ''}</button>`; }).join('')}</nav>
    <div class="side-foot">
      <button class="nav-item" data-action="about">${icon('info')}<span>About this scan</span></button>
      <button class="nav-item" data-action="keys">${icon('key')}<span>Keyboard shortcuts</span><span class="count"><span class="kbd">?</span></span></button>
      <button class="nav-item" data-action="theme">${icon(isDark() ? 'sun' : 'moon')}<span>${isDark() ? 'Light theme' : 'Dark theme'}</span></button>
    </div>`;
}
function topbar() {
  const r = ROUTES.find(x => x.id === S.route) || ROUTES[0];
  let sub = '';
  if (S.route === 'domains') { const n = list().length; sub = n === R.length ? `${R.length} websites` : `${n} of ${R.length} websites`; }
  else if (S.route === 'overview') sub = `Scanned ${esc(M.generated || '')}`;
  return `<h1>${esc(r.label)}</h1><span class="sub">${sub}</span><span class="spacer"></span>
    <button class="cmdk" data-action="palette" aria-label="Search websites, findings and actions">${icon('search')}<span class="lbl">Search websites, findings, actions</span><span class="kbd">Ctrl K</span></button>
    <button class="btn" data-action="print-exec" title="Executive summary as PDF">${icon('print')}<span>Executive PDF</span></button>`;
}

/* ================= overview ================= */
function overview() {
  const live = R.filter(r => r.profile !== 'nonexistent');
  const avg = weighted(live, r => r.overall_score), g = gradeOf(avg);
  let delta = null;
  if (diff) {
    const same = live.filter(r => r.change && !r.change.new && r.change.previous_score !== null && r.change.previous_score !== undefined);
    if (same.length) delta = weighted(same, r => r.overall_score) - weighted(same, r => +r.change.previous_score);
  }
  const n = R.length;
  const hi = R.filter(r => r.overall_score >= 80).length, mid = R.filter(r => r.overall_score >= 50 && r.overall_score < 80).length;
  const nonmail = R.filter(r => r.profile === 'bypass').length, unreach = R.filter(r => r.profile === 'onboarding').length;
  const kpi = (val, label, cls, attrs) => `<button class="kpi ${cls || ''}" ${attrs}><b>${val}</b><span>${esc(label)}</span></button>`;
  let h = `<div class="print-head"><h1>Imperva WAF posture</h1><p class="muted">${R.length} websites, assessed ${esc(M.generated || '')}</p></div>
  <div class="ov-top">
    <section class="card grade-card" aria-label="Portfolio grade">
      <div class="letter g-${g}">${g}</div><div class="lbl">Portfolio grade</div>
      <div class="avg">${avg.toFixed(0)}<small>/100</small></div>
      <div class="lbl">${hasMeta ? 'Average weighted by tier' : 'Average score'}${delta !== null ? `, <span class="${delta >= 0 ? 'delta-up' : 'delta-down'}">${delta >= 0 ? '+' : ''}${delta.toFixed(1)} since baseline</span>` : ''}</div>
    </section>
    <section class="card kpi-card">
      ${kpi(n, 'websites assessed', '', 'data-route="domains"')}
      ${kpi(hi, 'well protected, 80+', 'k-pass', 'data-filter="score" data-value="hi"')}
      ${kpi(mid, 'need attention, 50 to 79', 'k-warn', 'data-filter="score" data-value="mid"')}
      ${kpi(n - hi - mid, 'critical risk, under 50', 'k-fail', 'data-filter="score" data-value="lo"')}
      ${nonmail ? kpi(nonmail, 'in bypass mode', 'k-fail', 'data-filter="profile" data-value="bypass"') : ''}
      ${unreach ? kpi(unreach, 'onboarding incomplete', '', 'data-filter="profile" data-value="onboarding"') : ''}
    </section>
  </div><div class="ov-grid">`;
  // control coverage
  const present = new Set();
  const rows = CHECKS.map(c => {
    const counts = {};
    R.forEach(r => { const s = r._st(c); counts[s] = (counts[s] || 0) + 1; });
    const segs = ST_ORDER.filter(s => counts[s]).map(s => { present.add(st(s)[0]); const lbl = `${L[c]}: ${st(s)[2]}, ${counts[s]} domain${counts[s] === 1 ? '' : 's'}`;
      return `<button class="c-${st(s)[0]}" style="flex:${counts[s]}" data-check="${c}" data-status="${s}" title="${esc(lbl)}" aria-label="${esc(lbl)}"></button>`; }).join('');
    return `<div class="cov-row"><span>${esc(L[c])}</span><div class="cov-bar">${segs}</div><span class="cov-num">${pct(counts.valid || 0, n)}%</span></div>`;
  }).join('');
  const LEG = {pass: 'Pass', warn: 'Warning or partial', fail: 'Fail', none: 'Missing', null: 'Null', na: 'Not tested', dns: 'Read error'};
  h += `<section class="card span2"><header><h2>Control coverage</h2><p>Share of websites passing each control. Select a segment to list those websites.</p></header>
    <div class="body"><div class="cov">${rows}</div><div class="legend">${Object.keys(LEG).filter(k => present.has(k)).map(k => `<span><i class="dot c-${k}"></i>${LEG[k]}</span>`).join('')}</div></div></section>`;
  // distribution
  const bins = Array(10).fill(0);
  live.forEach(r => { bins[Math.min(9, Math.floor(r.overall_score / 10))]++; });
  const max = Math.max(1, ...bins);
  const bars = bins.map((v, i) => { const hh = Math.max(v ? 3 : 0, Math.round(104 * v / max)), x = 14 + i * 37, y = 118 - hh;
    const col = i >= 8 ? 'var(--pass)' : i >= 5 ? 'var(--warn)' : 'var(--fail)';
    const lo = i * 10, hiB = i === 9 ? 100 : i * 10 + 9;
    return `<rect class="hbar" x="${x}" y="${y}" width="31" height="${hh}" rx="3" fill="${col}" data-smin="${lo}" data-smax="${hiB}" tabindex="0" role="button" aria-label="${v} websites scoring ${lo} to ${hiB}"><title>${v} websites, score ${lo}-${hiB}</title></rect>
      ${v ? `<text class="v" x="${x + 15.5}" y="${y - 4}" text-anchor="middle">${v}</text>` : ''}<text x="${x + 15.5}" y="134" text-anchor="middle">${lo}</text>`; }).join('');
  h += `<section class="card"><header><h2>Score distribution</h2></header><div class="body"><svg class="hist" viewBox="0 0 390 140" role="group" aria-label="Score distribution"><line x1="10" y1="118.5" x2="384" y2="118.5"/>${bars}</svg><p class="sub" style="margin-top:6px">Select a bar to list the websites in that range.</p></div></section>`;
  // fix first
  const risks = [...R].filter(r => r.priority > 0).sort((a, b) => b.priority - a.priority).slice(0, 6);
  h += `<section class="card"><header><h2>Fix first</h2><p>Highest priority</p></header><div class="body"><ul class="rows">${risks.map(r => {
    const top = r.issues.find(x => x.severity === 'critical') || r.issues[0];
    return `<li><button class="r-btn" data-open="${r._i}"><span class="r-main">${esc(r.domain)}</span><span class="r-val">${scoreHtml(r.overall_score)}</span>
      <span class="r-sub">${hasMeta ? esc(r.tier) + ' tier, ' : ''}${top ? esc(top.message) : ''}</span></button></li>`; }).join('') || '<li class="muted">Nothing urgent.</li>'}</ul></div></section>`;
  // top critical findings
  const crit = findingCounts().filter(([c]) => FIND[c] && FIND[c][0] === 'critical').slice(0, 6);
  h += `<section class="card"><header><h2>Most frequent critical findings</h2></header><div class="body"><ul class="rows">${crit.map(([c, k]) =>
    `<li><button class="r-btn" data-finding="${esc(c)}"><span class="r-main">${esc(findingTitle(c))}</span><span class="r-val num">${k}</span>
      <span class="r-sub">${esc(FIND[c][1])}, ${pct(k, n)}% of websites</span></button></li>`).join('') || '<li class="muted">No critical findings.</li>'}</ul></div></section>`;
  // risk by tier
  const tiers = TIER_ORDER.filter(t => R.some(r => r.tier === t));
  if (tiers.length > 1) {
    const bands = [['lo', 'Under 50', 'var(--fail)'], ['mid', '50 to 79', 'var(--warn)'], ['hi', '80+', 'var(--pass)']];
    const cnt = (t, b) => R.filter(r => r.tier === t && scoreCls(r.overall_score) === b).length;
    const mx = Math.max(1, ...tiers.flatMap(t => bands.map(b => cnt(t, b[0]))));
    h += `<section class="card"><header><h2>Risk by tier</h2><p>Domains by tier and score</p></header><div class="body"><div class="rm">
      <div class="rm-row"><span></span>${bands.map(b => `<span class="rm-head">${b[1]}</span>`).join('')}</div>
      ${tiers.map(t => `<div class="rm-row"><span class="tag tier-${t}" style="justify-self:start">${t}</span>${bands.map(b => { const v = cnt(t, b[0]);
        return `<button class="rm-cell${v ? '' : ' zero'}" style="background:color-mix(in srgb, ${b[2]} ${v ? 12 + Math.round(48 * v / mx) : 4}%, transparent)" data-tier="${t}" data-band="${b[0]}" aria-label="${v} ${t} tier domains scoring ${b[1]}">${v}</button>`; }).join('')}</div>`).join('')}
    </div></div></section>`;
  }
  // requirements
  const comp = Object.entries(COMP).map(([k, v]) => {
    const vals = R.map(r => (r.compliance || {})[k]).filter(x => x && x !== 'n/a');
    return {k, label: v[0], desc: v[1], pass: vals.filter(x => x === 'pass').length, fail: vals.filter(x => x === 'fail').length, total: vals.length};
  }).filter(c => c.total);
  if (comp.length) h += `<section class="card"><header><h2>Requirements met</h2><p>Select to list failing websites</p></header><div class="body">${comp.map(c =>
    `<button class="bar-row" data-comp="${c.k}:fail" title="${esc(c.desc)}"><span>${esc(c.label)}</span><span class="bar"><i class="b-pass" style="width:${pct(c.pass, c.total)}%"></i></span><span>${c.pass}/${c.total}</span></button>`).join('')}</div></section>`;
  // changes
  if (diff) h += `<section class="card${tiers.length > 1 ? '' : ' span2'}"><header><h2>Since the baseline</h2><p>${esc(diff.baseline_date || diff.baseline)}</p></header><div class="body"><div class="stat-strip">
      <button class="stat" data-route="changes"><b class="delta-up">${diff.improved}</b><span>improved</span></button>
      <button class="stat" data-route="changes"><b class="delta-down">${diff.worsened}</b><span>worsened</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_critical}</b><span>new critical findings</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_domains.length}/${diff.removed_domains.length}</b><span>domains added/removed</span></button></div></div></section>`;
  const DD = [['DDOS_THRESHOLD_LOW', 'Too low for real peaks'], ['DDOS_THRESHOLD_HIGH', 'Too high to trigger'],
    ['DDOS_ABOVE_ORIGIN', 'Above origin capacity'], ['DDOS_DEFAULT_THRESHOLD', 'Left at default 1000'], ['DDOS_OFF', 'Protection off']];
  const withData = R.filter(r => cd(r, 'ddos').recommended);
  if (CHECKS.includes('ddos') && withData.length) {
    const aligned = withData.filter(r => !DD.some(([c]) => r._codes.has(c))).length;
    h += `<section class="card"><header><h2>DDoS thresholds</h2><p>Compared with ${withData.length} sites' real traffic</p></header><div class="body"><ul class="rows">
      <li><div class="r-btn" style="cursor:default"><span class="r-main">Aligned with traffic</span><span class="r-val num score hi">${aligned}</span></div></li>
      ${DD.map(([c, l]) => { const k = R.filter(r => r._codes.has(c)).length; return k ? `<li><button class="r-btn" data-finding="${c}"><span class="r-main">${esc(l)}</span><span class="r-val num">${k}</span></button></li>` : ''; }).join('')}</ul></div></section>`;
  }
  if (ACC.length) h += `<section class="card span3"><header><h2>Account findings</h2><p>${ACC.length} item${ACC.length === 1 ? '' : 's'} affecting every website</p><span class="act"><button class="link" data-route="policies">Policies</button></span></header><div class="body">${issueList(ACC.slice(0, 6))}</div></section>`;
  return h + '</div>';
}
function findingCounts() {
  const counts = {};
  R.forEach(r => r._codes.forEach(c => { if (FIND[c]) counts[c] = (counts[c] || 0) + 1; }));
  return Object.entries(counts).sort((a, b) => SEV[FIND[a[0]][0]] - SEV[FIND[b[0]][0]] || b[1] - a[1]);
}

/* ================= domains ================= */
const COLS = () => [
  {id: 'tier', label: 'Tier', show: hasMeta, sort: 'tier', cell: r => tierTag(r.tier)},
  {id: 'score', label: 'Score', sort: 'score', cls: 'r', cell: r => `<div class="scorecell">${scoreHtml(r.overall_score)}<span class="mini"><i class="${scoreCls(r.overall_score)}" style="width:${r.overall_score}%"></i></span></div>`},
  {id: 'delta', label: 'Change', show: !!diff, sort: 'delta', cls: 'r', cell: deltaHtml},
  ...CHECKS.map(c => ({id: 'c.' + c, label: L[c], short: SHORT[c] || L[c], check: c, cls: P.density === 'compact' ? 'c' : '',
    cell: r => P.density === 'compact' ? sq(r._st(c), L[c]) : pill(r._st(c), DETAIL[c] ? DETAIL[c](r) : '')})),
  {id: 'findings', label: 'Findings', sort: 'findings', cell: r => r._crit || r._warn ? `<span class="counts">${r._crit ? `<span class="cnt crit" title="critical">${r._crit}</span>` : ''}${r._warn ? `<span class="cnt warn" title="warning">${r._warn}</span>` : ''}</span>` : '<span class="faint">None</span>'},
  {id: 'priority', label: 'Priority', sort: 'priority', cls: 'r', cell: r => `<span class="num">${r.priority}</span>`}
].filter(c => c.show !== false);
const visibleCols = () => COLS().filter(c => !P.hidden.includes(c.id));
const PRESETS = () => [
  ['all', 'All websites', {}],
  ['crit', 'Critical risk', {score: 'lo'}],
  ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
  ...(R.some(r => r.profile === 'bypass') ? [['byp', 'Bypass mode', {profile: 'bypass'}]] : []),
  ...(CHECKS.includes('origin') && R.some(r => r.probed) ? [['org', 'Origin exposed', {f: {origin: 'error'}}]] : []),
  ...(hasAuth ? [['pci', 'Fails PCI DSS 6.4.2', {comp: 'pci_642:fail'}], ['alert', 'WAF rules not blocking', {comp: 'owasp_block:fail'}]] : []),
  ...(diff ? [['chg', 'Changed', {changed: '1'}]] : [])
];
function presetActive(p) {
  const target = Object.assign(blank(), p[2]);
  return FKEYS.every(k => (S[k] || '') === (target[k] || '')) && JSON.stringify(S.f) === JSON.stringify(target.f || {});
}
function domains() {
  const all = list();
  const pages = Math.max(1, Math.ceil(all.length / P.size));
  if (S.page > pages) S.page = pages;
  const items = all.slice((S.page - 1) * P.size, S.page * P.size);
  const active = chips();
  const presetCounts = PRESETS().map(p => { const saved = {}; FKEYS.forEach(k => saved[k] = S[k]); const sf = S.f;
    Object.assign(S, blank(), p[2]); const c = R.filter(matches).length; Object.assign(S, saved); S.f = sf; return c; });
  let h = `<div class="presets" role="group" aria-label="Saved views">${PRESETS().map((p, k) =>
    `<button class="preset" data-preset="${k}" aria-pressed="${presetActive(p)}">${esc(p[1])}<span class="n">${presetCounts[k]}</span></button>`).join('')}</div>
  <div class="toolbar">
    <div class="search-box">${icon('search')}<input type="search" id="q" placeholder="Filter by website, site ID, account, owner or tag" value="${esc(S.q)}" aria-label="Filter domains"></div>
    <button class="btn" data-action="filters" aria-expanded="${S.filtersOpen}">${icon('filter')}Filters${active.length ? `<span class="badge-n">${active.length}</span>` : ''}</button>
    <span class="spacer"></span>
    <div class="seg" role="group" aria-label="Layout"><button data-view="table" aria-pressed="${P.view === 'table'}">Table</button><button data-view="heatmap" aria-pressed="${P.view === 'heatmap'}">Heatmap</button></div>
    ${P.view === 'table' ? `<div class="seg" role="group" aria-label="Density"><button data-density="comfortable" aria-pressed="${P.density === 'comfortable'}">Comfortable</button><button data-density="compact" aria-pressed="${P.density === 'compact'}">Compact</button></div>
    <div class="menu"><button class="btn" data-menu="cols" aria-expanded="${S.menu === 'cols'}">${icon('columns')}Columns</button>${S.menu === 'cols' ? `<div class="menu-pop">${COLS().map(c =>
      `<label class="check"><input type="checkbox" data-col="${c.id}"${P.hidden.includes(c.id) ? '' : ' checked'}> ${esc(c.label)}</label>`).join('')}<div class="sep"></div><button class="mi" data-action="cols-reset">Show all columns</button></div>` : ''}</div>` : ''}
    <div class="menu"><button class="btn" data-menu="export" aria-expanded="${S.menu === 'export'}">${icon('download')}Export</button>${S.menu === 'export' ? `<div class="menu-pop">
      <button class="mi" data-action="csv">Filtered websites as CSV<small>${all.length}</small></button>
      <button class="mi" data-action="json">Filtered websites as JSON<small>${all.length}</small></button>
      ${S.sel.size ? `<div class="sep"></div><button class="mi" data-action="csv-sel">Selected websites as CSV<small>${S.sel.size}</small></button>` : ''}
      <div class="sep"></div><button class="mi" data-action="copy-list">Copy website list</button><button class="mi" data-action="copy-link">Copy link to this view</button></div>` : ''}</div>
  </div>`;
  if (S.filtersOpen) h += filterPanel();
  h += `<div class="chips">${active.length ? active.map(([k, lbl]) => `<span class="chip">${esc(lbl)}<button data-chip="${esc(k)}" aria-label="Remove filter ${esc(lbl)}">${icon('x', 12)}</button></span>`).join('') + '<button class="link" data-action="clear">Clear all</button>' : `<span>${all.length} domains</span>`}</div>`;
  if (S.sel.size) h += `<div class="selbar"><b>${S.sel.size} selected</b><button class="btn small" data-action="csv-sel">Export CSV</button><button class="btn small" data-action="copy-sel">Copy domains</button><span class="spacer"></span><button class="link" data-action="sel-clear">Clear selection</button></div>`;
  if (!all.length) h += `<div class="grid-wrap"><div class="empty"><b>No website matches these filters</b><button class="btn" data-action="clear">Clear filters</button></div></div>`;
  else h += `<div class="grid-wrap" id="grid">${P.view === 'heatmap' ? heatmap(items) : table(items)}</div>`;
  return h + pager(all.length, pages);
}
function filterPanel() {
  const sel = (key, label, opts, cur, fmt) => `<label class="field">${esc(label)}<select data-k="${key}"><option value="">All</option>${opts.map(o => `<option value="${esc(o)}"${o === cur ? ' selected' : ''}>${esc(fmt ? fmt(o) : o)}</option>`).join('')}</select></label>`;
  const owners = uniq(R.map(r => r.owner)), bus = uniq(R.map(r => r.bu)), tags = uniq(R.flatMap(r => r.tags || []));
  const tiers = TIER_ORDER.filter(t => R.some(r => r.tier === t));
  const compOpts = Object.keys(COMP).flatMap(k => ['fail', 'pass'].map(v => `${k}:${v}`)).filter(o => { const [k, v] = o.split(':'); return R.some(r => (r.compliance || {})[k] === v); });
  return `<div class="filter-panel">
    ${CHECKS.map(c => `<label class="field">${esc(L[c])}<select data-f="${c}"><option value="">All</option>${uniq(R.map(r => r._st(c))).map(v => `<option value="${esc(v)}"${S.f[c] === v ? ' selected' : ''}>${esc(st(v)[2])}</option>`).join('')}</select></label>`).join('')}
    ${sel('score', 'Score band', ['hi', 'mid', 'lo'], S.score, v => ({hi: '80 and above', mid: '50 to 79', lo: 'Under 50'})[v])}
    <label class="field">Score range<span class="range"><input type="number" min="0" max="100" data-k="smin" value="${esc(S.smin)}" placeholder="0" aria-label="Minimum score"><span>to</span><input type="number" min="0" max="100" data-k="smax" value="${esc(S.smax)}" placeholder="100" aria-label="Maximum score"></span></label>
    ${tiers.length > 1 ? sel('tier', 'Tier', tiers, S.tier) : ''}${owners.length ? sel('owner', 'Owner', owners, S.owner) : ''}
    ${bus.length ? sel('bu', 'Business unit', bus, S.bu) : ''}${tags.length ? sel('tag', 'Tag', tags, S.tag) : ''}
    ${sel('finding', 'Finding', findingCounts().map(x => x[0]), S.finding, findingTitle)}
    ${compOpts.length ? sel('comp', 'Requirement', compOpts, S.comp, o => { const [k, v] = o.split(':'); return `${COMP[k][0]}: ${v}`; }) : ''}
    ${diff ? `<label class="check" style="align-self:end"><input type="checkbox" data-k="changed"${S.changed ? ' checked' : ''}> Changed since baseline</label>` : ''}
  </div>`;
}
function th(c) {
  if (!c.sort) return `<th class="${c.cls || ''}" title="${esc(c.label)}">${esc(P.density === 'compact' && c.short ? c.short : c.label)}</th>`;
  const cur = S.sort.k === c.sort ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<th class="${c.cls || ''}" aria-sort="${cur}"><button class="sort" data-sort="${c.sort}">${esc(c.label)}</button></th>`;
}
function table(items) {
  const cols = visibleCols();
  const allSel = items.length && items.every(r => S.sel.has(r._i));
  const cur = S.sort.k === 'domain' ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<table class="grid${P.density === 'compact' ? ' compact' : ''}"><thead><tr>
    <th class="sticky" aria-sort="${cur}"><div class="cell-domain"><input type="checkbox" data-selall aria-label="Select all on this page"${allSel ? ' checked' : ''}><button class="sort" data-sort="domain">Website</button></div></th>
    ${cols.map(th).join('')}</tr></thead><tbody>${items.map((r, k) => `<tr data-row="${r._i}" class="${k === S.cursor ? 'cursor ' : ''}${S.open === r._i ? 'active' : ''}">
      <td class="sticky"><div class="cell-domain"><input type="checkbox" data-sel="${r._i}" aria-label="Select ${esc(r.domain)}"${S.sel.has(r._i) ? ' checked' : ''}>
        <div><button class="dom" data-open="${r._i}">${esc(r.domain)}</button>${P.density !== 'compact' ? `<div class="dom-sub">${domSub(r)}</div>` : ''}</div></div></td>
      ${cols.map(c => `<td class="${c.cls || ''}">${c.cell(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function heatmap(items) {
  return `<div class="heat" style="--cols:${CHECKS.length}" role="table" aria-label="Security heatmap">
    <div class="heat-row heat-head" role="row"><div role="columnheader">Website</div>${CHECKS.map(c => `<div role="columnheader" title="${esc(L[c])}">${esc(SHORT[c] || L[c])}</div>`).join('')}<div role="columnheader" style="text-align:right">Score</div></div>
    ${items.map(r => `<div class="heat-row" role="row"><button class="dom" role="rowheader" data-open="${r._i}" title="${esc(r.domain)}">${esc(r.domain)}</button>
      ${CHECKS.map(c => { const s = r._st(c), m = st(s), det = DETAIL[c] ? DETAIL[c](r) : '';
        const lbl = `${r.domain}, ${L[c]}: ${m[2]}${det ? ', ' + det : ''}`;
        return `<button class="cell c-${m[0]}" role="cell" data-open="${r._i}" data-dtab="${tabFor(c)}" title="${esc(lbl)}" aria-label="${esc(lbl)}">${m[1]}</button>`; }).join('')}
      <span class="score ${scoreCls(r.overall_score)}" role="cell">${r.overall_score}</span></div>`).join('')}</div>`;
}
function pager(total, pages) {
  const cur = S.page, nums = [];
  for (let p = 1; p <= pages; p++) if (p === 1 || p === pages || Math.abs(p - cur) <= 2) nums.push(p);
  let prev = 0, out = '';
  nums.forEach(p => { if (p - prev > 1) out += '<span class="faint">\u2026</span>'; out += `<button class="btn small" data-page="${p}"${p === cur ? ' aria-current="page"' : ''}>${p}</button>`; prev = p; });
  const from = total ? (cur - 1) * P.size + 1 : 0, to = Math.min(cur * P.size, total);
  return `<nav class="pager" aria-label="Pagination"><span>Rows ${from} to ${to} of ${total}
      <select data-k="size" aria-label="Rows per page" style="margin-left:8px">${[25, 50, 100, 250, 500].map(s => `<option value="${s}"${s === P.size ? ' selected' : ''}>${s} per page</option>`).join('')}</select></span>
    ${pages > 1 ? `<div class="pages"><button class="btn small" data-page="${cur - 1}"${cur <= 1 ? ' disabled' : ''}>${icon('left', 14)}Previous</button>${out}<button class="btn small" data-page="${cur + 1}"${cur >= pages ? ' disabled' : ''}>Next${icon('right', 14)}</button></div>` : ''}
    <span class="faint">Keys: <span class="kbd">j</span> <span class="kbd">k</span> move, <span class="kbd">Enter</span> open</span></nav>`;
}

/* ================= findings ================= */
function findings() {
  const fq = S.fq.trim().toLowerCase();
  const rows = findingCounts().filter(([c]) => (!S.fsev || FIND[c][0] === S.fsev) && (!fq || findingTitle(c).toLowerCase().includes(fq) || FIND[c][1].toLowerCase().includes(fq)));
  const sevCount = s => findingCounts().filter(([c]) => FIND[c][0] === s).length;
  return `<div class="toolbar"><div class="search-box">${icon('search')}<input type="search" id="fq" placeholder="Filter findings" value="${esc(S.fq)}" aria-label="Filter findings"></div>
    <div class="seg" role="group" aria-label="Severity">${[['', 'All'], ['critical', 'Critical'], ['warning', 'Warning'], ['info', 'Info']].map(([v, l]) =>
      `<button data-fsev="${v}" aria-pressed="${S.fsev === v}">${l}${v ? ` <span class="faint">${sevCount(v)}</span>` : ''}</button>`).join('')}</div></div>
    <div class="flist">${rows.map(([c, k]) => { const f = FIND[c];
      const doms = R.filter(r => r._codes.has(c)).sort((a, b) => b.priority - a.priority);
      return `<details class="finding"><summary><span class="sev sev-${f[0]}" title="${f[0]}"></span>
        <span class="ttl"><b>${esc(f[2])}</b><span>${esc(f[1])}, ${esc(f[0])}</span></span>
        <span class="bar fbar" title="${pct(k, R.length)}% of domains"><i class="b-${f[0] === 'critical' ? 'fail' : f[0] === 'warning' ? 'warn' : 'acc'}" style="width:${pct(k, R.length)}%"></i></span>
        <span class="num" style="text-align:right">${k}</span><span class="chev">${icon('chev')}</span></summary>
        <div class="fbody"><p>${esc(f[3])}</p>${(FW[f[1]] || []).length ? `<div class="fw">${FW[f[1]].map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : ''}
          <div class="dlist">${doms.slice(0, 40).map(r => `<button data-open="${r._i}">${esc(r.domain)}</button>`).join('')}${doms.length > 40 ? `<span class="faint">and ${doms.length - 40} more</span>` : ''}</div>
          <div><button class="btn small" data-finding="${esc(c)}">Show the ${k} domain${k === 1 ? '' : 's'} in the list${icon('arrow', 14)}</button></div></div></details>`; }).join('') || '<div class="card empty"><b>No findings</b>Nothing matches this filter.</div>'}</div>`;
}

/* ================= changes, groups, policies ================= */
function changes() {
  const changed = R.filter(r => r.change && r.change.changed).sort((a, b) => (a.change.score_delta || 0) - (b.change.score_delta || 0));
  return `<div class="stat-strip" style="margin-bottom:16px">
      <div class="stat"><b class="delta-up">${diff.improved}</b><span>improved</span></div><div class="stat"><b class="delta-down">${diff.worsened}</b><span>worsened</span></div>
      <div class="stat"><b>${diff.unchanged}</b><span>unchanged</span></div><div class="stat"><b>${diff.new_critical}</b><span>new critical findings</span></div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Domain</th><th class="r">Score</th><th>Control changes</th><th>New findings</th><th>Resolved</th></tr></thead><tbody>
    ${changed.map(r => { const c = r.change;
      return `<tr data-row="${r._i}"><td class="sticky"><button class="dom" data-open="${r._i}">${esc(r.domain)}</button>${c.new ? '<div class="dom-sub">new domain</div>' : ''}</td>
        <td class="r nowrap">${c.new ? scoreHtml(r.overall_score) : `<span class="faint num">${esc(c.previous_score)}</span> ${icon('arrow', 12).replace('class="ico"', 'class="ico" style="display:inline;vertical-align:-1px"')} ${scoreHtml(r.overall_score)} ${deltaHtml(r)}`}</td>
        <td>${c.status_changes.map(s => `<div class="nowrap" style="margin:2px 0">${esc(L[s.check] || s.check)} ${pill(s.from)} ${pill(s.to)}</div>`).join('')}</td>
        <td class="sub">${c.new_issues.map(x => esc(findingTitle(x))).join('<br>')}</td><td class="sub">${c.resolved_issues.map(x => esc(findingTitle(x))).join('<br>')}</td></tr>`; }).join('')
      || '<tr><td colspan="5" class="empty">No changes since the baseline.</td></tr>'}</tbody></table></div>
    ${diff.removed_domains.length ? `<p class="muted" style="margin-top:12px">No longer scanned: ${diff.removed_domains.map(esc).join(', ')}</p>` : ''}`;
}
function groups() {
  const keyFn = {account: r => [r._acc || '(account)'], owner: r => [r.owner || '(no owner)'], bu: r => [r.bu || '(no unit)'], tier: r => [r.tier], tag: r => (r.tags && r.tags.length ? r.tags : ['(no tag)'])}[S.groupBy];
  const g = {};
  R.forEach(r => keyFn(r).forEach(k => (g[k] = g[k] || []).push(r)));
  const rows = Object.entries(g).map(([k, rs]) => ({k, rs, avg: rs.reduce((a, r) => a + r.overall_score, 0) / rs.length,
    crit: rs.reduce((a, r) => a + r._crit, 0), worst: rs.reduce((w, r) => r.overall_score < w.overall_score ? r : w, rs[0])})).sort((a, b) => a.avg - b.avg);
  return `<div class="toolbar"><div class="seg" role="group" aria-label="Group by">${[['account', 'Account'], ['owner', 'Owner'], ['bu', 'Business unit'], ['tier', 'Tier'], ['tag', 'Tag']].map(([v, l]) =>
      `<button data-groupby="${v}" aria-pressed="${S.groupBy === v}">${l}</button>`).join('')}</div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Group</th><th class="r">Domains</th><th>Average score</th><th class="r">Critical findings</th><th>Weakest domain</th></tr></thead><tbody>
    ${rows.map(x => `<tr><td class="sticky"><button class="dom" data-group="${S.groupBy}" data-value="${esc(x.k.startsWith('(') ? '' : x.k)}">${esc(x.k)}</button></td><td class="r num">${x.rs.length}</td>
      <td><div class="scorecell" style="justify-content:flex-start">${scoreHtml(Math.round(x.avg))}<span class="mini" style="width:120px"><i class="${scoreCls(x.avg)}" style="width:${x.avg}%"></i></span></div></td>
      <td class="r num">${x.crit}</td><td><button class="link" data-open="${x.worst._i}">${esc(x.worst.domain)}</button> ${scoreHtml(x.worst.overall_score)}</td></tr>`).join('')}</tbody></table></div>`;
}
function policies() {
  const typeOrder = {WAF_RULES: 0, WHITELIST: 1, ACL: 2, FILE_UPLOAD: 3};
  const rows = [...POL].sort((a, b) => (typeOrder[a.type] ?? 9) - (typeOrder[b.type] ?? 9) || String(a.name).localeCompare(String(b.name)));
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Account findings</h2><p>Configuration that affects every website</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  return accHtml + `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky" style="min-width:200px">Policy</th><th>Type</th><th>State</th><th class="r">Assets</th><th class="r">In this scan</th><th>Settings</th><th class="r">Exceptions</th><th>Last change</th></tr></thead><tbody>
    ${rows.map(p => `<tr><td class="sticky" style="min-width:200px"><button class="dom" style="word-break:normal" data-policy="${esc(p.id)}">${esc(p.name)}</button><div class="dom-sub">#${esc(p.id)}${p.account ? ', account ' + esc(p.account) : ''}</div></td>
      <td><span class="tag">${esc(p.type)}</span>${p.default ? ' <span class="tag tier-high">default</span>' : ''}</td>
      <td>${p.enabled ? '<span class="pill s-pass">Enabled</span>' : '<span class="pill s-fail">Disabled</span>'}</td><td class="r num">${esc(p.assets)}</td><td class="r num">${esc(p.in_scan)}</td>
      <td class="sub">${esc(p.settings)}</td><td class="r num">${esc(p.exceptions)}</td><td class="sub nowrap">${esc(p.modified)}${p.modified_by ? '<br>' + esc(p.modified_by) : ''}</td></tr>`).join('')
      || '<tr><td colspan="8" class="empty">No policies returned by the API.</td></tr>'}</tbody></table></div>`;
}

/* ================= website drawer ================= */
const CONFIG = ['onboarding', 'waf', 'allowlist', 'bots', 'ddos', 'tls'], EXPOSURE = ['origin'];
const tabFor = c => EXPOSURE.includes(c) ? 'exposure' : 'config';
const DTABS = [
  {id: 'overview', label: 'Summary', show: () => true},
  {id: 'findings', label: 'Findings', show: () => true, n: r => r.issues.length},
  {id: 'fixes', label: 'Fixes', show: r => (r.remediation || []).length > 0, n: r => r.remediation.length},
  {id: 'config', label: 'Configuration', show: r => CONFIG.some(c => vis(r, c))},
  {id: 'exposure', label: 'Internet exposure', show: r => vis(r, 'origin') || r.probed}
];
const kv = (label, value, cls) => `<div><span>${esc(label)}</span><b class="${cls || ''}">${value === null || value === undefined || value === '' ? '<span class="faint">none</span>' : esc(value)}</b></div>`;
const yesNo = v => v === true ? 'Yes' : v === false ? 'No' : (v === null || v === undefined ? '' : String(v));
const sec = (id, title, body, act) => `<section class="dr-sec" id="sec-${id}"><h3>${esc(title)}${act ? `<span class="act">${act}</span>` : ''}</h3>${body}</section>`;
function issueList(issues) {
  return issues.map(i => `<div class="issue"><span class="sev sev-${esc(i.severity)}" title="${esc(i.severity)}"></span>
    <div><div class="msg">${esc(i.message)}</div><div class="proto">${esc(i.protocol)}, ${esc(i.severity)}</div></div>
    <div class="rec">${esc(i.recommendation)}</div>${(FW[i.protocol] || []).length ? `<div class="fw">${FW[i.protocol].map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : ''}</div>`).join('');
}
const actionPill = a => BLOCKING.includes(a) ? pill('valid', ({BLOCK: 'Block request', BLOCK_REQUEST: 'Block request', BLOCK_USER: 'Block user', BLOCK_IP: 'Block IP', QUARANTINE: 'Quarantine'})[a])
  : a === 'ALERT' ? pill('warning', 'Alert only') : a ? pill('error', a === 'IGNORE' ? 'Ignore' : a) : pill('missing', 'not set');
function tabOverview(r) {
  const b = r.score_breakdown || {}, comps = Object.entries(b.components || {});
  const comp = Object.entries(r.compliance || {}).filter(([, v]) => v !== 'n/a');
  let h = `<div class="dr-cols">${sec('score', 'How the score is built', `${comps.map(([c, v]) => `<div class="bar-row"><span>${esc(L[c])}</span>
      <span class="bar"><i class="b-${v.got >= v.max ? 'pass' : v.got > 0 ? 'warn' : 'fail'}" style="width:${pct(v.got, v.max)}%"></i></span><span>${v.got}/${v.max}</span></div>`).join('')}
      ${b.normalized ? `<p class="sub" style="margin-top:8px">Normalized to 100 over the evaluated checks (${b.max} points available).</p>` : ''}
      ${b.cap ? `<p class="note-box" style="margin-top:10px">${esc(b.cap)}</p>` : ''}`)}
    ${sec('compliance', 'Requirements', comp.length ? comp.map(([k, v]) => `<div class="bar-row" style="grid-template-columns:1fr auto" title="${esc(COMP[k][1])}"><span>${esc(COMP[k][0])}</span>${pill({pass: 'valid', fail: 'error', unknown: 'unknown'}[v] || 'na')}</div>`).join('')
      + '<p class="sub" style="margin-top:8px">Indicative: based on the configuration read from the API and, with --probe, on tests from the Internet.</p>' : '<p class="muted">Not applicable to the selected checks.</p>')}</div>`;
  h += sec('controls', 'Controls', `<div class="ctl-grid">${CHECKS.filter(c => vis(r, c)).map(c => `<button class="ctl" data-dtab="${tabFor(c)}" data-anchor="${c}"><span>${esc(L[c])}</span>${pill(r._st(c), DETAIL[c] ? DETAIL[c](r) : '')}</button>`).join('')}</div>`);
  if (r.change && r.change.changed) {
    const c = r.change;
    h += sec('changes', 'Since the baseline', c.new ? '<p>New website in this scan.</p>' : `<p>Score <span class="num">${esc(c.previous_score)}</span> to ${scoreHtml(r.overall_score)} ${deltaHtml(r)}</p>
      ${c.status_changes.map(s => `<div style="margin-top:6px">${esc(L[s.check] || s.check)} ${pill(s.from)} ${pill(s.to)}</div>`).join('')}
      ${c.new_issues.length ? `<p style="margin-top:10px"><b>New:</b> ${c.new_issues.map(x => esc(findingTitle(x))).join(', ')}</p>` : ''}
      ${c.resolved_issues.length ? `<p style="margin-top:6px"><b>Resolved:</b> ${c.resolved_issues.map(x => esc(findingTitle(x))).join(', ')}</p>` : ''}`);
  }
  const top = r.issues.filter(i => i.severity !== 'info').slice(0, 4);
  h += sec('top', 'Most important findings', top.length ? issueList(top) : '<p class="muted">No critical or warning findings.</p>',
    r.issues.length > top.length ? `<button class="link" data-dtab="findings">All ${r.issues.length} findings</button>` : '');
  return h;
}
function tabFindings(r) {
  if (!r.issues.length) return sec('issues', 'Findings', '<p class="muted">No findings: the configuration matches every selected check.</p>');
  return ['critical', 'warning', 'info'].map(s => { const xs = r.issues.filter(i => i.severity === s);
    return xs.length ? sec('issues-' + s, `${s[0].toUpperCase() + s.slice(1)} (${xs.length})`, issueList(xs)) : ''; }).join('');
}
function tabFixes(r) {
  return sec('fixes', 'Suggested fixes', `<p class="sub" style="margin-bottom:12px">Terraform snippets for the Imperva (incapsula) provider. Check attribute names against your provider version and plan before applying.</p>` +
    r.remediation.map((x, k) => `<div class="fix"><h4>${esc(x.title)}</h4><div class="where">${esc(x.type)}, <span class="mono">${esc(x.name)}</span></div>
      ${x.value ? `<div class="rowx"><pre class="record" id="fix-${r._i}-${k}">${esc(x.value)}</pre><button class="btn small copy" data-copy="fix-${r._i}-${k}">${icon('copy', 14)}Copy</button></div>` : ''}
      ${x.note ? `<p class="note">${esc(x.note)}</p>` : ''}</div>`).join(''));
}
function tabConfig(r) {
  let h = '';
  if (vis(r, 'onboarding')) { const d = cd(r, 'onboarding');
    h += sec('onboarding', 'Website', `<div class="kv">${kv('Site ID', r.site_id)}${kv('Account', r._acc)}${kv('Status', d.status)}${kv('Mode', d.active)}${kv('Display name', d.display_name)}
      ${kv('Policies applied', (r.policies || []).map(p => `${p.name} (${p.type}${p.enabled ? '' : ', disabled'})`).join(', '))}</div>
      ${(d.dns || []).length ? `<table style="margin-top:14px"><thead><tr><th>DNS record</th><th>Type</th><th>Point to</th></tr></thead><tbody>${d.dns.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(x.type)}</td><td class="mono">${esc([].concat(x.value || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}`, pill(r._st('onboarding'))); }
  if (vis(r, 'waf')) { const d = cd(r, 'waf');
    h += sec('waf', 'WAF rules', `<p class="sub" style="margin-bottom:10px">${d.policy ? `Policy <b>${esc(d.policy.name)}</b> #${esc(d.policy.id)}${d.policy.enabled ? '' : ' (disabled)'}` : d.legacy ? 'Legacy per-site rules (no WAF Rules policy applied)' : 'No WAF rules found'}</p>
      <table><thead><tr><th>Rule</th><th>Action</th><th>Source</th><th class="r">Exceptions</th></tr></thead><tbody>${(d.rules || []).map(x => `<tr><td>${esc(x.rule)}</td><td>${actionPill(x.action)}</td><td class="sub">${esc(x.source)}</td><td class="r num">${esc(x.exceptions)}</td></tr>`).join('')}</tbody></table>
      <div class="kv" style="margin-top:14px">${kv('Backdoor protection', d.backdoor)}${kv('Data leakage protection', d.data_leak)}${kv('Exceptions', d.exception_count)}</div>
      ${(d.exceptions || []).length ? `<details class="more"${d.exceptions.some(e => e.broad) ? ' open' : ''}><summary>Exceptions (${d.exception_count})</summary><table style="margin-top:8px"><thead><tr><th>Rule</th><th>Type</th><th>Values</th><th>Comment</th></tr></thead><tbody>
        ${d.exceptions.map(e => `<tr><td>${esc(e.rule)}</td><td>${esc(e.type)}${e.broad ? ' ' + pill('warning', 'broad') : ''}</td><td class="mono">${esc(e.values.join(', '))}</td><td class="sub">${esc(e.comment) || '<span class="faint">none</span>'}</td></tr>`).join('')}</tbody></table></details>` : ''}`, pill(r._st('waf'))); }
  if (vis(r, 'allowlist')) { const d = cd(r, 'allowlist');
    h += sec('allowlist', 'Allow-lists and access control', `<div class="kv">${kv('Allow-listed IPs', d.allowed_ip_count)}${kv('Blocked countries', (d.blocked_countries || []).join(', '))}${kv('Blocked continents', (d.blocked_continents || []).join(', '))}${kv('Blocked IPs', d.blocked_ips)}${kv('Blocked URLs', d.blocked_urls)}</div>
      ${(d.allowed_ips || []).length ? `<details class="more"><summary>Allow-listed IPs (${d.allowed_ip_count})</summary><div class="tree">${d.allowed_ips.map(esc).join('<br>')}</div></details>` : ''}
      ${(d.allowed_urls || []).length ? `<details class="more"><summary>Allow-listed URLs</summary><div class="tree">${d.allowed_urls.map(esc).join('<br>')}</div></details>` : ''}`, pill(r._st('allowlist'))); }
  const bd = [];
  if (vis(r, 'bots')) { const d = cd(r, 'bots'); bd.push(kv('Block bad bots', yesNo(d.block_bad_bots)), kv('Challenge suspected bots', yesNo(d.challenge_suspected_bots))); }
  if (bd.length) h += sec('bots', 'Bot access control', `<div class="kv">${bd.join('')}</div>`, pill(r._st('bots')));
  if (vis(r, 'ddos')) { const d = cd(r, 'ddos'), t = d.traffic;
    h += sec('ddos', 'DDoS protection', `<div class="kv">${kv('Activation mode', d.mode)}${kv('Current threshold', d.threshold ? d.threshold + ' req/s' : '')}
      ${t ? kv('Recommended threshold', d.recommended + ' req/s', d.recommended === d.threshold ? 'score hi' : '') + kv('Peak legitimate traffic', `${t.peak} req/s`) + kv('Peak at', t.peak_at + ' UTC')
        + kv('Peak vs threshold', d.peak_ratio !== undefined ? d.peak_ratio + '%' : '', d.peak_ratio >= 90 ? 'score lo' : '') + kv('95th percentile', `${t.p95} req/s`) + kv('Average', `${t.avg} req/s`)
        + kv('Blocked peak', `${t.blocked_peak} req/s`) + kv('DDoS incidents', t.ddos_incidents) : ''}${kv('Origin capacity', d.origin_max_rps ? d.origin_max_rps + ' req/s' : 'not provided')}</div>
      ${t ? ddosChart(d) + `<p class="sub" style="margin-top:8px">Last ${esc(t.days)} days, ${t.granularity_s ? (t.granularity_s >= 86400 ? Math.round(t.granularity_s / 86400) + '-day' : Math.round(t.granularity_s / 3600) + '-hour') : 'default'} buckets (${t.points} points)${d.coarse ? ': coarse data, the API did not accept hourly granularity, so peaks are strongly smoothed' : ''}. Values are averages per bucket: short bursts are higher. Recommended: ${esc(d.recommended_why)}.</p>`
        : '<p class="sub" style="margin-top:10px">Traffic statistics not available: the threshold could not be compared with real traffic.</p>'}`, pill(r._st('ddos'))); }
  if (vis(r, 'tls')) { const d = cd(r, 'tls');
    h += sec('tls', 'TLS', `<div class="kv">${kv('Certificate', d.certificate)}${kv('Expires', d.expires)}${kv('Days left', d.days_left)}${kv('Validation', d.validation)}${kv('TLS to origin', yesNo(d.origin_tls))}
      ${r.probed ? kv('HSTS', d.hsts || 'not served') + kv('HTTP to HTTPS redirect', yesNo(d.redirects_https)) + kv('TLS 1.0 accepted', yesNo(d.tls10)) + kv('TLS 1.1 accepted', yesNo(d.tls11)) + kv('Negotiated', d.served_tls) : ''}</div>
      ${r.probed ? '' : '<p class="sub" style="margin-top:10px">HSTS, redirect and legacy TLS are tested with --probe.</p>'}`, pill(r._st('tls'))); }
  return h;
}
function tabExposure(r) {
  const o = cd(r, 'origin'), p = cd(r, 'onboarding').probe;
  let h = '';
  if (p) h += sec('dns', 'DNS routing', `<div class="kv">${kv('Routed through Imperva', yesNo(p.routed))}${kv('CNAME chain', (p.cnames || []).join(' > '))}${kv('Resolves to', (p.addresses || []).join(', '))}${kv('Expected', (p.expected || []).join(', '))}${kv('Imperva edge headers', yesNo(p.imperva_edge))}</div>`);
  if (vis(r, 'origin')) h += sec('origin', 'Origin servers', o.results ? `<p class="sub" style="margin-bottom:10px">One GET / per origin address on 443 and 80, with the website host name. An origin that answers lets attackers bypass the WAF.</p>
      <table><thead><tr><th>Origin</th><th>Address</th><th>Result</th><th>Port</th><th>HTTP</th></tr></thead><tbody>${o.results.map(x => `<tr><td class="mono">${esc(x.origin)}</td><td class="mono">${esc(x.ip)}</td>
        <td>${x.result === 'serves' ? pill('error', 'answers directly') : x.result === 'reachable' ? pill('warning', 'port open') : x.result === 'private' ? pill('na', 'private address') : pill('valid', 'closed')}</td><td class="num">${esc(x.port || '')}</td><td class="num">${esc(x.status || '')}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">No origin addresses in the configuration.</td></tr>'}</tbody></table>`
    : `<p class="muted">${esc(o.note || 'Not tested.')}</p><div class="kv" style="margin-top:10px">${kv('Configured origins', (o.origins || []).join(', '))}</div>`, pill(r._st('origin')));
  return h || '<p class="muted">Run with --probe to test DNS routing, origin exposure, HSTS and TLS versions from the Internet.</p>';
}
function ddosChart(d) {
  const t = d.traffic, pts = (t && t.chart) || [];
  if (pts.length < 2) return '';
  const W = 640, H = 190, L = 46, Rr = 10, T = 14, B = 26;
  const top = Math.max(d.threshold || 0, d.recommended || 0, ...pts.map(p => p[1] + p[2])) * 1.1 || 1;
  const x = i => L + i * (W - L - Rr) / (pts.length - 1), y = v => H - B - (v / top) * (H - T - B);
  const path = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`).join('');
  const blocked = pts.some(p => p[2] > 0) ? pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[1] + p[2]).toFixed(1)}`).join('') : '';
  const hl = (v, cls, lbl) => v ? `<line x1="${L}" x2="${W - Rr}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" class="${cls}"/><text x="${W - Rr}" y="${(y(v) - 5).toFixed(1)}" text-anchor="end" class="${cls}-t">${lbl} ${v}</text>` : '';
  const day = ts => new Date(ts).toISOString().slice(0, 10);
  const ticks = [0, 0.5, 1].map(f => `<text x="${L - 6}" y="${(y(top * f) + 3).toFixed(1)}" text-anchor="end" class="ax">${Math.round(top * f)}</text><line x1="${L}" x2="${W - Rr}" y1="${y(top * f).toFixed(1)}" y2="${y(top * f).toFixed(1)}" class="grid"/>`).join('');
  return `<svg class="ddos-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Legitimate requests per second against the DDoS threshold">${ticks}
    <path d="${path}L${x(pts.length - 1).toFixed(1)},${y(0)}L${L},${y(0)}Z" class="area"/>${blocked ? `<path d="${blocked}" class="blk"/>` : ''}<path d="${path}" class="ln"/>
    ${hl(d.threshold, 'thr', 'Current')}${d.recommended !== d.threshold ? hl(d.recommended, 'rec', 'Recommended') : ''}
    <text x="${L}" y="${H - 6}" class="ax">${day(pts[0][0])}</text><text x="${W - Rr}" y="${H - 6}" text-anchor="end" class="ax">${day(pts[pts.length - 1][0])}</text></svg>
    <div class="legend"><span><i class="dot" style="background:var(--accent)"></i>Legitimate req/s (peak per bucket)</span>${blocked ? '<span><i class="dot" style="background:var(--dns)"></i>Including blocked</span>' : ''}<span><i class="dot" style="background:var(--fail)"></i>Current threshold</span><span><i class="dot" style="background:var(--pass)"></i>Recommended</span></div>`;
}
const TAB_RENDER = {overview: tabOverview, findings: tabFindings, fixes: tabFixes, config: tabConfig, exposure: tabExposure};
let lastOpen = null, lastAnchor = null;
function drawer() {
  const root = $('#drawer-root');
  if (S.open === null) {
    if (lastOpen !== null) { root.innerHTML = ''; document.body.classList.remove('locked');
      const back = document.querySelector(`[data-open="${lastOpen}"]`); if (back) back.focus({preventScroll: true}); }
    lastOpen = null; return;
  }
  const r = R[S.open], lst = list(), pos = lst.findIndex(x => x._i === r._i);
  const prev = pos > 0 ? lst[pos - 1]._i : null, next = pos >= 0 && pos < lst.length - 1 ? lst[pos + 1]._i : null;
  const tabs = DTABS.filter(t => t.show(r));
  if (S.dtab !== 'all' && !tabs.some(t => t.id === S.dtab)) S.dtab = 'overview';
  const badge = {bypass: 'Bypass mode', onboarding: 'Onboarding incomplete', error: 'Partially read'}[r.profile];
  const body = S.dtab === 'all' ? tabs.map(t => `<h2 class="dr-print-title">${esc(t.label)}</h2>` + TAB_RENDER[t.id](r)).join('') : TAB_RENDER[S.dtab](r);
  const fresh = lastOpen === null;
  root.innerHTML = `<div class="scrim${fresh ? ' enter' : ''}" data-action="close"></div>
    <aside class="drawer${fresh ? ' enter' : ''}" role="dialog" aria-modal="true" aria-labelledby="dr-title">
      <header class="dr-head">
        <div class="dr-nav"><button class="btn icon ghost" data-open="${prev}" ${prev === null ? 'disabled' : ''} aria-label="Previous website" title="Previous (k)">${icon('left')}</button>
          <button class="btn icon ghost" data-open="${next}" ${next === null ? 'disabled' : ''} aria-label="Next website" title="Next (j)">${icon('right')}</button>
          <span>${pos >= 0 ? `${pos + 1} of ${lst.length}` : ''}</span><span class="spacer"></span>
          <button class="btn ghost small" data-action="copy-link">${icon('link', 14)}Copy link</button>
          <button class="btn ghost small" data-action="print-domain">${icon('print', 14)}Print</button>
          <button class="btn icon ghost" data-action="close" id="dr-close" aria-label="Close" title="Close (Esc)">${icon('x')}</button></div>
        <div class="dr-id">${ring(r.overall_score)}<div style="min-width:0"><h2 id="dr-title">${esc(r.domain)}</h2>
          <div class="meta">${hasMeta ? tierTag(r.tier) : ''}${badge ? `<span class="tag tier-critical">${esc(badge)}</span>` : ''}<span class="tag">#${esc(r.site_id)}</span>${r._acc ? `<span class="tag">${esc(r._acc)}</span>` : ''}
            ${r.owner ? `<span class="tag">Owner ${esc(r.owner)}</span>` : ''}${(r.tags || []).map(t => `<span class="tag">#${esc(t)}</span>`).join('')}<span class="t">Grade ${gradeOf(r.overall_score)}, priority ${r.priority}${r.probed ? ', tested from the Internet' : ''}</span></div>
          ${r.error ? `<p class="note-box" style="margin-top:8px">${esc(r.error)}</p>` : ''}</div></div>
        <nav class="dr-tabs" role="tablist">${tabs.map(t => `<button role="tab" data-dtab="${t.id}" aria-selected="${S.dtab === t.id}">${esc(t.label)}${t.n ? `<span class="n">${t.n(r)}</span>` : ''}</button>`).join('')}</nav>
      </header>
      <div class="dr-body" id="dr-body">${body}</div></aside>`;
  document.body.classList.add('locked');
  if (fresh) { const c = $('#dr-close'); if (c) c.focus({preventScroll: true}); }
  if (lastAnchor) { const el = document.getElementById('sec-' + lastAnchor); if (el) el.scrollIntoView({block: 'start'}); lastAnchor = null; }
  lastOpen = S.open;
}

/* ================= overlays: command palette, dialogs ================= */
let pal = null;
function paletteItems(q) {
  q = q.trim().toLowerCase();
  const items = [];
  ROUTES.filter(x => x.show()).forEach(x => { if (!q || x.label.toLowerCase().includes(q)) items.push({g: 'Go to', t: x.label, h: '', run: () => go({route: x.id, open: null})}); });
  const doms = (q ? R.filter(r => r.domain.includes(q) || String(r.site_id).includes(q) || (r.owner || '').toLowerCase().includes(q)) : [...R].sort((a, b) => b.priority - a.priority)).slice(0, q ? 8 : 5);
  doms.forEach(r => items.push({g: 'Websites', t: r.domain, h: `score ${r.overall_score}`, run: () => go({open: r._i, dtab: 'overview'})}));
  findingCounts().filter(([c]) => q && findingTitle(c).toLowerCase().includes(q)).slice(0, 6).forEach(([c, k]) =>
    items.push({g: 'Findings', t: findingTitle(c), h: `${k} domains`, run: () => filterTo({finding: c})}));
  [['Toggle light or dark theme', toggleTheme], ['Executive summary as PDF', printExec], ['Export filtered websites as CSV', () => exportCsv(list())],
   ['Clear all filters', () => filterTo({})], ['Copy link to this view', copyLink], ['Keyboard shortcuts', showKeys], ['About this scan', showAbout]]
    .forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) items.push({g: 'Actions', t, h: '', run: fn}); });
  return items;
}
function openPalette() {
  pal = {q: '', idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search websites, findings and actions" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul>
    <div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette();
  $('#pal-q').focus();
}
function renderPalette() {
  let g = '', html = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; html += `<li class="pal-group" role="presentation">${esc(g)}</li>`; }
    html += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h)}</span></li>`; });
  $('#pal-list').innerHTML = html || '<li class="pal-group">No results</li>';
  const q = $('#pal-q'); if (q) q.setAttribute('aria-activedescendant', 'pal-' + pal.idx);
  const cur = $('#pal-' + pal.idx); if (cur) cur.scrollIntoView({block: 'nearest'});
}
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }
function dialog(title, body) {
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t">
    <header><h2 id="dlg-t">${esc(title)}</h2><button class="btn icon ghost" data-action="overlay-close" aria-label="Close">${icon('x')}</button></header><div class="dbody">${body}</div></div></div>`;
  const b = $('#overlay-root [data-action="overlay-close"]'); if (b) b.focus();
}
function closeOverlay() { $('#overlay-root').innerHTML = ''; pal = null; }
function showKeys() {
  const k = [['Ctrl K or /', 'Search websites, findings and actions'], ['1 to 7', 'Switch section'], ['j / k', 'Next or previous website (list and detail)'],
    ['Enter', 'Open the highlighted website'], ['x', 'Select the highlighted website'], ['f', 'Show or hide filters'], ['Esc', 'Close the detail or dialog'], ['?', 'This help']];
  dialog('Keyboard shortcuts', `<table class="keys">${k.map(([a, b]) => `<tr><td><span class="kbd">${esc(a)}</span></td><td>${esc(b)}</td></tr>`).join('')}</table>`);
}
function showAbout() {
  const w = D.weights || {};
  dialog('About this scan', `<div class="kv" style="margin-bottom:16px">${kv('Generated', M.generated)}${kv('Tool', 'WAFGuard ' + (M.version || ''))}${kv('Websites', R.length)}${kv('Source', M.resolver)}</div>
    <p style="margin-bottom:6px"><b>Checks</b></p><p class="muted" style="margin-bottom:14px">${CHECKS.map(c => esc(L[c]) + (w[c] ? ` (${w[c]} pts)` : '')).join(', ')}</p>
    <p style="margin-bottom:6px"><b>Notes</b></p><ul style="margin:0;padding-left:18px;color:var(--muted)">${(M.notes || []).map(n => `<li style="margin-bottom:4px">${esc(n)}</li>`).join('')}</ul>`);
}

/* ================= actions ================= */
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !matchMedia('(prefers-color-scheme: light)').matches; };
function toggleTheme() { P.theme = isDark() ? 'light' : 'dark'; savePrefs(); applyTheme(); render(); }
function applyTheme() { if (P.theme) document.documentElement.dataset.theme = P.theme; }
function toast(msg) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2600); }
function copyText(text, okMsg) {
  const done = () => toast(okMsg || 'Copied');
  const fallback = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed: select the text manually'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
}
function copyLink() { copyText(location.href, 'Link copied'); }
function download(name, mime, text) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], {type: mime})); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  toast(`Downloaded ${name}`);
}
const csvCell = v => { let s = String(v === null || v === undefined ? '' : v); if (/^[=+\-@\t\r|%]/.test(s)) s = "'" + s; return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function exportCsv(rows, name) {
  const head = ['website', 'site_id', 'account', 'score', 'priority', 'tier', 'owner', 'bu', 'tags', ...CHECKS.map(c => L[c]), 'critical', 'warning', 'issue_codes'];
  const body = rows.map(r => [r.domain, r.site_id, r._acc, r.overall_score, r.priority, r.tier, r.owner, r.bu, (r.tags || []).join('|'), ...CHECKS.map(c => r._st(c)), r._crit, r._warn, [...r._codes].join('|')]);
  download(name || 'wafguard-websites.csv', 'text/csv;charset=utf-8', '\ufeff' + [head, ...body].map(x => x.map(csvCell).join(';')).join('\r\n'));
}
function exportJson(rows) {
  download('wafguard-websites.json', 'application/json', JSON.stringify(rows.map(r => { const o = {}; Object.keys(r).forEach(k => { if (k[0] !== '_') o[k] = r[k]; }); return o; }), null, 2));
}
function printExec() {
  if (S.route !== 'overview' || S.open !== null) go({route: 'overview', open: null});
  document.body.classList.add('print-exec');
  setTimeout(() => window.print(), 60);
}
function printDomain() {
  const prev = S.dtab; S.dtab = 'all'; drawer();
  document.body.classList.add('print-drawer');
  setTimeout(() => { window.print(); }, 60);
  window.__restoreTab = prev;
}
window.addEventListener('afterprint', () => {
  document.body.classList.remove('print-exec', 'print-drawer');
  if (window.__restoreTab) { S.dtab = window.__restoreTab; window.__restoreTab = null; drawer(); }
});

/* ================= render ================= */
const VIEWS = {overview, domains, findings, changes, groups, policies};
function render() {
  applyTheme();
  $('#side').innerHTML = side();
  $('#topbar').innerHTML = topbar();
  const view = VIEWS[S.route] || overview;
  $('#view').innerHTML = view();
  drawer();
  const rt = ROUTES.find(x => x.id === S.route);
  document.title = (S.open !== null ? R[S.open].domain + ' - ' : '') + (rt ? rt.label + ' - ' : '') + 'WAFGuard';
}
function rerenderKeepFocus(id) {
  const el = document.getElementById(id), pos = el ? el.selectionStart : null;
  render();
  const n = document.getElementById(id); if (n) { n.focus(); if (pos !== null) try { n.setSelectionRange(pos, pos); } catch (e) { /* number inputs */ } }
}

/* ================= events ================= */
document.addEventListener('click', e => {
  const t = e.target.closest('button, [data-open], [data-smin], tr[data-row], [data-pal], [data-overlay], .scrim');
  if (S.menu && !e.target.closest('.menu')) { S.menu = null; if (!t) { render(); return; } }
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.open !== undefined && ds.open !== 'null') { if (ds.dtab) lastAnchor = null; go({open: +ds.open, dtab: ds.dtab || (S.open === +ds.open ? S.dtab : 'overview')}); return; }
  if (ds.smin !== undefined) { filterTo({smin: ds.smin, smax: ds.smax}); return; }
  if (ds.route) { go({route: ds.route, open: null, page: 1, cursor: -1}); $('#view').focus({preventScroll: true}); window.scrollTo(0, 0); return; }
  if (ds.check) { filterTo({f: {[ds.check]: ds.status}}); return; }
  if (ds.filter) { if (ds.filter.startsWith('c.')) filterTo({f: {[ds.filter.slice(2)]: ds.value}}); else filterTo({[ds.filter]: ds.value}); return; }
  if (ds.tier) { filterTo({tier: ds.tier, score: ds.band}); return; }
  if (ds.finding) { filterTo({finding: ds.finding}); return; }
  if (ds.comp) { filterTo({comp: ds.comp}); return; }
  if (ds.group) { filterTo({[ds.group]: ds.value}); return; }
  if (ds.policy) { filterTo({policy: ds.policy}); return; }
  if (ds.preset !== undefined) { const p = PRESETS()[+ds.preset]; filterTo(JSON.parse(JSON.stringify(p[2]))); return; }
  if (ds.chip) { clearChip(ds.chip); go({page: 1, cursor: -1}, false); return; }
  if (ds.sort) { const k = ds.sort; go({sort: {k, d: S.sort.k === k ? -S.sort.d : (k === 'domain' ? 1 : -1)}, page: 1}, false); return; }
  if (ds.page) { go({page: +ds.page, cursor: -1}, false); const g = $('#grid'); if (g) g.scrollTop = 0; return; }
  if (ds.view) { P.view = ds.view; savePrefs(); render(); return; }
  if (ds.density) { P.density = ds.density; savePrefs(); render(); return; }
  if (ds.menu) { S.menu = S.menu === ds.menu ? null : ds.menu; render(); return; }
  if (ds.dtab) { if (ds.anchor) lastAnchor = ds.anchor; go({dtab: ds.dtab}, false); const b = $('#dr-body'); if (b && !lastAnchor) b.scrollTop = 0; return; }
  if (ds.fsev !== undefined) { S.fsev = ds.fsev; render(); return; }
  if (ds.groupby) { S.groupBy = ds.groupby; render(); return; }
  if (ds.copy) { const el = document.getElementById(ds.copy); if (el) copyText(el.textContent, 'Record copied'); return; }
  if (t.tagName === 'TR' && ds.row !== undefined && !e.target.closest('input, button, a')) { go({open: +ds.row, dtab: 'overview'}); return; }
  const a = ds.action;
  const acts = {
    close: () => go({open: null}), palette: openPalette, about: showAbout, keys: showKeys, theme: toggleTheme,
    'overlay-close': closeOverlay, 'print-exec': printExec, 'print-domain': printDomain, 'copy-link': () => { S.menu = null; copyLink(); render(); },
    filters: () => { S.filtersOpen = !S.filtersOpen; render(); }, clear: () => filterTo({}),
    csv: () => { S.menu = null; exportCsv(list()); render(); }, json: () => { S.menu = null; exportJson(list()); render(); },
    'csv-sel': () => { S.menu = null; exportCsv(R.filter(r => S.sel.has(r._i)), 'wafguard-selected.csv'); render(); },
    'copy-list': () => { S.menu = null; copyText(list().map(r => r.domain).join('\n'), `${list().length} domains copied`); render(); },
    'copy-sel': () => copyText(R.filter(r => S.sel.has(r._i)).map(r => r.domain).join('\n'), `${S.sel.size} domains copied`),
    'sel-clear': () => { S.sel.clear(); render(); }, 'cols-reset': () => { P.hidden = []; savePrefs(); render(); }
  };
  if (acts[a]) acts[a]();
});
document.addEventListener('change', e => {
  const t = e.target, ds = t.dataset;
  if (ds.f) { S.f[ds.f] = t.value; if (!t.value) delete S.f[ds.f]; go({page: 1, cursor: -1}, false); }
  else if (ds.sel !== undefined) { const i = +ds.sel; S.sel.has(i) ? S.sel.delete(i) : S.sel.add(i); render(); }
  else if (ds.selall !== undefined) { const items = list().slice((S.page - 1) * P.size, S.page * P.size); items.forEach(r => t.checked ? S.sel.add(r._i) : S.sel.delete(r._i)); render(); }
  else if (ds.col) { P.hidden = t.checked ? P.hidden.filter(x => x !== ds.col) : [...P.hidden, ds.col]; savePrefs(); render(); }
  else if (ds.lmx !== undefined) { S.lmx = t.checked; render(); }
  else if (ds.k === 'size') { P.size = +t.value; savePrefs(); go({page: 1}, false); }
  else if (ds.k === 'changed') { go({changed: t.checked ? '1' : '', page: 1}, false); }
  else if (ds.k === 'smin' || ds.k === 'smax') { const v = t.value === '' ? '' : String(Math.max(0, Math.min(100, +t.value))); go({[ds.k]: v, page: 1}, false); }
  else if (ds.k) { go({[ds.k]: t.value, page: 1, cursor: -1}, false); }
});
let qTimer = null;
document.addEventListener('input', e => {
  const id = e.target.id;
  if (id === 'pal-q') { pal.q = e.target.value; pal.items = paletteItems(pal.q); pal.idx = 0; renderPalette(); return; }
  if (id !== 'q' && id !== 'fq') return;
  clearTimeout(qTimer);
  const v = e.target.value;
  qTimer = setTimeout(() => {
    if (id === 'q') { Object.assign(S, {q: v, page: 1, cursor: -1}); history.replaceState(null, '', toHash()); }
    else S.fq = v;
    rerenderKeepFocus(id);
  }, 160);
});
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); }
    else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape') {
    if ($('#overlay-root').innerHTML) closeOverlay();
    else if (S.menu) { S.menu = null; render(); }
    else if (S.open !== null) go({open: null});
    else if (typing) e.target.blur();
    return;
  }
  if ($('#overlay-root').innerHTML) {  // keep focus inside dialogs
    if (e.key === 'Tab') { const f = [...$('#overlay-root').querySelectorAll('button, input')]; if (f.length) { e.preventDefault(); const i = f.indexOf(document.activeElement); f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus(); } }
    return;
  }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  if (e.key === '?') { showKeys(); return; }
  if (S.open !== null) {
    const lst = list(), pos = lst.findIndex(x => x._i === S.open);
    if ((e.key === 'j' || e.key === ']') && pos < lst.length - 1) go({open: lst[pos + 1]._i}, false);
    else if ((e.key === 'k' || e.key === '[') && pos > 0) go({open: lst[pos - 1]._i}, false);
    return;
  }
  const n = parseInt(e.key, 10), visible = ROUTES.filter(x => x.show());
  if (n >= 1 && n <= visible.length) { go({route: visible[n - 1].id, open: null, page: 1, cursor: -1}); return; }
  if (S.route === 'domains') {
    const items = list().slice((S.page - 1) * P.size, S.page * P.size);
    if (e.key === 'f') { S.filtersOpen = !S.filtersOpen; render(); return; }
    if (!items.length) return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); S.cursor = Math.min(items.length - 1, S.cursor + 1); render(); scrollCursor(); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); S.cursor = Math.max(0, S.cursor - 1); render(); scrollCursor(); }
    else if (e.key === 'Enter' && S.cursor >= 0) { e.preventDefault(); go({open: items[S.cursor]._i, dtab: 'overview'}); }
    else if (e.key === 'x' && S.cursor >= 0) { const i = items[S.cursor]._i; S.sel.has(i) ? S.sel.delete(i) : S.sel.add(i); render(); }
  }
});
function scrollCursor() { const row = document.querySelector('tr.cursor'); if (row) row.scrollIntoView({block: 'nearest'}); }

/* ================= start ================= */
applyTheme();
fromHash();
history.replaceState(null, '', toHash());
render();
})();
"""

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<button class="skip" type="button" onclick="document.getElementById('view').focus()">Skip to content</button>
<div class="app">
  <aside class="side" id="side" aria-label="Navigation"></aside>
  <div class="main">
    <header class="topbar" id="topbar"></header>
    <main class="content" id="view" tabindex="-1"></main>
  </div>
</div>
<div id="drawer-root"></div>
<div id="overlay-root"></div>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>
<script type="application/json" id="mg-data">__DATA__</script>
<script>__JS__</script>
</body>
</html>
"""



def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[SiteResult], account_issues: List[Issue], policies: List[dict],
                         output_file: str, meta: dict) -> None:
    checks = meta["checks"]
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        "Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
        + " (normalized over the checks that could be evaluated).",
        "Bypass mode, DNS not routed, missing or disabled WAF policy, exposed origin, broad allow-lists and expired "
        "certificates cap the score. Priority = tier weight x (100 - score + 15 x critical findings).",
        "WAF rules are read from the WAF Rules policy applied to each website; legacy per-site rules are used only when no policy is applied.",
        "Origin exposure, DNS routing, HSTS, redirects and TLS versions are tested only with --probe.",
        f"DDoS threshold: recommended = {meta.get('ddos_factor', DDOS_FACTOR):g} x peak legitimate requests/s "
        f"(minimum {meta.get('ddos_floor', DDOS_FLOOR)}), rounded up to an accepted value. Peaks are averages per time "
        "bucket, so short bursts are higher than shown.",
        "Compliance and framework references are indicative.",
    ] + [n for n in meta.get("notes", []) if n]
    payload = {
        "meta": {"version": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "resolver": meta.get("source", ""), "notes": notes, "tool": "WAFGuard"},
        "checks": checks, "labels": CHECK_LABELS, "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()}, "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()}, "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"), "account_issues": [asdict(i) for i in account_issues], "policies": policies,
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE.replace("__TITLE__", html.escape(f"Imperva WAF posture - {len(results)} websites"))
            .replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS).replace("__DATA__", _json_for_html(payload)))
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_Parser = Parser




def build_parser() -> _Parser:
    p = _Parser(description="Imperva Cloud WAF security posture and configuration assessment (read-only)",
                formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Credentials: set IMPERVA_API_ID and IMPERVA_API_KEY (preferred), or use --api-key-file.
An API key with read access to sites and policies is enough; the tool never changes anything.

Examples:
    securityhub waf --account-id 1234567
    securityhub waf --account-id 1234567 --include-subaccounts --probe --json --csv
    securityhub waf --account-id 1234567 --sites www.example.com,12345678
    securityhub waf --account-id 1234567 --save-raw snapshot.json
    securityhub waf --from-json snapshot.json --metadata sites.csv --baseline previous.json

Checks: onboarding, waf, allowlist, bots, ddos, tls, origin (default: all; origin needs --probe)
Metadata CSV: site_id or domain, tier (critical/high/medium/low), owner, bu, tags (separated by |),
              max_rps (requests/s the origin can serve, from load tests: upper bound for the DDoS threshold)
DDoS tuning: peak legitimate requests/s over --traffic-days (hourly buckets when available);
             recommended threshold = --ddos-factor x peak (min --ddos-floor), rounded up to a value Imperva accepts.
Exit codes: 0 ok, 1 usage/API error, 2 a website scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--account-id", type=int, help="Imperva account ID (parent account)")
    p.add_argument("--include-subaccounts", action="store_true", help="Also assess every sub-account")
    p.add_argument("--sites", default="", help="Only these websites: comma-separated site IDs or domains")
    p.add_argument("--api-id", default=os.environ.get("IMPERVA_API_ID"), help="API ID (default: $IMPERVA_API_ID)")
    p.add_argument("--api-key-file", help="File containing the API key (instead of $IMPERVA_API_KEY)")
    p.add_argument("--api-key", help=argparse.SUPPRESS)
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API")
    p.add_argument("--save-raw", help="Save the raw configuration snapshot (no credentials) to this JSON file")
    p.add_argument("-o", "--output", default="wafguard_report.html", help="Output HTML file")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV summary")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--probe", action="store_true",
                   help="Also test from the Internet: DNS routing, HSTS, redirect, TLS versions, direct origin access")
    p.add_argument("--metadata", help="CSV with tier/owner/bu/tags (and origin max_rps) per website")
    p.add_argument("--no-traffic", action="store_true", help="Do not read traffic statistics (DDoS threshold not validated)")
    p.add_argument("--traffic-days", type=int, default=90, help="Traffic window for DDoS tuning, in days (default: 90)")
    p.add_argument("--ddos-factor", type=float, default=DDOS_FACTOR, help=f"Recommended threshold = factor x peak rps (default: {DDOS_FACTOR})")
    p.add_argument("--ddos-floor", type=int, default=DDOS_FLOOR, help=f"Minimum recommended threshold (default: {DDOS_FLOOR})")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--workers", type=int, default=8, help="Parallel API calls / probes (default: 8)")
    p.add_argument("--qps", type=float, default=8.0, help="Max API requests per second (default: 8)")
    p.add_argument("--timeout", type=float, default=30.0, help="API timeout in seconds (default: 30)")
    p.add_argument("--v1-base", default="https://my.imperva.com", help=argparse.SUPPRESS)
    p.add_argument("--api-base", default="https://api.imperva.com", help=argparse.SUPPRESS)
    p.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any website scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"WAFGuard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        checks = parse_checks(args.checks, args.skip)
    except ValueError as e:
        parser.error(str(e))
    log = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    site_filter = {s.strip().lower() for s in args.sites.split(",") if s.strip()}

    metadata: Dict[str, dict] = {}
    if args.metadata:
        try:
            metadata = load_metadata(args.metadata)
        except OSError as e:
            print(f"Error: cannot read metadata file: {e}", file=sys.stderr)
            return EXIT_USAGE

    t0 = time.monotonic()
    if args.from_json:
        try:
            with open(args.from_json, encoding="utf-8") as f:
                snap = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read snapshot: {e}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Snapshot {os.path.basename(args.from_json)} collected {snap.get('collected', '?')}"
        if site_filter:
            for acc in snap.get("accounts", []):
                acc["sites"] = [s for s in acc.get("sites", []) if str(s.get("site_id")) in site_filter
                                or str(s.get("domain", "")).lower() in site_filter]
    else:
        if args.api_key:
            print("Warning: --api-key is visible in the process list and shell history; prefer IMPERVA_API_KEY.", file=sys.stderr)
        api_key = args.api_key or os.environ.get("IMPERVA_API_KEY")
        if args.api_key_file:
            try:
                with open(args.api_key_file, encoding="utf-8") as f:
                    api_key = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read API key file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if not args.api_id or not api_key:
            parser.error("API credentials missing: set IMPERVA_API_ID and IMPERVA_API_KEY (or use --from-json)")
        if not args.account_id:
            parser.error("--account-id is required when reading from the API")
        api = ImpervaAPI(args.api_id, api_key, args.v1_base, args.api_base, args.timeout, args.qps,
                         verify_tls=not args.insecure)
        log(f"Reading Imperva configuration (account {args.account_id}{', with sub-accounts' if args.include_subaccounts else ''})...")
        try:
            snap = collect(api, args.account_id, args.include_subaccounts, site_filter, args.workers, log,
                           0 if args.no_traffic else max(1, args.traffic_days))
        except KeyboardInterrupt:
            print("\nInterrupted.", file=sys.stderr)
            return EXIT_INTERRUPTED
        auth_errors = [e for e in snap["errors"] if "authentication" in e["error"] or "permission" in e["error"]]
        if auth_errors and not any(a.get("sites") for a in snap["accounts"]):
            print(f"Error: {auth_errors[0]['error']}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Imperva API, account {args.account_id}, {api.stats['requests']} requests"

    sites = [(acc, s) for acc in snap.get("accounts", []) for s in acc.get("sites", [])]
    if not sites:
        print("No websites found (check the account ID, the --sites filter or the API key scope).", file=sys.stderr)
        return EXIT_USAGE

    probes: Dict[str, dict] = dict(snap.get("probes") or {})
    if args.probe:
        log(f"Testing {len(sites)} website(s) from the Internet...")
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = {ex.submit(probe_site, s): str(s.get("site_id")) for _, s in sites}
            for k, fut in enumerate(as_completed(futs), 1):
                try:
                    probes[futs[fut]] = fut.result()
                except Exception as e:
                    probes[futs[fut]] = {"error": str(e), "addresses": [], "origins": []}
                if k % 10 == 0 or k == len(futs):
                    log(f"  probed {k}/{len(futs)}")
        snap["probes"] = probes

    if args.save_raw:
        try:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Raw snapshot saved: {args.save_raw}")
        except OSError as e:
            print(f"Warning: cannot save snapshot: {e}", file=sys.stderr)

    results, account_issues, policy_rows = analyze_snapshot(snap, checks, probes, metadata, args.ddos_factor, args.ddos_floor)
    results.sort(key=lambda r: (-r.priority, r.domain))
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    notes = []
    if not args.probe and not snap.get("probes"):
        notes.append("Internet tests were not run (--probe): origin exposure and DNS routing are not evaluated.")
    if snap.get("errors"):
        notes.append(f"{len(snap['errors'])} API call(s) failed: see the account findings.")
    try:
        generate_html_report(results, account_issues, policy_rows, args.output,
                             {"checks": checks, "source": source, "diff": diff, "notes": notes,
                              "ddos_factor": args.ddos_factor, "ddos_floor": args.ddos_floor})
        log(f"Report generated: {args.output}")
        base = args.output.rsplit(".", 1)[0]
        if args.json:
            write_json(results, account_issues, base + ".json")
            log(f"JSON output: {base}.json")
        if args.csv:
            write_csv(results, checks, base + ".csv")
            log(f"CSV output: {base}.csv")
    except OSError as e:
        print(f"Error: cannot write output: {e}", file=sys.stderr)
        return EXIT_USAGE

    sev = Counter(i.severity for r in results for i in r.issues)
    print(f"\n{'=' * 60}\nSUMMARY\n{'=' * 60}")
    print(f"Websites assessed:        {len(results)}")
    print(f"Well protected (>=80):    {sum(r.overall_score >= 80 for r in results)}")
    print(f"Need attention (50-79):   {sum(50 <= r.overall_score < 80 for r in results)}")
    print(f"Critical risk (<50):      {sum(r.overall_score < 50 for r in results)}")
    print(f"In bypass mode:           {sum(r.profile == 'bypass' for r in results)}")
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    if account_issues:
        print(f"Account findings:         {len(account_issues)}")
    for r in [r for r in results if r.priority > 0][:5]:
        first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
        print(f"  {r.domain:<38} score {r.overall_score:>3}  {first.message[:70] if first else ''}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
