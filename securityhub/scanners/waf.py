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
from .. import ui

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

REPORT_CSS = ui.asset("waf.css")


REPORT_JS = ui.asset("waf.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')



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
