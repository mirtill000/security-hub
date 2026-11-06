"""EmailSecurityAnalyzer: runs the selected checks on a domain (checks live in the mixins)."""

from __future__ import annotations

import ssl
from dataclasses import asdict, fields
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .checks_auth import AuthChecks, _SPFEval
from .checks_dns import DNSHygieneChecks
from .checks_exposure import ExposureChecks
from .checks_transport import TransportChecks
from .constants import (CHECKS, CHECK_ATTRS, CHECK_DEPENDENCIES, DEFAULT_CHECKS, DEFAULT_DKIM_SELECTORS,
                        PROTECTED_MX_PROVIDERS, SEVERITY_RANK)
from .dnsclient import DNSClient
from .domains import org_domain, tier_weight
from .models import DomainInput, DomainResult, Issue, make_issue
from .rdap import RDAPClient
from .remediation import suggest_remediation
from .scoring import Scoring


class EmailSecurityAnalyzer(AuthChecks, TransportChecks, DNSHygieneChecks, ExposureChecks, Scoring):
    """Analyzes email security configurations for domains via live DNS queries."""

    COMMON_DKIM_SELECTORS = DEFAULT_DKIM_SELECTORS
    PROTECTED_MX_PROVIDERS = PROTECTED_MX_PROVIDERS
    DKIM_MAX_ERRORS = 3          # DNS errors before DKIM probing is aborted for a domain
    LOOKALIKE_FRESH_DAYS = 90

    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None,
                 use_system_resolver: bool = False, selectors: Optional[List[str]] = None,
                 fast_dkim: bool = False, http_checks: bool = True, dkim_threads: int = 32, full_dkim: bool = False,
                 checks: Optional[List[str]] = None, dns_client: Optional[DNSClient] = None,
                 rdap: Optional[RDAPClient] = None, allow_private: bool = False,
                 report_data: Optional[Dict[str, dict]] = None, known_domains: Iterable[str] = (),
                 lookalike_limit: int = 150, lookalike_tiers: Optional[Set[str]] = None, qps: float = 0,
                 cache=None, discovery_max_age: float = 24.0):
        self.timeout = timeout
        self.checks = set(checks or DEFAULT_CHECKS)
        unknown = self.checks - set(CHECKS)
        if unknown:
            raise ValueError(f"unknown checks: {', '.join(sorted(unknown))}")
        self._run = set(self.checks)
        for c in self.checks:
            self._run |= CHECK_DEPENDENCIES.get(c, set())
        self.dns = dns_client or DNSClient(nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"], timeout,
                                           use_system_resolver, qps)
        self.selectors = list(dict.fromkeys(self.COMMON_DKIM_SELECTORS if selectors is None else selectors))
        self.fast_dkim = fast_dkim
        self.full_dkim = full_dkim
        self.extra_selectors: List[str] = []  # given by the user: always probed in the first round
        self.domain_selectors: Dict[str, List[str]] = {}  # dkim.csv: the selectors each domain uses, probed first and expected
        self.domain_dkim_expected: Dict[Tuple[str, str], dict] = {}  # dkim.csv: (domain, selector) -> key fingerprint / CNAME
        self.http_checks = http_checks
        self.allow_private = allow_private
        self.rdap = rdap
        self.report_data = report_data or {}
        # DKIM selectors observed in DMARC reports, keyed by the signing domain (d=)
        self.report_selectors: Dict[str, List[str]] = {}
        for info in self.report_data.values():
            for (sig_domain, sel) in info.get("selector_pairs", []):
                self.report_selectors.setdefault(sig_domain, [])
                if sel not in self.report_selectors[sig_domain]:
                    self.report_selectors[sig_domain].append(sel)
        self.known_domains = {d.lower() for d in known_domains}
        self.known_orgs: Set[str] = {org_domain(d) for d in self.known_domains}
        self.lookalike_limit = lookalike_limit
        self.lookalike_tiers = lookalike_tiers
        self._pool = ThreadPoolExecutor(max_workers=dkim_threads, thread_name_prefix="probe")
        self._check_pool = ThreadPoolExecutor(max_workers=dkim_threads, thread_name_prefix="check")
        self._spf_memo: Dict[str, _SPFEval] = {}
        self._spf_lock = threading.Lock()
        self._org_cache: Dict[str, Any] = {}
        self._org_lock = threading.Lock()
        self._wildcard_tlds: Dict[str, bool] = {}
        self._ssl_ctx = ssl.create_default_context()
        # Discovery results kept between runs (securityhub.cache.Store): full DKIM selector search, lookalikes,
        # name server consistency, zone transfer test, MTA-STS policy body. Core records are always queried.
        self.cache = cache
        self.discovery_max_age = discovery_max_age

    def _cached(self, section: str, key: str, cls, fn, fingerprint: Optional[str] = None):
        """fn() or, when a recent result is stored, that result (rebuilt as `cls`). Unknown / DNS-error
        results are never stored: they are retried on the next run."""
        if self.cache is None:
            return fn()
        stored = self.cache.get(section, key, self.discovery_max_age, fingerprint)
        if isinstance(stored, dict):
            try:
                names = {f.name for f in fields(cls)}
                data = {k: v for k, v in stored.items() if k in names and k != "issues"}
                return cls(**data, issues=[Issue(**i) for i in stored.get("issues") or []])
            except TypeError:
                pass  # stored by another version: compute again
        res = fn()
        if getattr(res, "status", None) not in ("unknown", "dns_error", "skipped"):
            self.cache.put(section, key, asdict(res), fingerprint)
        return res

    def close(self):
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._check_pool.shutdown(wait=False, cancel_futures=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _once_per_org(self, key: str, fn):
        """Compute fn() once per key (thread-safe), e.g. lookalikes per organizational domain."""
        with self._org_lock:
            entry = self._org_cache.get(key)
            if entry is None:
                entry = self._org_cache[key] = {"event": threading.Event(), "value": None, "owner": True}
                owner = True
            else:
                owner = False
        if owner:
            try:
                entry["value"] = fn()
            finally:
                entry["event"].set()
        else:
            entry["event"].wait()
        return entry["value"]

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def analyze_domain(self, domain, meta: Optional[DomainInput] = None) -> DomainResult:
        """Perform a complete email security analysis for a domain."""
        if isinstance(domain, DomainInput):
            meta, domain = domain, domain.domain
        t0 = time.monotonic()
        result = DomainResult(
            domain=domain,
            scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        if meta:
            result.tier, result.owner, result.bu, result.tags = meta.tier, meta.owner, meta.bu, list(meta.tags)
        try:
            self._analyze_into(result)
        except Exception as e:  # never lose a domain from the report
            result.error = f"{type(e).__name__}: {e}"
            result.issues.append(make_issue("DNS_ERROR", f"analysis aborted ({result.error})"))
        result.issues.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
        try:
            self._finalize(result)
        except Exception as e:  # pragma: no cover - reporting helpers must never break a scan
            result.error = result.error or f"finalize: {type(e).__name__}: {e}"
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    def _analyze_into(self, result: DomainResult) -> None:
        domain = result.domain
        sel, run = self.checks, self._run

        def timed(name, fn, *args):
            t = time.monotonic()
            value = fn(*args)
            result.timings[name] = result.timings.get(name, 0) + int((time.monotonic() - t) * 1000)
            return value

        # Existence (+ DNSSEC) - always performed
        soa = timed("soa", self.dns.query, domain, "SOA")
        if soa.status == "error":
            # A validating resolver answers SERVFAIL for DNSSEC-bogus zones: retry with CD=1.
            soa_cd = timed("soa", self.dns.query, domain, "SOA", True, True)
            if soa_cd.status != "error":
                self.dns.mark_bogus(domain)
                result.dnssec.status = "bogus"
                result.dnssec.issues.append(make_issue(
                    "DNSSEC_BOGUS", "answers only with DNSSEC checking disabled (CD=1)"))
                soa = soa_cd
            else:
                soa = timed("soa", self.dns.query, domain, "SOA", True)  # one more plain retry
        if soa.status == "nxdomain":
            result.exists = False
            result.profile = "nonexistent"
            self._mark_skipped(result)
            result.issues.append(make_issue("DOMAIN_NXDOMAIN"))
            return
        if soa.status == "error":
            # Name servers unreachable: every other query would burn the full timeout - stop here.
            result.profile = "unreachable"
            self._mark_skipped(result)
            for check, attr in CHECK_ATTRS.items():
                if check in sel:
                    getattr(result, attr).status = "unknown" if check in ("dnssec", "takeover", "axfr", "consistency", "lookalikes") else "dns_error"
            result.issues.append(make_issue(
                "DNS_ERROR", f"name servers unreachable ({soa.error}) - remaining checks skipped"))
            return
        if "dnssec" in run and result.dnssec.status != "bogus":
            if self.dns.validating is False:
                result.dnssec.status = "unknown"
            elif soa.ad:
                result.dnssec.status = "valid"
            else:
                result.dnssec.status = "missing"
                result.dnssec.issues.append(make_issue("DNSSEC_UNSIGNED"))

        # MX is always collected (decides the mail / non-mail profile);
        # MX host resolution only when the MX or takeover check is selected.
        result.mx = timed("mx", self._analyze_mx, domain, bool({"mx", "takeover"} & sel))
        # No MX at all (even with an A record, the implicit-MX fallback) or a Null MX: the domain is treated as
        # not handling mail - SPF and DKIM are then not applicable (their absence is not a finding)
        if result.mx.null_mx or result.mx.status == "missing":
            result.profile = "non-mail"
        mail_enabled = result.profile == "mail"

        # Independent checks run concurrently; DKIM probing stays in this thread (it fans out
        # on the probe pool). Checks that need other results (BIMI, takeover...) run afterwards.
        pending: Dict[str, Any] = {}

        def submit(check: str, fn, *args) -> None:
            pending[check] = self._check_pool.submit(timed, check, fn, *args)

        if "spf" in run:
            submit("spf", self._analyze_spf, domain, mail_enabled)
        if "dmarc" in run:
            submit("dmarc", self._analyze_dmarc, domain)
        if "mta-sts" in run:
            mx_hosts = [r.host for r in result.mx.records if r.host]
            submit("mta-sts", self._analyze_mta_sts, domain, mx_hosts, mail_enabled)
        if "tls-rpt" in run:
            submit("tls-rpt", self._analyze_tls_rpt, domain, mail_enabled)
        if "consistency" in run:
            submit("consistency", self._analyze_consistency, domain)
        if "caa" in run:
            submit("caa", self._analyze_caa, domain)
        if "axfr" in run:
            submit("axfr", self._analyze_axfr, domain)
        if "dkim" in run:
            result.dkim = timed("dkim", self._analyze_dkim, domain, mail_enabled, result.mx.providers)
        for check, fut in pending.items():
            setattr(result, CHECK_ATTRS[check], fut.result())
        if "bimi" in run:
            result.bimi = timed("bimi", self._analyze_bimi, domain, result.dmarc)
        if "takeover" in run:
            result.takeover = timed("takeover", self._analyze_takeover, result)
        if "lookalikes" in run:
            result.lookalikes = timed("lookalikes", self._analyze_lookalikes, result)
        if self.report_data:
            result.dmarc_reports = timed("reports", self._attach_reports, result)

        cross = self._cross_check(result)
        self._mark_skipped(result)
        result.issues = [i for c in CHECKS if c in sel for i in getattr(result, CHECK_ATTRS[c]).issues]
        result.issues += result.dmarc_reports.issues + cross

    def _mark_skipped(self, result: DomainResult) -> None:
        """Replace components that were not selected with an empty 'skipped' placeholder."""
        for check, attr in CHECK_ATTRS.items():
            if check not in self.checks:
                setattr(result, attr, type(getattr(result, attr))(status="skipped"))

    def _finalize(self, r: DomainResult) -> None:
        r.overall_score = self._calculate_score(r)
        r.compliance = self._evaluate_compliance(r)
        crit = sum(1 for i in r.issues if i.severity == "critical")
        r.priority = tier_weight(r.tier) * (100 - r.overall_score + 15 * crit)
        r.remediation = suggest_remediation(r, self.checks)
