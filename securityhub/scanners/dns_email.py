"""
MailGuard DNS v3 - Email Security Analyzer (Live DNS)

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

import argparse
import base64
import binascii
import csv
import email
import email.policy
import gzip
import html
import http.client
import importlib.util
import io
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..common import (EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, Parser, RateLimiter,
                      csv_safe, json_for_html)
from .. import ui

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
except ImportError:  # pragma: no cover
    raise ImportError("The DNS / e-mail module needs dnspython: pip install dnspython")

try:  # IDNA 2008 / UTS-46 (Python's built-in codec is IDNA 2003)
    import idna as _idna
except ImportError:  # pragma: no cover
    _idna = None

try:  # hardened XML parsing for DMARC reports
    from defusedxml import ElementTree as _SafeET
except ImportError:  # pragma: no cover
    _SafeET = None
import xml.etree.ElementTree as _ET

__version__ = "3.1.0"
USER_AGENT = f"MailGuardDNS/{__version__}"

# ---------------------------------------------------------------------------
# Findings catalogue: code -> (severity, protocol, title, recommendation)
# Central place to tune severities and wording.
# ---------------------------------------------------------------------------

FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # Domain / DNS
    "DOMAIN_NXDOMAIN": ("critical", "DNS", "Domain does not exist (NXDOMAIN)",
                        "Verify the domain name or remove it from the assessment scope"),
    "DNS_ERROR": ("warning", "DNS", "DNS query failed (timeout/SERVFAIL)",
                  "Some checks could not be completed - re-run the scan or check the authoritative name servers"),
    "DNSSEC_UNSIGNED": ("info", "DNSSEC", "DNSSEC not enabled",
                        "Sign the zone to protect MX, SPF, DMARC and MTA-STS records against spoofing"),
    # MX
    "MX_MISSING": ("warning", "MX", "No MX records and no A/AAAA fallback",
                   "If the domain does not receive mail, publish a Null MX (\"0 .\", RFC 7505)"),
    "MX_IMPLICIT": ("warning", "MX", "No MX records - mail falls back to the A/AAAA record (implicit MX)",
                    "Publish explicit MX records, or a Null MX if the domain does not receive mail"),
    "MX_NULL": ("info", "MX", "Null MX - domain does not accept mail (RFC 7505)",
                "Pair it with 'v=spf1 -all' and DMARC p=reject to prevent spoofing"),
    "MX_NULL_MIXED": ("warning", "MX", "Null MX published together with other MX records",
                      "A Null MX must be the only MX record - remove it or the other MX records"),
    "MX_PARTIAL": ("warning", "MX", "Not all MX hosts use a protected gateway",
                   "Route all inbound mail through the protected gateway (backup MX can bypass filtering)"),
    "MX_UNPROTECTED": ("warning", "MX", "No known protected email gateway",
                       "Consider Proofpoint, Microsoft 365 EOP/Defender, Mimecast or similar"),
    "MX_DANGLING": ("critical", "MX", "MX host does not resolve",
                    "Remove or fix the stale MX - a dangling MX can be hijacked if its domain expires"),
    "MX_CNAME": ("info", "MX", "MX host is a CNAME (RFC 5321 violation)",
                 "Point the MX record to the canonical host name"),
    # SPF
    "SPF_MISSING": ("critical", "SPF", "No SPF record",
                    "Publish an SPF record authorizing your legitimate senders (or 'v=spf1 -all' if the domain sends no mail)"),
    "SPF_MULTIPLE": ("critical", "SPF", "Multiple SPF records (PermError)",
                     "Merge them into a single 'v=spf1' record"),
    "SPF_SYNTAX": ("critical", "SPF", "SPF syntax error (PermError)",
                   "Fix the invalid term(s) - receivers treat the whole record as broken"),
    "SPF_LOOKUP_LIMIT": ("critical", "SPF", "SPF exceeds the 10 DNS lookup limit (PermError)",
                         "Remove unused includes, replace a/mx with ip4/ip6, or move senders to subdomains"),
    "SPF_LOOKUP_NEAR": ("warning", "SPF", "SPF close to the 10 DNS lookup limit",
                        "Watch the lookup count when adding new services"),
    "SPF_VOID_LIMIT": ("critical", "SPF", "More than 2 void DNS lookups (PermError)",
                       "Remove includes/a/mx pointing to names that do not exist"),
    "SPF_VOID": ("warning", "SPF", "Void DNS lookups in SPF",
                 "Remove mechanisms pointing to names that return no records"),
    "SPF_INCLUDE_NO_SPF": ("critical", "SPF", "Included domain has no SPF record (PermError)",
                           "Remove or fix the include - the target publishes no SPF record"),
    "SPF_LOOP": ("critical", "SPF", "SPF include/redirect loop (PermError)",
                 "Break the circular include chain"),
    "SPF_DNS_ERROR": ("warning", "SPF", "SPF lookup failed (DNS error)",
                      "Re-run the scan; persistent errors make receivers return TempError"),
    "SPF_PASS_ALL": ("critical", "SPF", "'+all' authorizes the whole Internet",
                     "Replace '+all' with '-all' immediately"),
    "SPF_NEUTRAL": ("warning", "SPF", "Neutral '?all' provides no protection",
                    "Use '-all' (or '~all' together with an enforcing DMARC policy)"),
    "SPF_NO_ALL": ("warning", "SPF", "No 'all' mechanism or redirect (defaults to neutral)",
                   "Terminate the record with '-all' or '~all'"),
    "SPF_SOFTFAIL": ("warning", "SPF", "Soft fail ('~all') used",
                     "Move to '-all' once all senders are validated, or enforce DMARC"),
    "SPF_PTR": ("warning", "SPF", "Deprecated 'ptr' mechanism used",
                "Replace ptr with ip4/ip6 or include (RFC 7208 §5.5)"),
    "SPF_BROAD_IP": ("warning", "SPF", "Very broad IP range authorized",
                     "Restrict ip4/ip6 ranges to the actual sending hosts"),
    "SPF_MACROS": ("info", "SPF", "SPF macros used - not fully evaluated",
                   "Lookup counts involving macros are estimated"),
    "SPF_MX_TOO_MANY": ("warning", "SPF", "'mx' mechanism resolves to more than 10 hosts (PermError)",
                        "Use ip4/ip6 or include instead of mx"),
    "SPF_PARKED_NOT_STRICT": ("warning", "SPF", "Non-mail domain without a strict 'v=spf1 -all' record",
                              "For domains that send no mail publish exactly 'v=spf1 -all'"),
    # DKIM
    "DKIM_NOT_FOUND": ("warning", "DKIM", "No DKIM key found on the probed selectors",
                       "Enable DKIM signing with your provider (custom selectors can be passed with --selectors)"),
    "DKIM_WEAK": ("warning", "DKIM", "DKIM key shorter than 2048 bit",
                  "Rotate to a 2048-bit RSA (or Ed25519 + RSA) key"),
    "DKIM_BROKEN_KEY": ("critical", "DKIM", "DKIM key shorter than 1024 bit (rejected by receivers, RFC 8301)",
                        "Rotate to a 2048-bit RSA key immediately"),
    "DKIM_INVALID": ("warning", "DKIM", "Unparseable or unsupported DKIM key",
                     "Re-publish the selector using the value provided by your mail platform"),
    "DKIM_TESTING": ("info", "DKIM", "DKIM selector in testing mode (t=y)",
                     "Remove t=y once signing is validated"),
    "DKIM_SHA1": ("warning", "DKIM", "DKIM selector restricted to SHA-1 (h=sha1)",
                  "Allow sha256 (RFC 8301)"),
    "DKIM_REVOKED": ("info", "DKIM", "Revoked DKIM selector (empty p=)",
                     "Fine after a rotation - remove it when no longer needed"),
    "DKIM_DNS_ERROR": ("warning", "DKIM", "DKIM probing failed (DNS errors)",
                       "Re-run the scan"),
    # DMARC
    "DMARC_MISSING": ("critical", "DMARC", "No DMARC record",
                      "Publish 'v=DMARC1; p=none; rua=mailto:...' and move towards p=reject"),
    "DMARC_MULTIPLE": ("critical", "DMARC", "Multiple DMARC records (DMARC is ignored)",
                       "Keep exactly one record at _dmarc"),
    "DMARC_INVALID": ("critical", "DMARC", "Invalid DMARC record (missing or bad p= tag)",
                      "Use p=none, p=quarantine or p=reject right after v=DMARC1"),
    "DMARC_NONE": ("critical", "DMARC", "Policy p=none - monitoring only, no protection",
                   "Analyze rua reports, then move to p=quarantine and p=reject"),
    "DMARC_QUARANTINE": ("info", "DMARC", "Policy p=quarantine - partial protection",
                         "Move to p=reject for full protection"),
    "DMARC_PCT": ("warning", "DMARC", "Policy applied to less than 100% of messages (pct<100)",
                  "Raise pct to 100 (pct is removed in DMARCbis)"),
    "DMARC_SP_NONE": ("warning", "DMARC", "Subdomain policy weaker than the domain policy",
                      "Set sp= (and np=) to quarantine/reject - subdomains are an easy spoofing target"),
    "DMARC_NO_RUA": ("warning", "DMARC", "No aggregate reporting (rua) configured",
                     "Add rua=mailto:... to get visibility on who sends as your domain"),
    "DMARC_RUA_INVALID": ("warning", "DMARC", "Invalid rua destination (must be mailto:)",
                          "Use rua=mailto:address@domain"),
    "DMARC_RUA_UNAUTHORIZED": ("warning", "DMARC", "External rua destination not authorized (reports are dropped)",
                               "The receiving domain must publish <domain>._report._dmarc.<rua-domain> TXT \"v=DMARC1\""),
    "DMARC_INHERITED": ("info", "DMARC", "DMARC policy inherited from the organizational domain",
                        "Publish a dedicated _dmarc record if this subdomain needs a different policy"),
    "DMARC_DNS_ERROR": ("warning", "DMARC", "DMARC lookup failed (DNS error)",
                        "Re-run the scan"),
    "DMARC_PARKED_NOT_REJECT": ("warning", "DMARC", "Non-mail domain without DMARC p=reject",
                                "For domains that send no mail publish 'v=DMARC1; p=reject'"),
    # Transport / brand
    "MTASTS_MISSING": ("info", "MTA-STS", "MTA-STS not configured",
                       "Publish _mta-sts TXT and an HTTPS policy to enforce TLS on inbound mail"),
    "MTASTS_TESTING": ("info", "MTA-STS", "MTA-STS in testing mode",
                       "Switch to mode: enforce once TLS-RPT reports are clean"),
    "MTASTS_NONE": ("warning", "MTA-STS", "MTA-STS policy mode 'none'",
                    "Use mode: testing or enforce"),
    "MTASTS_POLICY_ERROR": ("warning", "MTA-STS", "MTA-STS policy unreachable or invalid",
                            "Serve https://mta-sts.<domain>/.well-known/mta-sts.txt (valid cert, HTTP 200, text/plain, no redirects)"),
    "MTASTS_MX_MISMATCH": ("warning", "MTA-STS", "MX hosts not covered by the MTA-STS policy",
                           "Add every MX host to the policy 'mx:' lines (in enforce mode mail will bounce)"),
    "TLSRPT_MISSING": ("info", "TLS-RPT", "TLS-RPT not configured",
                       "Publish _smtp._tls TXT \"v=TLSRPTv1; rua=mailto:...\" to receive TLS failure reports"),
    "TLSRPT_INVALID": ("warning", "TLS-RPT", "Invalid TLS-RPT record",
                       "rua must be mailto: or https:"),
    "BIMI_NO_ENFORCEMENT": ("warning", "BIMI", "BIMI published without an enforcing DMARC policy",
                            "BIMI requires DMARC p=quarantine/reject at pct=100"),
    # Cross-checks
    "X_DMARC_SPF_BROKEN": ("critical", "Cross-Check", "DMARC configured but SPF is missing or broken",
                           "DMARC can only pass through DKIM - fix SPF"),
    "X_DMARC_NO_DKIM": ("warning", "Cross-Check", "DMARC configured but no DKIM found",
                        "DMARC relies on SPF only, which breaks on forwarding - enable DKIM"),
    "X_ENFORCED_NO_AUTH": ("critical", "Cross-Check", "Enforcing DMARC without working SPF or DKIM",
                           "Legitimate mail from this domain will fail DMARC - fix SPF/DKIM (unless it sends no mail)"),
}


FINDINGS.update({
    # DNS / registration
    "DNSSEC_BOGUS": ("critical", "DNSSEC", "DNSSEC validation fails (bogus signatures)",
                     "Fix the DS/DNSKEY chain or re-sign the zone - validating resolvers and MTAs cannot resolve this domain"),
    "DOMAIN_EXPIRING": ("warning", "Registration", "Domain registration expires within 30 days",
                        "Renew now and enable auto-renew and registrar lock"),
    "DOMAIN_EXPIRED": ("critical", "Registration", "Domain registration expired or pending deletion",
                       "Renew immediately - an expired domain can be re-registered by anyone"),
    "DMARC_BAD_TAG": ("warning", "DMARC", "Invalid DMARC tag value",
                      "Fix the tag syntax (pct must be 0-100, aspf/adkim must be r or s)"),
    # Takeover
    "TAKEOVER_UNREGISTERED": ("critical", "Takeover", "Dependency domain is not registered (takeover risk)",
                              "Remove every reference (include, MX, NS, CNAME, rua) or register the domain - anyone can buy it"),
    "TAKEOVER_EXPIRED": ("critical", "Takeover", "Dependency domain expired or pending deletion",
                         "Remove the reference or make sure the owner renews it - it can be re-registered by anyone"),
    "TAKEOVER_EXPIRING": ("warning", "Takeover", "Dependency domain expires within 30 days",
                          "Confirm the owner renews it, or plan to remove the reference"),
    "TAKEOVER_UNRESOLVABLE": ("warning", "Takeover", "Dependency domain is registered but does not resolve",
                              "Check with the owner: domains on hold or in grace period often lapse next"),
    "TAKEOVER_DANGLING_CNAME": ("warning", "Takeover", "Dangling CNAME to a name that does not exist",
                                "Remove the CNAME or re-provision the target - the service account may be claimable by others"),
    "TAKEOVER_LAME_NS": ("critical", "Takeover", "Name server host does not resolve (lame delegation)",
                         "Fix the NS set at the registrar - a lame NS on a lapsed domain allows full zone takeover"),
    # DMARC aggregate reports
    "REPORT_UNALIGNED_SOURCES": ("warning", "Reports", "Senders with valid SPF/DKIM fail DMARC alignment",
                                 "Configure DKIM with your domain (or a custom MAIL FROM) on these senders before enforcing"),
    "REPORT_SPOOFING": ("warning", "Reports", "Unauthenticated mail using this domain is being delivered",
                        "Move DMARC to p=quarantine / p=reject once legitimate senders are aligned"),
    "REPORT_READY_FOR_REJECT": ("info", "Reports", "DMARC reports indicate the domain is ready for p=reject",
                                "At least 98% of legitimate volume passes DMARC - move to p=reject"),
    # Lookalikes
    "LOOKALIKE_FRESH": ("critical", "Lookalike", "Recently registered lookalike domain with mail servers",
                        "Investigate now: block it on the mail gateway, alert users and request takedown"),
    "LOOKALIKE_MX": ("warning", "Lookalike", "Registered lookalike domain with mail servers",
                     "Monitor it, block it on the mail gateway and consider takedown or defensive registration"),
    "LOOKALIKE_REGISTERED": ("info", "Lookalike", "Registered lookalike domains without mail servers",
                             "Keep under watch - MX records can be added at any time"),
    # Consistency
    "DNS_AUTH_INCONSISTENT": ("warning", "Consistency", "Authoritative name servers return different data",
                              "Synchronize the zone on every name server (stale secondary or failed transfer)"),
    "DNS_INCONSISTENT": ("warning", "Consistency", "Public resolvers disagree with the authoritative servers",
                         "Usually a recent change still cached; if it persists investigate split-horizon or tampering"),
})

SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

# Indicative mapping of finding protocols to frameworks / sender requirements.
FRAMEWORK_MAP: Dict[str, List[str]] = {
    "SPF": ["Gmail/Yahoo senders", "Microsoft senders", "NIS2 Art.21(2)(g)", "ISO 27001 A.5.14"],
    "DKIM": ["Gmail/Yahoo senders", "Microsoft senders", "NIS2 Art.21(2)(h)", "ISO 27001 A.8.24"],
    "DMARC": ["Gmail/Yahoo senders", "Microsoft senders", "NIS2 Art.21(2)(g)", "ISO 27001 A.5.14"],
    "Cross-Check": ["Gmail/Yahoo senders", "Microsoft senders", "ISO 27001 A.5.14"],
    "MX": ["ISO 27001 A.8.21"],
    "MTA-STS": ["NIS2 Art.21(2)(h)", "ISO 27001 A.8.24"],
    "TLS-RPT": ["ISO 27001 A.8.16"],
    "DNSSEC": ["NIS2 Art.21(2)(e)", "ISO 27001 A.8.20"],
    "DNS": ["ISO 27001 A.8.20"],
    "Registration": ["NIS2 Art.21(2)(i)", "ISO 27001 A.5.9"],
    "Takeover": ["NIS2 Art.21(2)(d)", "ISO 27001 A.5.19", "ISO 27001 A.5.21"],
    "Reports": ["NIS2 Art.21(2)(f)", "ISO 27001 A.8.16"],
    "Lookalike": ["NIS2 Art.21(2)(b)", "ISO 27001 A.5.7"],
    "Consistency": ["ISO 27001 A.8.20"],
    "BIMI": [],
}

# Compliance profiles evaluated per domain (what DNS can show).
COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "gmail_yahoo": ("Gmail/Yahoo bulk senders",
                    "SPF and DKIM (key >= 1024 bit) published, DMARC p=none or stronger. "
                    "Alignment, PTR, TLS, unsubscribe and spam rate are not visible from DNS."),
    "microsoft": ("Microsoft high-volume senders",
                  "SPF and DKIM published, DMARC p=none or stronger. Alignment is not visible from DNS."),
    "dmarc_enforcement": ("DMARC enforcement",
                          "p=reject at 100%, subdomain policy not none, aggregate reports enabled."),
    "transport": ("Inbound TLS enforcement", "MTA-STS in enforce mode and TLS-RPT reporting."),
}

TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
TIER_ALIASES = {
    "critical": "critical", "critica": "critical", "crit": "critical", "c": "critical", "1": "critical",
    "high": "high", "alta": "high", "alto": "high", "h": "high", "2": "high",
    "medium": "medium", "media": "medium", "medio": "medium", "m": "medium", "3": "medium", "": "medium",
    "low": "low", "bassa": "low", "basso": "low", "l": "low", "4": "low",
}

# Selectable checks (--checks / --skip): name -> weight in the 0-100 score.
# With a subset, the score is normalized over the selected weights.
CHECKS: Dict[str, int] = {
    "mx": 0, "spf": 25, "dkim": 25, "dmarc": 35, "mta-sts": 7, "tls-rpt": 3, "bimi": 0, "dnssec": 5,
    "takeover": 0, "consistency": 0, "lookalikes": 0,
}
DEFAULT_CHECKS = ["mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt", "bimi", "dnssec", "takeover"]
CHECK_ALIASES = {
    "mtasts": "mta-sts", "mta_sts": "mta-sts", "sts": "mta-sts",
    "tlsrpt": "tls-rpt", "tls_rpt": "tls-rpt", "tls": "tls-rpt",
    "lookalike": "lookalikes", "typosquatting": "lookalikes", "rdap": "takeover",
}
CHECK_LABELS = {"mx": "MX", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "mta-sts": "MTA-STS",
                "tls-rpt": "TLS-RPT", "bimi": "BIMI", "dnssec": "DNSSEC", "takeover": "Takeover",
                "consistency": "Consistency", "lookalikes": "Lookalikes"}
# Data other checks need: collected silently, never reported unless selected.
# (MX is always collected in light mode: it decides whether the domain handles mail.)
CHECK_DEPENDENCIES = {"bimi": {"dmarc"}, "takeover": {"spf", "dkim", "dmarc", "tls-rpt"}}
CHECK_ATTRS = {"mx": "mx", "spf": "spf", "dkim": "dkim", "dmarc": "dmarc", "mta-sts": "mta_sts",
               "tls-rpt": "tls_rpt", "bimi": "bimi", "dnssec": "dnssec", "takeover": "takeover",
               "consistency": "consistency", "lookalikes": "lookalikes"}
# Findings that make "fully protected" impossible regardless of the other controls.
SCORE_CAP_CODES = {"TAKEOVER_UNREGISTERED": 30, "TAKEOVER_EXPIRED": 30, "TAKEOVER_LAME_NS": 30,
                   "DNSSEC_BOGUS": 30, "DOMAIN_EXPIRED": 20}


def parse_checks(spec: str = "all", skip: str = "") -> List[str]:
    """'all' = default checks, 'full' = every check; names can be combined: 'all,lookalikes'."""
    def names(text: str) -> List[str]:
        out = []
        for raw in re.split(r"[,\s]+", (text or "").strip().lower()):
            if not raw:
                continue
            name = CHECK_ALIASES.get(raw, raw)
            if name not in ("all", "full") and name not in CHECKS:
                raise ValueError(f"unknown check '{raw}' (valid: {', '.join(CHECKS)}, all, full)")
            out.append(name)
        return out

    selected: Set[str] = set()
    for n in names(spec) or ["all"]:
        if n == "all":
            selected |= set(DEFAULT_CHECKS)
        elif n == "full":
            selected |= set(CHECKS)
        else:
            selected.add(n)
    selected -= set(names(skip))
    if not selected:
        raise ValueError("no checks left to run")
    return [c for c in CHECKS if c in selected]

DEFAULT_DKIM_SELECTORS = [
    # generic
    "default", "dkim", "mail", "email", "smtp", "mx", "key1", "key2", "sig1", "dk",
    "s1", "s2", "k1", "k2", "k3",
    # Microsoft 365 / Google Workspace
    "selector1", "selector2", "google",
    # ESPs and SaaS
    "mandrill", "mailjet", "mailgun", "mg", "pic", "krs", "smtpapi", "sendgrid",
    "amazonses", "postmark", "pm", "mailchimp", "everlytickey1", "everlytickey2",
    "ctct1", "ctct2", "hubspot", "zendesk1", "zendesk2", "zendesk", "freshdesk",
    "salesforce", "sf1", "sf2",
    # mailbox providers
    "zoho", "zmail", "protonmail", "protonmail2", "protonmail3",
    "fm1", "fm2", "fm3", "mxvault",
]

# suffix -> provider (matched on label boundaries, most specific first)
PROTECTED_MX_PROVIDERS: Dict[str, str] = {
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint Essentials",
    "mail.protection.outlook.com": "Microsoft 365 / EOP",
    "outlook.com": "Microsoft 365",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "mimecast.com": "Mimecast",
    "mimecast.co.za": "Mimecast",
    "mimecast-offshore.com": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "messagelabs.com": "Symantec/Broadcom",
    "iphmx.com": "Cisco Secure Email",
    "fireeyecloud.com": "Trellix",
    "sophos.com": "Sophos",
    "trendmicro.com": "Trend Micro",
    "trendmicro.eu": "Trend Micro",
    "hornetsecurity.com": "Hornetsecurity",
    "mailcontrol.com": "Forcepoint",
    "mxrecord.io": "Cloudflare Area 1",
    "mxrecord.mx": "Cloudflare Area 1",
    "libraesva.com": "Libraesva",
    "retarus.com": "Retarus",
    "retarus.net": "Retarus",
    "vadesecure.com": "Vade",
    "antispamcloud.com": "N-able SpamExperts",
    "spamtitan.com": "SpamTitan",
    "spamh.com": "SpamHero",
    "securemx.net": "SecureMX",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "protonmail.ch": "Proton Mail",
    "messagingengine.com": "Fastmail",
}
_MX_SUFFIXES = sorted(PROTECTED_MX_PROVIDERS, key=len, reverse=True)

SPF_RE = re.compile(r"^v=spf1(\s|$)", re.I)
SPF_TERM_RE = re.compile(r"([+\-~?]?)([A-Za-z][A-Za-z0-9_.\-]*)(?:([:=/])(.*))?")
SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DMARC_RE = re.compile(r"^v\s*=\s*DMARC1\s*(;|$)", re.I)
DOMAIN_RE = re.compile(r"(?=.{4,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+(xn--[a-z0-9-]{1,59}|[a-z]{2,63})")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

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
    source: str = "probe"            # probe | report (seen in DMARC aggregate reports)


@dataclass
class DKIMResult:
    status: str = "missing"  # valid, partial, error, missing, na, dns_error, skipped
    selectors: List[DKIMSelector] = field(default_factory=list)
    valid_selectors: int = 0
    total_selectors: int = 0
    weak_keys: int = 0
    probed: int = 0
    dangling: List[dict] = field(default_factory=list)  # {"name", "target"}
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
    takeover: TakeoverResult = field(default_factory=TakeoverResult)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_tags(record: str) -> Dict[str, str]:
    """Parse 'k=v; k2=v2' tag lists (DKIM, DMARC, MTA-STS, TLS-RPT, BIMI). First occurrence wins."""
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        if k and k not in tags:
            tags[k] = v.strip()
    return tags


def _der_header(buf: bytes, i: int) -> Tuple[int, int, int]:
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, i, length


def rsa_key_bits(b64: str) -> Optional[int]:
    """Exact RSA modulus size from a DKIM p= value (SubjectPublicKeyInfo or PKCS#1)."""
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None

    def modulus_bits(buf: bytes) -> Optional[int]:
        tag, i, _ = _der_header(buf, 0)
        if tag != 0x30:
            return None
        tag2, j, ln2 = _der_header(buf, i)
        if tag2 == 0x30:  # SPKI: AlgorithmIdentifier, then BIT STRING
            tag3, k, ln3 = _der_header(buf, j + ln2)
            if tag3 != 0x03:
                return None
            return modulus_bits(buf[k + 1:k + ln3])  # skip "unused bits" byte
        if tag2 == 0x02:  # PKCS#1 RSAPublicKey: modulus INTEGER
            return int.from_bytes(buf[j:j + ln2], "big").bit_length()
        return None

    try:
        return modulus_bits(der)
    except (IndexError, ValueError):
        return None


def match_provider(host: str) -> Optional[str]:
    for suffix in _MX_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return PROTECTED_MX_PROVIDERS[suffix]
    return None


def issues_from_problems(problems: List[Tuple[str, str]], max_details: int = 3) -> List[Issue]:
    """Group (code, detail) tuples into one Issue per code."""
    grouped: Dict[str, List[str]] = {}
    for code, detail in problems:
        lst = grouped.setdefault(code, [])
        if detail and detail not in lst:
            lst.append(detail)
    out = []
    for code, details in grouped.items():
        txt = ", ".join(details[:max_details])
        if len(details) > max_details:
            txt += f" (+{len(details) - max_details} more)"
        out.append(make_issue(code, txt or None))
    return out




def cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    path = os.path.join(base, "mailguard")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = os.path.join(os.getcwd(), ".mailguard-cache")
        os.makedirs(path, exist_ok=True)
    return path


def http_get(url: str, timeout: float, accept: str = "*/*", max_bytes: int = 8 * 1024 * 1024) -> Tuple[int, bytes]:
    """Plain HTTPS GET for well-known public endpoints (PSL, IANA bootstrap, RDAP)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            return resp.status, resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        return e.code, b""


# ---------------------------------------------------------------------------
# Public Suffix List (organizational / registrable domain)
# ---------------------------------------------------------------------------

PSL_URLS = [
    "https://publicsuffix.org/list/public_suffix_list.dat",
    "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",
]


class PublicSuffixList:
    def __init__(self, text: str, source: str = ""):
        self.rules: Set[str] = set()
        self.wildcards: Set[str] = set()
        self.exceptions: Set[str] = set()
        self.source = source
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            try:
                if rule.startswith("!"):
                    self.exceptions.add(to_ascii(rule[1:]))
                elif rule.startswith("*."):
                    self.wildcards.add(to_ascii(rule[2:]))
                else:
                    self.rules.add(to_ascii(rule))
            except UnicodeError:
                continue
        if len(self.rules) < 1000:
            raise ValueError("public suffix list looks truncated")

    def registrable(self, domain: str) -> Optional[str]:
        """eTLD+1 (e.g. comune.milano.it -> comune.milano.it, a.b.example.co.uk -> example.co.uk)."""
        labels = domain.lower().rstrip(".").split(".")
        suffix_len = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exceptions:
                suffix_len = len(labels) - i - 1
                break
            if cand in self.rules or (i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wildcards):
                suffix_len = len(labels) - i
                break
        if suffix_len >= len(labels):
            return None  # the name itself is a public suffix
        return ".".join(labels[-(suffix_len + 1):])

    @classmethod
    def load(cls, path: Optional[str] = None, allow_download: bool = True, timeout: float = 10.0,
             max_age_days: int = 7) -> Tuple[Optional["PublicSuffixList"], str]:
        if path:
            with open(path, encoding="utf-8") as f:
                return cls(f.read(), path), f"Public Suffix List: {path}"
        cached = os.path.join(cache_dir(), "public_suffix_list.dat")
        fresh = os.path.exists(cached) and time.time() - os.path.getmtime(cached) < max_age_days * 86400
        if fresh:
            try:
                with open(cached, encoding="utf-8") as f:
                    return cls(f.read(), cached), "Public Suffix List: cached"
            except (OSError, ValueError):
                pass
        if allow_download:
            for url in PSL_URLS:
                try:
                    status, body = http_get(url, timeout)
                    if status == 200:
                        psl = cls(body.decode("utf-8"), url)
                        try:
                            with open(cached, "wb") as f:
                                f.write(body)
                        except OSError:
                            pass
                        return psl, "Public Suffix List: downloaded"
                except Exception:
                    continue
        if os.path.exists(cached):
            try:
                with open(cached, encoding="utf-8") as f:
                    return cls(f.read(), cached), "Public Suffix List: stale cache"
            except (OSError, ValueError):
                pass
        if importlib.util.find_spec("tldextract") is not None:  # tldextract ships an offline snapshot
            return None, "Public Suffix List: tldextract snapshot"
        else:
            return None, ("WARNING: Public Suffix List unavailable - organizational domains are guessed "
                          "(use --psl-file or install tldextract)")


_PSL: Optional[PublicSuffixList] = None
_TLD_EXTRACT = None
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar", "com.tr", "co.za",
    "com.cn", "com.hk", "com.sg", "co.in", "co.il", "com.tw", "co.kr", "gov.it",
}


def set_psl(psl: Optional[PublicSuffixList]) -> None:
    global _PSL, _TLD_EXTRACT
    _PSL = psl
    if psl is None and _TLD_EXTRACT is None:
        try:
            import tldextract
            _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            _TLD_EXTRACT = None


def org_domain(domain: str) -> str:
    """Organizational (registrable) domain via the Public Suffix List."""
    domain = domain.lower().rstrip(".")
    if _PSL is not None:
        return _PSL.registrable(domain) or domain
    if _TLD_EXTRACT is not None:
        try:
            ext = _TLD_EXTRACT(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def to_ascii(host: str) -> str:
    """IDNA 2008 / UTS-46 (non-transitional): 'straße.de' stays 'xn--strae-oqa.de'."""
    host = host.strip().rstrip(".").lower()
    if host.isascii():
        return host
    if _idna is not None:
        return _idna.encode(host, uts46=True, transitional=False).decode("ascii")
    if any(ch in host for ch in "ßς\u200c\u200d"):
        raise UnicodeError("this name needs IDNA 2008 - pip install idna")
    return host.encode("idna").decode("ascii")


def normalize_domain(raw: str) -> Optional[str]:
    """Accepts domains, URLs, e-mail addresses; returns an ASCII (IDNA) lowercase domain or None."""
    s = raw.split("#", 1)[0].strip().strip(",;\"'")
    if not s:
        return None
    if "://" in s:
        s = urlparse(s).hostname or ""
    s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = s.strip().rstrip(".").lower()
    if s.startswith("*."):
        s = s[2:]
    try:
        s = to_ascii(s)
    except (UnicodeError, ValueError, Exception):
        return None
    return s if DOMAIN_RE.fullmatch(s) else None


def tier_weight(tier: str) -> int:
    return TIER_WEIGHTS.get(tier, 2)


# ---------------------------------------------------------------------------
# DNS client: shared cache, in-flight coalescing, retry, rate limit, CD for bogus zones
# ---------------------------------------------------------------------------

@dataclass
class DNSAnswer:
    status: str  # ok, nodata, nxdomain, error
    records: list = field(default_factory=list)
    ad: bool = False
    canonical: Optional[str] = None  # CNAME target (also set on NXDOMAIN = dangling CNAME)
    error: Optional[str] = None




class DNSClient:
    """Thread-safe resolver wrapper.
    - answers are memoized for the run; concurrent identical queries are coalesced
    - errors are retried once and only cached for ERROR_TTL seconds, so a transient
      timeout on a shared include does not poison every other domain
    - zones marked bogus (broken DNSSEC) are queried with the CD bit"""

    ERROR_TTL = 60.0

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 5.0,
                 use_system: bool = False, qps: float = 0):
        self.timeout = timeout
        self.resolver = self._make_resolver(nameservers, use_system, timeout, cd=False)
        self.resolver_cd = self._make_resolver(nameservers, use_system, timeout, cd=True)
        self.nameservers = [str(n) for n in self.resolver.nameservers]
        self.validating: Optional[bool] = None  # set by preflight()
        self._memo: Dict[tuple, Tuple[DNSAnswer, float]] = {}
        self._inflight: Dict[tuple, threading.Event] = {}
        self._bogus: Set[str] = set()
        self._lock = threading.Lock()
        self._rate = RateLimiter(qps) if qps and qps > 0 else None
        self.stats = Counter()

    @staticmethod
    def _make_resolver(nameservers, use_system, timeout, cd):
        if use_system or not nameservers:
            r = dns.resolver.Resolver(configure=True)
        else:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = list(nameservers)
        # Total budget per query = timeout; each attempt gets half of it so a lost UDP
        # packet fails over to the next resolver.
        r.lifetime = timeout
        r.timeout = max(1.0, timeout / 2)
        # AD in the query (RFC 6840 §5.7) instead of DO: DNSSEC status without RRSIG bloat,
        # so answers stay small (no truncation, no TCP retries).
        r.flags = dns.flags.RD | (dns.flags.CD if cd else dns.flags.AD)
        r.use_edns(0, 0, 1232)
        return r

    def mark_bogus(self, zone: str) -> None:
        with self._lock:
            self._bogus.add(zone.lower().rstrip("."))
            # drop cached SERVFAILs for that zone so they are re-queried with CD
            for key in [k for k, (a, _) in self._memo.items() if a.status == "error" and self._in_zone(k[0], zone)]:
                del self._memo[key]

    @staticmethod
    def _in_zone(name: str, zone: str) -> bool:
        return name == zone or name.endswith("." + zone)

    def _cd_for(self, name: str) -> bool:
        return any(self._in_zone(name, z) for z in self._bogus)

    def query(self, name: str, rdtype: str, fresh: bool = False, cd: Optional[bool] = None) -> DNSAnswer:
        name = name.lower().rstrip(".")
        if cd is None:
            with self._lock:
                cd = self._cd_for(name)
        key = (name, rdtype, bool(cd))
        while True:
            with self._lock:
                if not fresh:
                    hit = self._memo.get(key)
                    if hit is not None:
                        ans, ts = hit
                        if ans.status != "error" or time.monotonic() - ts < self.ERROR_TTL:
                            self.stats["cache_hits"] += 1
                            return ans
                event = self._inflight.get(key)
                if event is None:
                    event = self._inflight[key] = threading.Event()
                    break
                self.stats["coalesced"] += 1
            event.wait()
            fresh = False
        ans = DNSAnswer("error", error="internal error")
        try:
            resolver = self.resolver_cd if cd else self.resolver
            ans = self._resolve(name, rdtype, resolver)
            if ans.status == "error":  # one immediate retry before giving up
                self.stats["retries"] += 1
                ans = self._resolve(name, rdtype, resolver)
        finally:
            with self._lock:
                self._memo[key] = (ans, time.monotonic())
                self.stats["queries"] += 1
                if ans.status == "error":
                    self.stats["errors"] += 1
                del self._inflight[key]
            event.set()
        return ans

    def _resolve(self, name: str, rdtype: str, resolver) -> DNSAnswer:
        if self._rate:
            self._rate.wait()
        try:
            a = resolver.resolve(name, rdtype, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN as e:
            canonical = None
            try:
                c = str(e.canonical_name).rstrip(".").lower()
                canonical = c if c != name else None
            except Exception:
                pass
            return DNSAnswer("nxdomain", canonical=canonical)
        except dns.resolver.NoNameservers:
            return DNSAnswer("error", error="SERVFAIL")
        except dns.exception.Timeout:
            return DNSAnswer("error", error="timeout")
        except dns.exception.DNSException as e:
            return DNSAnswer("error", error=type(e).__name__)
        except Exception as e:  # defensive: malformed names etc.
            return DNSAnswer("error", error=str(e) or type(e).__name__)

        ad = bool(a.response.flags & dns.flags.AD)
        canonical = str(a.canonical_name).rstrip(".").lower()
        canonical = canonical if canonical != name else None
        if a.rrset is None:
            return DNSAnswer("nodata", ad=ad, canonical=canonical)
        records: list = []
        for r in a.rrset:
            if rdtype == "TXT":
                records.append(b"".join(r.strings).decode("utf-8", errors="replace"))
            elif rdtype == "MX":
                records.append((int(r.preference), str(r.exchange).rstrip(".").lower()))
            elif rdtype in ("NS", "CNAME", "PTR"):
                records.append(str(r.target).rstrip(".").lower())
            else:
                records.append(r.to_text())
        return DNSAnswer("ok", records, ad, canonical)

    def has_address(self, host: str) -> Optional[bool]:
        """True if A or AAAA exists, False if neither, None on DNS error."""
        a = self.query(host, "A")
        if a.status == "ok":
            return True
        aaaa = self.query(host, "AAAA")
        if aaaa.status == "ok":
            return True
        if "error" in (a.status, aaaa.status):
            return None
        return False

    def addresses(self, host: str) -> List[str]:
        out: List[str] = []
        for rdtype in ("A", "AAAA"):
            ans = self.query(host, rdtype)
            if ans.status == "ok":
                out.extend(ans.records)
        return out

    def ptr(self, ip: str) -> Optional[str]:
        try:
            rev = dns.reversename.from_address(ip).to_text()
        except Exception:
            return None
        ans = self.query(rev, "PTR")
        return ans.records[0] if ans.status == "ok" and ans.records else None

    def query_server(self, name: str, rdtype: str, server: str, recursion: bool = True) -> Tuple[str, List[str]]:
        """Uncached query sent to one server (consistency checks)."""
        q = dns.message.make_query(name, rdtype)
        if not recursion:
            q.flags &= ~dns.flags.RD
        if self._rate:
            self._rate.wait()
        try:
            r = dns.query.udp(q, server, timeout=self.timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(q, server, timeout=self.timeout)
        except Exception as e:
            return "error", [type(e).__name__]
        rcode = r.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return "nxdomain", []
        if rcode != dns.rcode.NOERROR:
            return "error", [dns.rcode.to_text(rcode)]
        want = dns.rdatatype.from_text(rdtype)
        values = set()
        for rrset in r.answer:
            if rrset.rdtype != want:
                continue
            for rd in rrset:
                if rdtype == "TXT":
                    values.add(b"".join(rd.strings).decode("utf-8", errors="replace"))
                elif rdtype == "MX":
                    values.add(f"{rd.preference} {str(rd.exchange).rstrip('.').lower()}")
                elif rdtype == "NS":
                    values.add(str(rd.target).rstrip(".").lower())
                else:
                    values.add(rd.to_text())
        return ("ok" if values else "nodata"), sorted(values)


def preflight(client: DNSClient) -> Tuple[bool, str]:
    """Check that the resolver answers and whether it validates DNSSEC (AD on the root zone)."""
    try:
        a = client.resolver.resolve(dns.name.root, "SOA", raise_on_no_answer=False)
    except Exception as e:
        return False, (f"the resolver(s) {', '.join(client.nameservers)} do not answer "
                       f"({type(e).__name__}). Outbound DNS may be blocked: try --system-resolver "
                       f"or --nameservers <internal resolver>")
    if a.rrset is None:
        return False, "the resolver returned an empty answer for the root zone"
    client.validating = bool(a.response.flags & dns.flags.AD)
    if not client.validating:
        return True, ("WARNING: the resolver does not validate DNSSEC - DNSSEC results will be 'unknown'. "
                      "Use a validating resolver (e.g. 1.1.1.1, 8.8.8.8, 9.9.9.9) for DNSSEC checks.")
    return True, "Resolver OK (DNSSEC-validating)"


# ---------------------------------------------------------------------------
# RDAP (registration data) client
# ---------------------------------------------------------------------------

class RDAPClient:
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    MAX_ERRORS = 25

    def __init__(self, timeout: float = 10.0, max_parallel: int = 4, allow_download: bool = True):
        self.timeout = timeout
        self.allow_download = allow_download
        self._bootstrap: Optional[Dict[str, str]] = None
        self._boot_lock = threading.Lock()
        self._cache: Dict[str, dict] = {}
        self._inflight: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_parallel)
        self.errors = 0
        self.enabled = True
        self.note = ""

    def _load_bootstrap(self) -> Dict[str, str]:
        with self._boot_lock:
            if self._bootstrap is not None:
                return self._bootstrap
            path = os.path.join(cache_dir(), "rdap_dns.json")
            data = None
            if os.path.exists(path) and time.time() - os.path.getmtime(path) < 7 * 86400:
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                except (OSError, ValueError):
                    data = None
            if data is None and self.allow_download:
                try:
                    status, body = http_get(self.BOOTSTRAP_URL, self.timeout, "application/json")
                    if status == 200:
                        data = json.loads(body)
                        with open(path, "wb") as f:
                            f.write(body)
                except Exception:
                    data = None
            mapping: Dict[str, str] = {}
            for service in (data or {}).get("services", []):
                tlds, urls = service[0], service[1]
                url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
                for tld in tlds:
                    if url:
                        mapping[tld.lower()] = url
            if not mapping:
                self.enabled = False
                self.note = "RDAP bootstrap unavailable - registration checks limited to DNS"
            self._bootstrap = mapping
            return mapping

    def lookup(self, domain: str) -> dict:
        domain = domain.lower()
        while True:
            with self._lock:
                if domain in self._cache:
                    return self._cache[domain]
                ev = self._inflight.get(domain)
                if ev is None:
                    ev = self._inflight[domain] = threading.Event()
                    break
            ev.wait()
        result = {"state": "unknown"}
        try:
            result = self._lookup(domain)
        finally:
            with self._lock:
                self._cache[domain] = result
                del self._inflight[domain]
            ev.set()
        return result

    def _lookup(self, domain: str) -> dict:
        if not self.enabled or self.errors >= self.MAX_ERRORS:
            return {"state": "unknown", "error": "RDAP disabled"}
        base = self._load_bootstrap().get(domain.rsplit(".", 1)[-1])
        if not base:
            return {"state": "unknown", "error": f"no RDAP service for .{domain.rsplit('.', 1)[-1]}"}
        url = base.rstrip("/") + "/domain/" + domain
        for attempt in range(3):
            with self._sem:
                try:
                    status, body = http_get(url, self.timeout, "application/rdap+json", 2 * 1024 * 1024)
                except Exception as e:
                    status, body = -1, str(e).encode()
            if status == 429 and attempt < 2:
                time.sleep(2 * (attempt + 1) + random.random())
                continue
            break
        if status == 404:
            return {"state": "unregistered"}
        if status != 200:
            with self._lock:
                self.errors += 1
            return {"state": "unknown", "error": f"RDAP HTTP {status}"}
        try:
            data = json.loads(body)
        except ValueError:
            return {"state": "unknown", "error": "invalid RDAP response"}
        out = {"state": "registered", "status": [s.lower() for s in data.get("status", [])]}
        for ev in data.get("events", []):
            action = (ev.get("eventAction") or "").lower()
            if action in ("expiration", "registration") and ev.get("eventDate"):
                out["expires" if action == "expiration" else "created"] = ev["eventDate"]
        dead = {"redemption period", "pending delete", "pendingdelete", "redemptionperiod"}
        if any(s in dead for s in out["status"]):
            out["state"] = "expired"
        elif out.get("expires"):
            try:
                exp = datetime.fromisoformat(out["expires"].replace("Z", "+00:00"))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                out["days_left"] = days
                if days < 0:
                    out["state"] = "expired"
                elif days <= 30:
                    out["state"] = "expiring"
            except ValueError:
                pass
        return out


# ---------------------------------------------------------------------------
# SSRF-safe HTTPS fetch (MTA-STS policy)
# ---------------------------------------------------------------------------

def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP while keeping SNI / certificate checks on the host name
    (prevents DNS rebinding between validation and connection)."""

    def __init__(self, host: str, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@dataclass
class _SPFEval:
    lookups: int = 0
    voids: int = 0
    nodes: List[dict] = field(default_factory=list)
    problems: List[Tuple[str, str]] = field(default_factory=list)
    all_q: Optional[str] = None


# Registrable domains of large providers: never expire in practice, skip RDAP for them.
WELL_KNOWN_PROVIDERS = {
    "outlook.com", "microsoft.com", "office365.com", "onmicrosoft.com", "google.com", "googlemail.com",
    "gmail.com", "amazonses.com", "amazonaws.com", "sendgrid.net", "mcsv.net", "mailchimp.com",
    "mandrillapp.com", "salesforce.com", "exacttarget.com", "zendesk.com", "hubspot.com",
    "hubspotemail.net", "mailgun.org", "sparkpostmail.com", "pphosted.com", "ppe-hosted.com",
    "mimecast.com", "messagelabs.com", "iphmx.com", "zoho.com", "zoho.eu", "protonmail.ch",
    "messagingengine.com", "cloudflare.com", "cloudflare.net", "awsdns-00.com", "azure-dns.com",
    "azure-dns.net", "azure-dns.org", "azure-dns.info", "googledomains.com", "domaincontrol.com",
    "aruba.it", "register.it", "akam.net", "ultradns.com", "ultradns.net", "nsone.net", "dnsmadeeasy.com",
}


class EmailSecurityAnalyzer:
    """Analyzes email security configurations for domains via live DNS queries."""

    COMMON_DKIM_SELECTORS = DEFAULT_DKIM_SELECTORS
    PROTECTED_MX_PROVIDERS = PROTECTED_MX_PROVIDERS
    DKIM_MAX_ERRORS = 3          # DNS errors before DKIM probing is aborted for a domain
    LOOKALIKE_FRESH_DAYS = 90

    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None,
                 use_system_resolver: bool = False, selectors: Optional[List[str]] = None,
                 fast_dkim: bool = False, http_checks: bool = True, dkim_threads: int = 32,
                 checks: Optional[List[str]] = None, dns_client: Optional[DNSClient] = None,
                 rdap: Optional[RDAPClient] = None, allow_private: bool = False,
                 report_data: Optional[Dict[str, dict]] = None, known_domains: Iterable[str] = (),
                 lookalike_limit: int = 150, lookalike_tiers: Optional[Set[str]] = None, qps: float = 0):
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
        self.selectors = list(dict.fromkeys(selectors or self.COMMON_DKIM_SELECTORS))
        self.fast_dkim = fast_dkim
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
                    getattr(result, attr).status = "unknown" if check in ("dnssec", "takeover", "consistency", "lookalikes") else "dns_error"
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
        if result.mx.null_mx or (result.mx.status == "missing" and not result.mx.implicit):
            result.profile = "non-mail"
        mail_enabled = result.profile == "mail"

        # Independent checks run concurrently; DKIM probing stays in this thread (it fans out
        # on the probe pool). Checks that need other results (BIMI, takeover...) run afterwards.
        pending: Dict[str, Any] = {}

        def submit(check: str, fn, *args) -> None:
            pending[check] = self._check_pool.submit(timed, check, fn, *args)

        if "spf" in run:
            submit("spf", self._analyze_spf, domain)
        if "dmarc" in run:
            submit("dmarc", self._analyze_dmarc, domain)
        if "mta-sts" in run:
            mx_hosts = [r.host for r in result.mx.records if r.host]
            submit("mta-sts", self._analyze_mta_sts, domain, mx_hosts, mail_enabled)
        if "tls-rpt" in run:
            submit("tls-rpt", self._analyze_tls_rpt, domain, mail_enabled)
        if "consistency" in run:
            submit("consistency", self._analyze_consistency, domain)
        if "dkim" in run:
            result.dkim = timed("dkim", self._analyze_dkim, domain, mail_enabled)
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

    # ------------------------------------------------------------------
    # MX
    # ------------------------------------------------------------------

    def _analyze_mx(self, domain: str, resolve_hosts: bool = True) -> MXResult:
        result = MXResult()
        ans = self.dns.query(domain, "MX")

        if ans.status == "error":
            result.status = "dns_error"
            result.issues.append(make_issue("DNS_ERROR", f"MX ({ans.error})"))
            return result

        if ans.status != "ok" or not ans.records:
            has_addr = self.dns.has_address(domain)
            result.status = "missing"
            if has_addr:
                result.implicit = True
                result.issues.append(make_issue("MX_IMPLICIT"))
            elif has_addr is False:
                result.issues.append(make_issue("MX_MISSING"))
            else:
                result.status = "dns_error"
                result.issues.append(make_issue("DNS_ERROR", "A/AAAA lookup failed while checking implicit MX"))
            return result

        mx_list = sorted(ans.records)
        null_entries = [m for m in mx_list if m[1] in ("", ".")]
        if null_entries:
            if len(mx_list) == 1:
                result.status = "null"
                result.null_mx = True
                result.records.append(MXRecord(priority=mx_list[0][0], host=""))
                result.issues.append(make_issue("MX_NULL"))
                return result
            result.issues.append(make_issue("MX_NULL_MIXED"))
            mx_list = [m for m in mx_list if m[1] not in ("", ".")]

        providers: List[str] = []
        dangling: List[str] = []
        cnames: List[str] = []
        for prio, host in mx_list:
            provider = match_provider(host)
            rec = MXRecord(priority=prio, host=host, is_protected=provider is not None, provider=provider)
            if resolve_hosts:
                a = self.dns.query(host, "A")
                rec.is_cname = a.canonical is not None
                rec.resolves = True if a.status == "ok" else self.dns.has_address(host)
            if rec.resolves is False:
                dangling.append(host)
            if rec.is_cname:
                cnames.append(host)
            if provider:
                result.protected_count += 1
                if provider not in providers:
                    providers.append(provider)
            result.records.append(rec)

        result.total_count = len(result.records)
        result.providers = providers
        if dangling:
            result.issues.append(make_issue("MX_DANGLING", ", ".join(dangling)))
        if cnames:
            result.issues.append(make_issue("MX_CNAME", ", ".join(cnames)))

        if result.protected_count == result.total_count:
            result.status = "valid"
        elif result.protected_count > 0:
            result.status = "partial"
            result.issues.append(make_issue("MX_PARTIAL", f"{result.protected_count}/{result.total_count} protected"))
        else:
            result.status = "warning"
            result.issues.append(make_issue("MX_UNPROTECTED"))
        return result

    # ------------------------------------------------------------------
    # SPF (RFC 7208)
    # ------------------------------------------------------------------

    def _fetch_spf(self, domain: str) -> Tuple[str, List[str], Optional[str]]:
        ans = self.dns.query(domain, "TXT")
        if ans.status == "error":
            return "dns_error", [], ans.error
        if ans.status != "ok":
            return ans.status, [], None  # nxdomain / nodata -> void lookup
        recs = [r.strip() for r in ans.records if SPF_RE.match(r.strip())]
        return ("ok" if recs else "nospf"), recs, None

    def _spf_follow(self, target: str, stack: Tuple[str, ...]) -> _SPFEval:
        """Evaluate an include/redirect target. Returned nodes are relative (target at depth 0)."""
        target = target.lower().rstrip(".")
        if target in stack:
            return _SPFEval(problems=[("SPF_LOOP", " -> ".join(stack + (target,)))])
        if len(stack) > 10:
            return _SPFEval(problems=[("SPF_LOOP", f"nesting too deep at {target}")])
        with self._spf_lock:
            cached = self._spf_memo.get(target)
        if cached is not None:
            return cached

        ev = _SPFEval()
        status, recs, err = self._fetch_spf(target)
        node = {"domain": target, "depth": 0, "lookups": 0, "status": "ok"}
        if status == "dns_error":
            node["status"] = "dns error"
            ev.problems.append(("SPF_DNS_ERROR", f"{target} ({err})"))
        elif status in ("nxdomain", "nodata", "nospf"):
            node["status"] = "no SPF"
            if status in ("nxdomain", "nodata"):
                ev.voids += 1
            ev.problems.append(("SPF_INCLUDE_NO_SPF", target))
        else:
            if len(recs) > 1:
                ev.problems.append(("SPF_MULTIPLE", target))
            sub = self._spf_eval(target, recs[0], stack + (target,), top=False)
            ev.lookups, ev.voids, ev.all_q = sub.lookups, sub.voids, sub.all_q
            ev.problems.extend(sub.problems)
            node["lookups"] = sub.lookups
            ev.nodes = [{**n, "depth": n["depth"] + 1} for n in sub.nodes]
        ev.nodes.insert(0, node)

        if not any(code in ("SPF_LOOP", "SPF_DNS_ERROR") for code, _ in ev.problems):
            with self._spf_lock:
                self._spf_memo[target] = ev
        return ev

    def _spf_eval(self, domain: str, record: str, stack: Tuple[str, ...], top: bool = True) -> _SPFEval:
        ev = _SPFEval()
        seen_all = False
        redirect: Optional[str] = None

        def merge(sub: _SPFEval):
            ev.lookups += sub.lookups
            ev.voids += sub.voids
            ev.nodes.extend(sub.nodes)
            ev.problems.extend(sub.problems)

        for term in record.split()[1:]:
            m = SPF_TERM_RE.fullmatch(term)
            if not m:
                ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                continue
            qual, name, sep, val = m.group(1), m.group(2).lower(), m.group(3), m.group(4) or ""

            if sep == "=":  # modifier
                if qual:
                    ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                elif name == "redirect":
                    redirect = val
                continue  # exp= and unknown modifiers are ignored (RFC 7208 §6)
            if name not in SPF_MECHANISMS:
                ev.problems.append(("SPF_SYNTAX", f"unknown mechanism '{term}' in {domain}"))
                continue
            if seen_all:
                continue  # evaluation never goes past 'all'

            if name == "all":
                if sep:
                    ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                ev.all_q = qual or "+"
                seen_all = True
                continue

            if name in ("ip4", "ip6"):
                try:
                    if sep != ":":
                        raise ValueError
                    net = ipaddress.ip_network(val, strict=False)
                    if (net.version == 4) != (name == "ip4"):
                        raise ValueError
                    if top and qual in ("", "+") and (
                            (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32)):
                        ev.problems.append(("SPF_BROAD_IP", f"{name}:{val}"))
                except ValueError:
                    ev.problems.append(("SPF_SYNTAX", f"invalid '{term}' in {domain}"))
                continue

            # DNS-querying mechanisms: include, a, mx, ptr, exists
            ev.lookups += 1
            if sep == ":":
                target = val.split("/", 1)[0]
            else:
                target = domain
            if name in ("include", "exists") and (sep != ":" or not target):
                ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                continue
            if "%" in target:
                ev.problems.append(("SPF_MACROS", term))
                continue

            if name == "ptr":
                ev.problems.append(("SPF_PTR", domain))
            elif name == "include":
                merge(self._spf_follow(target, stack))
            elif name == "a":
                if self.dns.has_address(target) is False:
                    ev.voids += 1
                    ev.problems.append(("SPF_VOID", f"a:{target}"))
            elif name == "mx":
                mx = self.dns.query(target, "MX")
                if mx.status in ("nxdomain", "nodata"):
                    ev.voids += 1
                    ev.problems.append(("SPF_VOID", f"mx:{target}"))
                elif mx.status == "ok" and len(mx.records) > 10:
                    ev.problems.append(("SPF_MX_TOO_MANY", target))

        if redirect and not seen_all:
            ev.lookups += 1
            if "%" in redirect:
                ev.problems.append(("SPF_MACROS", f"redirect={redirect}"))
            else:
                sub = self._spf_follow(redirect, stack)
                merge(sub)
                ev.all_q = sub.all_q
        return ev

    def _analyze_spf(self, domain: str) -> SPFResult:
        result = SPFResult()
        status, recs, err = self._fetch_spf(domain)

        if status == "dns_error":
            result.status = "dns_error"
            result.issues.append(make_issue("SPF_DNS_ERROR", err))
            return result
        if status != "ok":
            result.status = "missing"
            result.issues.append(make_issue("SPF_MISSING"))
            return result

        problems: List[Tuple[str, str]] = []
        if len(recs) > 1:
            problems.append(("SPF_MULTIPLE", f"{len(recs)} records"))

        record = recs[0]
        result.record = record
        result.records = recs
        ev = self._spf_eval(domain, record, (domain,))
        problems.extend(ev.problems)
        result.lookups = ev.lookups
        result.void_lookups = ev.voids
        result.include_tree = ev.nodes
        result.includes = [n["domain"] for n in ev.nodes if n["depth"] == 0]
        result.mechanism = {"-": "-all", "~": "~all", "?": "?all", "+": "+all"}.get(ev.all_q or "")

        if result.lookups > 10:
            problems.append(("SPF_LOOKUP_LIMIT", f"{result.lookups}/10"))
        elif result.lookups >= 8:
            problems.append(("SPF_LOOKUP_NEAR", f"{result.lookups}/10"))
        if result.void_lookups > 2:
            problems.append(("SPF_VOID_LIMIT", f"{result.void_lookups}/2"))

        if result.mechanism == "+all":
            problems.append(("SPF_PASS_ALL", ""))
        elif result.mechanism == "?all":
            problems.append(("SPF_NEUTRAL", ""))
        elif result.mechanism == "~all":
            problems.append(("SPF_SOFTFAIL", ""))
        elif result.mechanism is None:
            problems.append(("SPF_NO_ALL", ""))

        result.issues = issues_from_problems(problems)
        codes = {c for c, _ in problems}
        permerror_codes = {"SPF_MULTIPLE", "SPF_SYNTAX", "SPF_LOOKUP_LIMIT", "SPF_VOID_LIMIT",
                           "SPF_INCLUDE_NO_SPF", "SPF_LOOP", "SPF_MX_TOO_MANY"}
        result.permerror = bool(codes & permerror_codes)

        if result.permerror or result.mechanism in ("+all", "?all"):
            result.status = "error"
        elif codes & {"SPF_LOOKUP_NEAR", "SPF_SOFTFAIL", "SPF_NO_ALL", "SPF_PTR", "SPF_BROAD_IP",
                      "SPF_VOID", "SPF_DNS_ERROR"}:
            result.status = "warning"
        else:
            result.status = "valid"
        return result

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    def _probe_selector(self, domain: str, selector: str) -> Tuple[Optional[DKIMSelector], bool, Optional[dict]]:
        name = f"{selector}._domainkey.{domain}"
        ans = self.dns.query(name, "TXT")
        if ans.status == "error":
            return None, True, None
        if ans.status == "nxdomain" and ans.canonical:
            return None, False, {"name": name, "target": ans.canonical}
        if ans.status != "ok":
            return None, False, None
        for txt in ans.records:
            tags = parse_tags(txt)
            if "p" not in tags:
                continue
            if "v" in tags and tags["v"] != "DKIM1":
                continue
            algo = tags.get("k", "rsa").lower()
            key = re.sub(r"\s+", "", tags["p"])
            sel = DKIMSelector(name=selector, algorithm=algo, cname=ans.canonical)
            if not key:
                sel.status = "revoked"
            elif algo == "ed25519":
                try:
                    raw = base64.b64decode(key + "=" * (-len(key) % 4), validate=True)
                    sel.key_size, sel.status = 256, ("valid" if len(raw) == 32 else "invalid")
                except (binascii.Error, ValueError):
                    sel.status = "invalid"
            elif algo == "rsa":
                bits = rsa_key_bits(key)
                sel.key_size = bits
                sel.status = "invalid" if bits is None else ("valid" if bits >= 2000 else "weak")
            else:
                sel.status = "invalid"
            sel.testing = "y" in [f.strip().lower() for f in tags.get("t", "").split(":")]
            if "h" in tags:
                sel.hash_algorithms = tags["h"].lower().replace(" ", "")
            return sel, False, None
        return None, False, None

    def _analyze_dkim(self, domain: str, mail_enabled: bool = True) -> DKIMResult:
        result = DKIMResult()

        if self.fast_dkim:
            # RFC 8020: NXDOMAIN on _domainkey means no selector can exist below it
            base = self.dns.query(f"_domainkey.{domain}", "TXT")
            if base.status == "nxdomain":
                result.status = "missing" if mail_enabled else "na"
                if mail_enabled:
                    result.issues.append(make_issue("DKIM_NOT_FOUND", "_domainkey does not exist"))
                return result

        # All selectors are probed in parallel on the shared pool. Circuit breaker: once
        # DKIM_MAX_ERRORS probes of this domain fail (zone not answering), the probes
        # still queued are skipped instead of each waiting for the full timeout.
        state = {"errors": 0, "skipped": 0}
        state_lock = threading.Lock()

        def probe(selector: str):
            with state_lock:
                if state["errors"] >= self.DKIM_MAX_ERRORS:
                    state["skipped"] += 1
                    return None, False, None
            return self._probe_selector(domain, selector)

        from_reports = self.report_selectors.get(domain, [])
        selectors = list(dict.fromkeys(from_reports + self.selectors))
        for fut in [self._pool.submit(probe, s) for s in selectors]:
            sel, err, dangling = fut.result()
            if err:
                with state_lock:
                    state["errors"] += 1
            if sel:
                if sel.name in from_reports:
                    sel.source = "report"
                result.selectors.append(sel)
            if dangling:
                result.dangling.append(dangling)
        dns_errors = state["errors"]
        aborted = state["skipped"] > 0
        probed = len(selectors) - state["skipped"]
        result.probed = probed
        result.total_selectors = len(result.selectors)

        problems: List[Tuple[str, str]] = []
        strong = weak = 0
        for s in result.selectors:
            label = f"{s.name} ({s.key_size} bit)" if s.key_size else s.name
            if s.status == "valid":
                strong += 1
            elif s.status == "weak":
                weak += 1
                problems.append(("DKIM_BROKEN_KEY" if (s.key_size or 0) < 1000 else "DKIM_WEAK", label))
            elif s.status == "invalid":
                problems.append(("DKIM_INVALID", s.name))
            elif s.status == "revoked":
                problems.append(("DKIM_REVOKED", s.name))
            if s.testing:
                problems.append(("DKIM_TESTING", s.name))
            if s.hash_algorithms and "sha256" not in s.hash_algorithms:
                problems.append(("DKIM_SHA1", s.name))
        result.valid_selectors = strong + weak
        result.weak_keys = weak
        result.issues = issues_from_problems(problems)

        if result.valid_selectors == 0:
            if aborted or dns_errors > probed // 2:
                result.status = "dns_error"
                detail = f"{dns_errors}/{probed} probes failed" + (", probing aborted" if aborted else "")
                result.issues.append(make_issue("DKIM_DNS_ERROR", detail))
            elif any(s.status == "invalid" for s in result.selectors):
                result.status = "error"
            elif not mail_enabled:
                result.status = "na"
            else:
                result.status = "missing"
                result.issues.append(make_issue("DKIM_NOT_FOUND", f"{len(selectors)} selectors probed"))
        elif weak:
            result.status = "partial"
        else:
            result.status = "valid"
        return result

    # ------------------------------------------------------------------
    # DMARC (RFC 7489)
    # ------------------------------------------------------------------

    def _fetch_dmarc(self, name: str) -> Tuple[str, List[str], Optional[str]]:
        ans = self.dns.query(f"_dmarc.{name}", "TXT")
        if ans.status == "error":
            return "dns_error", [], ans.error
        if ans.status != "ok":
            return "missing", [], None
        recs = [r.strip() for r in ans.records if DMARC_RE.match(r.strip())]
        return ("ok" if recs else "missing"), recs, None

    @staticmethod
    def _same_org(a: str, b: str) -> bool:
        return a == b or a.endswith("." + b) or b.endswith("." + a) or org_domain(a) == org_domain(b)

    def _analyze_dmarc(self, domain: str) -> DMARCResult:
        result = DMARCResult()
        source = domain
        status, recs, err = self._fetch_dmarc(domain)

        if status == "missing":
            org = org_domain(domain)
            if org != domain:
                st2, recs2, err2 = self._fetch_dmarc(org)
                if st2 == "ok":
                    status, recs, source = st2, recs2, org
                    result.inherited_from = org
                elif st2 == "dns_error":
                    status, err = st2, err2

        if status == "dns_error":
            result.status = "dns_error"
            result.issues.append(make_issue("DMARC_DNS_ERROR", err))
            return result
        if status != "ok":
            result.status = "missing"
            result.issues.append(make_issue("DMARC_MISSING"))
            return result

        result.record = recs[0]
        if len(recs) > 1:
            result.status = "misconfigured"
            result.issues.append(make_issue("DMARC_MULTIPLE", f"{len(recs)} records"))
            return result
        if result.inherited_from:
            result.issues.append(make_issue("DMARC_INHERITED", result.inherited_from))

        tags = parse_tags(result.record)
        valid_policies = ("none", "quarantine", "reject")
        p = tags.get("p", "").lower()
        sp = tags.get("sp", "").lower() or None
        np_ = tags.get("np", "").lower() or None
        rua_raw = tags.get("rua")
        if p not in valid_policies:
            result.status = "misconfigured"
            result.issues.append(make_issue("DMARC_INVALID", f"p={p}" if p else "p= missing"))
            if not rua_raw:
                return result
            p = "none"  # RFC 7489 §6.6.3: with a valid rua, treat as p=none

        record_sp = sp if sp in valid_policies else p
        result.policy = record_sp if result.inherited_from else p
        result.subdomain_policy = record_sp
        result.nonexistent_policy = np_ if np_ in valid_policies else record_sp

        bad_tags = []
        pct_raw = tags.get("pct", "100").strip()
        if pct_raw.isdigit() and 0 <= int(pct_raw) <= 100:
            result.pct = int(pct_raw)
        else:
            result.pct = 100
            bad_tags.append(f"pct={pct_raw}")
        for key in ("aspf", "adkim"):
            val = tags.get(key, "r").strip().lower()
            if val not in ("r", "s"):
                bad_tags.append(f"{key}={val}")
        if bad_tags:
            result.issues.append(make_issue("DMARC_BAD_TAG", ", ".join(bad_tags)))
        result.aspf = "strict" if tags.get("aspf", "r").strip().lower() == "s" else "relaxed"
        result.adkim = "strict" if tags.get("adkim", "r").strip().lower() == "s" else "relaxed"
        result.rua = rua_raw
        result.ruf = tags.get("ruf")

        # Policy
        if result.status != "misconfigured":
            if result.policy == "reject":
                result.status = "valid" if result.pct == 100 else "warning"
            elif result.policy == "quarantine":
                result.status = "warning"
                result.issues.append(make_issue("DMARC_QUARANTINE"))
            else:
                result.status = "misconfigured"
                result.issues.append(make_issue("DMARC_NONE"))
        if result.policy in ("quarantine", "reject"):
            if result.pct < 100:
                result.issues.append(make_issue("DMARC_PCT", f"pct={result.pct}"))
            weaker = [f"{k}=none" for k, v in (("sp", sp), ("np", np_)) if v == "none"]
            if weaker and not result.inherited_from:
                result.issues.append(make_issue("DMARC_SP_NONE", ", ".join(weaker)))

        # Aggregate reporting
        if not rua_raw:
            result.issues.append(make_issue("DMARC_NO_RUA"))
        else:
            bad, unauthorized = [], []
            for uri in (u.strip() for u in rua_raw.split(",") if u.strip()):
                if not uri.lower().startswith("mailto:") or "@" not in uri:
                    bad.append(uri)
                    continue
                addr = uri[7:].split("!", 1)[0].strip()
                result.rua_destinations.append(addr)
                rdomain = addr.rsplit("@", 1)[1].lower().rstrip(".")
                if not self._same_org(source, rdomain):
                    auth = self.dns.query(f"{source}._report._dmarc.{rdomain}", "TXT")
                    if auth.status in ("ok", "nodata", "nxdomain") and not any(
                            DMARC_RE.match(r.strip()) for r in auth.records):
                        unauthorized.append(rdomain)
            if bad:
                result.issues.append(make_issue("DMARC_RUA_INVALID", ", ".join(bad)))
            if unauthorized:
                result.issues.append(make_issue("DMARC_RUA_UNAUTHORIZED", ", ".join(sorted(set(unauthorized)))))
            if not result.rua_destinations and not bad:
                result.issues.append(make_issue("DMARC_NO_RUA"))
        return result

    # ------------------------------------------------------------------
    # MTA-STS (RFC 8461), TLS-RPT (RFC 8460), BIMI
    # ------------------------------------------------------------------

    @staticmethod
    def _mx_matches(host: str, pattern: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return host.endswith(suffix) and "." not in host[: -len(suffix)]
        return host == pattern

    def _analyze_mta_sts(self, domain: str, mx_hosts: List[str], applicable: bool) -> MTASTSResult:
        result = MTASTSResult()
        ans = self.dns.query(f"_mta-sts.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=STSv1\s*(;|$)", r.strip())]
        if not recs:
            result.status = "missing" if applicable else "na"
            if applicable:
                result.issues.append(make_issue("MTASTS_MISSING"))
            return result

        result.txt_record = recs[0]
        result.policy_id = parse_tags(recs[0]).get("id")
        if len(recs) > 1:
            result.status = "error"
            result.policy_error = "multiple _mta-sts TXT records"
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", result.policy_error))
            return result
        if not self.http_checks:
            result.status = "partial"
            return result

        body, note = self._fetch_policy(f"mta-sts.{domain}", "/.well-known/mta-sts.txt")
        if body is None:
            result.status = "error"
            result.policy_error = note
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", note))
            return result

        policy: Dict[str, str] = {}
        for line in body.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "mx":
                    result.mx_patterns.append(v)
                else:
                    policy.setdefault(k, v)
        result.mode = policy.get("mode", "").lower() or None
        try:
            result.max_age = int(policy.get("max_age", ""))
        except ValueError:
            result.max_age = None

        errors = []
        if note:
            errors.append(note)
        if policy.get("version") != "STSv1":
            errors.append("missing 'version: STSv1'")
        if result.mode not in ("enforce", "testing", "none"):
            errors.append(f"invalid mode '{result.mode}'")
        if result.max_age is None:
            errors.append("missing/invalid max_age")
        if result.mode != "none" and not result.mx_patterns:
            errors.append("no mx: lines")
        if errors:
            result.policy_error = "; ".join(errors)
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", result.policy_error))

        unmatched = [h for h in mx_hosts if not any(self._mx_matches(h, p) for p in result.mx_patterns)]
        if unmatched and result.mode in ("enforce", "testing"):
            sev = "critical" if result.mode == "enforce" else "warning"
            result.issues.append(make_issue("MTASTS_MX_MISMATCH", ", ".join(unmatched), severity=sev))

        if result.mode == "enforce" and not errors and not unmatched:
            result.status = "valid"
        elif result.mode == "testing":
            result.status = "warning"
            result.issues.append(make_issue("MTASTS_TESTING"))
        elif result.mode == "none":
            result.status = "warning"
            result.issues.append(make_issue("MTASTS_NONE"))
        else:
            result.status = "error" if (errors or unmatched) else "warning"
        return result

    def _analyze_tls_rpt(self, domain: str, applicable: bool) -> TLSRPTResult:
        result = TLSRPTResult()
        ans = self.dns.query(f"_smtp._tls.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=TLSRPTv1\s*(;|$)", r.strip())]
        if not recs:
            result.status = "missing" if applicable else "na"
            if applicable:
                result.issues.append(make_issue("TLSRPT_MISSING"))
            return result
        result.record = recs[0]
        result.rua = parse_tags(recs[0]).get("rua")
        uris = [u.strip().lower() for u in (result.rua or "").split(",") if u.strip()]
        if len(recs) > 1 or not uris or not all(u.startswith(("mailto:", "https:")) for u in uris):
            result.status = "error"
            result.issues.append(make_issue("TLSRPT_INVALID", "multiple records" if len(recs) > 1 else result.rua))
        else:
            result.status = "valid"
        return result

    def _analyze_bimi(self, domain: str, dmarc: DMARCResult) -> BIMIResult:
        result = BIMIResult()
        ans = self.dns.query(f"default._bimi.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=BIMI1\s*(;|$)", r.strip(), re.I)]
        if not recs:
            return result
        tags = parse_tags(recs[0])
        result.record = recs[0]
        result.logo_url = tags.get("l") or None
        result.vmc_url = tags.get("a") or None
        enforcing = (dmarc.policy in ("quarantine", "reject") and dmarc.pct == 100
                     and dmarc.subdomain_policy != "none")
        if enforcing:
            result.status = "valid"
        else:
            result.status = "warning"
            result.issues.append(make_issue("BIMI_NO_ENFORCEMENT"))
        return result


    # ------------------------------------------------------------------
    # SSRF-safe policy fetch (MTA-STS)
    # ------------------------------------------------------------------

    def _fetch_policy(self, host: str, path: str) -> Tuple[Optional[str], Optional[str]]:
        """GET https://host/path with redirects refused (RFC 8461 §3.3), the target IP validated
        as public (no requests into internal networks) and pinned for the connection."""
        ips = self.dns.addresses(host)
        if not ips:
            return None, f"{host} does not resolve"
        if not self.allow_private:
            blocked = [ip for ip in ips if not is_public_ip(ip)]
            if blocked:
                return None, (f"{host} resolves to non-public address {blocked[0]} - fetch blocked "
                              f"(SSRF protection, see --allow-private)")
        ip = next((i for i in ips if ":" not in i), ips[0])
        conn = _PinnedHTTPSConnection(host, ip, self.timeout, self._ssl_ctx)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "text/plain"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                return None, f"redirect not allowed (HTTP {resp.status})"
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            body = resp.read(65537)
            if len(body) > 65536:
                return None, "policy larger than 64 KB"
            ctype = (resp.getheader("Content-Type") or "").lower()
            note = None if ctype.startswith("text/plain") else f"Content-Type '{ctype or 'missing'}' (expected text/plain)"
            return body.decode("utf-8", errors="replace"), note
        except ssl.SSLCertVerificationError as e:
            return None, f"invalid TLS certificate ({e.verify_message})"
        except (socket.timeout, TimeoutError):
            return None, "timeout"
        except (OSError, http.client.HTTPException) as e:
            return None, f"{type(e).__name__}: {e}"
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Takeover risk of external dependencies
    # ------------------------------------------------------------------

    def _analyze_takeover(self, r: DomainResult) -> TakeoverResult:
        res = TakeoverResult(rdap=bool(self.rdap and self.rdap.enabled))
        domain = r.domain
        own = org_domain(domain)
        deps: Dict[str, Set[str]] = defaultdict(set)

        def add(host: str, usage: str) -> None:
            host = (host or "").lower().rstrip(".")
            if not host or "%" in host or not DOMAIN_RE.fullmatch(host):
                return
            reg = org_domain(host)
            if reg and reg != own and reg not in self.known_orgs:
                deps[reg].add(usage)

        for node in r.spf.include_tree:
            add(node["domain"], "SPF include")
        for rec in r.spf.records:
            for m in re.finditer(r"(?:^|\s)[+\-~?]?(?:a|mx|exists|ptr):([^\s/]+)", rec, re.I):
                add(m.group(1), "SPF mechanism")
        for mx in r.mx.records:
            if mx.host:
                add(mx.host, "MX")
                if mx.resolves is False:
                    a = self.dns.query(mx.host, "A")
                    if a.canonical:
                        res.dangling.append({"name": mx.host, "target": a.canonical, "used_by": "MX"})
                        add(a.canonical, "MX CNAME")

        ns = self.dns.query(domain, "NS")
        if ns.status != "ok" and own != domain:
            ns = self.dns.query(own, "NS")
        if ns.status == "ok":
            res.ns_hosts = sorted(ns.records)
            lame = []
            for host in res.ns_hosts:
                add(host, "NS")
                if self.dns.has_address(host) is False:
                    lame.append(host)
            if lame:
                res.issues.append(make_issue("TAKEOVER_LAME_NS", ", ".join(lame)))

        for s in r.dkim.selectors:
            if s.cname:
                add(s.cname, f"DKIM {s.name}")
        for d in r.dkim.dangling:
            res.dangling.append({**d, "used_by": "DKIM"})
            add(d["target"], "DKIM CNAME")
        if r.mta_sts.txt_record:
            a = self.dns.query(f"mta-sts.{domain}", "A")
            if a.canonical:
                add(a.canonical, "MTA-STS host")
                if a.status == "nxdomain":
                    res.dangling.append({"name": f"mta-sts.{domain}", "target": a.canonical, "used_by": "MTA-STS"})
        for addr in r.dmarc.rua_destinations:
            add(addr.rsplit("@", 1)[-1], "DMARC rua")
        for uri in (r.tls_rpt.rua or "").split(","):
            uri = uri.strip()
            host = uri[7:].rsplit("@", 1)[-1] if uri.lower().startswith("mailto:") else (urlparse(uri).hostname or "")
            add(host, "TLS-RPT rua")

        rdap_on = bool(self.rdap and self.rdap.enabled)

        def check(reg: str) -> dict:
            entry = {"domain": reg, "used_by": sorted(deps[reg]), "state": "ok", "expires": None}
            soa = self.dns.query(reg, "SOA")
            if soa.status == "nxdomain":
                entry["state"] = "unregistered"
                if rdap_on:
                    info = self.rdap.lookup(reg)
                    if info["state"] in ("registered", "expiring"):
                        entry["state"] = "no-dns"  # registered but not resolving (e.g. on hold)
                    elif info["state"] == "expired":
                        entry["state"] = "expired"
            elif soa.status == "error":
                entry["state"] = "unknown"
            elif rdap_on and reg not in WELL_KNOWN_PROVIDERS:
                info = self.rdap.lookup(reg)
                entry["expires"] = info.get("expires")
                if info["state"] in ("expired", "expiring"):
                    entry["state"] = info["state"]
            return entry

        res.dependencies = list(self._pool.map(check, sorted(deps)))
        problems: List[Tuple[str, str]] = []
        unregistered = set()
        for e in res.dependencies:
            label = f"{e['domain']} ({', '.join(e['used_by'])})"
            if e["state"] == "unregistered":
                unregistered.add(e["domain"])
                problems.append(("TAKEOVER_UNREGISTERED", label))
            elif e["state"] == "expired":
                problems.append(("TAKEOVER_EXPIRED", label))
            elif e["state"] == "no-dns":
                problems.append(("TAKEOVER_UNRESOLVABLE", label))
            elif e["state"] == "expiring":
                problems.append(("TAKEOVER_EXPIRING", f"{label}, expires {(e['expires'] or '')[:10]}"))
        for d in res.dangling:
            if org_domain(d["target"]) not in unregistered:
                problems.append(("TAKEOVER_DANGLING_CNAME", f"{d['name']} -> {d['target']}"))
        res.issues += issues_from_problems(problems, max_details=4)

        if rdap_on:
            info = self.rdap.lookup(own)
            res.domain_expires = info.get("expires")
            if info["state"] == "expired":
                res.issues.append(make_issue("DOMAIN_EXPIRED", own))
            elif info["state"] == "expiring":
                res.issues.append(make_issue("DOMAIN_EXPIRING", f"{own} expires {(info.get('expires') or '')[:10]}"))

        sev = {i.severity for i in res.issues}
        res.status = "error" if "critical" in sev else "warning" if "warning" in sev else "valid"
        return res

    # ------------------------------------------------------------------
    # Resolver vs authoritative consistency
    # ------------------------------------------------------------------

    CONSISTENCY_RECORDS = (("", "MX"), ("", "TXT"), ("_dmarc.", "TXT"), ("", "NS"))

    def _analyze_consistency(self, domain: str) -> ConsistencyResult:
        res = ConsistencyResult()
        own = org_domain(domain)
        ns = self.dns.query(domain, "NS")
        if ns.status != "ok" and own != domain:
            ns = self.dns.query(own, "NS")
        auth: List[Tuple[str, str]] = []
        for host in (sorted(ns.records)[:4] if ns.status == "ok" else []):
            ips = self.dns.addresses(host)
            ip = next((i for i in ips if ":" not in i), ips[0] if ips else None)
            if ip:
                auth.append((host, ip))
        resolvers = [(f"resolver {ip}", ip) for ip in self.dns.nameservers]
        res.sources = [n for n, _ in resolvers] + [f"auth {h}" for h, _ in auth]
        if not auth:
            res.status = "unknown"
            return res

        def norm(answer):
            st, vals = answer
            if st == "error":
                return None
            return tuple(vals) if st == "ok" else ()

        problems: List[Tuple[str, str]] = []
        for prefix, rdtype in self.CONSISTENCY_RECORDS:
            name = prefix + domain
            auth_vals = {f"auth {h}": norm(self.dns.query_server(name, rdtype, ip, recursion=False)) for h, ip in auth}
            res_vals = {src: norm(self.dns.query_server(name, rdtype, ip)) for src, ip in resolvers}
            auth_vals = {k: v for k, v in auth_vals.items() if v is not None}
            res_vals = {k: v for k, v in res_vals.items() if v is not None}
            answers = {k: list(v) for k, v in {**auth_vals, **res_vals}.items()}
            distinct = set(auth_vals.values())
            if len(distinct) > 1:
                res.differences.append({"name": name, "type": rdtype, "kind": "authoritative", "answers": answers})
                problems.append(("DNS_AUTH_INCONSISTENT", f"{rdtype} {name}"))
            elif distinct:
                truth = next(iter(distinct))
                bad = [k for k, v in res_vals.items() if v != truth]
                if bad:
                    res.differences.append({"name": name, "type": rdtype, "kind": "resolver", "answers": answers})
                    problems.append(("DNS_INCONSISTENT", f"{rdtype} {name} ({', '.join(bad)})"))
        res.issues = issues_from_problems(problems)
        res.status = "warning" if problems else "valid"
        return res

    # ------------------------------------------------------------------
    # Lookalike domains
    # ------------------------------------------------------------------

    def _tld_has_wildcard(self, tld: str) -> bool:
        if tld not in self._wildcard_tlds:
            label = "mg-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            self._wildcard_tlds[tld] = self.dns.query(f"{label}.{tld}", "NS").status in ("ok", "nodata")
        return self._wildcard_tlds[tld]

    def _analyze_lookalikes(self, r: DomainResult) -> LookalikeResult:
        res = LookalikeResult()
        if self.lookalike_tiers and r.tier not in self.lookalike_tiers:
            res.status = "na"
            return res
        org = org_domain(r.domain)
        res.base = org

        def compute():
            candidates = generate_lookalikes(org, self.lookalike_limit)

            def check(item):
                cand, kind = item
                if cand in self.known_domains or org_domain(cand) in self.known_orgs:
                    return None
                if self._tld_has_wildcard(cand.split(".", 1)[1]):
                    return None
                ns = self.dns.query(cand, "NS")
                if ns.status == "nxdomain":
                    return None
                mx = self.dns.query(cand, "MX")
                has_mx = mx.status == "ok" and any(h not in ("", ".") for _, h in mx.records)
                entry = {"domain": cand, "kind": kind, "mx": has_mx,
                         "a": bool(self.dns.has_address(cand)), "created": None,
                         "dns": "error" if ns.status == "error" else "ok"}
                if has_mx and self.rdap and self.rdap.enabled:
                    entry["created"] = self.rdap.lookup(cand).get("created")
                return entry

            found = [e for e in self._pool.map(check, candidates.items()) if e]
            return len(candidates), found

        generated, registered = self._once_per_org("lookalikes:" + org, compute)
        res.generated = generated
        res.registered = sorted(registered, key=lambda e: (not e["mx"], e["domain"]))
        now = datetime.now(timezone.utc)
        fresh, with_mx, plain = [], [], []
        for e in res.registered:
            created = None
            if e.get("created"):
                try:
                    created = datetime.fromisoformat(e["created"].replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                except ValueError:
                    created = None
            if e["mx"] and created and (now - created).days <= self.LOOKALIKE_FRESH_DAYS:
                fresh.append(f"{e['domain']} (registered {e['created'][:10]})")
            elif e["mx"]:
                with_mx.append(e["domain"])
            else:
                plain.append(e["domain"])
        problems = [("LOOKALIKE_FRESH", d) for d in fresh] + [("LOOKALIKE_MX", d) for d in with_mx]
        res.issues = issues_from_problems(problems, max_details=5)
        if plain:
            res.issues.append(make_issue("LOOKALIKE_REGISTERED", f"{len(plain)}: " + ", ".join(plain[:5])
                                         + (" ..." if len(plain) > 5 else "")))
        res.status = "error" if fresh else "warning" if with_mx else "partial" if plain else "valid"
        return res

    # ------------------------------------------------------------------
    # DMARC aggregate reports
    # ------------------------------------------------------------------

    def _attach_reports(self, r: DomainResult) -> DMARCReportResult:
        res = DMARCReportResult()
        info = self.report_data.get(r.domain)
        if not info:
            return res
        res.reports, res.messages, res.passed = info["reports"], info["messages"], info["passed"]
        res.pass_rate = round(100.0 * res.passed / res.messages, 1) if res.messages else 0.0
        res.period = [info.get("begin", ""), info.get("end", "")]
        res.reporters = [org for org, _ in info["reporters"].most_common(8)]
        own = org_domain(r.domain)
        res.selectors = sorted({sel for d, sel in info["selector_pairs"] if org_domain(d) == own})
        sources = []
        for ip, s in info["sources"].items():
            cat = max(("aligned", s["passed"]), ("unaligned", s["unaligned"]), ("spoof", s["spoofed"]),
                      key=lambda kv: kv[1])[0]
            sources.append({"ip": ip, "count": s["count"], "passed": s["passed"], "category": cat,
                            "envelope_from": sorted(s["envelope_from"])[:5],
                            "dkim_domains": sorted(s["dkim_domains"])[:5],
                            "dispositions": dict(s["disposition"]), "ptr": None})
        sources.sort(key=lambda x: -x["count"])
        lookup = [s for s in sources if s["category"] != "aligned"][:10] + \
                 [s for s in sources if s["category"] == "aligned"][:5]
        for s in lookup:
            s["ptr"] = self.dns.ptr(s["ip"])
        res.sources = sources[:50]
        res.unaligned = sum(s["count"] for s in sources if s["category"] == "unaligned")
        res.spoofed = sum(s["count"] for s in sources if s["category"] == "spoof")

        if res.messages < 100:
            res.status = "unknown"
            res.verdict = "Not enough data yet (fewer than 100 messages reported)"
            return res
        legit = res.passed + res.unaligned
        unaligned_srcs = [s for s in sources if s["category"] == "unaligned"]
        if legit and res.unaligned / legit > 0.02:
            names = [s["ptr"] or s["ip"] for s in unaligned_srcs[:4]]
            res.issues.append(make_issue("REPORT_UNALIGNED_SOURCES",
                                         f"{res.unaligned} messages from {len(unaligned_srcs)} sources ({', '.join(names)})"))
            res.verdict = "Not ready for p=reject: align the senders listed below first"
        else:
            res.verdict = "Ready for p=reject: legitimate senders pass DMARC"
            if r.dmarc.policy != "reject":
                res.issues.append(make_issue("REPORT_READY_FOR_REJECT", f"{res.pass_rate}% of {res.messages} messages pass"))
        if res.spoofed and (r.dmarc.policy in (None, "none") or r.dmarc.pct < 100):
            res.issues.append(make_issue("REPORT_SPOOFING", f"{res.spoofed} messages"))
        res.status = "warning" if any(i.severity != "info" for i in res.issues) else "valid"
        return res

    # ------------------------------------------------------------------
    # Cross-checks
    # ------------------------------------------------------------------

    def _cross_check(self, r: DomainResult) -> List[Issue]:
        issues: List[Issue] = []
        on = self.checks
        dmarc_present = r.dmarc.status not in ("missing", "dns_error", "skipped")
        enforcing = r.dmarc.policy in ("quarantine", "reject")
        spf_broken = r.spf.status in ("missing", "error")
        no_dkim = r.dkim.status in ("missing", "error")

        if r.profile == "non-mail":
            if "spf" in on and r.spf.status != "dns_error" and (
                    r.spf.record is None or not re.fullmatch(r"v=spf1\s+-all", r.spf.record.strip(), re.I)):
                issues.append(make_issue("SPF_PARKED_NOT_STRICT"))
            if "dmarc" in on and r.dmarc.status != "dns_error" and r.dmarc.policy != "reject":
                issues.append(make_issue("DMARC_PARKED_NOT_REJECT"))
            return issues

        if {"dmarc", "spf", "dkim"} <= on and dmarc_present and enforcing and spf_broken and no_dkim:
            issues.append(make_issue("X_ENFORCED_NO_AUTH"))
        else:
            if {"dmarc", "spf"} <= on and dmarc_present and spf_broken:
                issues.append(make_issue("X_DMARC_SPF_BROKEN"))
            if {"dmarc", "dkim"} <= on and dmarc_present and r.dkim.status == "missing":
                issues.append(make_issue("X_DMARC_NO_DKIM"))

        # ~all is acceptable when DMARC fully enforces: downgrade to info
        if enforcing and r.dmarc.pct == 100:
            for i in r.spf.issues:
                if i.code == "SPF_SOFTFAIL":
                    i.severity = "info"
        return issues

    # ------------------------------------------------------------------
    # Score (0-100)
    #   SPF 25 | DKIM 25 | DMARC 35 | MTA-STS 7 | TLS-RPT 3 | DNSSEC 5
    #   Non-mail domains get DKIM / MTA-STS / TLS-RPT points by design.
    #   With --checks the score is normalized over the selected weights; if only
    #   unweighted checks run it is derived from the findings. Takeover / bogus
    #   DNSSEC / expired registration cap the score (SCORE_CAP_CODES).
    # ------------------------------------------------------------------

    @staticmethod
    def _component_points(r: DomainResult) -> Dict[str, float]:
        parked = r.profile == "non-mail"
        pts: Dict[str, float] = {}

        spf = r.spf
        pts["spf"] = 0.0
        if spf.status in ("valid", "warning") and not spf.permerror:
            pts["spf"] = {"-all": 25, "~all": 20}.get(spf.mechanism or "", 8) - (4 if spf.lookups >= 8 else 0)

        pts["dkim"] = 25 if parked else {"valid": 25, "partial": 15, "error": 5}.get(r.dkim.status, 0)

        d = r.dmarc
        pts["dmarc"] = 0.0
        if d.policy and d.status != "dns_error" and not any(i.code == "DMARC_MULTIPLE" for i in d.issues):
            base = {"none": 8, "quarantine": 25, "reject": 35}.get(d.policy, 0)
            if d.policy in ("quarantine", "reject"):
                if d.pct < 100:
                    base = 8 + (base - 8) * d.pct / 100
                if d.subdomain_policy == "none" or d.nonexistent_policy == "none":
                    base -= 5
            if not d.rua_destinations:
                base -= 3
            pts["dmarc"] = max(base, 0)

        pts["mta-sts"] = 7 if parked else {"valid": 7, "warning": 4, "partial": 4}.get(r.mta_sts.status, 0)
        pts["tls-rpt"] = 3 if parked or r.tls_rpt.status == "valid" else 0
        pts["dnssec"] = 5 if r.dnssec.status == "valid" else 0
        return pts

    def _calculate_score(self, r: DomainResult) -> int:
        weighted = [c for c in CHECKS if c in self.checks and CHECKS[c]]
        max_total = sum(CHECKS[c] for c in weighted)
        if not r.exists or r.profile == "unreachable":
            r.score_breakdown = {"components": {}, "max": max_total, "normalized": False, "cap": None,
                                 "note": "Domain does not exist" if not r.exists else "Name servers unreachable"}
            return 0
        if max_total == 0:
            sev = Counter(i.severity for i in r.issues)
            score = max(0, 100 - 40 * sev["critical"] - 15 * sev["warning"])
            r.score_breakdown = {"components": {}, "max": 0, "normalized": False, "cap": None,
                                 "note": "No weighted check selected: 100 - 40 per critical - 15 per warning finding"}
            return score
        pts = self._component_points(r)
        comps = {c: {"got": round(max(pts.get(c, 0), 0), 1), "max": CHECKS[c]} for c in weighted}
        score = int(round(min(max(100 * sum(v["got"] for v in comps.values()) / max_total, 0), 100)))
        cap = None
        for i in r.issues:
            limit = SCORE_CAP_CODES.get(i.code)
            if limit is not None and score > limit and (cap is None or limit < cap[0]):
                cap = (limit, FINDINGS[i.code][2])
        if cap:
            score = cap[0]
        r.score_breakdown = {"components": comps, "max": max_total, "normalized": max_total != 100,
                             "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}
        return score

    # ------------------------------------------------------------------
    # Compliance (what DNS can show)
    # ------------------------------------------------------------------

    def _evaluate_compliance(self, r: DomainResult) -> Dict[str, str]:
        on = self.checks
        if not r.exists:
            return {k: "n/a" for k in COMPLIANCE_PROFILES}

        def state(ok: bool, needed: List[str], applicable: bool = True) -> str:
            if not set(needed) <= on or not applicable:
                return "n/a"
            if r.profile == "unreachable" or any(
                    getattr(r, CHECK_ATTRS[c]).status == "dns_error" for c in needed):
                return "unknown"
            return "pass" if ok else "fail"

        sending = r.profile == "mail"
        spf_ok = r.spf.status in ("valid", "warning") and not r.spf.permerror and r.spf.mechanism != "+all"
        dkim_ok = any((s.status in ("valid", "weak") and (s.key_size or 0) >= 1000)
                      or (s.algorithm == "ed25519" and s.status == "valid") for s in r.dkim.selectors)
        dmarc_ok = bool(r.dmarc.policy) and not any(i.code == "DMARC_MULTIPLE" for i in r.dmarc.issues)
        d = r.dmarc
        return {
            "gmail_yahoo": state(spf_ok and dkim_ok and dmarc_ok, ["spf", "dkim", "dmarc"], sending),
            "microsoft": state(spf_ok and dkim_ok and dmarc_ok, ["spf", "dkim", "dmarc"], sending),
            "dmarc_enforcement": state(d.policy == "reject" and d.pct == 100 and d.subdomain_policy != "none"
                                       and bool(d.rua_destinations), ["dmarc"]),
            "transport": state(r.mta_sts.status == "valid" and r.tls_rpt.status == "valid",
                               ["mta-sts", "tls-rpt"], sending),
        }


# ---------------------------------------------------------------------------
# Lookalike generation
# ---------------------------------------------------------------------------

_QWERTY_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
KEYBOARD_NEIGHBOURS: Dict[str, str] = {}
for _r, _row in enumerate(_QWERTY_ROWS):
    for _c, _ch in enumerate(_row):
        _near = []
        for _dr in (-1, 0, 1):
            _rr = _r + _dr
            if 0 <= _rr < len(_QWERTY_ROWS):
                for _dc in (-1, 0, 1):
                    _cc = _c + _dc
                    if (_dr or _dc) and 0 <= _cc < len(_QWERTY_ROWS[_rr]):
                        _near.append(_QWERTY_ROWS[_rr][_cc])
        KEYBOARD_NEIGHBOURS[_ch] = "".join(_near)

ASCII_HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
                    "e": ["3"], "a": ["4"], "s": ["5"], "g": ["q", "9"], "b": ["6"], "z": ["2"], "t": ["7"]}
MULTI_HOMOGLYPHS = [("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl"), ("nn", "m")]
IDN_HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ"}
LOOKALIKE_TLDS = ["com", "net", "org", "it", "eu", "co", "io", "info", "biz", "online", "site", "shop",
                  "app", "de", "fr", "es", "ch", "nl", "us", "co.uk"]
COMBO_WORDS = ["mail", "secure", "login", "account", "support", "online", "group", "web", "portal", "it"]
LOOKALIKE_PRIORITY = ["homoglyph", "idn-homoglyph", "tld-swap", "omission", "transposition", "repetition",
                      "hyphenation", "combo", "replacement", "vowel-swap", "insertion"]


def generate_lookalikes(reg_domain: str, limit: int = 150) -> Dict[str, str]:
    """Typosquatting candidates for a registrable domain -> technique. Ordered by likelihood."""
    name, _, suffix = reg_domain.partition(".")
    buckets: Dict[str, List[str]] = defaultdict(list)
    seen = {reg_domain}

    def add(label: str, kind: str, sfx: str = suffix) -> None:
        label = label.strip("-")
        if not label or len(label) > 63:
            return
        if not label.startswith("xn--") and not re.fullmatch(r"[a-z0-9-]+", label):
            return
        cand = f"{label}.{sfx}"
        if cand not in seen:
            seen.add(cand)
            buckets[kind].append(cand)

    n = len(name)
    for i, ch in enumerate(name):
        for rep in ASCII_HOMOGLYPHS.get(ch, []):
            add(name[:i] + rep + name[i + 1:], "homoglyph")
    for a, b in MULTI_HOMOGLYPHS:
        idx = name.find(a)
        while idx >= 0:
            add(name[:idx] + b + name[idx + len(a):], "homoglyph")
            idx = name.find(a, idx + 1)
    for i, ch in enumerate(name):
        if ch in IDN_HOMOGLYPHS:
            try:
                add(to_ascii(name[:i] + IDN_HOMOGLYPHS[ch] + name[i + 1:]), "idn-homoglyph")
            except Exception:
                pass
    for t in LOOKALIKE_TLDS:
        if t != suffix:
            add(name, "tld-swap", t)
    for i in range(n):
        add(name[:i] + name[i + 1:], "omission")
    for i in range(n - 1):
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
    for i in range(n):
        add(name[:i] + name[i] + name[i:], "repetition")
    for i in range(1, n):
        add(name[:i] + "-" + name[i:], "hyphenation")
    for w in COMBO_WORDS:
        add(f"{name}-{w}", "combo")
        add(f"{name}{w}", "combo")
        add(f"{w}-{name}", "combo")
    for i, ch in enumerate(name):
        for k in KEYBOARD_NEIGHBOURS.get(ch, ""):
            add(name[:i] + k + name[i + 1:], "replacement")
    for i, ch in enumerate(name):
        if ch in "aeiou":
            for v in "aeiou":
                if v != ch:
                    add(name[:i] + v + name[i + 1:], "vowel-swap")
    for i, ch in enumerate(name):
        for k in KEYBOARD_NEIGHBOURS.get(ch, ""):
            add(name[:i] + k + name[i:], "insertion")

    out: Dict[str, str] = {}
    pointers = {k: 0 for k in LOOKALIKE_PRIORITY}
    while len(out) < limit and any(pointers[k] < len(buckets[k]) for k in LOOKALIKE_PRIORITY):
        for k in LOOKALIKE_PRIORITY:  # round-robin across techniques, in priority order
            if pointers[k] < len(buckets[k]) and len(out) < limit:
                out[buckets[k][pointers[k]]] = k
                pointers[k] += 1
    return out


# ---------------------------------------------------------------------------
# DMARC aggregate reports (RFC 7489 appendix C)
# ---------------------------------------------------------------------------

MAX_REPORT_BYTES = 50 * 1024 * 1024


def _safe_xml(data: bytes):
    if _SafeET is not None:
        return _SafeET.fromstring(data, forbid_dtd=True)
    head = data.lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise ValueError("DTD/entities are not allowed in DMARC reports")
    return _ET.fromstring(data)


def _report_payloads(name: str, data: bytes, depth: int = 0) -> Iterable[Tuple[str, bytes]]:
    """Yield (label, xml bytes) from xml / gz / zip / eml content, with decompression limits."""
    if depth > 3:
        return
    low = name.lower()
    if data[:2] == b"\x1f\x8b" or low.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            raw = g.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("decompressed report too large")
        yield from _report_payloads(low[:-3] if low.endswith(".gz") else low + ".xml", raw, depth + 1)
    elif data[:4] == b"PK\x03\x04" or low.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_REPORT_BYTES:
                    continue
                yield from _report_payloads(info.filename, z.read(info), depth + 1)
    elif low.endswith((".eml", ".msg")) or data[:5] in (b"Retur", b"Recei", b"From ", b"Deliv", b"MIME-"):
        msg = email.message_from_bytes(data, policy=email.policy.default)
        for part in msg.walk():
            fname = part.get_filename() or ""
            ctype = part.get_content_type()
            if fname or ctype in ("application/zip", "application/gzip", "application/x-gzip", "text/xml",
                                  "application/xml"):
                payload = part.get_payload(decode=True) or b""
                if payload:
                    yield from _report_payloads(fname or ("x.zip" if "zip" in ctype else "x.xml"), payload, depth + 1)
    elif data.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] == b"<":
        yield name, data.lstrip(b"\xef\xbb\xbf")


def load_dmarc_reports(paths: List[str]) -> Tuple[Dict[str, dict], List[str], int]:
    """Aggregate DMARC reports by header_from domain. Returns (data, errors, report_count)."""
    files: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files.extend(os.path.join(root, n) for n in sorted(names))
        elif os.path.exists(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)

    data: Dict[str, dict] = {}
    errors: List[str] = []
    seen_ids: Set[Tuple[str, str]] = set()

    def new_domain():
        return {"reports": 0, "messages": 0, "passed": 0, "begin": "", "end": "", "reporters": Counter(),
                "sources": {}, "selector_pairs": set()}

    for path in files:
        try:
            if os.path.getsize(path) > MAX_REPORT_BYTES:
                raise ValueError("file too large")
            with open(path, "rb") as f:
                blob = f.read()
            for label, xml in _report_payloads(os.path.basename(path), blob):
                root = _safe_xml(xml)
                if root.tag != "feedback":
                    continue
                org = (root.findtext("report_metadata/org_name") or "unknown").strip()
                rid = (root.findtext("report_metadata/report_id") or label).strip()
                if (org, rid) in seen_ids:
                    continue
                seen_ids.add((org, rid))
                begin = root.findtext("report_metadata/date_range/begin") or ""
                end = root.findtext("report_metadata/date_range/end") or ""
                touched = set()
                for rec in root.findall("record"):
                    hdr = (rec.findtext("identifiers/header_from") or
                           root.findtext("policy_published/domain") or "").strip().lower().rstrip(".")
                    if not hdr:
                        continue
                    d = data.setdefault(hdr, new_domain())
                    touched.add(hdr)
                    try:
                        count = int(rec.findtext("row/count") or 0)
                    except ValueError:
                        count = 0
                    ip = (rec.findtext("row/source_ip") or "?").strip()
                    pe_dkim = (rec.findtext("row/policy_evaluated/dkim") or "").lower()
                    pe_spf = (rec.findtext("row/policy_evaluated/spf") or "").lower()
                    disp = (rec.findtext("row/policy_evaluated/disposition") or "none").lower()
                    auth_pass = False
                    dkim_domains = set()
                    for dk in rec.findall("auth_results/dkim"):
                        dom = (dk.findtext("domain") or "").lower()
                        sel = (dk.findtext("selector") or "").strip()
                        res = (dk.findtext("result") or "").lower()
                        if res == "pass":
                            auth_pass = True
                            dkim_domains.add(dom)
                            if sel and dom:
                                d["selector_pairs"].add((dom, sel))
                    for sp in rec.findall("auth_results/spf"):
                        if (sp.findtext("result") or "").lower() == "pass":
                            auth_pass = True
                    src = d["sources"].setdefault(ip, {"count": 0, "passed": 0, "unaligned": 0, "spoofed": 0,
                                                       "envelope_from": set(), "dkim_domains": set(),
                                                       "disposition": Counter()})
                    src["count"] += count
                    src["disposition"][disp] += count
                    src["dkim_domains"] |= dkim_domains
                    env = (rec.findtext("identifiers/envelope_from") or "").strip().lower()
                    if env:
                        src["envelope_from"].add(env)
                    d["messages"] += count
                    if pe_dkim == "pass" or pe_spf == "pass":
                        src["passed"] += count
                        d["passed"] += count
                    elif auth_pass:
                        src["unaligned"] += count
                    else:
                        src["spoofed"] += count
                for hdr in touched:
                    d = data[hdr]
                    d["reports"] += 1
                    d["reporters"][org] += 1
                    if begin and (not d["begin"] or begin < d["begin"]):
                        d["begin"] = begin
                    if end and end > d["end"]:
                        d["end"] = end
        except Exception as e:
            errors.append(f"{os.path.basename(path)}: {type(e).__name__}: {e}")

    for d in data.values():
        for key in ("begin", "end"):
            if d[key].isdigit():
                d[key] = datetime.fromtimestamp(int(d[key]), timezone.utc).strftime("%Y-%m-%d")
        d["selector_pairs"] = sorted(d["selector_pairs"])
    return data, errors, len(seen_ids)


# ---------------------------------------------------------------------------
# Remediation: copy-ready records
# ---------------------------------------------------------------------------

SPF_PROVIDER_INCLUDES = {
    "Microsoft 365 / EOP": "include:spf.protection.outlook.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "Google Workspace": "include:_spf.google.com",
}


def _dmarc_record(tags: Dict[str, str]) -> str:
    order = ["v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf", "fo", "ri"]
    keys = [k for k in order if k in tags] + [k for k in tags if k not in order]
    return "; ".join(f"{k}={tags[k]}" for k in keys)


def suggest_remediation(r: DomainResult, checks: Set[str]) -> List[dict]:
    """Copy-ready DNS records for the most impactful fixes (to be reviewed before publishing)."""
    out: List[dict] = []
    domain = r.domain
    if not r.exists or r.profile == "unreachable":
        return out

    def rec(title, name, rtype, value, note=""):
        out.append({"title": title, "name": name, "type": rtype, "value": value, "note": note})

    codes = {i.code for i in r.issues}
    report_addr = f"mailto:dmarc-reports@{org_domain(domain)}"
    existing = parse_tags(r.dmarc.record) if r.dmarc.record and not r.dmarc.inherited_from else {}

    if r.profile == "non-mail":
        if "mx" in checks and not r.mx.null_mx:
            rec("Declare that the domain receives no mail (Null MX)", domain, "MX", "0 .")
        if "spf" in checks and "SPF_PARKED_NOT_STRICT" in codes:
            rec("Authorize no sender", domain, "TXT", "v=spf1 -all")
        if "dmarc" in checks and "DMARC_PARKED_NOT_REJECT" in codes:
            tags = {"v": "DMARC1", "p": "reject", "sp": "reject", "adkim": "s", "aspf": "s"}
            if existing.get("rua"):
                tags["rua"] = existing["rua"]
            rec("Reject every message claiming to come from this domain", f"_dmarc.{domain}", "TXT", _dmarc_record(tags))
        if "dkim" in checks:
            rec("Optional: revoke any DKIM key under this domain", f"*._domainkey.{domain}", "TXT", "v=DKIM1; p=",
                "Recommended by M3AAWG for parked domains")
        return out

    if "spf" in checks:
        s = r.spf
        if s.status == "missing":
            mechs = list(dict.fromkeys(SPF_PROVIDER_INCLUDES[p] for p in r.mx.providers if p in SPF_PROVIDER_INCLUDES))
            rec("Publish an SPF record", domain, "TXT", f"v=spf1 {' '.join(mechs or ['mx'])} ~all",
                "Add every other service that sends as this domain, then move to -all")
        elif "SPF_MULTIPLE" in codes and s.records:
            terms = []
            for record in s.records:
                for t in record.split()[1:]:
                    if not re.fullmatch(r"[+\-~?]?all", t, re.I) and t not in terms:
                        terms.append(t)
            rec("Merge the SPF records into one", domain, "TXT", f"v=spf1 {' '.join(terms)} ~all",
                "Delete the other v=spf1 records")
        elif s.record and s.mechanism in ("+all", "?all", None) and not s.permerror:
            base = re.sub(r"\s+[+\-~?]?all\b", "", s.record, flags=re.I).strip()
            rec("Terminate SPF with a fail mechanism", domain, "TXT", f"{base} ~all",
                "Use -all once DMARC reports confirm every sender is listed")
        if "SPF_LOOKUP_LIMIT" in codes:
            rec("Reduce SPF DNS lookups", "", "", "",
                "Remove unused includes, replace a/mx with ip4/ip6 or move bulk senders to a subdomain")

    if "dmarc" in checks and r.dmarc.status != "dns_error":
        d = r.dmarc
        if d.status == "missing":
            rec("Start DMARC in monitoring mode", f"_dmarc.{domain}", "TXT",
                _dmarc_record({"v": "DMARC1", "p": "none", "rua": report_addr, "fo": "1"}),
                "Collect reports for 2-4 weeks, then move to quarantine and reject")
        elif "DMARC_MULTIPLE" in codes:
            rec("Keep a single DMARC record", f"_dmarc.{domain}", "TXT", d.record or "", "Delete the other records")
        elif not d.inherited_from and existing:
            tags = dict(existing)
            nxt = {"none": "quarantine", "quarantine": "reject"}.get((tags.get("p") or "").lower())
            blockers = codes & {"X_ENFORCED_NO_AUTH", "X_DMARC_SPF_BROKEN", "X_DMARC_NO_DKIM", "REPORT_UNALIGNED_SOURCES"}
            changed = False
            if nxt and not blockers:
                tags["p"] = nxt
                changed = True
            elif nxt:
                rec("Fix SPF/DKIM before tightening DMARC", "", "", "",
                    "Moving to a stricter policy now would block legitimate mail: resolve the SPF/DKIM findings first")
                nxt = None
            if "pct" in tags and tags["pct"] != "100":
                tags.pop("pct")
                changed = True
            for key in ("aspf", "adkim"):
                if key in tags and tags[key].strip().lower() not in ("r", "s"):
                    tags.pop(key)
                    changed = True
            if (tags.get("sp") or "").lower() == "none" and tags.get("p") in ("quarantine", "reject"):
                tags["sp"] = tags["p"]
                changed = True
            if not tags.get("rua"):
                tags["rua"] = report_addr
                changed = True
            if changed:
                step = f"Move DMARC to p={tags['p']}" if nxt else "Correct the DMARC record"
                rec(step, f"_dmarc.{domain}", "TXT", _dmarc_record(tags),
                    "Check DMARC reports first: senders that are not aligned will be blocked" if nxt
                    else "Fixes invalid or weakening tags without changing the policy")

    if "dkim" in checks and r.dkim.status == "missing":
        if any("Microsoft" in p for p in r.mx.providers):
            label = domain.replace(".", "-")
            for sel in ("selector1", "selector2"):
                rec(f"Enable DKIM in Microsoft 365 ({sel})", f"{sel}._domainkey.{domain}", "CNAME",
                    f"{sel}-{label}._domainkey.<tenant>.onmicrosoft.com",
                    "Replace <tenant>; copy the exact value from the Defender portal")
        elif "Google Workspace" in r.mx.providers:
            rec("Enable DKIM in Google Workspace", f"google._domainkey.{domain}", "TXT", "v=DKIM1; k=rsa; p=<key>",
                "Generate a 2048-bit key in Admin console > Apps > Gmail > Authenticate email")
        else:
            rec("Enable DKIM signing", "", "", "", "Generate a 2048-bit key with every platform that sends as this domain")
    if "dkim" in checks and r.dkim.weak_keys:
        rec("Rotate weak DKIM keys", "", "", "", "Publish a new 2048-bit selector, switch signing, then revoke the old key (p=)")

    mx_hosts = [m.host for m in r.mx.records if m.host]
    if "mta-sts" in checks and mx_hosts and (r.mta_sts.status in ("missing", "error") or "MTASTS_MX_MISMATCH" in codes):
        patterns = []
        for h in mx_hosts:
            pat = "*.mail.protection.outlook.com" if h.endswith(".mail.protection.outlook.com") else h
            if pat not in patterns:
                patterns.append(pat)
        policy = "version: STSv1\nmode: testing\n" + "".join(f"mx: {p}\n" for p in patterns) + "max_age: 604800"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        rec("Publish the MTA-STS policy record", f"_mta-sts.{domain}", "TXT", f"v=STSv1; id={stamp}",
            "Change the id every time the policy file changes")
        rec("Serve the MTA-STS policy file", f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "FILE", policy,
            "HTTPS with a valid certificate, text/plain, no redirects; switch to mode: enforce after clean TLS reports")
    if "tls-rpt" in checks and r.tls_rpt.status == "missing" and r.profile == "mail":
        rec("Receive TLS failure reports", f"_smtp._tls.{domain}", "TXT",
            f"v=TLSRPTv1; rua=mailto:tls-reports@{org_domain(domain)}")
    if "dnssec" in checks and r.dnssec.status == "missing":
        rec("Enable DNSSEC", "", "", "", "Sign the zone at your DNS provider and publish the DS record at the registrar")
    if "takeover" in checks:
        for e in r.takeover.dependencies:
            if e["state"] in ("unregistered", "expired"):
                rec(f"Remove the reference to {e['domain']}", "", "", "",
                    f"Used by: {', '.join(e['used_by'])}. Remove it from DNS or make sure the domain is registered")
        for dgl in r.takeover.dangling:
            rec(f"Remove dangling CNAME {dgl['name']}", dgl["name"], "CNAME", "(delete)",
                f"Points to {dgl['target']}, which does not exist")
    return out


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Input (plain list or CSV with metadata) and configuration
# ---------------------------------------------------------------------------

CSV_COLUMNS = {
    "domain": ("domain", "dominio", "domains", "fqdn"),
    "tier": ("tier", "criticality", "criticita", "criticità", "priority", "priorita"),
    "owner": ("owner", "referente", "responsabile"),
    "bu": ("bu", "business_unit", "business unit", "unit", "department", "dipartimento"),
    "tags": ("tags", "tag", "labels"),
}


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read().lstrip("\ufeff")
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


def load_domains(path: str) -> Tuple[List[DomainInput], List[str]]:
    text = _read_input(path)
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    first = lines[0].lower() if lines else ""
    is_csv = path.lower().endswith((".csv", ".tsv")) or bool(
        re.match(r"^\s*\"?(domain|dominio|domains|fqdn)\"?\s*[,;\t]", first))
    inputs: Dict[str, DomainInput] = {}
    invalid: List[str] = []
    if is_csv:
        try:
            dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO("\n".join(lines)), dialect=dialect)
        colmap = {}
        for col in reader.fieldnames or []:
            key = col.strip().lower()
            for target, aliases in CSV_COLUMNS.items():
                if key in aliases:
                    colmap[target] = col
        if "domain" not in colmap:
            raise ValueError("CSV input needs a 'domain' column")
        for row in reader:
            raw = (row.get(colmap["domain"]) or "").strip()
            d = normalize_domain(raw)
            if not d:
                if raw:
                    invalid.append(raw)
                continue
            if d in inputs:
                continue
            tier_raw = (row.get(colmap.get("tier", ""), "") or "").strip().lower()
            tags = [t.strip() for t in re.split(r"[|,;]", row.get(colmap.get("tags", ""), "") or "") if t.strip()]
            inputs[d] = DomainInput(domain=d, tier=TIER_ALIASES.get(tier_raw, "medium"),
                                    owner=(row.get(colmap.get("owner", ""), "") or "").strip(),
                                    bu=(row.get(colmap.get("bu", ""), "") or "").strip(), tags=tags)
    else:
        for line in lines:
            for token in re.split(r"[,\s;]+", line.split("#", 1)[0].strip()):
                if not token:
                    continue
                d = normalize_domain(token)
                if not d:
                    invalid.append(token)
                elif d not in inputs:
                    inputs[d] = DomainInput(domain=d)
    return list(inputs.values()), invalid


def load_config(path: str, profile: Optional[str]) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ValueError("YAML config needs PyYAML (pip install pyyaml) - or use a .json config")
        cfg = yaml.safe_load(text) or {}
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise ValueError("config must be a mapping of option: value")
    profiles = cfg.pop("profiles", {}) or {}
    if profile:
        if profile not in profiles:
            raise ValueError(f"profile '{profile}' not found (available: {', '.join(profiles) or 'none'})")
        cfg.update(profiles[profile] or {})
    out = {}
    for k, v in cfg.items():
        key = str(k).replace("-", "_")
        if isinstance(v, list) and key in ("checks", "skip", "selectors", "nameservers", "lookalike_tiers"):
            v = ",".join(str(x) for x in v)
        out[key] = v
    return out


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def write_json(results: List[DomainResult], path: str) -> None:
    # Same top-level shape as v1/v2 (list of domain objects); new fields are additive.
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)


CSV_EXPORT_COLUMNS = [
    "domain", "score", "priority", "tier", "owner", "bu", "tags", "profile", "mx_status", "mx_providers",
    "spf_status", "spf_all", "spf_lookups", "spf_void_lookups", "dkim_status", "dkim_selectors", "dmarc_status",
    "dmarc_policy", "dmarc_sp", "dmarc_pct", "dmarc_rua", "mta_sts_mode", "tls_rpt", "bimi", "dnssec",
    "takeover", "lookalikes_with_mx", "gmail_yahoo", "microsoft", "dmarc_enforcement", "score_delta",
    "critical", "warning", "info", "issue_codes",
]


def write_csv(results: List[DomainResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel opens it as UTF-8
        w = csv.writer(f, delimiter=";")
        w.writerow(CSV_EXPORT_COLUMNS)
        for r in results:
            sev = Counter(i.severity for i in r.issues)
            row = [
                r.domain, r.overall_score, r.priority, r.tier, r.owner, r.bu, "|".join(r.tags), r.profile,
                r.mx.status, ", ".join(r.mx.providers), r.spf.status, r.spf.mechanism or "", r.spf.lookups,
                r.spf.void_lookups, r.dkim.status,
                ", ".join(f"{s.name}:{s.key_size or s.status}" for s in r.dkim.selectors), r.dmarc.status,
                r.dmarc.policy or "", r.dmarc.subdomain_policy or "", r.dmarc.pct, ", ".join(r.dmarc.rua_destinations),
                r.mta_sts.mode or r.mta_sts.status, r.tls_rpt.status, r.bimi.status, r.dnssec.status,
                r.takeover.status, sum(1 for e in r.lookalikes.registered if e.get("mx")),
                r.compliance.get("gmail_yahoo", ""), r.compliance.get("microsoft", ""),
                r.compliance.get("dmarc_enforcement", ""),
                "" if not r.change or r.change.get("score_delta") is None else r.change["score_delta"],
                sev["critical"], sev["warning"], sev["info"], "|".join(i.code for i in r.issues),
            ]
            w.writerow([csv_safe(v) for v in row])


# ---------------------------------------------------------------------------
# HTML report: self-contained application (no CDN, no web fonts, no network)
# ---------------------------------------------------------------------------

REPORT_CSS = ui.asset("dns.css")

REPORT_JS = ui.asset("dns.js")

REPORT_TEMPLATE = ui.asset("report.html").replace("__NOSCRIPT__", '<noscript><p style="padding:24px">This report needs JavaScript to display the results. The same data is available in the JSON export.</p></noscript>\n')


def _json_for_html(obj: Any) -> str:
    return json_for_html(obj, default=list)


def generate_html_report(results: List[DomainResult], output_file: str, meta: Optional[dict] = None) -> None:
    """Self-contained single-file application: CSS and JS inline, results embedded as JSON."""
    meta = meta or {}
    checks = [c for c in CHECKS if c in (meta.get("checks") or DEFAULT_CHECKS)]
    weighted = [c for c in checks if CHECKS[c]]
    notes = [
        ("Score weights: " + ", ".join(f"{CHECK_LABELS[c]} {CHECKS[c]}" for c in weighted)
         + (" (normalized to 100 over the selected checks)." if sum(CHECKS[c] for c in weighted) != 100 else ".")
         if weighted else "Score derived from findings: 100 minus 40 per critical and 15 per warning finding."),
        "Takeover exposure, broken DNSSEC and expired registrations cap the score. "
        "Priority = tier weight x (100 - score + 15 x critical findings).",
        "DKIM is detected by probing common selectors and the selectors seen in DMARC reports: "
        "not found does not prove it is absent.",
        "Compliance and framework references are indicative: they cover what DNS can show.",
    ] + [n for n in meta.get("notes", []) if n]
    if meta.get("stats"):
        notes.append(meta["stats"])
    payload = {
        "meta": {
            "version": __version__,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "resolver": meta.get("resolver", ""),
            "notes": notes,
        },
        "checks": checks,
        "labels": CHECK_LABELS,
        "attrs": CHECK_ATTRS,
        "weights": {c: CHECKS[c] for c in checks},
        "findings": {k: list(v) for k, v in FINDINGS.items()},
        "frameworks": FRAMEWORK_MAP,
        "compliance": {k: list(v) for k, v in COMPLIANCE_PROFILES.items()},
        "tiers": TIER_WEIGHTS,
        "diff": meta.get("diff"),
        "unscanned_report_domains": meta.get("unscanned_report_domains", []),
        "results": [asdict(r) for r in results],
    }
    page = (REPORT_TEMPLATE
            .replace("__TITLE__", html.escape(f"Email security posture - {len(results)} domains"))
            .replace("__CSS__", REPORT_CSS)
            .replace("__JS__", REPORT_JS)
            .replace("__DATA__", _json_for_html(payload)))  # data last: placeholders inside data stay inert
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_Parser = Parser




class Progress:
    """Single-line progress bar with ETA on a terminal, one line per domain otherwise."""

    def __init__(self, total: int, quiet: bool = False):
        self.total, self.quiet = total, quiet
        self.done = 0
        self.counts = Counter()
        self.start = time.monotonic()
        self.tty = sys.stderr.isatty()
        self._last = 0.0
        self.width = len(str(total))

    def update(self, r: DomainResult) -> None:
        self.done += 1
        key = "err" if r.error or r.profile == "unreachable" else "ok" if r.overall_score >= 80 else \
            "warn" if r.overall_score >= 50 else "crit"
        self.counts[key] += 1
        if self.quiet:
            return
        if not self.tty:
            tag = {"ok": " OK", "warn": "  !", "crit": "  X", "err": "ERR"}[key]
            print(f"  [{self.done:>{self.width}}/{self.total}] {tag} {r.domain} (score: {r.overall_score})", file=sys.stderr)
            return
        now = time.monotonic()
        if now - self._last < 0.15 and self.done < self.total:
            return
        self._last = now
        elapsed = now - self.start
        eta = elapsed / self.done * (self.total - self.done) if self.done else 0
        filled = int(28 * self.done / self.total)
        bar = "#" * filled + "." * (28 - filled)
        line = (f"\r  [{bar}] {self.done}/{self.total} {100 * self.done // self.total:3d}%  "
                f"ETA {int(eta // 60)}m{int(eta % 60):02d}s  ok {self.counts['ok']}  ! {self.counts['warn']}  "
                f"X {self.counts['crit']}  err {self.counts['err']}   ")
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self) -> None:
        if self.tty and not self.quiet:
            sys.stderr.write("\n")


def print_timing_summary(results: List[DomainResult], top: int = 5) -> None:
    """Where does the time go? Average/max per check and the slowest domains."""
    per_check: Dict[str, List[int]] = {}
    for r in results:
        for name, ms in r.timings.items():
            per_check.setdefault(name, []).append(ms)
    if not per_check:
        return
    print("\nTiming per check (avg / max ms):")
    for name, values in sorted(per_check.items(), key=lambda kv: -sum(kv[1]) / len(kv[1])):
        print(f"  {name:<12} {sum(values) / len(values):8.0f} / {max(values):6d}")
    print("Slowest domains:")
    for r in sorted(results, key=lambda r: -r.duration_ms)[:top]:
        worst = max(r.timings.items(), key=lambda kv: kv[1], default=("-", 0))
        print(f"  {r.domain:<40} {r.duration_ms:7d} ms  (slowest: {worst[0]} {worst[1]} ms)")
    unreachable = sum(1 for r in results if r.profile == "unreachable")
    if unreachable:
        print(f"Unreachable name servers: {unreachable} domain(s) - checks skipped after retries")


def build_parser() -> _Parser:
    parser = _Parser(
        description="Email security posture of a domain portfolio via live DNS "
                    "(MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, takeover, consistency, lookalikes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    securityhub dns domains.txt
    securityhub dns portfolio.csv -o report.html --json --csv
    securityhub dns domains.txt --checks spf,dmarc,takeover
    securityhub dns domains.txt --checks all,lookalikes --lookalike-tiers critical,high
    securityhub dns domains.txt --dmarc-reports ./rua/ --baseline previous.json
    securityhub dns domains.txt --config mailguard.yaml --profile weekly

Checks: mx, spf, dkim, dmarc, mta-sts, tls-rpt, bimi, dnssec, takeover (= 'all', the default),
        plus the opt-in consistency and lookalikes ('full' = everything). Combine: --checks all,lookalikes
Input: text (one domain per line; URLs/e-mails accepted; '#' comments) or CSV with a 'domain' column
       and optional tier (critical/high/medium/low), owner, bu, tags (separated by |).
Config: JSON or YAML with option names as keys (e.g. checks, workers, nameservers) and optional
        'profiles: {name: {...}}' selected with --profile. Command-line options override it.
Exit codes: 0 ok, 1 usage/input/resolver error, 2 a domain scored below --fail-under, 130 interrupted.
        """,
    )
    parser.add_argument("input_file", help="Text or CSV file with domains ('-' for stdin)")
    parser.add_argument("-o", "--output", default="mailguard_dns_report.html", help="Output HTML file")
    parser.add_argument("-c", "--checks", default="all",
                        help="Checks to run, comma-separated: " + ",".join(CHECKS) + ", all, full (default: all)")
    parser.add_argument("--skip", default="", help="Checks to exclude, e.g. --skip dkim,bimi")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Per-query DNS/HTTP timeout in seconds (default: 5)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Domains analyzed in parallel (default: 10)")
    parser.add_argument("-j", "--json", action="store_true", help="Also write JSON results")
    parser.add_argument("--csv", action="store_true", help="Also write a CSV summary (';' separated, Excel friendly)")
    parser.add_argument("--nameservers", default="1.1.1.1,8.8.8.8,9.9.9.9",
                        help="Comma-separated resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)")
    parser.add_argument("--system-resolver", action="store_true", help="Use the OS resolver configuration")
    parser.add_argument("--qps", type=float, default=0, help="Max DNS queries per second (0 = unlimited)")
    parser.add_argument("--skip-preflight", action="store_true", help="Do not test the resolver before scanning")
    parser.add_argument("--selectors", default="", help="Extra DKIM selectors, comma-separated")
    parser.add_argument("--selectors-file", help="File with extra DKIM selectors (one per line)")
    parser.add_argument("--only-selectors", action="store_true", help="Probe only the selectors you provide")
    parser.add_argument("--fast-dkim", action="store_true",
                        help="Skip selector probing when _domainkey is NXDOMAIN (RFC 8020; faster on large portfolios)")
    parser.add_argument("--no-http", action="store_true", help="Do not fetch MTA-STS policies over HTTPS")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow MTA-STS fetches to private/loopback addresses (internal assessments only)")
    parser.add_argument("--no-rdap", action="store_true", help="Skip RDAP registration lookups (takeover/lookalikes)")
    parser.add_argument("--offline", action="store_true",
                        help="No downloads at all (PSL, RDAP): use cached data or fallbacks")
    parser.add_argument("--psl-file", help="Local copy of public_suffix_list.dat")
    parser.add_argument("--dmarc-reports", action="append", default=[], metavar="PATH",
                        help="DMARC aggregate reports (.xml/.gz/.zip/.eml) - file or folder, repeatable")
    parser.add_argument("--baseline", help="Previous JSON export to compare with")
    parser.add_argument("--lookalike-limit", type=int, default=150, help="Lookalike candidates per domain (default: 150)")
    parser.add_argument("--lookalike-tiers", default="", help="Only check lookalikes for these tiers, e.g. critical,high")
    parser.add_argument("--fail-under", type=int, help="Exit with code 2 if any domain scores below this value")
    parser.add_argument("--config", help="JSON/YAML configuration file")
    parser.add_argument("--profile", help="Profile name inside the configuration file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    parser.add_argument("--version", action="version", version=f"MailGuard DNS {__version__}")
    return parser


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.config:
        try:
            cfg = load_config(args.config, args.profile)
        except (OSError, ValueError) as e:
            parser.error(f"config: {e}")
        known = {a.dest for a in parser._actions}
        unknown = sorted(k for k in cfg if k not in known)
        if unknown:
            print(f"Config: ignoring unknown option(s) {', '.join(unknown)}", file=sys.stderr)
        parser.set_defaults(**{k: v for k, v in cfg.items() if k in known and k not in ("config", "profile")})
        args = parser.parse_args(argv)  # command line wins over the config file
    elif args.profile:
        parser.error("--profile needs --config")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)
    parser = build_parser()
    try:
        checks = parse_checks(args.checks, args.skip)
    except ValueError as e:
        parser.error(str(e))

    # Public Suffix List first: everything that computes organizational domains depends on it
    try:
        psl, psl_note = PublicSuffixList.load(args.psl_file, allow_download=not args.offline)
    except (OSError, ValueError) as e:
        parser.error(f"--psl-file: {e}")
    set_psl(psl)
    if psl_note.startswith("WARNING"):
        print(psl_note, file=sys.stderr)

    try:
        inputs, invalid = load_domains(args.input_file)
    except (OSError, ValueError) as e:
        print(f"Error: cannot read '{args.input_file}': {e}", file=sys.stderr)
        return EXIT_USAGE
    if invalid:
        print(f"Skipped {len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: "
              f"{', '.join(invalid[:5])}{' ...' if len(invalid) > 5 else ''}", file=sys.stderr)
    if not inputs:
        print("Error: no valid domains found in input", file=sys.stderr)
        return EXIT_USAGE

    extra = [s.strip() for s in args.selectors.split(",") if s.strip()]
    if args.selectors_file:
        try:
            with open(args.selectors_file, encoding="utf-8") as f:
                extra += [l.split("#", 1)[0].strip() for l in f if l.split("#", 1)[0].strip()]
        except OSError as e:
            print(f"Error: cannot read selectors file '{args.selectors_file}': {e.strerror or e}", file=sys.stderr)
            return EXIT_USAGE
    if args.only_selectors and not extra:
        parser.error("--only-selectors needs --selectors or --selectors-file")
    selectors = extra if args.only_selectors else DEFAULT_DKIM_SELECTORS + extra
    nameservers = [n.strip() for n in args.nameservers.split(",") if n.strip()]
    workers = max(1, args.workers)

    client = DNSClient(nameservers, args.timeout, args.system_resolver, args.qps)
    notes: List[str] = [psl_note]
    if not args.skip_preflight:
        ok, message = preflight(client)
        if not ok:
            print(f"Error: {message}", file=sys.stderr)
            return EXIT_USAGE
        if message.startswith("WARNING"):
            print(message, file=sys.stderr)
            notes.append(message)

    report_data: Dict[str, dict] = {}
    unscanned: List[str] = []
    if args.dmarc_reports:
        try:
            report_data, report_errors, n_reports = load_dmarc_reports(args.dmarc_reports)
        except FileNotFoundError as e:
            print(f"Error: DMARC reports path not found: {e}", file=sys.stderr)
            return EXIT_USAGE
        print(f"DMARC reports: {n_reports} report(s), {len(report_data)} domain(s)"
              + (f", {len(report_errors)} file(s) skipped" if report_errors else ""), file=sys.stderr)
        for err in report_errors[:5]:
            print(f"  skipped {err}", file=sys.stderr)
        scanned = {i.domain for i in inputs}
        unscanned = sorted(d for d in report_data if d not in scanned)
        notes.append(f"DMARC reports: {n_reports} aggregate reports loaded.")

    rdap = None
    if ("takeover" in checks or "lookalikes" in checks) and not args.no_rdap and not args.offline:
        rdap = RDAPClient(timeout=max(args.timeout, 8.0))
    lookalike_tiers = {TIER_ALIASES.get(t.strip().lower(), t.strip().lower())
                       for t in args.lookalike_tiers.split(",") if t.strip()} or None

    checks_label = "default set" if checks == DEFAULT_CHECKS else ", ".join(CHECK_LABELS[c] for c in checks)
    dkim_info = f"; {len(selectors)} DKIM selectors" if "dkim" in checks else ""
    print(f"Analyzing {len(inputs)} domain(s) via live DNS "
          f"({'system resolver' if args.system_resolver else ', '.join(nameservers)}; "
          f"{workers} workers{dkim_info})\nChecks: {checks_label}", file=sys.stderr)

    t0 = time.monotonic()
    results: List[DomainResult] = []
    interrupted = False
    analyzer = EmailSecurityAnalyzer(timeout=args.timeout, selectors=selectors, fast_dkim=args.fast_dkim,
                                     http_checks=not args.no_http, dkim_threads=min(64, workers * 4),
                                     checks=checks, dns_client=client, rdap=rdap, allow_private=args.allow_private,
                                     report_data=report_data, known_domains=[i.domain for i in inputs],
                                     lookalike_limit=args.lookalike_limit, lookalike_tiers=lookalike_tiers)
    progress = Progress(len(inputs), args.quiet)
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="domain")
    try:
        futures = [executor.submit(analyzer.analyze_domain, item) for item in inputs]
        for fut in as_completed(futures):
            r = fut.result()  # analyze_domain never raises
            results.append(r)
            progress.update(r)
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted - writing a partial report...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        progress.finish()
        executor.shutdown(wait=not interrupted)
        analyzer.close()

    elapsed = time.monotonic() - t0
    st = client.stats
    stats_line = (f"{len(results)} domains in {elapsed:.1f}s, {st['queries']} DNS queries, {st['cache_hits']} cache hits, "
                  f"{st['coalesced']} coalesced, {st['retries']} retries, {st['errors']} DNS errors")
    results.sort(key=lambda x: (-x.priority, x.domain))

    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    if rdap and rdap.note:
        notes.append(rdap.note)

    meta = {"resolver": "System resolver" if args.system_resolver else f"Resolvers: {', '.join(nameservers)}",
            "stats": stats_line, "checks": checks, "diff": diff, "notes": notes,
            "unscanned_report_domains": unscanned}
    try:
        generate_html_report(results, args.output, meta)
        print(f"Report generated: {args.output}", file=sys.stderr)
        base = args.output.rsplit(".", 1)[0]
        if args.json:
            write_json(results, base + ".json")
            print(f"JSON output: {base}.json", file=sys.stderr)
        if args.csv:
            write_csv(results, base + ".csv")
            print(f"CSV output: {base}.csv", file=sys.stderr)
    except OSError as e:
        print(f"Error: cannot write output: {e}", file=sys.stderr)
        return EXIT_USAGE

    print(f"\n{'=' * 56}\nSUMMARY{' (partial)' if interrupted else ''}\n{'=' * 56}")
    print(f"Checks:                   {checks_label}")
    print(f"Total domains analyzed:   {len(results)}")
    print(f"Fully protected (>=80):   {sum(1 for r in results if r.overall_score >= 80)}")
    print(f"Needs attention (50-79):  {sum(1 for r in results if 50 <= r.overall_score < 80)}")
    print(f"Critical risk (<50):      {sum(1 for r in results if r.overall_score < 50)}")
    print(f"Non-mail domains:         {sum(1 for r in results if r.profile == 'non-mail')}")
    if diff:
        print(f"Since baseline:           {diff['improved']} improved, {diff['worsened']} worsened, "
              f"{diff['new_critical']} new critical findings")
    top = [r for r in results if r.priority > 0][:5]
    if top:
        print("Fix first:")
        for r in top:
            first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
            print(f"  {r.domain:<36} score {r.overall_score:>3}  {first.message[:70] if first else ''}")
    print(f"Stats: {stats_line}")
    print_timing_summary(results)

    if interrupted:
        return EXIT_INTERRUPTED
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
