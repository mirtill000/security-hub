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
.print-head { display: none; margin-bottom: 16px; }
.print-head h1 { font-size: 20px; }
"""

REPORT_JS = r"""
(function () {
'use strict';
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const R = D.results, CHECKS = D.checks, L = D.labels, ATTR = D.attrs, M = D.meta || {};
const FIND = D.findings, FW = D.frameworks, COMP = D.compliance;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ESC[c]);
const $ = (s, r) => (r || document).querySelector(s);
const SEV = {critical: 0, warning: 1, info: 2};
const ST = {
  valid: ['pass', '\u2713', 'Pass'], warning: ['warn', '!', 'Warning'], partial: ['warn', '\u25D0', 'Partial'],
  error: ['fail', '\u2715', 'Fail'], misconfigured: ['fail', '\u2715', 'Misconfigured'], bogus: ['fail', '\u2715', 'Bogus'],
  missing: ['none', '\u2013', 'Missing'], null: ['null', '\u2205', 'Null MX'], na: ['na', '\u00B7', 'Not applicable'],
  dns_error: ['dns', '?', 'DNS error'], unknown: ['dns', '?', 'Unknown'], skipped: ['na', '\u00B7', 'Skipped']
};
const ST_ORDER = ['valid', 'partial', 'warning', 'misconfigured', 'error', 'bogus', 'missing', 'null', 'na', 'dns_error', 'unknown', 'skipped'];
const st = s => ST[s] || ST.missing;
const scoreCls = n => n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const gradeOf = n => n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 65 ? 'C' : n >= 50 ? 'D' : 'F';
const pct = (n, t) => t ? Math.round(100 * n / t) : 0;
const TIER_ORDER = ['critical', 'high', 'medium', 'low'];
const tierW = t => D.tiers[t] || 2;
const SHORT = {'mta-sts': 'STS', 'tls-rpt': 'TLS', takeover: 'Deps', consistency: 'Sync', lookalikes: 'Look'};
const DETAIL = {
  mx: r => r.mx.total_count ? `${r.mx.protected_count}/${r.mx.total_count} protected` : '',
  spf: r => r.spf.record ? `${r.spf.lookups}/10 lookups` : '',
  dkim: r => r.dkim.total_selectors ? `${r.dkim.valid_selectors} key${r.dkim.valid_selectors === 1 ? '' : 's'}` : '',
  dmarc: r => r.dmarc.policy ? `p=${r.dmarc.policy}` : '',
  'mta-sts': r => r.mta_sts.mode ? `mode ${r.mta_sts.mode}` : '',
  takeover: r => r.takeover.dependencies.length ? `${r.takeover.dependencies.length} deps` : '',
  lookalikes: r => r.lookalikes.registered.length ? `${r.lookalikes.registered.length} found` : ''
};
R.forEach((r, i) => {
  r._i = i;
  r._crit = r.issues.filter(x => x.severity === 'critical').length;
  r._warn = r.issues.filter(x => x.severity === 'warning').length;
  r._codes = new Set(r.issues.map(x => x.code));
  r._st = c => (r[ATTR[c]] || {}).status || 'missing';
});
const hasMeta = R.some(r => r.owner || r.bu || (r.tags && r.tags.length)) || new Set(R.map(r => r.tier)).size > 1;
const diff = D.diff;
const hasReports = R.some(r => r.dmarc_reports && r.dmarc_reports.status !== 'missing') || (D.unscanned_report_domains || []).length > 0;
const hasLook = CHECKS.includes('lookalikes');
const hasAuth = ['spf', 'dkim', 'dmarc'].every(c => CHECKS.includes(c));
const vis = (r, c) => CHECKS.includes(c) && r._st(c) !== 'skipped';
const uniq = a => [...new Set(a.filter(Boolean))].sort();

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
const PREF_KEY = 'mailguard-prefs-v31';
const P = {density: 'comfortable', view: 'table', size: 50, hidden: [], theme: null};
try { Object.assign(P, JSON.parse(localStorage.getItem(PREF_KEY) || '{}')); } catch (e) { /* storage unavailable */ }
const savePrefs = () => { try { localStorage.setItem(PREF_KEY, JSON.stringify(P)); } catch (e) { /* ignore */ } };
const FKEYS = ['q', 'score', 'smin', 'smax', 'tier', 'owner', 'bu', 'tag', 'finding', 'changed', 'comp', 'profile'];
const blank = () => ({q: '', f: {}, score: '', smin: '', smax: '', tier: '', owner: '', bu: '', tag: '', finding: '', changed: '', comp: '', profile: ''});
const S = Object.assign({route: 'overview', sort: {k: 'priority', d: -1}, page: 1, open: null, dtab: 'overview', sel: new Set(),
  groupBy: hasMeta ? 'owner' : 'tier', cursor: -1, menu: null, filtersOpen: false, fsev: '', fq: '', lmx: false, overlay: null}, blank());

/* ================= routing (state in the URL hash: shareable views) ================= */
const ROUTES = [
  {id: 'overview', label: 'Overview', icon: 'grid', show: () => true},
  {id: 'domains', label: 'Domains', icon: 'list', show: () => true, count: () => R.length},
  {id: 'findings', label: 'Findings', icon: 'alert', show: () => true, count: () => findingCounts().length},
  {id: 'changes', label: 'Changes', icon: 'diff', show: () => !!diff, count: () => R.filter(r => r.change && r.change.changed).length},
  {id: 'groups', label: 'Groups', icon: 'layers', show: () => hasMeta},
  {id: 'lookalikes', label: 'Lookalikes', icon: 'copy', show: () => hasLook, count: () => lookRows().length},
  {id: 'reports', label: 'DMARC reports', icon: 'mail', show: () => hasReports}
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
  if (q && !(r.domain.includes(q) || (r.owner || '').toLowerCase().includes(q) || (r.bu || '').toLowerCase().includes(q)
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
  if (S.profile) out.push(['profile', {'non-mail': 'Does not handle mail', unreachable: 'DNS unreachable', nonexistent: 'Does not exist', mail: 'Handles mail'}[S.profile] || S.profile]);
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
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>MailGuard DNS</b><small>Email security posture</small></div></div>
    <button class="posture" data-route="overview" title="Portfolio grade"><span class="letter g-${g}">${g}</span>
      <span><b class="num">${avg.toFixed(0)}/100</b><br>${R.length} domains</span></button>
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
  if (S.route === 'domains') { const n = list().length; sub = n === R.length ? `${R.length} domains` : `${n} of ${R.length} domains`; }
  else if (S.route === 'overview') sub = `Scanned ${esc(M.generated || '')}`;
  return `<h1>${esc(r.label)}</h1><span class="sub">${sub}</span><span class="spacer"></span>
    <button class="cmdk" data-action="palette" aria-label="Search domains, findings and actions">${icon('search')}<span class="lbl">Search domains, findings, actions</span><span class="kbd">Ctrl K</span></button>
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
  const nonmail = R.filter(r => r.profile === 'non-mail').length, unreach = R.filter(r => r.profile === 'unreachable').length;
  const kpi = (val, label, cls, attrs) => `<button class="kpi ${cls || ''}" ${attrs}><b>${val}</b><span>${esc(label)}</span></button>`;
  let h = `<div class="print-head"><h1>Email security posture</h1><p class="muted">${R.length} domains, scanned ${esc(M.generated || '')}</p></div>
  <div class="ov-top">
    <section class="card grade-card" aria-label="Portfolio grade">
      <div class="letter g-${g}">${g}</div><div class="lbl">Portfolio grade</div>
      <div class="avg">${avg.toFixed(0)}<small>/100</small></div>
      <div class="lbl">${hasMeta ? 'Average weighted by tier' : 'Average score'}${delta !== null ? `, <span class="${delta >= 0 ? 'delta-up' : 'delta-down'}">${delta >= 0 ? '+' : ''}${delta.toFixed(1)} since baseline</span>` : ''}</div>
    </section>
    <section class="card kpi-card">
      ${kpi(n, 'domains analyzed', '', 'data-route="domains"')}
      ${kpi(hi, 'fully protected, 80+', 'k-pass', 'data-filter="score" data-value="hi"')}
      ${kpi(mid, 'need attention, 50 to 79', 'k-warn', 'data-filter="score" data-value="mid"')}
      ${kpi(n - hi - mid, 'critical risk, under 50', 'k-fail', 'data-filter="score" data-value="lo"')}
      ${nonmail ? kpi(nonmail, 'do not handle mail', '', 'data-filter="profile" data-value="non-mail"') : ''}
      ${unreach ? kpi(unreach, 'DNS unreachable', '', 'data-filter="profile" data-value="unreachable"') : ''}
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
  const LEG = {pass: 'Pass', warn: 'Warning or partial', fail: 'Fail', none: 'Missing', null: 'Null MX', na: 'Not applicable', dns: 'DNS error'};
  h += `<section class="card span2"><header><h2>Control coverage</h2><p>Share of domains passing each control. Select a segment to list those domains.</p></header>
    <div class="body"><div class="cov">${rows}</div><div class="legend">${Object.keys(LEG).filter(k => present.has(k)).map(k => `<span><i class="dot c-${k}"></i>${LEG[k]}</span>`).join('')}</div></div></section>`;
  // distribution
  const bins = Array(10).fill(0);
  live.forEach(r => { bins[Math.min(9, Math.floor(r.overall_score / 10))]++; });
  const max = Math.max(1, ...bins);
  const bars = bins.map((v, i) => { const hh = Math.max(v ? 3 : 0, Math.round(104 * v / max)), x = 14 + i * 37, y = 118 - hh;
    const col = i >= 8 ? 'var(--pass)' : i >= 5 ? 'var(--warn)' : 'var(--fail)';
    const lo = i * 10, hiB = i === 9 ? 100 : i * 10 + 9;
    return `<rect class="hbar" x="${x}" y="${y}" width="31" height="${hh}" rx="3" fill="${col}" data-smin="${lo}" data-smax="${hiB}" tabindex="0" role="button" aria-label="${v} domains scoring ${lo} to ${hiB}"><title>${v} domains, score ${lo}-${hiB}</title></rect>
      ${v ? `<text class="v" x="${x + 15.5}" y="${y - 4}" text-anchor="middle">${v}</text>` : ''}<text x="${x + 15.5}" y="134" text-anchor="middle">${lo}</text>`; }).join('');
  h += `<section class="card"><header><h2>Score distribution</h2></header><div class="body"><svg class="hist" viewBox="0 0 390 140" role="group" aria-label="Score distribution"><line x1="10" y1="118.5" x2="384" y2="118.5"/>${bars}</svg><p class="sub" style="margin-top:6px">Select a bar to list the domains in that range.</p></div></section>`;
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
      <span class="r-sub">${esc(FIND[c][1])}, ${pct(k, n)}% of domains</span></button></li>`).join('') || '<li class="muted">No critical findings.</li>'}</ul></div></section>`;
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
  if (comp.length) h += `<section class="card"><header><h2>Requirements met</h2><p>Select to list failing domains</p></header><div class="body">${comp.map(c =>
    `<button class="bar-row" data-comp="${c.k}:fail" title="${esc(c.desc)}"><span>${esc(c.label)}</span><span class="bar"><i class="b-pass" style="width:${pct(c.pass, c.total)}%"></i></span><span>${c.pass}/${c.total}</span></button>`).join('')}</div></section>`;
  // changes
  if (diff) h += `<section class="card${tiers.length > 1 ? '' : ' span2'}"><header><h2>Since the baseline</h2><p>${esc(diff.baseline_date || diff.baseline)}</p></header><div class="body"><div class="stat-strip">
      <button class="stat" data-route="changes"><b class="delta-up">${diff.improved}</b><span>improved</span></button>
      <button class="stat" data-route="changes"><b class="delta-down">${diff.worsened}</b><span>worsened</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_critical}</b><span>new critical findings</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_domains.length}/${diff.removed_domains.length}</b><span>domains added/removed</span></button></div></div></section>`;
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
  ['all', 'All domains', {}],
  ['crit', 'Critical risk', {score: 'lo'}],
  ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
  ...(CHECKS.includes('takeover') ? [['tko', 'Takeover exposure', {f: {takeover: 'error'}}]] : []),
  ...(hasAuth ? [['bulk', 'Fails Gmail/Yahoo rules', {comp: 'gmail_yahoo:fail'}]] : []),
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
    <div class="search-box">${icon('search')}<input type="search" id="q" placeholder="Filter by domain, owner, unit or tag" value="${esc(S.q)}" aria-label="Filter domains"></div>
    <button class="btn" data-action="filters" aria-expanded="${S.filtersOpen}">${icon('filter')}Filters${active.length ? `<span class="badge-n">${active.length}</span>` : ''}</button>
    <span class="spacer"></span>
    <div class="seg" role="group" aria-label="Layout"><button data-view="table" aria-pressed="${P.view === 'table'}">Table</button><button data-view="heatmap" aria-pressed="${P.view === 'heatmap'}">Heatmap</button></div>
    ${P.view === 'table' ? `<div class="seg" role="group" aria-label="Density"><button data-density="comfortable" aria-pressed="${P.density === 'comfortable'}">Comfortable</button><button data-density="compact" aria-pressed="${P.density === 'compact'}">Compact</button></div>
    <div class="menu"><button class="btn" data-menu="cols" aria-expanded="${S.menu === 'cols'}">${icon('columns')}Columns</button>${S.menu === 'cols' ? `<div class="menu-pop">${COLS().map(c =>
      `<label class="check"><input type="checkbox" data-col="${c.id}"${P.hidden.includes(c.id) ? '' : ' checked'}> ${esc(c.label)}</label>`).join('')}<div class="sep"></div><button class="mi" data-action="cols-reset">Show all columns</button></div>` : ''}</div>` : ''}
    <div class="menu"><button class="btn" data-menu="export" aria-expanded="${S.menu === 'export'}">${icon('download')}Export</button>${S.menu === 'export' ? `<div class="menu-pop">
      <button class="mi" data-action="csv">Filtered domains as CSV<small>${all.length}</small></button>
      <button class="mi" data-action="json">Filtered domains as JSON<small>${all.length}</small></button>
      ${S.sel.size ? `<div class="sep"></div><button class="mi" data-action="csv-sel">Selected domains as CSV<small>${S.sel.size}</small></button>` : ''}
      <div class="sep"></div><button class="mi" data-action="copy-list">Copy domain list</button><button class="mi" data-action="copy-link">Copy link to this view</button></div>` : ''}</div>
  </div>`;
  if (S.filtersOpen) h += filterPanel();
  h += `<div class="chips">${active.length ? active.map(([k, lbl]) => `<span class="chip">${esc(lbl)}<button data-chip="${esc(k)}" aria-label="Remove filter ${esc(lbl)}">${icon('x', 12)}</button></span>`).join('') + '<button class="link" data-action="clear">Clear all</button>' : `<span>${all.length} domains</span>`}</div>`;
  if (S.sel.size) h += `<div class="selbar"><b>${S.sel.size} selected</b><button class="btn small" data-action="csv-sel">Export CSV</button><button class="btn small" data-action="copy-sel">Copy domains</button><span class="spacer"></span><button class="link" data-action="sel-clear">Clear selection</button></div>`;
  if (!all.length) h += `<div class="grid-wrap"><div class="empty"><b>No domain matches these filters</b><button class="btn" data-action="clear">Clear filters</button></div></div>`;
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
    <th class="sticky" aria-sort="${cur}"><div class="cell-domain"><input type="checkbox" data-selall aria-label="Select all on this page"${allSel ? ' checked' : ''}><button class="sort" data-sort="domain">Domain</button></div></th>
    ${cols.map(th).join('')}</tr></thead><tbody>${items.map((r, k) => `<tr data-row="${r._i}" class="${k === S.cursor ? 'cursor ' : ''}${S.open === r._i ? 'active' : ''}">
      <td class="sticky"><div class="cell-domain"><input type="checkbox" data-sel="${r._i}" aria-label="Select ${esc(r.domain)}"${S.sel.has(r._i) ? ' checked' : ''}>
        <div><button class="dom" data-open="${r._i}">${esc(r.domain)}</button>${(r.owner || r.bu) && P.density !== 'compact' ? `<div class="dom-sub">${esc([r.owner, r.bu].filter(Boolean).join(', '))}</div>` : ''}</div></div></td>
      ${cols.map(c => `<td class="${c.cls || ''}">${c.cell(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function heatmap(items) {
  return `<div class="heat" style="--cols:${CHECKS.length}" role="table" aria-label="Security heatmap">
    <div class="heat-row heat-head" role="row"><div role="columnheader">Domain</div>${CHECKS.map(c => `<div role="columnheader" title="${esc(L[c])}">${esc(SHORT[c] || L[c])}</div>`).join('')}<div role="columnheader" style="text-align:right">Score</div></div>
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

/* ================= changes, groups, lookalikes, reports ================= */
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
  const keyFn = {owner: r => [r.owner || '(no owner)'], bu: r => [r.bu || '(no unit)'], tier: r => [r.tier], tag: r => (r.tags && r.tags.length ? r.tags : ['(no tag)'])}[S.groupBy];
  const g = {};
  R.forEach(r => keyFn(r).forEach(k => (g[k] = g[k] || []).push(r)));
  const rows = Object.entries(g).map(([k, rs]) => ({k, rs, avg: rs.reduce((a, r) => a + r.overall_score, 0) / rs.length,
    crit: rs.reduce((a, r) => a + r._crit, 0), worst: rs.reduce((w, r) => r.overall_score < w.overall_score ? r : w, rs[0])})).sort((a, b) => a.avg - b.avg);
  return `<div class="toolbar"><div class="seg" role="group" aria-label="Group by">${[['owner', 'Owner'], ['bu', 'Business unit'], ['tier', 'Tier'], ['tag', 'Tag']].map(([v, l]) =>
      `<button data-groupby="${v}" aria-pressed="${S.groupBy === v}">${l}</button>`).join('')}</div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Group</th><th class="r">Domains</th><th>Average score</th><th class="r">Critical findings</th><th>Weakest domain</th></tr></thead><tbody>
    ${rows.map(x => `<tr><td class="sticky"><button class="dom" data-group="${S.groupBy}" data-value="${esc(x.k.startsWith('(') ? '' : x.k)}">${esc(x.k)}</button></td><td class="r num">${x.rs.length}</td>
      <td><div class="scorecell" style="justify-content:flex-start">${scoreHtml(Math.round(x.avg))}<span class="mini" style="width:120px"><i class="${scoreCls(x.avg)}" style="width:${x.avg}%"></i></span></div></td>
      <td class="r num">${x.crit}</td><td><button class="link" data-open="${x.worst._i}">${esc(x.worst.domain)}</button> ${scoreHtml(x.worst.overall_score)}</td></tr>`).join('')}</tbody></table></div>`;
}
function lookRows() {
  const seen = new Set(), rows = [];
  R.forEach(r => (r.lookalikes.registered || []).forEach(e => { const k = r.lookalikes.base + '|' + e.domain; if (!seen.has(k)) { seen.add(k); rows.push({r, e}); } }));
  return rows.sort((a, b) => (b.e.mx - a.e.mx) || String(b.e.created || '').localeCompare(String(a.e.created || '')));
}
function lookalikes() {
  const rows = lookRows().filter(x => !S.lmx || x.e.mx);
  return `<div class="toolbar"><label class="check"><input type="checkbox" data-lmx${S.lmx ? ' checked' : ''}> Only domains with mail servers</label></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Lookalike</th><th>Imitates</th><th>Technique</th><th>Mail servers</th><th>Website</th><th>Registered</th></tr></thead><tbody>
    ${rows.map(({r, e}) => `<tr data-row="${r._i}"><td class="sticky mono">${esc(e.domain)}</td><td><button class="link" data-open="${r._i}" data-dtab="exposure">${esc(r.lookalikes.base)}</button></td>
      <td>${esc(e.kind)}</td><td>${e.mx ? pill('error', 'MX') : '<span class="faint">No</span>'}</td><td>${e.a ? 'Yes' : '<span class="faint">No</span>'}</td>
      <td class="nowrap">${esc((e.created || '').slice(0, 10)) || '<span class="faint">unknown</span>'}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No registered lookalikes found.</td></tr>'}</tbody></table></div>`;
}
function reports() {
  const rows = R.filter(r => r.dmarc_reports.status !== 'missing').sort((a, b) => a.dmarc_reports.pass_rate - b.dmarc_reports.pass_rate);
  const un = D.unscanned_report_domains || [];
  return `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Domain</th><th class="r">Messages</th><th>Pass rate</th><th class="r">Not aligned</th><th class="r">Unauthenticated</th><th>Verdict</th></tr></thead><tbody>
    ${rows.map(r => { const x = r.dmarc_reports;
      return `<tr data-row="${r._i}"><td class="sticky"><button class="dom" data-open="${r._i}" data-dtab="reports">${esc(r.domain)}</button><div class="dom-sub">${esc(x.period.filter(Boolean).join(' to '))}</div></td>
        <td class="r num">${x.messages}</td><td><div class="scorecell" style="justify-content:flex-start"><span class="num">${x.pass_rate}%</span><span class="mini" style="width:80px"><i class="${x.pass_rate >= 98 ? 'hi' : x.pass_rate >= 90 ? 'mid' : 'lo'}" style="width:${x.pass_rate}%"></i></span></div></td>
        <td class="r num">${x.unaligned}</td><td class="r num">${x.spoofed}</td><td>${esc(x.verdict)}</td></tr>`; }).join('') || '<tr><td colspan="6" class="empty">No report matches the scanned domains.</td></tr>'}</tbody></table></div>
    ${un.length ? `<p class="muted" style="margin-top:12px">Seen in reports but not scanned: <span class="mono">${un.map(esc).join(', ')}</span></p>` : ''}`;
}

/* ================= domain drawer ================= */
const EVIDENCE = ['mx', 'spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'bimi', 'dnssec'], EXPOSURE = ['takeover', 'consistency', 'lookalikes'];
const tabFor = c => EXPOSURE.includes(c) ? 'exposure' : 'evidence';
const DTABS = [
  {id: 'overview', label: 'Summary', show: () => true},
  {id: 'findings', label: 'Findings', show: () => true, n: r => r.issues.length},
  {id: 'fixes', label: 'Fixes', show: r => (r.remediation || []).length > 0, n: r => r.remediation.length},
  {id: 'evidence', label: 'DNS evidence', show: r => EVIDENCE.some(c => vis(r, c))},
  {id: 'exposure', label: 'Exposure', show: r => EXPOSURE.some(c => vis(r, c))},
  {id: 'reports', label: 'DMARC reports', show: r => r.dmarc_reports.status !== 'missing'}
];
const kv = (label, value, cls) => `<div><span>${esc(label)}</span><b class="${cls || ''}">${value === null || value === undefined || value === '' ? '<span class="faint">none</span>' : esc(value)}</b></div>`;
const sec = (id, title, body, act) => `<section class="dr-sec" id="sec-${id}"><h3>${esc(title)}${act ? `<span class="act">${act}</span>` : ''}</h3>${body}</section>`;
function issueList(issues) {
  return issues.map(i => `<div class="issue"><span class="sev sev-${esc(i.severity)}" title="${esc(i.severity)}"></span>
    <div><div class="msg">${esc(i.message)}</div><div class="proto">${esc(i.protocol)}, ${esc(i.severity)}</div></div>
    <div class="rec">${esc(i.recommendation)}</div>${(FW[i.protocol] || []).length ? `<div class="fw">${FW[i.protocol].map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : ''}</div>`).join('');
}
function tabOverview(r) {
  const b = r.score_breakdown || {}, comps = Object.entries(b.components || {});
  const comp = Object.entries(r.compliance || {}).filter(([, v]) => v !== 'n/a');
  let h = `<div class="dr-cols">${sec('score', 'How the score is built', `${comps.map(([c, v]) => `<div class="bar-row"><span>${esc(L[c])}</span>
      <span class="bar"><i class="b-${v.got >= v.max ? 'pass' : v.got > 0 ? 'warn' : 'fail'}" style="width:${pct(v.got, v.max)}%"></i></span><span>${v.got}/${v.max}</span></div>`).join('')}
      ${b.normalized ? `<p class="sub" style="margin-top:8px">Normalized to 100 over the selected checks (${b.max} points available).</p>` : ''}
      ${b.cap ? `<p class="note-box" style="margin-top:10px">${esc(b.cap)}</p>` : ''}${b.note ? `<p class="sub">${esc(b.note)}</p>` : ''}`)}
    ${sec('compliance', 'Requirements', comp.length ? comp.map(([k, v]) => `<div class="bar-row" style="grid-template-columns:1fr auto" title="${esc(COMP[k][1])}"><span>${esc(COMP[k][0])}</span>${pill({pass: 'valid', fail: 'error', unknown: 'unknown'}[v] || 'na', v === 'unknown' ? '' : '')}</div>`).join('')
      + '<p class="sub" style="margin-top:8px">Only what DNS can show. Alignment, PTR, spam rate and unsubscribe headers need message-level checks.</p>' : '<p class="muted">Not applicable to the selected checks.</p>')}</div>`;
  h += sec('controls', 'Controls', `<div class="ctl-grid">${CHECKS.filter(c => vis(r, c)).map(c => `<button class="ctl" data-dtab="${tabFor(c)}" data-anchor="${c}"><span>${esc(L[c])}</span>${pill(r._st(c), DETAIL[c] ? DETAIL[c](r) : '')}</button>`).join('')}</div>`);
  if (r.change && r.change.changed) {
    const c = r.change;
    h += sec('changes', 'Since the baseline', c.new ? '<p>New domain in this scan.</p>' : `<p>Score <span class="num">${esc(c.previous_score)}</span> to ${scoreHtml(r.overall_score)} ${deltaHtml(r)}</p>
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
  if (!r.issues.length) return sec('issues', 'Findings', '<p class="muted">No findings. The configuration matches every selected check.</p>');
  return ['critical', 'warning', 'info'].map(s => { const xs = r.issues.filter(i => i.severity === s);
    return xs.length ? sec('issues-' + s, `${s[0].toUpperCase() + s.slice(1)} (${xs.length})`, issueList(xs)) : ''; }).join('');
}
function tabFixes(r) {
  return sec('fixes', 'Suggested fixes', `<p class="sub" style="margin-bottom:12px">Review every value before publishing: these records are generated from the current configuration.</p>` +
    r.remediation.map((x, k) => `<div class="fix"><h4>${esc(x.title)}</h4>${x.name ? `<div class="where">${esc(x.type)} record at <span class="mono">${esc(x.name)}</span></div>` : ''}
      ${x.value ? `<div class="rowx"><pre class="record" id="fix-${r._i}-${k}">${esc(x.value)}</pre><button class="btn small copy" data-copy="fix-${r._i}-${k}">${icon('copy', 14)}Copy</button></div>` : ''}
      ${x.note ? `<p class="note">${esc(x.note)}</p>` : ''}</div>`).join(''));
}
function tabEvidence(r) {
  let h = '';
  if (vis(r, 'mx')) h += sec('mx', 'Mail servers (MX)', r.mx.records.length ? `<table><thead><tr><th>Priority</th><th>Host</th><th>Protection</th></tr></thead><tbody>
      ${r.mx.records.map(m => `<tr><td class="num">${m.priority}</td><td class="mono">${esc(m.host || '.')}${m.resolves === false ? ' ' + pill('error', 'does not resolve') : ''}${m.is_cname ? ' ' + pill('warning', 'CNAME') : ''}</td>
        <td>${r.mx.null_mx ? pill('null') : m.is_protected ? `<span class="pill s-pass">${esc(m.provider)}</span>` : '<span class="faint">Unprotected</span>'}</td></tr>`).join('')}</tbody></table>`
    : `<p class="muted">${r.mx.implicit ? 'No MX records: mail falls back to the A/AAAA record.' : 'No MX records.'}</p>`, pill(r._st('mx')));
  if (vis(r, 'spf')) h += sec('spf', 'SPF', `${r.spf.record ? `<pre class="record">${esc(r.spf.record)}</pre>` : '<p class="muted" style="margin-bottom:10px">No SPF record.</p>'}
      <div class="kv">${kv('DNS lookups', `${r.spf.lookups}/10`, r.spf.lookups > 10 ? 'score lo' : '')}${kv('Void lookups', `${r.spf.void_lookups}/2`)}${kv('Ends with', r.spf.mechanism)}${kv('PermError', r.spf.permerror ? 'Yes' : 'No', r.spf.permerror ? 'score lo' : '')}</div>
      ${r.spf.include_tree.length ? `<details class="more"><summary>Include tree (${r.spf.include_tree.length})</summary><div class="tree">${r.spf.include_tree.map(nd =>
        `<div style="padding-left:${nd.depth * 16}px">${esc(nd.domain)} <span class="faint">${nd.lookups} nested${nd.status !== 'ok' ? ', ' + esc(nd.status) : ''}</span></div>`).join('')}</div></details>` : ''}`, pill(r._st('spf')));
  if (vis(r, 'dkim')) h += sec('dkim', 'DKIM', r.dkim.selectors.length ? `<table><thead><tr><th>Selector</th><th>Key</th><th>Status</th></tr></thead><tbody>
      ${r.dkim.selectors.map(s => `<tr><td class="mono">${esc(s.name)}${s.source === 'report' ? ' <span class="tag">from reports</span>' : ''}${s.cname ? `<div class="sub">CNAME ${esc(s.cname)}</div>` : ''}</td>
        <td class="nowrap">${esc(s.algorithm || '')} ${s.key_size ? s.key_size + ' bit' : ''}${s.testing ? ' <span class="tag">t=y</span>' : ''}${s.hash_algorithms ? ` <span class="tag">h=${esc(s.hash_algorithms)}</span>` : ''}</td>
        <td>${pill({valid: 'valid', weak: 'warning', revoked: 'missing', invalid: 'error'}[s.status] || 'missing', s.status)}</td></tr>`).join('')}</tbody></table>`
    : `<p class="muted">${r.dkim.status === 'na' ? 'Not needed: the domain does not handle mail.' : `No key found on ${r.dkim.probed} probed selectors. Add custom selectors with --selectors or load DMARC reports to discover them.`}</p>`, pill(r._st('dkim')));
  if (vis(r, 'dmarc')) h += sec('dmarc', 'DMARC', `${r.dmarc.record ? `<pre class="record">${esc(r.dmarc.record)}</pre>` : '<p class="muted" style="margin-bottom:10px">No DMARC record.</p>'}
      ${r.dmarc.inherited_from ? `<p class="sub" style="margin-bottom:10px">Inherited from ${esc(r.dmarc.inherited_from)}</p>` : ''}
      <div class="kv">${kv('Policy', r.dmarc.policy)}${kv('Subdomains', r.dmarc.subdomain_policy)}${kv('Applied to', r.dmarc.pct + '%')}${kv('Alignment', `SPF ${r.dmarc.aspf}, DKIM ${r.dmarc.adkim}`)}
      ${kv('Aggregate reports', r.dmarc.rua_destinations.join(', '))}${kv('Failure reports', r.dmarc.ruf)}</div>`, pill(r._st('dmarc')));
  const tr = [];
  if (vis(r, 'mta-sts')) tr.push(kv('MTA-STS', r.mta_sts.mode ? `${st(r.mta_sts.status)[2]}, mode ${r.mta_sts.mode}` : st(r.mta_sts.status)[2]),
    kv('Policy MX', r.mta_sts.mx_patterns.join(', ')), kv('Policy max_age', r.mta_sts.max_age), kv('Policy problem', r.mta_sts.policy_error));
  if (vis(r, 'tls-rpt')) tr.push(kv('TLS-RPT', r.tls_rpt.rua || st(r.tls_rpt.status)[2]));
  if (vis(r, 'bimi')) tr.push(kv('BIMI logo', r.bimi.logo_url || st(r.bimi.status)[2]));
  if (vis(r, 'dnssec')) tr.push(kv('DNSSEC', st(r.dnssec.status)[2]));
  if (tr.length) h += sec('mta-sts', 'Transport and DNS security', `<div class="kv">${tr.join('')}</div>`);
  return h;
}
function tabExposure(r) {
  let h = '';
  if (vis(r, 'takeover')) { const t = r.takeover;
    h += sec('takeover', 'External dependencies', `<p class="sub" style="margin-bottom:12px">Domains this one relies on. If one lapses, whoever registers it can pass SPF, receive mail or reports, or take over the zone.${t.rdap ? '' : ' Registration dates unavailable: RDAP was off.'}</p>
      ${t.dependencies.length ? `<table><thead><tr><th>Domain</th><th>Used by</th><th>State</th><th>Expires</th></tr></thead><tbody>${t.dependencies.map(e => `<tr><td class="mono">${esc(e.domain)}</td><td class="sub">${esc(e.used_by.join(', '))}</td>
        <td>${pill({ok: 'valid', unregistered: 'error', expired: 'error', expiring: 'warning', 'no-dns': 'warning', unknown: 'unknown'}[e.state] || 'unknown', e.state === 'ok' ? '' : e.state)}</td><td class="nowrap num">${esc((e.expires || '').slice(0, 10))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No external dependencies found.</p>'}
      ${t.dangling.length ? `<p style="margin-top:14px"><b>Dangling CNAMEs</b></p>${t.dangling.map(d => `<div class="mono" style="margin-top:4px">${esc(d.name)} \u2192 ${esc(d.target)}</div>`).join('')}` : ''}
      <div class="kv" style="margin-top:14px">${kv('Name servers', t.ns_hosts.join(', '))}${kv('Domain expires', (t.domain_expires || '').slice(0, 10))}</div>`, pill(r._st('takeover'))); }
  if (vis(r, 'consistency')) { const c = r.consistency;
    h += sec('consistency', 'Resolver and authoritative consistency', c.differences.length ? c.differences.map(d => `<p><b>${esc(d.type)} ${esc(d.name)}</b> <span class="sub">${d.kind === 'authoritative' ? 'authoritative servers disagree' : 'resolvers differ from the authoritative answer'}</span></p>
      <table style="margin:6px 0 14px"><tbody>${Object.entries(d.answers).map(([s, v]) => `<tr><td class="nowrap sub">${esc(s)}</td><td class="mono">${v.length ? v.map(esc).join('<br>') : '<span class="faint">no data</span>'}</td></tr>`).join('')}</tbody></table>`).join('')
      : `<p class="muted">${c.status === 'unknown' ? 'Authoritative servers could not be queried.' : 'All sources return the same data.'}</p><p class="sub" style="margin-top:6px">Sources: ${esc(c.sources.join(', '))}</p>`, pill(r._st('consistency'))); }
  if (vis(r, 'lookalikes')) { const lk = r.lookalikes;
    h += sec('lookalikes', 'Lookalike domains', lk.status === 'na' ? '<p class="muted">Not checked for this tier.</p>' : `<p class="sub" style="margin-bottom:10px">${lk.generated} variants of ${esc(lk.base)} checked, ${lk.registered.length} registered.</p>
      ${lk.registered.length ? `<table><thead><tr><th>Domain</th><th>Technique</th><th>MX</th><th>Registered</th></tr></thead><tbody>${lk.registered.map(e => `<tr><td class="mono">${esc(e.domain)}</td><td>${esc(e.kind)}</td><td>${e.mx ? pill('error', 'yes') : '<span class="faint">No</span>'}</td><td class="num">${esc((e.created || '').slice(0, 10))}</td></tr>`).join('')}</tbody></table>` : ''}`, pill(r._st('lookalikes'))); }
  return h;
}
function tabReports(r) {
  const x = r.dmarc_reports;
  return sec('reports', 'DMARC aggregate reports', `<p class="note-box" style="margin-bottom:14px">${esc(x.verdict)}</p>
    <div class="kv">${kv('Period', x.period.filter(Boolean).join(' to '))}${kv('Reports', x.reports)}${kv('Messages', x.messages)}${kv('Pass rate', x.pass_rate + '%')}${kv('Not aligned', x.unaligned)}${kv('Unauthenticated', x.spoofed)}${kv('Selectors seen', x.selectors.join(', '))}${kv('Reporters', x.reporters.join(', '))}</div>
    ${x.sources.length ? `<table style="margin-top:16px"><thead><tr><th>Source</th><th class="r">Messages</th><th>Result</th><th>Envelope or DKIM domains</th></tr></thead><tbody>${x.sources.slice(0, 30).map(s => `<tr>
      <td class="mono">${esc(s.ip)}${s.ptr ? `<div class="sub">${esc(s.ptr)}</div>` : ''}</td><td class="r num">${s.count}</td>
      <td>${pill({aligned: 'valid', unaligned: 'warning', spoof: 'error'}[s.category], {aligned: 'passes', unaligned: 'not aligned', spoof: 'unauthenticated'}[s.category])}</td>
      <td class="sub">${esc([...s.envelope_from, ...s.dkim_domains].join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}`);
}
const TAB_RENDER = {overview: tabOverview, findings: tabFindings, fixes: tabFixes, evidence: tabEvidence, exposure: tabExposure, reports: tabReports};
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
  const badges = [r.profile !== 'mail' ? {'non-mail': 'Does not handle mail', nonexistent: 'Domain does not exist', unreachable: 'DNS unreachable'}[r.profile] : ''].filter(Boolean);
  const body = S.dtab === 'all' ? tabs.map(t => `<h2 class="dr-print-title">${esc(t.label)}</h2>` + TAB_RENDER[t.id](r)).join('') : TAB_RENDER[S.dtab](r);
  const fresh = lastOpen === null;
  root.innerHTML = `<div class="scrim${fresh ? ' enter' : ''}" data-action="close"></div>
    <aside class="drawer${fresh ? ' enter' : ''}" role="dialog" aria-modal="true" aria-labelledby="dr-title">
      <header class="dr-head">
        <div class="dr-nav"><button class="btn icon ghost" data-open="${prev}" ${prev === null ? 'disabled' : ''} aria-label="Previous domain" title="Previous (k)">${icon('left')}</button>
          <button class="btn icon ghost" data-open="${next}" ${next === null ? 'disabled' : ''} aria-label="Next domain" title="Next (j)">${icon('right')}</button>
          <span>${pos >= 0 ? `${pos + 1} of ${lst.length}` : ''}</span><span class="spacer"></span>
          <button class="btn ghost small" data-action="copy-link">${icon('link', 14)}Copy link</button>
          <button class="btn ghost small" data-action="print-domain">${icon('print', 14)}Print</button>
          <button class="btn icon ghost" data-action="close" id="dr-close" aria-label="Close" title="Close (Esc)">${icon('x')}</button></div>
        <div class="dr-id">${ring(r.overall_score)}<div style="min-width:0"><h2 id="dr-title">${esc(r.domain)}</h2>
          <div class="meta">${hasMeta ? tierTag(r.tier) : ''}${badges.map(b => `<span class="tag">${esc(b)}</span>`).join('')}${r.owner ? `<span class="tag">Owner ${esc(r.owner)}</span>` : ''}${r.bu ? `<span class="tag">${esc(r.bu)}</span>` : ''}
            ${(r.tags || []).map(t => `<span class="tag">#${esc(t)}</span>`).join('')}<span class="t">Grade ${gradeOf(r.overall_score)}, priority ${r.priority}, scanned ${esc(r.scan_date)}</span></div>
          ${r.error ? `<p class="note-box" style="margin-top:8px">Analysis error: ${esc(r.error)}</p>` : ''}</div></div>
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
  const doms = (q ? R.filter(r => r.domain.includes(q) || (r.owner || '').toLowerCase().includes(q)) : [...R].sort((a, b) => b.priority - a.priority)).slice(0, q ? 8 : 5);
  doms.forEach(r => items.push({g: 'Domains', t: r.domain, h: `score ${r.overall_score}`, run: () => go({open: r._i, dtab: 'overview'})}));
  findingCounts().filter(([c]) => q && findingTitle(c).toLowerCase().includes(q)).slice(0, 6).forEach(([c, k]) =>
    items.push({g: 'Findings', t: findingTitle(c), h: `${k} domains`, run: () => filterTo({finding: c})}));
  [['Toggle light or dark theme', toggleTheme], ['Executive summary as PDF', printExec], ['Export filtered domains as CSV', () => exportCsv(list())],
   ['Clear all filters', () => filterTo({})], ['Copy link to this view', copyLink], ['Keyboard shortcuts', showKeys], ['About this scan', showAbout]]
    .forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) items.push({g: 'Actions', t, h: '', run: fn}); });
  return items;
}
function openPalette() {
  pal = {q: '', idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search domains, findings and actions" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
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
  const k = [['Ctrl K or /', 'Search domains, findings and actions'], ['1 to 7', 'Switch section'], ['j / k', 'Next or previous domain (list and detail)'],
    ['Enter', 'Open the highlighted domain'], ['x', 'Select the highlighted domain'], ['f', 'Show or hide filters'], ['Esc', 'Close the detail or dialog'], ['?', 'This help']];
  dialog('Keyboard shortcuts', `<table class="keys">${k.map(([a, b]) => `<tr><td><span class="kbd">${esc(a)}</span></td><td>${esc(b)}</td></tr>`).join('')}</table>`);
}
function showAbout() {
  const w = D.weights || {};
  dialog('About this scan', `<div class="kv" style="margin-bottom:16px">${kv('Generated', M.generated)}${kv('Tool', 'MailGuard DNS ' + (M.version || ''))}${kv('Domains', R.length)}${kv('Resolvers', M.resolver)}</div>
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
  const head = ['domain', 'score', 'priority', 'tier', 'owner', 'bu', 'tags', ...CHECKS.map(c => L[c]), 'critical', 'warning', 'issue_codes'];
  const body = rows.map(r => [r.domain, r.overall_score, r.priority, r.tier, r.owner, r.bu, (r.tags || []).join('|'), ...CHECKS.map(c => r._st(c)), r._crit, r._warn, [...r._codes].join('|')]);
  download(name || 'mailguard-domains.csv', 'text/csv;charset=utf-8', '\ufeff' + [head, ...body].map(x => x.map(csvCell).join(';')).join('\r\n'));
}
function exportJson(rows) {
  download('mailguard-domains.json', 'application/json', JSON.stringify(rows.map(r => { const o = {}; Object.keys(r).forEach(k => { if (k[0] !== '_') o[k] = r[k]; }); return o; }), null, 2));
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
const VIEWS = {overview, domains, findings, changes, groups, lookalikes, reports};
function render() {
  applyTheme();
  $('#side').innerHTML = side();
  $('#topbar').innerHTML = topbar();
  const view = VIEWS[S.route] || overview;
  $('#view').innerHTML = view();
  drawer();
  const rt = ROUTES.find(x => x.id === S.route);
  document.title = (S.open !== null ? R[S.open].domain + ' - ' : '') + (rt ? rt.label + ' - ' : '') + 'MailGuard DNS';
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
    'csv-sel': () => { S.menu = null; exportCsv(R.filter(r => S.sel.has(r._i)), 'mailguard-selected.csv'); render(); },
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
