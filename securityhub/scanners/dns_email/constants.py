"""Findings catalogue, frameworks, compliance profiles, checks and weights, provider tables."""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

__version__ = "4.0.0"
USER_AGENT = f"MailGuardDNS/{__version__}"


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
    # CAA (RFC 8659): which certificate authorities may issue certificates for the domain
    "CAA_MISSING": ("warning", "CAA", "No CAA record: any certificate authority may issue certificates for the domain",
                    "Publish CAA records naming only the CAs you use (and 0 issue \";\" on domains that need no certificate)"),
    "CAA_NO_IODEF": ("info", "CAA", "CAA without iodef: refused issuance requests are not reported",
                     "Add 0 iodef \"mailto:security@<domain>\" so CAs can report requests that violate the policy"),
    "CAA_INVALID": ("warning", "CAA", "CAA record malformed or with an unknown critical tag",
                    "Fix the record: with an unknown critical tag (flag 128) CAs must refuse every certificate"),
    "CAA_DNS_ERROR": ("warning", "CAA", "CAA lookup fails (SERVFAIL/timeout)",
                      "Some DNS providers mishandle CAA queries: CAs treat a failed lookup as a reason to refuse issuance"),
    # Zone transfer
    "AXFR_OPEN": ("critical", "Zone transfer", "Zone transfer (AXFR) allowed to anyone",
                  "Restrict zone transfers to the secondary name servers (allow-transfer / TSIG): the full zone is a reconnaissance map"),
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
    "CAA": ["NIS2 Art.21(2)(h)", "ISO 27001 A.8.24"],
    "Zone transfer": ["NIS2 Art.21(2)(e)", "ISO 27001 A.8.20", "ISO 27001 A.8.22"],
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
    "mx": 0, "spf": 25, "dkim": 25, "dmarc": 35, "mta-sts": 7, "tls-rpt": 3, "bimi": 0, "dnssec": 5, "caa": 0,
    "takeover": 0, "axfr": 0, "consistency": 0, "lookalikes": 0,
}
# axfr is opt-in: it sends a zone transfer request to every authoritative name server (an active test).
# BIMI (brand logo) is not part of the assessment by default: it is a marketing feature, not a protection.
# It can still be requested explicitly (--checks all,bimi or full).
DEFAULT_CHECKS = ["mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt", "dnssec", "caa", "takeover"]
CHECK_ALIASES = {
    "mtasts": "mta-sts", "mta_sts": "mta-sts", "sts": "mta-sts",
    "tlsrpt": "tls-rpt", "tls_rpt": "tls-rpt", "tls": "tls-rpt",
    "lookalike": "lookalikes", "typosquatting": "lookalikes", "rdap": "takeover",
    "zone-transfer": "axfr", "zonetransfer": "axfr", "xfr": "axfr",
}
CHECK_LABELS = {"mx": "MX", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "mta-sts": "MTA-STS",
                "tls-rpt": "TLS-RPT", "bimi": "BIMI", "dnssec": "DNSSEC", "caa": "CAA", "takeover": "Takeover",
                "axfr": "Zone transfer", "consistency": "Consistency", "lookalikes": "Lookalikes"}


# Data other checks need: collected silently, never reported unless selected.
# (MX is always collected in light mode: it decides whether the domain handles mail.)
CHECK_DEPENDENCIES = {"bimi": {"dmarc"}, "takeover": {"spf", "dkim", "dmarc", "tls-rpt"}}
CHECK_ATTRS = {"mx": "mx", "spf": "spf", "dkim": "dkim", "dmarc": "dmarc", "mta-sts": "mta_sts",
               "tls-rpt": "tls_rpt", "bimi": "bimi", "dnssec": "dnssec", "caa": "caa", "takeover": "takeover",
               "axfr": "axfr", "consistency": "consistency", "lookalikes": "lookalikes"}


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

# DKIM is probed in two rounds. Round 1: selectors of the mail provider seen in MX, selectors from
# DMARC reports or --selectors, and the most common ones. Only if round 1 finds no valid key are the
# other selectors probed, so "DKIM not found" still means every known selector was tried.
DKIM_FIRST_ROUND = ["selector1", "selector2", "google", "default", "dkim", "s1", "s2", "k1", "mail", "key1"]
DKIM_PROVIDER_SELECTORS = {  # substring of the MX provider name -> its selectors
    "microsoft": ["selector1", "selector2"], "google": ["google"], "zoho": ["zoho", "zmail"],
    "proton": ["protonmail", "protonmail2", "protonmail3"], "fastmail": ["fm1", "fm2", "fm3"],
    "mailgun": ["mailgun", "mg", "pic", "krs"], "sendgrid": ["s1", "s2", "smtpapi"], "amazon": ["amazonses"],
}


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
