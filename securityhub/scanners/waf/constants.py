"""Findings catalogue, frameworks, compliance profiles, checks, Imperva rule identifiers, DDoS values."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

__version__ = "1.1.0"
USER_AGENT = f"WAFGuard/{__version__} (read-only assessment)"


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


FINDINGS["TLS_NOT_ENABLED"] = ("critical", "TLS", "HTTPS not enabled on the website",
                               "Enable SSL support with an Imperva-generated or a custom certificate")
