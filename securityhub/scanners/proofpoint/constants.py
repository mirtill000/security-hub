"""Findings catalogue, checks and weights, frameworks and compliance profiles of the Proofpoint assessment."""

from __future__ import annotations

from typing import Dict, List, Tuple

__version__ = "1.0.0"
USER_AGENT = f"PPGuard/{__version__} (read-only posture assessment)"

# code -> (severity, area, title, recommendation)
FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # mail routing (DNS)
    "MX_DNS_ERROR": ("warning", "Routing", "MX records could not be read",
                     "Check the authoritative name servers of the domain"),
    "DIRECT_DELIVERY": ("warning", "Direct delivery", "The mailbox service accepts mail directly, bypassing the MX",
                        "Restrict inbound mail on the mailbox service to Proofpoint (Microsoft 365: partner inbound "
                        "connector limited to Proofpoint IPs or certificate, with mail from other sources rejected)"),
    "SPF_NO_PROOFPOINT": ("warning", "SPF", "SPF does not authorize Proofpoint for outbound mail",
                          "If outbound mail is relayed by Proofpoint, add the SPF include of your cluster (*.pphosted.com)"),
    "SPF_MISSING": ("warning", "SPF", "No SPF record", "Publish an SPF record ending with -all or ~all"),
    # TAP (threat telemetry)
    "THREAT_DELIVERED": ("critical", "Threats", "Malicious messages delivered to users",
                         "Pull the messages from the mailboxes (TRAP / Threat Response or a mailbox search) and "
                         "review why they were delivered"),
    "IMPOSTOR_DELIVERED": ("warning", "Threats", "Impostor (BEC) messages delivered",
                           "Tune the impostor classifier / Email Fraud Defense and warn the recipients"),
    "SAFELIST_DELIVERY": ("critical", "Threats", "Threat delivered through a safelist or allow route",
                          "Narrow the safelist or allow rule that let the threat through (sender, IP or domain allow-list)"),
    "CLICK_PERMITTED": ("critical", "Clicks", "Users clicked a malicious URL that was not blocked",
                        "Treat the users as potentially compromised: reset credentials, check the endpoint, "
                        "and review URL Defense / isolation settings"),
    "URL_NOT_REWRITTEN": ("warning", "URL Defense", "Delivered threats with URLs not rewritten by URL Defense",
                          "Enable URL rewriting for every inbound message so clicks are checked at time of click"),
    "VAP_PRESENT": ("info", "People", "Very Attacked People in the domain",
                    "Apply stronger controls to these users: isolation, MFA, targeted training"),
    "VAP_VIP": ("warning", "People", "VIPs among the Very Attacked People",
                "Protect VIP mailboxes with adaptive controls (browser isolation, stricter policies)"),
    "CLICK_REPEAT": ("critical", "Clicks", "Users with more than one malicious click permitted",
                     "Treat these users as compromised and apply URL isolation to them: they keep clicking and URL "
                     "Defense let the clicks through"),
    "THREAT_LATE_VERDICT": ("warning", "Threats", "Threats identified only hours after delivery",
                            "Make sure delivered threats are pulled automatically from the mailboxes (Threat Response "
                            "Auto-Pull) as soon as TAP condemns them"),
    # account level
    "TOP_CLICKERS": ("warning", "People", "Users who repeatedly click on threats",
                     "Assign targeted awareness training and adaptive controls (isolation) to the top clickers"),
    "TAP_DOMAINS_NOT_LISTED": ("info", "Coverage", "Domains handled by Proofpoint (TAP or PoD log) but not in the domain list",
                               "Add them to the domain list so their routing is assessed too"),
    "TAP_NO_EVENTS": ("info", "API", "No TAP events in the time window",
                      "Normal for a quiet window; otherwise check that the service principal covers every cluster"),
    "TAP_NOT_CONFIGURED": ("info", "API", "TAP not configured: delivered threats, clicks, URL Defense and attacked people not assessed",
                           "Create a TAP service credential (TAP Dashboard > Settings > Connected Applications; not the PoD "
                           "Logging API token) and set PROOFPOINT_PRINCIPAL and PROOFPOINT_SECRET"),
    "API_ERROR": ("warning", "API", "Part of the TAP data could not be read",
                  "Check the service principal (TAP > Settings > Connected applications) and its access"),
    # Threat Protection API (Dash Reports, Email Bomb Events)
    "TR_PULLED_AFTER_READ": ("warning", "Threat Response", "Threats removed from mailboxes after users had read them",
                             "Pull condemned messages automatically and immediately (Threat Response Auto-Pull on every "
                             "TAP alert), and review why they were delivered"),
    "TR_SKIPPED": ("info", "Threat Response", "Condemned messages not removed (skiplist or external recipients)",
                   "Review the Threat Response skiplist: every skipped copy stays in a mailbox"),
    "URL_REWRITE_GAP": ("warning", "URL Defense", "A significant share of URLs is not rewritten by URL Defense",
                        "Review the URL Defense exclusions and rewrite settings so clicks are checked at time of click"),
    "BEC_VIP_TARGETED": ("warning", "BEC", "VIPs targeted by BEC (business email compromise)",
                         "Brief the VIPs and their assistants, require out-of-band verification of payment and data requests"),
    "BEC_VIP_TARGETED_RISK": ("critical", "BEC", "Privileged or high-exposure VIPs targeted by BEC",
                              "Check the accounts for takeover (sign-ins, mailbox rules), enforce phishing-resistant MFA, "
                              "verify payment and data requests out of band"),
    "ATTACK_INDEX_ABOVE_INDUSTRY": ("info", "BEC", "Attack index higher than the industry average",
                                    "Context for the risk owner: the organization is more targeted than its peers"),
    "MAIL_BOMB_TARGETED": ("warning", "People", "Users targeted by email bombing",
                           "Email bombing buries fraud alerts and one-time codes: check these users' accounts for "
                           "takeover and recent changes (MFA methods, forwarding, payments)"),
    "TP_API_ERROR": ("warning", "API", "Part of the Threat Protection reports could not be read",
                     "Check the Threat Protection API key (Cloud Admin UI > Settings > API Key Management)"),
    "TP_NOT_CONFIGURED": ("info", "API", "Threat Protection API not configured: Threat Response, URL rewrite coverage, BEC and email bombing not assessed",
                          "Create a key in Cloud Admin UI > Settings > API Key Management > Threat Protection and set "
                          "PROOFPOINT_TP_KEY and PROOFPOINT_TP_SECRET"),
    # PoD Log API (gateway configuration as seen in the message and audit logs)
    "POD_AUTH_FAIL_DELIVERED": ("warning", "Gateway", "Inbound mail failing SPF/DMARC is delivered",
                                "Enforce sender authentication in the PoD policy: quarantine or reject messages that fail "
                                "DMARC with p=reject/quarantine, and review the sender exceptions"),
    "POD_SPOOF_DELIVERED": ("critical", "Gateway", "Messages spoofing your own domains were delivered",
                            "Reject inbound mail that uses your domains as sender and fails DMARC (anti-spoofing rule), "
                            "and publish DMARC p=reject"),
    "POD_SPOOF_ATTEMPTS": ("info", "Gateway", "Spoofing attempts of your own domains (blocked)",
                           "No action needed: the gateway blocked them"),
    "POD_INBOUND_NO_TLS": ("warning", "Gateway", "Inbound mail received without TLS 1.2 or later",
                           "Require TLS with the listed partners (TLS policy per domain) and keep TLS 1.0/1.1 disabled"),
    "POD_URL_EXCLUDED_DOMAINS": ("warning", "URL Defense", "URLs not rewritten because their domain is excluded",
                                 "Review the URL Defense excluded domains: excluded links are never checked at time of click"),
    "POD_SANDBOX_ERRORS": ("warning", "Gateway", "Attachments that Attachment Defense could not analyze",
                           "Check the Attachment Defense errors with Proofpoint support (size, password-protected or "
                           "unsupported files) and the policy for unscanned attachments"),
    "POD_SAMPLED": ("info", "API", "PoD message log sampled", "The window had more events than the cap: figures are a sample"),
    "POD_ADMIN_MANY_IPS": ("warning", "Admin", "PoD administrators signing in from many IP addresses",
                           "Restrict console access (SSO with MFA, IP allow-list) and confirm the sign-ins are legitimate"),
    "POD_API_KEY_CREATED": ("warning", "Admin", "API keys created in the PoD console",
                            "Confirm each new API key is expected, documented and has an owner"),
    "POD_CONFIG_CHANGES": ("info", "Admin", "Configuration changes in the PoD console",
                           "Check the changes against approved change requests"),
    "POD_API_ERROR": ("warning", "API", "The PoD log stream could not be read",
                      "Check the cluster ID and the PoD Log API token (one session per token: use a dedicated token)"),
    "POD_NOT_CONFIGURED": ("info", "API", "PoD Log API not configured: sender authentication, spoofing, TLS and console audit not assessed",
                           "Set PROOFPOINT_POD_CLUSTER and PROOFPOINT_POD_TOKEN (token from Proofpoint, Remote Syslog "
                           "Forwarding license; a token dedicated to this tool)"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

# Mail routing is informational (which MX hosts are Proofpoint): not scored. The score measures what Proofpoint
# protects: direct delivery that skips it, SPF for its outbound relay, threats that reached users, clicks allowed.
CHECKS: Dict[str, int] = {"routing": 0, "direct": 20, "spf": 10, "threats": 40, "clicks": 30, "rewrite": 0, "people": 0}
DNS_CHECKS = ("routing", "direct", "spf")
TAP_CHECKS = ("threats", "clicks", "rewrite", "people")
CHECK_LABELS = {"routing": "Mail routing", "direct": "Direct delivery", "spf": "SPF", "threats": "Delivered threats",
                "clicks": "Permitted clicks", "rewrite": "URL Defense", "people": "Attacked people"}
CHECK_ALIASES = {"mx": "routing", "bypass": "direct", "tap": "threats", "click": "clicks", "vap": "people",
                 "url": "rewrite", "urldefense": "rewrite"}
SCORE_CAPS = {"CLICK_PERMITTED": 40,
              "SAFELIST_DELIVERY": 50, "THREAT_DELIVERED": 60}

FRAMEWORK_MAP: Dict[str, List[str]] = {
    "Routing": ["ISO 27001 A.8.23", "CIS Control 9", "NIS2 Art.21(2)(e)"],
    "Direct delivery": ["ISO 27001 A.8.23", "CIS Control 9"],
    "SPF": ["ISO 27001 A.8.21", "CIS Control 9"],
    "Threats": ["ISO 27001 A.8.7", "NIS2 Art.21(2)(b)", "CIS Control 9"],
    "Clicks": ["ISO 27001 A.6.3", "ISO 27001 A.5.26", "CIS Control 14"],
    "URL Defense": ["ISO 27001 A.8.23", "CIS Control 9"],
    "People": ["ISO 27001 A.6.3", "CIS Control 14"],
    "Coverage": ["ISO 27001 A.5.9"],
    "Threat Response": ["ISO 27001 A.5.26", "NIS2 Art.21(2)(b)"],
    "BEC": ["ISO 27001 A.5.7", "ISO 27001 A.6.3"],
    "Gateway": ["ISO 27001 A.8.21", "ISO 27001 A.8.23", "CIS Control 9"],
    "Admin": ["ISO 27001 A.8.2", "ISO 27001 A.8.15", "CIS Control 5"],
    "API": [],
}
COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "gateway_enforced": ("Gateway enforced", "Every MX through Proofpoint and no unrestricted direct delivery"),
    "no_exposure": ("No user exposure", "No malicious message delivered and no malicious click permitted in the window"),
}
TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Host names of Proofpoint mail gateways (PoD and Essentials). Extra suffixes: --gateway-hosts (e.g. on-prem PPS).
PROOFPOINT_HOSTS = ("pphosted.com", "ppe-hosted.com", "proofpoint.com", "ppops.net")
SPF_PROOFPOINT = ("pphosted.com", "ppe-hosted.com", "proofpoint.com")
MALICIOUS = {"malware", "phish", "phishing"}
SAFE_ROUTE_WORDS = ("safe", "allow", "whitelist", "bypass", "trusted")
WINDOW_HOURS = 24
PEOPLE_WINDOW_DAYS = 30
