"""Findings catalogue, checks and weights, frameworks and compliance profiles of the Proofpoint assessment."""

from __future__ import annotations

from typing import Dict, List, Tuple

__version__ = "1.0.0"
USER_AGENT = f"PPGuard/{__version__} (read-only posture assessment)"

# code -> (severity, area, title, recommendation)
FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # mail routing (DNS)
    "MX_NOT_PROOFPOINT": ("critical", "Routing", "Inbound mail does not go through Proofpoint",
                          "Point every MX record to the Proofpoint hosts of your cluster (*.pphosted.com)"),
    "MX_BYPASS": ("critical", "Routing", "MX records that bypass Proofpoint",
                  "Remove the MX records not served by Proofpoint: attackers send to the unfiltered host on purpose"),
    "MX_BYPASS_PREFERRED": ("critical", "Routing", "A host that bypasses Proofpoint is the preferred MX",
                            "Give the Proofpoint MX the lowest preference value, then remove the others"),
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
    # account level
    "TOP_CLICKERS": ("warning", "People", "Users who repeatedly click on threats",
                     "Assign targeted awareness training and adaptive controls (isolation) to the top clickers"),
    "TAP_DOMAINS_NOT_LISTED": ("info", "Coverage", "Domains seen by TAP but not in the domain list",
                               "Add them to the domain list so their routing is assessed too"),
    "TAP_NO_EVENTS": ("info", "API", "No TAP events in the time window",
                      "Normal for a quiet window; otherwise check that the service principal covers every cluster"),
    "API_ERROR": ("warning", "API", "Part of the TAP data could not be read",
                  "Check the service principal (TAP > Settings > Connected applications) and its access"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

CHECKS: Dict[str, int] = {"routing": 40, "direct": 10, "spf": 5, "threats": 25, "clicks": 20, "rewrite": 0, "people": 0}
DNS_CHECKS = ("routing", "direct", "spf")
TAP_CHECKS = ("threats", "clicks", "rewrite", "people")
CHECK_LABELS = {"routing": "Mail routing", "direct": "Direct delivery", "spf": "SPF", "threats": "Delivered threats",
                "clicks": "Permitted clicks", "rewrite": "URL Defense", "people": "Attacked people"}
CHECK_ALIASES = {"mx": "routing", "bypass": "direct", "tap": "threats", "click": "clicks", "vap": "people",
                 "url": "rewrite", "urldefense": "rewrite"}
SCORE_CAPS = {"MX_NOT_PROOFPOINT": 30, "MX_BYPASS_PREFERRED": 30, "MX_BYPASS": 50, "CLICK_PERMITTED": 40,
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
