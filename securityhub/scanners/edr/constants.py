"""Findings catalogue, checks and weights, frameworks and compliance profiles of the EDR assessment (SentinelOne)."""

from __future__ import annotations

from typing import Dict, List, Tuple

__version__ = "1.0.0"
USER_AGENT = f"EDRGuard/{__version__} (read-only posture assessment)"

# code -> (severity, area, title, recommendation)
FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # agent health and connectivity
    "AGENT_STALE": ("critical", "Health", "Agent not seen recently",
                    "Bring the endpoint back online or decommission the agent: stale agents hide unprotected machines"),
    "AGENT_DISABLED": ("critical", "Health", "Agent disabled (operational state)",
                       "Re-enable the agent: a disabled agent does not protect the endpoint"),
    "AGENT_ACTION_NEEDED": ("warning", "Health", "Agent needs an action (reboot, upgrade, incompatible OS...)",
                            "Complete the pending action, e.g. reboot after an upgrade"),
    "AGENT_MISSING_PERMISSIONS": ("warning", "Health", "Agent missing operating system permissions",
                                  "Grant the permissions (e.g. macOS Full Disk Access) through your MDM profile"),
    # protection
    "MODE_DETECT": ("critical", "Protection", "Malicious threats are only detected, not blocked (Detect mode)",
                    "Set the mitigation mode for malicious threats to Protect in the site or group policy"),
    "MODE_SUSPICIOUS_DETECT": ("info", "Protection", "Suspicious threats in Detect mode",
                               "Consider Protect for suspicious threats once false positives are tuned"),
    # policy hardening
    "ANTI_TAMPER_OFF": ("critical", "Policy", "Anti-tamper disabled",
                        "Enable anti-tampering: otherwise malware or users can stop or uninstall the agent"),
    "ENGINE_OFF": ("warning", "Policy", "Detection engine disabled",
                   "Enable every detection engine (Static AI, Behavioral AI, exploits, lateral movement, reputation...)"),
    "SNAPSHOTS_OFF": ("warning", "Policy", "VSS snapshots disabled: no ransomware rollback",
                      "Enable snapshots in the policy so Windows endpoints can be rolled back after ransomware"),
    "AUTO_MITIGATION_KILL_ONLY": ("info", "Policy", "Automatic mitigation only kills the process",
                                  "Quarantine (or remediate) threats automatically"),
    # version
    "AGENT_OUTDATED": ("warning", "Version", "Agent not up to date",
                       "Upgrade the agent to the latest GA version for the platform"),
    "AGENT_VERY_OLD": ("critical", "Version", "Agent far behind the latest GA (2 or more major versions)",
                       "Upgrade now: old agents miss detections and may be out of support"),
    # threats
    "THREAT_ACTIVE": ("critical", "Threats", "Threat not mitigated on the endpoint",
                      "Mitigate the threat (kill, quarantine, remediate or roll back) and investigate the endpoint"),
    "THREAT_UNRESOLVED": ("warning", "Threats", "Mitigated threat with the incident still open",
                          "Review the incident, set the analyst verdict and resolve it"),
    "THREAT_SLA": ("warning", "Threats", "Unresolved threat older than the triage SLA",
                   "Triage threats within the SLA: old open incidents hide real compromises"),
    # vulnerabilities and scan
    "APPS_VULNERABLE": ("warning", "Vulnerabilities", "Installed applications with known vulnerabilities",
                        "Patch the applications listed in SentinelOne Application Management / Vulnerability Management"),
    "NO_FULL_SCAN": ("info", "Scan", "Full disk scan never completed",
                     "Run a full disk scan to find dormant threats"),
    # console level
    "EXCLUSION_BROAD": ("critical", "Exclusions", "Overly broad exclusion",
                        "Narrow the exclusion to the specific binary or path: broad exclusions are a known evasion path"),
    "EXCLUSION_ALL_MONITORS": ("warning", "Exclusions", "Exclusion disables all monitors",
                               "Prefer 'suppress alerts' or interoperability modes; never disable every monitor"),
    "EXCLUSION_RISKY": ("warning", "Exclusions", "Risky exclusion (browser, signer certificate or file type)",
                        "Review whether the exclusion is still needed and restrict its scope"),
    "EXCLUSION_NO_DESCRIPTION": ("info", "Exclusions", "Exclusions without description",
                                 "Document owner, reason and review date of every exclusion"),
    "POLICY_DETECT": ("critical", "Policy", "Site or group policy in Detect mode",
                      "Set the policy mitigation mode for malicious threats to Protect"),
    "POLICY_ANTI_TAMPER_OFF": ("critical", "Policy", "Site or group policy with anti-tamper disabled",
                               "Enable anti-tampering in the policy"),
    "COVERAGE_GAP": ("critical", "Coverage", "Hosts in the inventory without a SentinelOne agent",
                     "Deploy the agent: unprotected hosts are where attacks land"),
    "AGENTS_DUPLICATE": ("info", "Coverage", "Several agents with the same host name",
                         "Decommission stale duplicates so counts and alerts are reliable"),
    "AGENTS_STALE_MANY": ("warning", "Coverage", "Agents not seen for a long time",
                          "Decommission the agents of retired machines, investigate the others"),
    "API_ERROR": ("warning", "API", "Part of the console configuration could not be read",
                  "Check the API token scope (a read-only Viewer role is enough) and the console URL"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

CHECKS: Dict[str, int] = {"health": 20, "protection": 30, "policy": 25, "version": 10, "threats": 15,
                          "vulnerabilities": 0, "scan": 0}
CHECK_LABELS = {"health": "Agent health", "protection": "Protection mode", "policy": "Policy hardening",
                "version": "Agent version", "threats": "Threats", "vulnerabilities": "Vulnerable apps",
                "scan": "Full disk scan"}
CHECK_ALIASES = {"mode": "protection", "tamper": "policy", "vulns": "vulnerabilities", "vuln": "vulnerabilities"}
SCORE_CAPS = {"THREAT_ACTIVE": 20, "AGENT_DISABLED": 30, "AGENT_STALE": 40, "MODE_DETECT": 50, "ANTI_TAMPER_OFF": 50,
              "AGENT_VERY_OLD": 70}

FRAMEWORK_MAP: Dict[str, List[str]] = {
    "Health": ["ISO 27001 A.8.7", "CIS Control 10"],
    "Protection": ["ISO 27001 A.8.7", "CIS Control 10"],
    "Policy": ["ISO 27001 A.8.7", "ISO 27001 A.8.9", "CIS Control 10"],
    "Version": ["ISO 27001 A.8.7", "ISO 27001 A.8.8"],
    "Threats": ["NIS2 Art.21(2)(b)", "ISO 27001 A.5.26"],
    "Vulnerabilities": ["NIS2 Art.21(2)(e)", "ISO 27001 A.8.8", "CIS Control 7"],
    "Scan": ["ISO 27001 A.8.7"],
    "Exclusions": ["ISO 27001 A.8.7", "ISO 27001 A.8.9"],
    "Coverage": ["ISO 27001 A.5.9", "CIS Control 1", "CIS Control 10"],
    "API": [],
}
COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "edr_baseline": ("EDR baseline", "Agent online, Protect mode, anti-tamper on, every engine on, agent up to date"),
    "ransomware_ready": ("Ransomware rollback", "Protect mode with VSS snapshots on (Windows endpoints)"),
}
TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
TIER_ALIASES = {"crit": "critical", "critico": "critical", "alta": "high", "alto": "high", "media": "medium",
                "medio": "medium", "bassa": "low", "basso": "low", "1": "critical", "2": "high", "3": "medium", "4": "low"}

# Policy engines: key -> label. Engines turned "off" in the effective policy are findings.
ENGINES = {"reputation": "Reputation", "preExecution": "Static AI", "preExecutionSuspicious": "Static AI (suspicious)",
           "executables": "Behavioral AI - executables", "dataFiles": "Documents and scripts", "exploits": "Exploits",
           "lateralMovement": "Lateral movement", "penetration": "Behavioral AI - fileless", "pup": "Potentially unwanted apps"}
OPTIONAL_ENGINES = {"pup"}  # off is a choice, reported as info

# Threat mitigation statuses that mean "the threat was stopped"
MITIGATED = {"mitigated", "blocked", "marked_as_benign", "suspicious_resolved", "resolved"}
EXECUTABLE_TYPES = {"exe", "dll", "sys", "scr", "com", "ps1", "psm1", "vbs", "js", "jse", "bat", "cmd", "hta", "msi",
                    "jar", "py", "sh", "elf", "so", "dylib", "app", "pkg", "lnk"}
STALE_DAYS = 14
THREAT_SLA_DAYS = 7
