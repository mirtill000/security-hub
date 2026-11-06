"""Findings catalogue, checks and weights of the BeyondTrust Privileged Remote Access (PRA) assessment."""

from __future__ import annotations

from typing import Dict, List, Tuple

__version__ = "1.0.0"
USER_AGENT = f"PRAGuard/{__version__} (read-only posture assessment)"

KINDS = {"user": "User", "vendor_user": "Vendor user", "asset": "Asset", "gateway": "Gateway",
         "api_account": "API account", "vault_account": "Vault account"}

# code -> (severity, area, title, recommendation)
FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # people
    "USER_NO_MFA": ("warning", "Authentication", "User without multi-factor authentication",
                    "Require TOTP or FIDO2 in the user's group policy (two_factor_type), or sign in through a SAML IdP with MFA"),
    "ADMIN_NO_MFA": ("critical", "Authentication", "Administrator without multi-factor authentication",
                     "Require FIDO2 or TOTP for every administrator"),
    "ADMIN_LOCAL": ("warning", "Authentication", "Administrator with a local PRA account",
                    "Administrators should sign in through the corporate IdP; keep at most one documented break-glass local admin"),
    "USER_ADMIN": ("info", "Privileges", "Site administrator", "Review the administrators regularly"),
    "USER_VAULT_ADMIN": ("info", "Privileges", "Allowed to administer the Vault", "Review who administers the Vault"),
    "USER_INACTIVE": ("warning", "Lifecycle", "Enabled account not used for a long time", "Disable accounts not used in the period"),
    "USER_NEVER_USED": ("warning", "Lifecycle", "Enabled account never used", "Disable accounts created and never used"),
    "FAILED_LOGINS": ("info", "Authentication", "Many failed sign-in attempts", "Check whether the account is under attack"),
    "VENDOR_NO_MFA": ("critical", "Authentication", "Vendor user without multi-factor authentication",
                      "Require two-factor authentication in the vendor group's group policy"),
    "VENDOR_NO_EXPIRY": ("critical", "Lifecycle", "Vendor account without an expiration date",
                         "Set an account expiration in the vendor group (and renew it on request)"),
    "VENDOR_INACTIVE": ("warning", "Lifecycle", "Vendor account not used for a long time", "Disable or expire the vendor account"),
    "VENDOR_ADMIN": ("info", "Privileges", "Vendor administrator (manages the vendor's own users)",
                     "Check that the vendor administrator is still the right person"),
    # assets and access policies
    "ASSET_NO_POLICY": ("warning", "Access policy", "Asset without an asset policy",
                        "Assign an asset policy: schedule, approval, notifications and recording are governed there"),
    "ASSET_RECORDING_OFF": ("critical", "Access policy", "Sessions on the asset are not recorded",
                            "Disable 'recordings_disabled' in the asset policy: privileged sessions must be recorded"),
    "ASSET_NO_APPROVAL": ("info", "Access policy", "No approval required to access the asset",
                          "Require approval for critical systems and for vendor access"),
    "ASSET_NO_MFA_CHALLENGE": ("info", "Access policy", "No MFA challenge before starting a session",
                               "Enable the two-factor challenge in the asset policy for critical systems"),
    "ASSET_NO_SCHEDULE": ("info", "Access policy", "Access not limited to a schedule", "Restrict access to working hours where possible"),
    "ASSET_PERSONAL": ("info", "Access policy", "Personal asset (owned by a user, outside shared asset groups)",
                       "Move it to a shared asset group governed by policies"),
    "ASSET_TELNET": ("critical", "Exposure", "Shell asset over Telnet (clear text)", "Use SSH"),
    "ASSET_RDP_UNTRUSTED": ("warning", "Exposure", "RDP asset ignores untrusted server certificates",
                            "Disable 'ignore untrusted': a forged server can capture the credentials"),
    "ASSET_TUNNEL": ("info", "Exposure", "Tunnel asset: the session content is not recorded",
                     "Keep tunnels to the systems that need them and require approval"),
    # gateways
    "GATEWAY_OFFLINE": ("warning", "Gateway", "Gateway enabled but not connected", "Fix or remove the gateway"),
    "GATEWAY_SINGLE_NODE": ("info", "Gateway", "Gateway with a single node (no high availability)", "Cluster critical gateways"),
    "GATEWAY_PROXY_OPEN": ("warning", "Gateway", "Gateway proxy without client address restrictions",
                           "Restrict the proxy to the networks that need it"),
    # API accounts
    "API_NO_IP": ("warning", "API", "API account without a network allow list", "Restrict the account to the integration's addresses"),
    "API_NO_IP_WRITE": ("critical", "API", "API account with write permissions and no network allow list",
                        "Restrict the account to the integration's addresses"),
    "API_WRITE": ("warning", "API", "API account with write or sensitive permissions",
                  "Keep only the permissions the integration needs"),
    "API_SELF_EXCESS": ("info", "API", "This tool's API account has permissions it does not use",
                        "Uncheck them: the tool needs Configuration API and the session / vault activity reports only"),
    # vault
    "VAULT_NO_ROTATION": ("warning", "Vault", "Vault account without automatic rotation",
                          "Use an account policy with rotation after check-in and/or scheduled rotation"),
    "VAULT_LONG_ROTATION": ("info", "Vault", "Scheduled rotation longer than 90 days", "Shorten the maximum password age"),
    "VAULT_CHECKOUT": ("warning", "Vault", "Users can check out (see) the credential, not only inject it",
                       "Prefer the 'inject' role: users use the credential without seeing it"),
    "VAULT_SHARED_USE": ("info", "Vault", "Simultaneous checkout allowed", "Disable simultaneous checkout for privileged accounts"),
    # site level
    "LOCAL_AUTH_ONLY": ("warning", "Authentication", "No enabled SAML or directory security provider for users",
                        "Sign users in through the corporate IdP (SAML) with MFA"),
    "POLICY_MFA_OPTIONAL": ("warning", "Authentication", "Group policies granting access with MFA optional",
                            "Set two_factor_type to require FIDO2 or TOTP"),
    "VENDOR_GROUP_NO_EXPIRY": ("warning", "Lifecycle", "Vendor group without account expiration",
                               "Set an account expiration (days) for new vendor users"),
    "VENDOR_GROUP_NO_APPROVAL": ("warning", "Lifecycle", "Vendor group without approval of new users",
                                 "Require approval before vendor users can sign in"),
    "SESSIONS_UNRECORDED": ("warning", "Sessions", "Sessions without a recording in the window",
                            "Check the asset policies and the global recording options"),
    "SESSIONS_FILE_TRANSFER": ("info", "Sessions", "Sessions with file transfers in the window",
                               "Review file transfers, in particular by vendors"),
    "API_ERROR": ("warning", "API", "Part of the configuration could not be read",
                  "Check the API account permissions (Configuration API, Reporting API) and network restrictions"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

CHECKS: Dict[str, int] = {"authentication": 30, "privileges": 15, "lifecycle": 15, "access_policy": 25, "exposure": 15}
CHECK_LABELS = {"authentication": "Authentication", "privileges": "Privileges", "lifecycle": "Lifecycle",
                "access_policy": "Access policy", "exposure": "Exposure"}
CHECK_ALIASES = {"auth": "authentication", "mfa": "authentication", "priv": "privileges", "policy": "access_policy"}
SCORE_CAPS = {"ADMIN_NO_MFA": 30, "VENDOR_NO_MFA": 30, "API_NO_IP_WRITE": 30, "ASSET_RECORDING_OFF": 40, "ASSET_TELNET": 40,
              "VENDOR_NO_EXPIRY": 50}

FRAMEWORK_MAP: Dict[str, List[str]] = {
    "Authentication": ["ISO 27001 A.8.5", "CIS Control 6", "NIS2 Art.21(2)(j)"],
    "Privileges": ["ISO 27001 A.8.2", "CIS Control 5"],
    "Lifecycle": ["ISO 27001 A.5.18", "CIS Control 5"],
    "Access policy": ["ISO 27001 A.8.2", "ISO 27001 A.8.15", "NIS2 Art.21(2)(d)"],
    "Exposure": ["ISO 27001 A.8.20", "CIS Control 12"],
    "Gateway": ["ISO 27001 A.8.14"],
    "API": ["ISO 27001 A.8.2"],
    "Vault": ["ISO 27001 A.5.17", "CIS Control 5"],
    "Sessions": ["ISO 27001 A.8.15", "NIS2 Art.21(2)(d)"],
}
COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "strong_auth": ("Strong authentication", "People sign in with MFA; API accounts restricted by network"),
    "governed_access": ("Governed access", "Assets under a policy that records sessions"),
}
TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
INACTIVE_DAYS = 90
NEVER_USED_GRACE_DAYS = 30
SESSION_DAYS = 7
ALL_OBJECTS_LIMIT = 5000
# Jump item (asset) types read from the Configuration API
ASSET_TYPES = {"shell-jump": "SSH / Telnet", "remote-rdp": "RDP", "remote-vnc": "VNC", "web-jump": "Web",
               "protocol-tunnel-jump": "Protocol tunnel", "network-tunnel-jump": "Network tunnel",
               "mysql-tunnel-jump": "MySQL tunnel", "psql-tunnel-jump": "PostgreSQL tunnel",
               "oracle-tunnel-jump": "Oracle tunnel", "mongodb-tunnel-jump": "MongoDB tunnel"}
