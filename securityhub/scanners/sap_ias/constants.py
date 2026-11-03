"""Findings catalogue, checks and weights of the SAP Cloud Identity Services (IAS) identity assessment."""

from __future__ import annotations

from typing import Dict, List, Tuple

__version__ = "1.0.0"
USER_AGENT = f"IASGuard/{__version__} (read-only posture assessment)"

# code -> (severity, area, title, recommendation)
FINDINGS: Dict[str, Tuple[str, str, str, str]] = {
    # sign-in
    "PASSWORD_LOGIN": ("warning", "Sign-in", "Can sign in with a local IAS password (not only through the corporate IdP)",
                       "Disable the IAS password (password status 'disabled') so the user signs in through the corporate "
                       "identity provider with its MFA and conditional access"),
    "PASSWORD_LOGIN_PRIVILEGED": ("critical", "Sign-in", "Member of a privileged group and can sign in with a local IAS password",
                                  "Privileged users must sign in only through the corporate identity provider with MFA"),
    "PASSWORD_NO_MFA": ("critical", "MFA", "Local IAS password without a second factor",
                        "Require two-factor authentication for the applications this user reaches, or disable the IAS password"),
    # password hygiene (only for users who can sign in with a password)
    "PASSWORD_OLD": ("warning", "Password", "Local password not changed for a long time",
                     "Enforce password expiry in the password policy, or remove the local password"),
    "PASSWORD_INITIAL": ("warning", "Password", "Initial password never changed",
                         "Force a password change at first sign-in, or disable unused accounts"),
    "PASSWORD_STANDARD_POLICY": ("warning", "Password", "Standard password policy (weaker than Enterprise)",
                                 "Assign the Enterprise (or a stricter custom) password policy to the applications"),
    "FAILED_LOGINS": ("info", "Password", "Many failed sign-in attempts",
                      "Check whether the account is under a password-guessing attack"),
    "LOCKED": ("info", "Password", "Account locked by failed sign-ins", "Unlock after verifying with the user"),
    # activity and lifecycle
    "INACTIVE": ("warning", "Activity", "Active account not used for a long time",
                 "Deactivate accounts not used in the period (the corporate leaver process may have missed it)"),
    "NEVER_USED": ("warning", "Activity", "Active account never used", "Deactivate accounts created and never used"),
    "EXPIRED_ACTIVE": ("critical", "Lifecycle", "Validity ended but the account is still active",
                       "Deactivate the account: its validity period is over"),
    "EMAIL_UNVERIFIED": ("info", "E-mail", "E-mail address not verified", "Verify the address before granting access"),
    "EMAIL_SHARED": ("warning", "E-mail", "E-mail address shared by several accounts",
                     "Give each person one account: shared addresses break accountability and password recovery"),
    # tenant level
    "PASSWORD_SHARE_HIGH": ("warning", "Sign-in", "Many active users can sign in with a local IAS password",
                            "Move these users to the corporate identity provider and disable their IAS password"),
    "MFA_NOT_VISIBLE": ("info", "MFA", "Second-factor enrollment is not exposed by the API",
                        "MFA for local passwords is checked on the application settings (conditional authentication)"),
    "LAST_LOGIN_NOT_VISIBLE": ("info", "Activity", "Last sign-in time is not exposed by the API",
                               "Inactive accounts are not evaluated"),
    "API_ERROR": ("warning", "API", "Part of the directory could not be read",
                  "Check the tenant URL and the technical user (read users / read groups authorization)"),
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

CHECKS: Dict[str, int] = {"signin": 40, "mfa": 25, "password": 15, "activity": 15, "lifecycle": 5, "email": 0}
CHECK_LABELS = {"signin": "Sign-in method", "mfa": "Second factor", "password": "Password hygiene",
                "activity": "Activity", "lifecycle": "Lifecycle", "email": "E-mail"}
CHECK_ALIASES = {"login": "signin", "auth": "signin", "tfa": "mfa", "2fa": "mfa", "pwd": "password", "inactive": "activity"}
SCORE_CAPS = {"PASSWORD_LOGIN_PRIVILEGED": 30, "PASSWORD_NO_MFA": 40, "EXPIRED_ACTIVE": 40, "PASSWORD_LOGIN": 70}

FRAMEWORK_MAP: Dict[str, List[str]] = {
    "Sign-in": ["ISO 27001 A.8.5", "CIS Control 6", "NIS2 Art.21(2)(j)"],
    "MFA": ["ISO 27001 A.8.5", "CIS Control 6", "NIS2 Art.21(2)(j)"],
    "Password": ["ISO 27001 A.5.17", "CIS Control 5"],
    "Activity": ["ISO 27001 A.5.18", "CIS Control 5"],
    "Lifecycle": ["ISO 27001 A.5.18", "CIS Control 5"],
    "E-mail": ["ISO 27001 A.5.16"],
    "API": [],
}
COMPLIANCE_PROFILES: Dict[str, Tuple[str, str]] = {
    "federated_only": ("Corporate sign-in only", "No local IAS password: the corporate IdP (MFA, conditional access) applies"),
    "account_hygiene": ("Account hygiene", "Used recently, within its validity, own e-mail address"),
}
TIER_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

SAP_EXT = "urn:ietf:params:scim:schemas:extension:sap:2.0:User"
CUSTOM_EXT = "urn:sap:cloud:scim:schemas:extension:custom:2.0:User"
LAST_LOGIN_KEYS = ("lastLoginTime", "loginTime", "lastLogonTime", "lastLogin", "lastSuccessfulLoginTime")
MFA_KEYS = ("mfaEnabled", "tfaEnabled", "twoFactorEnabled", "mfaActive", "tfaActive")
INACTIVE_DAYS = 90
PASSWORD_MAX_DAYS = 365
FAILED_LOGIN_ALERT = 5
NEVER_USED_GRACE_DAYS = 30
ALL_USERS_LIMIT = 5000   # above this, the report lists only users with findings (totals cover everyone)
