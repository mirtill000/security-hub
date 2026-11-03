"""IASGuard - SAP Cloud Identity Services identity posture (read-only SCIM 2.0 users and groups).

Per user: sign-in method (local IAS password vs corporate identity provider), second factor for local
passwords, password hygiene, activity, validity and e-mail. Tenant level: share of local passwords,
which attributes the tenant exposes (last sign-in, MFA).
"""

from .analysis import analyze_snapshot, compute_diff
from .api import APIError, IASClient, collect
from .cli import build_parser, main, parse_checks
from .constants import CHECKS, FINDINGS, __version__

__all__ = ["APIError", "CHECKS", "FINDINGS", "IASClient", "__version__", "analyze_snapshot", "build_parser",
           "collect", "compute_diff", "main", "parse_checks"]
