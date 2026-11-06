"""PRAGuard - BeyondTrust Privileged Remote Access posture (read-only Configuration and Reporting API).

Per object: users and vendor users (MFA, administrators, inactive accounts, vendor expiration), assets
(asset policy: recording, approval, schedule, MFA challenge; Telnet, untrusted RDP certificates, tunnels),
gateways, API accounts (network allow list, write permissions) and vault accounts (rotation, checkout).
Site level: identity providers, group policies with MFA optional, vendor groups, session statistics.
"""

from .analysis import analyze_snapshot, compute_diff
from .api import APIError, PRAClient, collect
from .cli import build_parser, main, parse_checks
from .constants import CHECKS, FINDINGS, __version__

__all__ = ["APIError", "CHECKS", "FINDINGS", "PRAClient", "__version__", "analyze_snapshot", "build_parser", "collect",
           "compute_diff", "main", "parse_checks"]
