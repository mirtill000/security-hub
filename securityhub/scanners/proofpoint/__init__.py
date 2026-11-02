"""PPGuard - Proofpoint email protection posture (read-only: TAP SIEM / People APIs and public DNS).

Per mail domain: inbound routing through Proofpoint (MX, bypass hosts), direct delivery to the mailbox
service, SPF, and - from TAP - malicious messages delivered, malicious clicks permitted, URL Defense
rewriting and Very Attacked People. Organization level: top clickers, threats, domains not listed.
"""

from .analysis import analyze_snapshot, compute_diff
from .api import APIError, TapAPI, collect
from .checks import check_routing
from .cli import build_parser, main, parse_checks
from .constants import CHECKS, FINDINGS, __version__
from .routing import collect_dns, lookup_domain, m365_direct_host

__all__ = ["APIError", "CHECKS", "FINDINGS", "TapAPI", "__version__", "analyze_snapshot", "build_parser", "check_routing",
           "collect", "collect_dns", "compute_diff", "lookup_domain", "m365_direct_host", "main", "parse_checks"]
