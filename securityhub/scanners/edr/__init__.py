"""EDRGuard - SentinelOne EDR security posture (read-only Management API v2.1).

Per endpoint: agent health and connectivity, protection mode, policy hardening (anti-tamper, engines,
snapshots), agent version, open threats, vulnerable applications, full disk scan. Console level:
risky exclusions, policies in Detect mode or without anti-tamper, coverage against an inventory.
"""

from .analysis import analyze_snapshot, compute_diff, load_inventory, load_metadata
from .api import APIError, SentinelOneAPI, collect
from .checks import assess_exclusion
from .cli import build_parser, main, parse_checks
from .constants import CHECKS, FINDINGS, __version__

__all__ = ["APIError", "CHECKS", "FINDINGS", "SentinelOneAPI", "__version__", "analyze_snapshot", "assess_exclusion",
           "build_parser", "collect", "compute_diff", "load_inventory", "load_metadata", "main", "parse_checks"]
