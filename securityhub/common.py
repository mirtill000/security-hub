"""Helpers shared by every Security Hub module (scanners, portal, orchestrator)."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from typing import Any, Callable, Optional

# Exit codes are the same for every command, so a scheduler / CI job can treat them uniformly.
EXIT_OK, EXIT_USAGE, EXIT_FAIL_UNDER, EXIT_INTERRUPTED = 0, 1, 2, 130

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "|", "%")


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formulas (CWE-1236): DNS/HTTP/API data is attacker-controlled."""
    if isinstance(value, str) and value[:1] in CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


def json_for_html(obj: Any, default: Optional[Callable[[Any], Any]] = None) -> str:
    """JSON safe to embed in a <script> element (no '</script>' / '<!--' breakouts)."""
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=default)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def grade(score: Optional[float]) -> str:
    """Letter grade used consistently by the reports and the portal."""
    if score is None:
        return "-"
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


class RateLimiter:
    """Global token bucket: at most `qps` operations per second across all threads (qps <= 0: unlimited)."""

    def __init__(self, qps: float):
        self.interval = 1.0 / qps if qps and qps > 0 else 0.0
        self.next = time.monotonic()
        self.lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next)
            self.next = slot + self.interval
        if slot > now:
            time.sleep(slot - now)


class Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit with EXIT_USAGE (argparse defaults to 2 = fail-under)."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")
