"""Helpers shared by every Security Hub module (scanners, portal, orchestrator)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
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
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 65 else "D" if score >= 50 else "F"


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


def _umask_mode() -> int:
    old = os.umask(0)
    os.umask(old)
    return 0o666 & ~old


def atomic_write(path: str, text: str, mode: Optional[int] = None) -> None:
    """Write `text` so that readers (a browser, a SIEM collector, a dashboard) never see a half-written file.

    The file gets `mode`, or the permissions a normal write would give (umask); never the 0600 of a temp file.
    """
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=os.path.splitext(path)[1], dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, _umask_mode() if mode is None else mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class LockBusy(RuntimeError):
    pass


class RunLock:
    """Exclusive lock on an output folder, released automatically if the process dies.

    Uses an OS file lock (flock / msvcrt) on '<folder>/.securityhub.lock'; the file records who holds it.
    """

    def __init__(self, folder: str):
        self.path = os.path.join(folder, ".securityhub.lock")
        self.fh = None

    def __enter__(self) -> "RunLock":
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fh = open(self.path, "a+", encoding="utf-8")
        try:
            if os.name == "nt":  # pragma: no cover - Windows
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.seek(0)
            holder = fh.read().strip()
            fh.close()
            raise LockBusy(f"another run is using this output folder ({holder or 'unknown process'})")
        fh.seek(0)
        fh.truncate()
        fh.write(f"pid {os.getpid()} since {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        fh.flush()
        self.fh = fh
        return self

    def __exit__(self, *exc) -> bool:
        if self.fh:
            try:
                self.fh.seek(0)
                self.fh.truncate()
            finally:
                self.fh.close()  # closing the file releases the OS lock
                self.fh = None
        return False
