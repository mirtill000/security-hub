"""Data kept between runs, so frequent runs do not repeat slow, rarely changing work.

One JSON file per module under ~/.cache/securityhub (or $SECURITYHUB_CACHE_DIR), readable only by the service
user. Each entry carries the time it was stored and, optionally, a fingerprint of what it depends on: it is
reused only while younger than the maximum age the caller gives and while the fingerprint matches. Entries
older than a week are dropped when the file is saved. A cache that cannot be read or written never fails
a run: the work is simply done again.

What is cached is decided by each module: discovery and statistics (DKIM selector search, RDAP registration
data, lookalikes, traffic statistics, legacy TLS probes...), never the configuration being assessed.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .common import atomic_write

KEEP_DAYS = 7


def cache_dir() -> str:
    base = os.environ.get("SECURITYHUB_CACHE_DIR")
    if base:
        return base
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(xdg, "securityhub")


def _parse(at: Any) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat(str(at).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


class Store:
    """Thread-safe {section: {key: entry}} store backed by one JSON file."""

    def __init__(self, name: str, enabled: bool = True, path: Optional[str] = None, now: Optional[datetime] = None):
        self.enabled = enabled
        self.path = path or os.path.join(cache_dir(), f"{name}.json")
        self.now = now or datetime.now(timezone.utc)
        self._lock = threading.Lock()
        self.hits: Dict[str, int] = {}
        self.data: Dict[str, Dict[str, dict]] = {}
        if enabled:
            try:
                with open(self.path, encoding="utf-8") as f:
                    raw = json.load(f)
                self.data = {s: dict(v) for s, v in raw.items() if isinstance(v, dict)} if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                self.data = {}

    def get(self, section: str, key: str, max_age_hours: float, fingerprint: Optional[str] = None) -> Any:
        """The stored value, or None when missing, too old, or stored for a different fingerprint."""
        if not self.enabled or max_age_hours <= 0:
            return None
        with self._lock:
            e = (self.data.get(section) or {}).get(key)
        if not isinstance(e, dict) or (fingerprint is not None and e.get("fp") != fingerprint):
            return None
        at = _parse(e.get("at"))
        if at is None or not timedelta(0) <= self.now - at < timedelta(hours=max_age_hours):
            return None
        with self._lock:
            self.hits[section] = self.hits.get(section, 0) + 1
        return e.get("v")

    def stored_at(self, section: str, key: str) -> Optional[str]:
        with self._lock:
            e = (self.data.get(section) or {}).get(key)
        return e.get("at") if isinstance(e, dict) else None

    def put(self, section: str, key: str, value: Any, fingerprint: Optional[str] = None) -> None:
        if not self.enabled:
            return
        e = {"at": self.now.isoformat(timespec="seconds"), "v": value}
        if fingerprint is not None:
            e["fp"] = fingerprint
        with self._lock:
            self.data.setdefault(section, {})[key] = e

    def drop(self, section: str, key: str) -> None:
        with self._lock:
            (self.data.get(section) or {}).pop(key, None)

    def save(self) -> Optional[str]:
        """Write the file (dropping entries older than a week). Returns an error message instead of raising."""
        if not self.enabled:
            return None
        limit = self.now - timedelta(days=KEEP_DAYS)
        with self._lock:
            data = {s: {k: e for k, e in entries.items() if (_parse(e.get("at")) or limit) > limit}
                    for s, entries in self.data.items()}
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            atomic_write(self.path, json.dumps(data, separators=(",", ":"), default=list), mode=0o600)
            return None
        except (OSError, TypeError, ValueError) as e:
            return str(e)
