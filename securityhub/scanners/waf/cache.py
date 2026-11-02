"""Slow-changing data kept between runs, so frequent runs do not repeat the heavy work.

- traffic statistics (90 days of hourly hits per site, only used to tune the DDoS threshold);
- the heavy part of the Internet probes (legacy TLS handshakes, direct connections to the origin servers).

Configuration (site status, applied policies) and the light probes (DNS routing, HTTPS) are read on every run.
An entry is reused while it is younger than its maximum age; a heavy probe is also redone when the domain or
the origin addresses of the site change.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ...common import atomic_write

HEAVY_PROBE_KEYS = ("tls10", "tls11", "origins")


def cache_path(account_id: Any) -> str:
    from ...cache import cache_dir
    return os.path.join(cache_dir(), f"waf-{account_id}.json")


def load(path: str) -> Dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {"traffic": dict(data.get("traffic") or {}), "probes": dict(data.get("probes") or {})}
    except (OSError, ValueError, AttributeError):
        return {"traffic": {}, "probes": {}}


def save(path: str, cache: Dict[str, dict]) -> Optional[str]:
    """Returns an error message instead of failing the run when the cache cannot be written."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        atomic_write(path, json.dumps(cache, separators=(",", ":")), mode=0o600)
        return None
    except OSError as e:
        return str(e)


def _age_hours(at: str, now: datetime) -> Optional[float]:
    try:
        t = datetime.fromisoformat(str(at).replace("Z", "+00:00"))
    except ValueError:
        return None
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return (now - t).total_seconds() / 3600


def fresh(entry: Optional[dict], max_age_hours: float, now: datetime, key: Optional[str] = None) -> bool:
    if not entry or max_age_hours <= 0:
        return False
    if key is not None and entry.get("key") != key:
        return False
    age = _age_hours(entry.get("at", ""), now)
    return age is not None and 0 <= age < max_age_hours


def probe_key(site: dict) -> str:
    """What the heavy probe depends on: the domain and the origin servers of the site."""
    raw = json.dumps([str(site.get("domain", "")).lower(), sorted(str(i) for i in site.get("ips") or [])])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
