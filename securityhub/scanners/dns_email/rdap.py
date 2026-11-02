"""RDAP client: registration and expiry of domains (takeover and lookalike checks)."""

from __future__ import annotations

import json
import os
import random
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from .util import cache_dir, http_get


class RDAPClient:
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    MAX_ERRORS = 25

    def __init__(self, timeout: float = 10.0, max_parallel: int = 4, allow_download: bool = True,
                 store=None, max_age_hours: float = 24.0):
        self.timeout = timeout
        self.allow_download = allow_download
        self._bootstrap: Optional[Dict[str, str]] = None
        self._boot_lock = threading.Lock()
        self._cache: Dict[str, dict] = {}
        self._inflight: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_parallel)
        self.errors = 0
        # registration data kept between runs (securityhub.cache.Store); "unregistered" is never kept:
        # it is the takeover signal and must be confirmed on every run
        self.store = store
        self.max_age_hours = max_age_hours
        self.enabled = True
        self.note = ""

    def _load_bootstrap(self) -> Dict[str, str]:
        with self._boot_lock:
            if self._bootstrap is not None:
                return self._bootstrap
            path = os.path.join(cache_dir(), "rdap_dns.json")
            data = None
            if os.path.exists(path) and time.time() - os.path.getmtime(path) < 7 * 86400:
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                except (OSError, ValueError):
                    data = None
            if data is None and self.allow_download:
                try:
                    status, body = http_get(self.BOOTSTRAP_URL, self.timeout, "application/json")
                    if status == 200:
                        data = json.loads(body)
                        with open(path, "wb") as f:
                            f.write(body)
                except Exception:
                    data = None
            mapping: Dict[str, str] = {}
            for service in (data or {}).get("services", []):
                tlds, urls = service[0], service[1]
                url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
                for tld in tlds:
                    if url:
                        mapping[tld.lower()] = url
            if not mapping:
                self.enabled = False
                self.note = "RDAP bootstrap unavailable - registration checks limited to DNS"
            self._bootstrap = mapping
            return mapping

    def lookup(self, domain: str) -> dict:
        domain = domain.lower()
        while True:
            with self._lock:
                if domain in self._cache:
                    return self._cache[domain]
                ev = self._inflight.get(domain)
                if ev is None:
                    ev = self._inflight[domain] = threading.Event()
                    break
            ev.wait()
        result = {"state": "unknown"}
        try:
            stored = self.store.get("rdap", domain, self.max_age_hours) if self.store is not None else None
            if isinstance(stored, dict):
                result = stored
            else:
                result = self._lookup(domain)
                if self.store is not None and result.get("state") in ("registered", "expiring"):
                    self.store.put("rdap", domain, result)
        finally:
            with self._lock:
                self._cache[domain] = result
                del self._inflight[domain]
            ev.set()
        return result

    def _lookup(self, domain: str) -> dict:
        if not self.enabled or self.errors >= self.MAX_ERRORS:
            return {"state": "unknown", "error": "RDAP disabled"}
        base = self._load_bootstrap().get(domain.rsplit(".", 1)[-1])
        if not base:
            return {"state": "unknown", "error": f"no RDAP service for .{domain.rsplit('.', 1)[-1]}"}
        url = base.rstrip("/") + "/domain/" + domain
        for attempt in range(3):
            with self._sem:
                try:
                    status, body = http_get(url, self.timeout, "application/rdap+json", 2 * 1024 * 1024)
                except Exception as e:
                    status, body = -1, str(e).encode()
            if status == 429 and attempt < 2:
                time.sleep(2 * (attempt + 1) + random.random())
                continue
            break
        if status == 404:
            return {"state": "unregistered"}
        if status != 200:
            with self._lock:
                self.errors += 1
            return {"state": "unknown", "error": f"RDAP HTTP {status}"}
        try:
            data = json.loads(body)
        except ValueError:
            return {"state": "unknown", "error": "invalid RDAP response"}
        out = {"state": "registered", "status": [s.lower() for s in data.get("status", [])]}
        for ev in data.get("events", []):
            action = (ev.get("eventAction") or "").lower()
            if action in ("expiration", "registration") and ev.get("eventDate"):
                out["expires" if action == "expiration" else "created"] = ev["eventDate"]
        dead = {"redemption period", "pending delete", "pendingdelete", "redemptionperiod"}
        if any(s in dead for s in out["status"]):
            out["state"] = "expired"
        elif out.get("expires"):
            try:
                exp = datetime.fromisoformat(out["expires"].replace("Z", "+00:00"))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                out["days_left"] = days
                if days < 0:
                    out["state"] = "expired"
                elif days <= 30:
                    out["state"] = "expiring"
            except ValueError:
                pass
        return out
