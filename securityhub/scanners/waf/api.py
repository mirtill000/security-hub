"""Imperva API client (read-only) and configuration snapshot collection."""

from __future__ import annotations

import json
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ...common import RateLimiter
from .checks import ddos_adaptive
from .constants import USER_AGENT, __version__


class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class ImpervaAPI:
    """Minimal read-only client. Credentials travel only in headers (never in URLs or logs)."""

    def __init__(self, api_id: str, api_key: str, v1_base: str = "https://my.imperva.com",
                 api_base: str = "https://api.imperva.com", timeout: float = 30.0, qps: float = 8.0,
                 retries: int = 4, verify_tls: bool = True):
        self._headers = {"x-API-Id": str(api_id), "x-API-Key": str(api_key), "Accept": "application/json",
                         "User-Agent": USER_AGENT}
        self.v1_base = v1_base.rstrip("/")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.stats = Counter()
        self._lock = threading.Lock()

    def _request(self, method: str, url: str, form: Optional[dict] = None) -> Tuple[int, Any]:
        data = None
        headers = dict(self._headers)
        if form is not None:
            data = urllib.parse.urlencode({k: v for k, v in form.items() if v is not None}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        last = None
        for attempt in range(self.retries + 1):
            self.rate.wait()
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    body = resp.read()
                    with self._lock:
                        self.stats["requests"] += 1
                    return resp.status, json.loads(body or b"null")
            except urllib.error.HTTPError as e:
                with self._lock:
                    self.stats["requests"] += 1
                    self.stats[f"http_{e.code}"] += 1
                if e.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    delay = float(retry_after) if retry_after and retry_after.isdigit() else 1.5 * 2 ** attempt
                    time.sleep(min(delay, 30) + random.random() * 0.5)
                    continue
                try:
                    payload = json.loads(e.read() or b"null")
                except ValueError:
                    payload = None
                return e.code, payload
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                last = e
                if attempt < self.retries:
                    time.sleep(1.5 * 2 ** attempt + random.random() * 0.5)
                    continue
        raise APIError(f"network error: {getattr(last, 'reason', last)}")

    @staticmethod
    def _explain(status: int, payload: Any) -> str:
        if status == 401:
            return "authentication failed (check API ID / API key)"
        if status == 403:
            return "permission denied for this API (check the API key role)"
        msg = ""
        if isinstance(payload, dict):
            msg = payload.get("res_message") or payload.get("message") or payload.get("error") or ""
        return f"HTTP {status}{': ' + str(msg) if msg else ''}"

    def v1(self, path: str, **params) -> dict:
        """POST to a v1 provisioning endpoint; v1 reports errors with a non-zero 'res'."""
        status, payload = self._request("POST", f"{self.v1_base}{path}", form=params)
        if status != 200 or not isinstance(payload, dict):
            raise APIError(self._explain(status, payload), status)
        res = payload.get("res", 0)
        if str(res) not in ("0", "None"):
            raise APIError(f"API error {res}: {payload.get('res_message', 'unknown')}", status)
        return payload

    def get(self, path: str, **params) -> Any:
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        status, payload = self._request("GET", f"{self.api_base}{path}{'?' + qs if qs else ''}")
        if status == 404:
            return None
        if status != 200:
            raise APIError(self._explain(status, payload), status)
        if isinstance(payload, dict) and payload.get("isError"):
            raise APIError(str(payload.get("value") or "API returned isError"), status)
        return payload


def _unwrap(payload: Any) -> list:
    if isinstance(payload, dict):
        value = payload.get("value", payload.get("data"))
        if isinstance(value, list):
            return value
    return payload if isinstance(payload, list) else []


TRAFFIC_GRANULARITY_MS = 3600000  # hourly buckets: finer data gives more realistic peaks


def fetch_traffic(api: ImpervaAPI, site_id: Any, days: int) -> dict:
    """hits_timeseries (+ threats) for one site. Falls back to the default granularity when the
    requested one is rejected (error 13002)."""
    if days in (7, 30, 90):
        window = {"time_range": f"last_{days}_days"}
    else:
        end = int(time.time() * 1000)
        window = {"time_range": "custom", "start": end - days * 86400000, "end": end}
    for granularity in (TRAFFIC_GRANULARITY_MS, None):
        try:
            resp = api.v1("/api/stats/v1", site_id=site_id, stats="hits_timeseries,threats",
                          granularity=granularity, **window)
            return {"days": days, "granularity": granularity, "hits_timeseries": resp.get("hits_timeseries") or [],
                    "threats": resp.get("threats") or []}
        except APIError as e:
            if granularity and "13002" in str(e):
                continue
            raise
    return {}


def collect(api: ImpervaAPI, account_id: Optional[int], include_subaccounts: bool, site_filter: Set[str],
            workers: int, log, traffic_days: int = 90, traffic_cache: Optional[Dict[str, dict]] = None) -> dict:
    """traffic_cache: site id -> recent traffic statistics to reuse instead of downloading them again."""
    traffic_cache = traffic_cache or {}
    snap = {"tool": f"WAFGuard {__version__}", "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "accounts": [], "errors": []}

    def err(where: str, e: Exception) -> None:
        snap["errors"].append({"where": where, "error": str(e)})
        log(f"  ! {where}: {e}")

    accounts: List[dict] = []
    try:
        info = api.v1("/api/prov/v1/account", account_id=account_id).get("account", {}) or {}
        accounts.append({"account_id": info.get("account_id", account_id), "name": info.get("account_name", ""),
                         "plan": info.get("plan_name", ""), "parent": True})
    except APIError as e:
        err("account info", e)
        accounts.append({"account_id": account_id, "name": "", "plan": "", "parent": True})
    if include_subaccounts:
        page = 0
        while True:
            try:
                resp = api.v1("/api/prov/v1/accounts/listSubAccounts", account_id=account_id, page_size=100, page_num=page)
            except APIError as e:
                err("sub-accounts", e)
                break
            items = resp.get("resultList") or resp.get("accounts") or []
            for s in items:
                accounts.append({"account_id": s.get("sub_account_id") or s.get("account_id"),
                                 "name": s.get("sub_account_name") or s.get("account_name", ""), "plan": "",
                                 "parent": False})
            if len(items) < 100:
                break
            page += 1

    for acc in accounts:
        aid = acc["account_id"]
        caid = None if acc["parent"] else aid
        log(f"Account {aid} {acc['name']}".rstrip())
        sites: List[dict] = []
        page = 0
        while True:
            try:
                resp = api.v1("/api/prov/v1/sites/list", account_id=aid, page_size=100, page_num=page)
            except APIError as e:
                err(f"sites list (account {aid})", e)
                break
            batch = resp.get("sites") or []
            sites.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        if site_filter:
            sites = [s for s in sites if str(s.get("site_id")) in site_filter or
                     str(s.get("domain", "")).lower() in site_filter]
        log(f"  {len(sites)} website(s)")
        try:
            policies = _unwrap(api.get("/policies/v2/policies", extended="true", caid=caid))
        except APIError as e:
            err(f"policies (account {aid})", e)
            policies = []

        def detail(site: dict) -> Tuple[dict, list, Optional[str], Optional[dict]]:
            sid = site.get("site_id")
            problem = None
            full = site
            try:
                full = api.v1("/api/prov/v1/sites/status", site_id=sid) or site
            except APIError as e:
                problem = f"site status: {e}"
            try:
                applied = _unwrap(api.get(f"/policies/v2/assets/WEBSITE/{sid}/policies", extended="true", caid=caid))
            except APIError as e:
                applied = None
                problem = (problem + "; " if problem else "") + f"applied policies: {e}"
            traffic = None
            if ddos_adaptive(full) is True:
                pass  # adaptive DDoS threshold: the traffic statistics would only tune a fixed threshold
            elif traffic_days and str(sid) in traffic_cache:
                traffic = traffic_cache[str(sid)]
            elif traffic_days:
                try:
                    traffic = fetch_traffic(api, sid, traffic_days)
                except APIError as e:
                    traffic = {"error": str(e)}
            return full, applied, problem, traffic

        acc_sites, applied_map, problems, traffic_map = [], {}, {}, {}
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futures = {ex.submit(detail, s): s for s in sites}
            for k, fut in enumerate(as_completed(futures), 1):
                full, applied, problem, traffic = fut.result()
                sid = str(full.get("site_id", futures[fut].get("site_id")))
                acc_sites.append(full)
                applied_map[sid] = applied
                if traffic is not None:
                    traffic_map[sid] = traffic
                if problem:
                    problems[sid] = problem
                if k % 25 == 0 or k == len(sites):
                    log(f"  read {k}/{len(sites)} websites")
        snap["accounts"].append({**acc, "sites": acc_sites, "policies": policies, "asset_policies": applied_map,
                                 "site_errors": problems, "traffic": traffic_map})
    snap["api_stats"] = dict(api.stats)
    snap["traffic_reused"] = sum(1 for acc in snap["accounts"] for sid in (acc.get("traffic") or {}) if sid in traffic_cache)
    return snap
