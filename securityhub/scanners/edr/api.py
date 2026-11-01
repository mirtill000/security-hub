"""SentinelOne Management API client (read-only) and console snapshot collection."""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from ...common import RateLimiter
from .constants import USER_AGENT, __version__

API_PREFIX = "/web/api/v2.1"
PAGE = 1000
# Agent fields kept in the snapshot: what the checks need, nothing more (no IPs, no logged-in users).
AGENT_FIELDS = ("id", "uuid", "computerName", "osName", "osType", "osRevision", "machineType", "agentVersion",
                "siteId", "siteName", "groupId", "groupName", "accountName", "lastActiveDate", "isActive",
                "networkStatus", "isDecommissioned", "isUninstalled", "isPendingUninstall", "mitigationMode",
                "mitigationModeSuspicious", "isUpToDate", "infected", "activeThreats", "appsVulnerabilityStatus",
                "scanStatus", "scanFinishedAt", "operationalState", "userActionsNeeded", "missingPermissions",
                "registeredAt", "domain")
EXCLUSION_TYPES = ("path", "white_hash", "certificate", "file_type", "browser")


class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class SentinelOneAPI:
    def __init__(self, console: str, token: str, timeout: float = 30.0, qps: float = 5.0, verify: bool = True):
        self.base = console.rstrip("/")
        if not self.base.startswith("https://"):
            raise ValueError("the console URL must start with https://")
        self.token = token
        self.timeout = timeout
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # noqa: S323
        self.stats = {"requests": 0, "retries": 0, "errors": 0}

    def get(self, path: str, **params: Any) -> dict:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        url = f"{self.base}{API_PREFIX}{path}" + (f"?{q}" if q else "")
        for attempt in range(4):
            self.rate.wait()
            req = urllib.request.Request(url, headers={"Authorization": f"ApiToken {self.token}", "Accept": "application/json",
                                                       "User-Agent": USER_AGENT})
            self.stats["requests"] += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    return json.loads(resp.read().decode("utf-8") or "{}")
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(min(30.0, float(e.headers.get("Retry-After") or 2 ** attempt)))
                    continue
                self.stats["errors"] += 1
                detail = ""
                try:
                    body = json.loads(e.read().decode("utf-8") or "{}")
                    detail = "; ".join(str(x.get("title") or x.get("detail") or x) for x in body.get("errors") or [])
                except Exception:
                    pass
                hint = " (token invalid or expired)" if e.code == 401 else " (token scope too narrow)" if e.code == 403 else ""
                raise APIError(f"HTTP {e.code} on {path}{hint}{': ' + detail if detail else ''}", e.code)
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                if attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(2 ** attempt)
                    continue
                self.stats["errors"] += 1
                raise APIError(f"{path}: {getattr(e, 'reason', e)}")
            except ValueError as e:
                self.stats["errors"] += 1
                raise APIError(f"{path}: invalid JSON ({e})")
        raise APIError(f"{path}: too many retries")

    def paginate(self, path: str, max_items: Optional[int] = None, **params: Any) -> Iterator[dict]:
        """Cursor pagination (data + pagination.nextCursor)."""
        cursor, n = None, 0
        while True:
            body = self.get(path, limit=PAGE, cursor=cursor, **params)
            data = body.get("data")
            items = data.get("sites", []) if isinstance(data, dict) and "sites" in data else data or []
            for it in items:
                yield it
                n += 1
                if max_items and n >= max_items:
                    return
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor or not items:
                return


def collect(api: SentinelOneAPI, site_filter: List[str], log: Callable[[str], None], max_threats: int = 5000) -> dict:
    """Read-only snapshot of the console: agents, sites, groups, policies, open threats, exclusions, GA packages."""
    snap: Dict[str, Any] = {"tool": f"EDRGuard {__version__}", "vendor": "SentinelOne", "console": api.base,
                            "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "agents": [], "sites": [], "groups": [], "policies": {}, "threats": [], "exclusions": [],
                            "packages": [], "errors": []}

    def err(where: str, e: Exception) -> None:
        snap["errors"].append({"where": where, "error": str(e)})
        log(f"  ! {where}: {e}")

    try:
        sites = list(api.paginate("/sites", state="active"))
    except APIError as e:
        err("sites", e)
        sites = []
    wanted = {s.lower() for s in site_filter}
    if wanted:
        sites = [s for s in sites if str(s.get("id")) in wanted or str(s.get("name", "")).lower() in wanted]
    snap["sites"] = [{k: s.get(k) for k in ("id", "name", "state", "accountName", "activeLicenses", "totalLicenses")} for s in sites]
    site_ids = [str(s["id"]) for s in sites if s.get("id")]
    log(f"{len(sites)} site(s)")
    scope = {"siteIds": ",".join(site_ids)} if wanted and site_ids else {}

    try:
        agents = list(api.paginate("/agents", isDecommissioned=False, **scope))
        snap["agents"] = [{k: a.get(k) for k in AGENT_FIELDS} for a in agents]
        log(f"{len(agents)} agent(s)")
    except APIError as e:
        err("agents", e)
    try:
        snap["groups"] = [{k: g.get(k) for k in ("id", "name", "siteId", "inherits", "type", "totalAgents")}
                          for g in api.paginate("/groups", **scope)]
    except APIError as e:
        err("groups", e)
    for s in site_ids:
        try:
            snap["policies"][f"site:{s}"] = api.get(f"/sites/{s}/policy").get("data") or {}
        except APIError as e:
            err(f"policy of site {s}", e)
    for g in snap["groups"]:
        if g.get("inherits") is False and g.get("id"):
            try:
                snap["policies"][f"group:{g['id']}"] = api.get(f"/groups/{g['id']}/policy").get("data") or {}
            except APIError as e:
                err(f"policy of group {g.get('name')}", e)
    try:
        snap["threats"] = [_threat(t) for t in api.paginate("/threats", max_items=max_threats,
                                                             incidentStatuses="unresolved,in_progress", **scope)]
        log(f"{len(snap['threats'])} open threat(s)")
    except APIError as e:
        err("threats", e)
    for t in EXCLUSION_TYPES:
        try:
            snap["exclusions"] += [{k: x.get(k) for k in ("id", "type", "value", "mode", "pathExclusionType", "osType",
                                                         "description", "scopeName", "scope", "source", "createdAt", "userName")}
                                   for x in api.paginate("/exclusions", type=t, **scope)]
        except APIError as e:
            if e.status not in (400, 404):  # an exclusion type the console does not know is not an error
                err(f"exclusions ({t})", e)
    try:
        snap["packages"] = [{k: p.get(k) for k in ("version", "osType", "status", "platformType", "fileExtension")}
                            for p in api.paginate("/update/agent/packages", max_items=500, status="ga",
                                                  sortBy="version", sortOrder="desc")]
    except APIError as e:
        err("agent packages", e)
    snap["api_stats"] = dict(api.stats)
    return snap


def _threat(t: dict) -> dict:
    """Flat, minimal view of a threat (v2.1 nests most fields in threatInfo / agentRealtimeInfo)."""
    info, agent = t.get("threatInfo") or t, t.get("agentRealtimeInfo") or t
    return {"id": t.get("id"), "agent_id": str(agent.get("agentId") or t.get("agentId") or ""),
            "hostname": agent.get("agentComputerName") or t.get("agentComputerName"),
            "name": info.get("threatName"), "classification": info.get("classification"),
            "confidence": info.get("confidenceLevel"), "mitigation": info.get("mitigationStatus"),
            "incident": info.get("incidentStatus"), "verdict": info.get("analystVerdict"),
            "created": info.get("createdAt") or info.get("identifiedAt") or t.get("createdDate")}
