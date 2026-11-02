"""Proofpoint TAP API client (read-only: SIEM and People APIs) and snapshot collection.

The snapshot keeps only what the checks need: no subjects, no message bodies, no click IPs or user agents,
no malicious URLs (only the link to the threat in the TAP dashboard).
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from ...common import RateLimiter
from .constants import PEOPLE_WINDOW_DAYS, USER_AGENT, WINDOW_HOURS, __version__

TAP_BASE = "https://tap-api-v2.proofpoint.com"


class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class TapAPI:
    def __init__(self, principal: str, secret: str, timeout: float = 60.0, qps: float = 1.0, base: str = TAP_BASE,
                 verify: bool = True):
        self.base = base.rstrip("/")
        if not self.base.startswith("https://"):
            raise ValueError("the TAP API URL must start with https://")
        self.auth = "Basic " + base64.b64encode(f"{principal}:{secret}".encode()).decode()
        self.timeout = timeout
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # noqa: S323
        self.stats = {"requests": 0, "retries": 0, "errors": 0}

    def get(self, path: str, **params: Any) -> dict:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, safe="/:")
        url = f"{self.base}{path}" + (f"?{q}" if q else "")
        for attempt in range(4):
            self.rate.wait()
            req = urllib.request.Request(url, headers={"Authorization": self.auth, "Accept": "application/json",
                                                       "User-Agent": USER_AGENT})
            self.stats["requests"] += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body.strip() else {}
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(min(60.0, float(e.headers.get("Retry-After") or 2 ** (attempt + 1))))
                    continue
                self.stats["errors"] += 1
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace").strip()[:200]
                except Exception:
                    pass
                hint = {401: " (service principal or secret invalid)", 403: " (principal without access to this API)",
                        429: " (TAP rate limit reached: retry later or widen the interval between runs)"}.get(e.code, "")
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


def _addr(v: Any) -> str:
    v = str(v or "").strip().strip("<>").lower()
    return v.split("<")[-1].rstrip(">") if "<" in v else v


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def _recipients(m: dict) -> List[str]:
    raw = m.get("recipient") or m.get("toAddresses") or []
    raw = raw if isinstance(raw, list) else [raw]
    return sorted({_addr(x) for x in raw if "@" in str(x)})


def _message(m: dict) -> dict:
    fa = m.get("fromAddress")
    sender = _addr((fa[0] if isinstance(fa, list) and fa else fa) or m.get("sender"))
    return {"guid": m.get("GUID"), "time": m.get("messageTime"), "recipients": _recipients(m), "from_domain": _domain(sender),
            "threats": [{"type": t.get("threatType"), "classification": str(t.get("classification") or "").lower(),
                         "status": str(t.get("threatStatus") or "").lower(), "id": t.get("threatID"),
                         "url": t.get("threatUrl"), "campaign": t.get("campaignId"), "time": t.get("threatTime")}
                        for t in m.get("threatsInfoMap") or []],
            "policy_routes": list(m.get("policyRoutes") or []), "quarantine": m.get("quarantineFolder"),
            "rewritten": m.get("completelyRewritten"), "phish_score": m.get("phishScore"), "impostor_score": m.get("impostorScore")}


def _click(c: dict) -> dict:
    return {"recipient": _addr(c.get("recipient")), "classification": str(c.get("classification") or "").lower(),
            "status": str(c.get("threatStatus") or "").lower(), "time": c.get("clickTime"), "threat_time": c.get("threatTime"),
            "threat_id": c.get("threatID"), "url": c.get("threatURL"), "campaign": c.get("campaignId"), "guid": c.get("GUID")}


def _person(u: dict, stat_key: str) -> dict:
    ident, stats = u.get("identity") or {}, u.get(stat_key) or {}
    return {"emails": [str(e).lower() for e in ident.get("emails") or []], "name": ident.get("name") or "",
            "department": ident.get("department") or "", "title": ident.get("title") or "", "vip": bool(ident.get("vip")),
            "attack_index": stats.get("attackIndex"), "clicks": stats.get("clickCount"),
            "families": [f.get("name") for f in stats.get("families") or [] if f.get("name")][:5]}


def collect(api: TapAPI, log: Callable[[str], None], hours: int = WINDOW_HOURS, people_days: int = PEOPLE_WINDOW_DAYS,
            now: Optional[datetime] = None) -> dict:
    """Read-only TAP snapshot: delivered threats and permitted clicks (detail), blocked ones (counts), VAP, top clickers."""
    end = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=hours)
    snap: Dict[str, Any] = {"tool": f"PPGuard {__version__}", "vendor": "Proofpoint", "api": api.base,
                            "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "window": {"start": start.isoformat(), "end": end.isoformat(), "hours": hours},
                            "messages_delivered": [], "clicks_permitted": [], "blocked": {}, "vap": [],
                            "top_clickers": [], "people_window_days": people_days, "errors": []}
    blocked: Dict[str, Counter] = defaultdict(Counter)

    def err(where: str, e: Exception) -> None:
        snap["errors"].append({"where": where, "error": str(e)})
        log(f"  ! {where}: {e}")

    t = start
    failed = total = 0
    while t < end:  # the SIEM API returns at most one hour per call
        t2 = min(end, t + timedelta(hours=1))
        total += 1
        try:
            body = api.get("/v2/siem/all", format="json",
                           interval=f"{t.strftime('%Y-%m-%dT%H:%M:%SZ')}/{t2.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            snap["messages_delivered"] += [_message(m) for m in body.get("messagesDelivered") or []]
            snap["clicks_permitted"] += [_click(c) for c in body.get("clicksPermitted") or []]
            for m in body.get("messagesBlocked") or []:
                for r in _recipients(m):
                    blocked[_domain(r)]["messages"] += 1
            for c in body.get("clicksBlocked") or []:
                blocked[_domain(_addr(c.get("recipient")))]["clicks"] += 1
        except APIError as e:
            failed += 1
            if failed <= 3:
                err(f"SIEM {t.strftime('%Y-%m-%d %H:%M')}", e)
            if e.status in (401, 403):
                break
        t = t2
    if failed > 3:
        err("SIEM", APIError(f"{failed} hourly intervals could not be read"))
    snap["blocked"] = {d: dict(c) for d, c in blocked.items() if d}
    snap["siem_failed"] = failed == total or any(e["error"].startswith("HTTP 401") or e["error"].startswith("HTTP 403")
                                                  for e in snap["errors"])
    log(f"{len(snap['messages_delivered'])} delivered threat message(s), {len(snap['clicks_permitted'])} permitted click(s) "
        f"in {hours}h")
    window = 14 if people_days <= 14 else 30 if people_days <= 30 else 90
    snap["people_window_days"] = window
    try:
        body = api.get("/v2/people/vap", window=window)
        snap["vap"] = [_person(u, "threatStatistics") for u in body.get("users") or []]
        snap["vap_threshold"] = body.get("vapAttackIndexThreshold")
        log(f"{len(snap['vap'])} Very Attacked People ({window} days)")
    except APIError as e:
        snap["vap"] = None
        err("People API (VAP)", e)
    try:
        body = api.get("/v2/people/top-clickers", window=window)
        snap["top_clickers"] = [_person(u, "clickStatistics") for u in body.get("users") or []]
    except APIError as e:
        snap["top_clickers"] = None
        err("People API (top clickers)", e)
    snap["api_stats"] = dict(api.stats)
    return snap
