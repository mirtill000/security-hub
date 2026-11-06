"""Proofpoint Threat Protection API (Dash Reports and Email Bomb Events): read-only client, collection and findings.

Credentials: an API key and secret from Cloud Admin UI > Settings > API Key Management > Threat Protection tab
(PROOFPOINT_TP_KEY / PROOFPOINT_TP_SECRET). They are exchanged for a one-hour bearer token at auth.proofpoint.com
(client credentials); every report call is a GET on https://threatprotection-api.proofpoint.com/api/v1/dash/reports.

Rate limits (documented): 10 requests per minute per key; 20 requests per day per report section; 100 requests per
day per customer for the Email Bomb Events API. A run makes at most one call per report and the results are reused
for a day (securityhub.cache), so four runs a day stay far below the limits.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from ...common import RateLimiter
from .constants import USER_AGENT
from .models import Issue, make_issue

TOKEN_URL = "https://auth.proofpoint.com/v1/token"
TP_BASE = "https://threatprotection-api.proofpoint.com/api/v1/dash/reports"
# The only requests this client can make: GET on these report paths (and the token POST).
READ_ONLY_PATHS = ("/effectiveness-reports/threat-response-quarantines", "/effectiveness-reports/url-rewritten-summary",
                   "/bec-reports/vips-targeted-by-bec-threats", "/executive-summary/industry-comparison",
                   "/mail-bomb-events")
REPORT_DAYS = 30            # reporting period of the reports (the API accepts up to 90 days)
CACHE_HOURS = 24.0          # reports are read again once a day


class TPError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class ThreatProtectionAPI:
    def __init__(self, key: str, secret: str, timeout: float = 60.0, base: str = TP_BASE, token_url: str = TOKEN_URL,
                 verify: bool = True):
        if not (base.startswith("https://") and token_url.startswith("https://")):
            raise ValueError("the Threat Protection API URLs must start with https://")
        self.key, self._secret = key, secret
        self.base, self.token_url = base.rstrip("/"), token_url
        self.timeout = timeout
        self.rate = RateLimiter(0.15)   # 10 requests per minute per key: stay below
        self.ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # noqa: S323
        self._token: Optional[str] = None
        self._token_until = 0.0
        self.stats = {"requests": 0, "retries": 0, "errors": 0}

    def _open(self, req: urllib.request.Request) -> dict:
        self.stats["requests"] += 1
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body.strip() else {}

    def token(self) -> str:
        if self._token and time.time() < self._token_until - 60:
            return self._token
        data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.key,
                                       "client_secret": self._secret}).encode()
        req = urllib.request.Request(self.token_url, data=data, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT})
        try:
            body = self._open(req)
        except urllib.error.HTTPError as e:
            self.stats["errors"] += 1
            raise TPError(f"HTTP {e.code} on the token request (Threat Protection API key or secret invalid: create them in "
                          "Cloud Admin UI > Settings > API Key Management > Threat Protection)", e.code)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ValueError) as e:
            self.stats["errors"] += 1
            raise TPError(f"token request: {getattr(e, 'reason', e)}")
        self._token = body.get("access_token")
        if not self._token:
            raise TPError("token request: no access_token in the answer")
        self._token_until = time.time() + float(body.get("expires_in") or 3600)
        return self._token

    def get(self, path: str, **params: Any) -> Any:
        if path not in READ_ONLY_PATHS:
            raise ValueError(f"not an allowed read-only path: {path}")
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True, safe=":")
        url = f"{self.base}{path}" + (f"?{q}" if q else "")
        for attempt in range(3):
            self.rate.wait()
            req = urllib.request.Request(url, method="GET", headers={"Authorization": f"Bearer {self.token()}",
                                                                     "Accept": "application/json", "User-Agent": USER_AGENT})
            try:
                return self._open(req)
            except urllib.error.HTTPError as e:
                if e.code in (500, 502, 503, 504) and attempt < 2:
                    self.stats["retries"] += 1
                    time.sleep(2 ** (attempt + 1))
                    continue
                if e.code == 401 and attempt == 0:   # token expired early: get a new one once
                    self._token = None
                    continue
                self.stats["errors"] += 1
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace").strip()[:200]
                except Exception:
                    pass
                hint = {403: " (the key has no access to this report)",
                        429: " (daily limit of this report section reached: it resets within 24 hours)"}.get(e.code, "")
                raise TPError(f"HTTP {e.code} on {path}{hint}{': ' + detail if detail else ''}", e.code)
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                if attempt < 2:
                    self.stats["retries"] += 1
                    time.sleep(2 ** attempt)
                    continue
                self.stats["errors"] += 1
                raise TPError(f"{path}: {getattr(e, 'reason', e)}")
            except ValueError as e:
                self.stats["errors"] += 1
                raise TPError(f"{path}: invalid JSON ({e})")
        raise TPError(f"{path}: too many retries")


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _num(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _mail_bomb_users(body: Any) -> Tuple[List[dict], Optional[int]]:
    """Users targeted by email bombs. The public documentation names the fields only partly (a nullable 'name', a
    total count and zero-based pagination): read the usual shapes and keep name / e-mail / count."""
    rows: List[Any] = []
    total = None
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        for k in ("users", "events", "data", "items", "content", "results"):
            if isinstance(body.get(k), list):
                rows = body[k]
                break
        for k in ("total", "totalCount", "totalElements", "count", "totalEvents"):
            if isinstance(body.get(k), (int, float)):
                total = int(body[k])
                break
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        email = next((r.get(k) for k in ("email", "emailAddress", "recipient", "user", "userEmail") if isinstance(r.get(k), str)), "")
        out.append({"name": r.get("name") or "", "email": str(email).lower(),
                    "events": next((_num(r.get(k)) for k in ("eventCount", "count", "events", "messageCount", "totalEvents")
                                    if r.get(k) is not None), None),
                    "last": next((r.get(k) for k in ("lastEventTime", "lastSeen", "endTime", "time") if r.get(k)), None)})
    return out, total


def collect(api: ThreatProtectionAPI, log: Callable[[str], None], days: int = REPORT_DAYS, now: Optional[datetime] = None,
            store=None, max_age_hours: float = CACHE_HOURS) -> dict:
    """The reports the posture needs, minimized. Each report is read at most once per max_age_hours."""
    end = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    out: Dict[str, Any] = {"period": {"start": _iso(start), "end": _iso(end), "days": days}, "errors": [], "reused": []}

    def read(name: str, path: str, shape: Callable[[Any], Any], **params: Any) -> None:
        cached = store.get("tp", name, max_age_hours, str(days)) if store is not None else None
        if cached is not None:
            out[name] = cached
            out["reused"].append(name)
            return
        try:
            out[name] = shape(api.get(path, **params))
            if store is not None:
                store.put("tp", name, out[name], str(days))
        except TPError as e:
            out[name] = None
            out["errors"].append({"where": name, "error": str(e), "status": e.status})
            log(f"  ! Threat Protection {name}: {e}")

    period = {"start": _iso(start), "end": _iso(end)}
    read("quarantines", "/effectiveness-reports/threat-response-quarantines",
         lambda b: {k: _num(v) for k, v in ((b or {}).get("total") or {}).items()}, groupBy="MONTH", **period)
    read("url_rewrite", "/effectiveness-reports/url-rewritten-summary",
         lambda b: {k: {"urls": _num((b or {}).get(k, {}).get("countURLs")), "messages": _num((b or {}).get(k, {}).get("countMessages")),
                        "reasons": [{"reason": r.get("reason"), "urls": _num(r.get("countURLs"))}
                                    for r in ((b or {}).get(k, {}).get("reasons") or [])[:10]]}
                    for k in ("rewrittenURLs", "nonRewrittenURLsDueToPPS", "nonRewrittenURLs")}, **period)
    read("bec_vips", "/bec-reports/vips-targeted-by-bec-threats",
         lambda b: [{k: u.get(k) for k in ("person", "title", "department", "vip", "ato", "riskExposure", "isPrivileged",
                                           "attackIndex", "becEmailThreats", "suspiciousLoginsFromCloud")}
                    for u in ((b or {}).get("users") or [])[:100]], **period)
    # industry comparison: a quarter, starting from a month the API accepts (last 13 months to 3 months ago)
    month = (end.replace(day=1) - timedelta(days=95)).strftime("%Y-%m")
    read("industry", "/executive-summary/industry-comparison",
         lambda b: {"customer": ((b or {}).get("customer") or {}).get("attackIndex"), "start_month": month,
                    "verticals": [{"name": v.get("name"), "attack_index": v.get("attackIndex")} for v in (b or {}).get("verticals") or []]},
         startMonth=month)
    read("mail_bomb", "/mail-bomb-events",
         lambda b: dict(zip(("users", "total"), _mail_bomb_users(b))), page=0, size=100, **period)
    out["api_stats"] = dict(api.stats)
    return out


def findings(tp: Optional[dict]) -> Tuple[List[Issue], dict]:
    """Organization findings and the figures shown in the report."""
    issues: List[Issue] = []
    if not tp:
        return issues, {}
    for e in tp.get("errors") or []:
        issues.append(make_issue("TP_API_ERROR", f"{e.get('where')}: {e.get('error')}"))
    data: Dict[str, Any] = {"period": tp.get("period")}
    q = tp.get("quarantines")
    if q:
        read, unread = q.get("numberOfMessageCopiesQuarantinedRead", 0), q.get("numberOfMessageCopiesQuarantinedUnread", 0)
        skipped = q.get("numberOfMessageCopiesSkippedSkiplisted", 0) + q.get("numberOfMessageCopiesSkippedExternal", 0)
        data["quarantines"] = {"messages": q.get("numberOfTapMessages", 0), "pulled_unread": unread, "pulled_read": read,
                               "skipped": skipped, "read_share": round(100 * read / (read + unread)) if read + unread else None}
        if read:
            issues.append(make_issue("TR_PULLED_AFTER_READ", f"{read} of {read + unread} message copies were already read "
                                                             "when Threat Response removed them"))
        if skipped:
            issues.append(make_issue("TR_SKIPPED", f"{skipped} message copies not removed (skiplist or external)"))
    u = tp.get("url_rewrite")
    if u:
        done, pps, other = (u.get(k, {}).get("urls", 0) for k in ("rewrittenURLs", "nonRewrittenURLsDueToPPS", "nonRewrittenURLs"))
        total = done + pps + other
        data["url_rewrite"] = {"rewritten": done, "not_rewritten_pps": pps, "not_rewritten": other,
                               "coverage": round(100 * done / total, 1) if total else None,
                               "reasons": (u.get("nonRewrittenURLsDueToPPS", {}).get("reasons") or [])
                               + (u.get("nonRewrittenURLs", {}).get("reasons") or [])}
        if total and (pps + other) / total > 0.05:
            issues.append(make_issue("URL_REWRITE_GAP", f"{100 * (pps + other) / total:.1f}% of {total} URLs not rewritten"))
    vips = tp.get("bec_vips")
    if vips:
        data["bec_vips"] = vips
        risky = [v for v in vips if v.get("ato") or v.get("isPrivileged") or str(v.get("riskExposure") or "").upper() == "HIGH"]
        issues.append(make_issue("BEC_VIP_TARGETED_RISK" if risky else "BEC_VIP_TARGETED",
                                 f"{len(vips)} VIP(s)" + (f", {len(risky)} privileged, at account-takeover risk or high exposure: "
                                                          + ", ".join(str(v.get('person') or '?') for v in risky[:3]) if risky else "")))
    ind = tp.get("industry")
    if ind and ind.get("customer") is not None:
        data["industry"] = ind
        higher = [v for v in ind.get("verticals") or [] if v.get("attack_index") is not None and ind["customer"] > v["attack_index"]]
        if higher:
            issues.append(make_issue("ATTACK_INDEX_ABOVE_INDUSTRY", f"attack index {ind['customer']} vs "
                                     + ", ".join(f"{v['name']} {v['attack_index']}" for v in higher[:3])
                                     + f" (quarter from {ind.get('start_month')})"))
    mb = tp.get("mail_bomb")
    if mb is not None:
        users = mb.get("users") or []
        data["mail_bomb"] = {"users": users[:50], "total": mb.get("total")}
        if users or mb.get("total"):
            issues.append(make_issue("MAIL_BOMB_TARGETED", f"{len(users) or mb.get('total')} user(s): "
                                     + ", ".join(x.get("email") or x.get("name") or "?" for x in users[:3])))
    return issues, data
