"""SAP Cloud Identity Services client (read-only SCIM 2.0: users and groups) and snapshot collection.

Authentication: a technical user (client id + secret, HTTP Basic) or an X.509 client certificate.
The snapshot keeps what the checks need: no phone numbers, addresses, names split in parts or passwords.
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
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, Optional

from ...common import RateLimiter
from .constants import CUSTOM_EXT, LAST_LOGIN_KEYS, MFA_KEYS, SAP_EXT, USER_AGENT, __version__

PAGE = 100


class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class IASClient:
    def __init__(self, tenant: str, client_id: Optional[str] = None, secret: Optional[str] = None,
                 cert: Optional[str] = None, key: Optional[str] = None, timeout: float = 30.0, qps: float = 5.0):
        tenant = tenant.strip().rstrip("/")
        if not tenant.startswith("https://"):
            tenant = "https://" + tenant.split("://", 1)[-1]
        self.base = tenant
        self.timeout = timeout
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context()
        self.headers = {"Accept": "application/scim+json", "User-Agent": USER_AGENT}
        if cert:
            self.ctx.load_cert_chain(cert, key)
        elif client_id and secret:
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        else:
            raise ValueError("credentials missing: client id and secret, or a client certificate")
        self.stats = {"requests": 0, "retries": 0, "errors": 0}

    def get(self, path: str, **params: Any) -> dict:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base}{path}" + (f"?{q}" if q else "")
        for attempt in range(4):
            self.rate.wait()
            self.stats["requests"] += 1
            try:
                req = urllib.request.Request(url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body.strip() else {}
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(min(30.0, float(e.headers.get("Retry-After") or 2 ** attempt)))
                    continue
                self.stats["errors"] += 1
                hint = {401: " (client id / secret or certificate not accepted)",
                        403: " (the technical user lacks the 'read users' / 'read groups' authorization)"}.get(e.code, "")
                raise APIError(f"HTTP {e.code} on {path}{hint}", e.code)
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

    def pages(self, path: str, max_items: int = 200000, **params: Any) -> Iterator[dict]:
        """SCIM pagination: cursor (startId / nextId) where the tenant supports it, index (startIndex) otherwise."""
        try:  # cursor pagination has no result limit; tenants that do not support it answer 400
            body = self.get(path, startId="initial", count=PAGE, **params)
        except APIError as e:
            if e.status != 400:
                raise
            body = self.get(path, startIndex=1, count=PAGE, **params)
        cursor = "nextId" in body
        n, index = 0, 1
        while True:
            items = body.get("Resources") or []
            for it in items:
                yield it
                n += 1
                if n >= max_items:
                    return
            if cursor:
                nxt = body.get("nextId")
                if not nxt or nxt == "end" or not items:
                    return
                body = self.get(path, startId=nxt, count=PAGE, **params)
            else:
                total = int(body.get("totalResults") or 0)
                index += len(items)
                if not items or index > total:
                    return
                body = self.get(path, startIndex=index, count=PAGE, **params)


def _first(d: dict, keys) -> Any:
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


def _user(u: dict) -> dict:
    """Minimal view of a SCIM user: what the checks need."""
    sap = u.get(SAP_EXT) or {}
    pwd = sap.get("passwordDetails") or {}
    emails = u.get("emails") or sap.get("emails") or []
    primary = next((e for e in emails if e.get("primary")), emails[0] if emails else {})
    sap_emails = sap.get("emails") or []
    verified = sap.get("mailVerified")
    if verified is None and sap_emails:
        verified = any(e.get("verified") for e in sap_emails)
    custom = {a.get("name"): a.get("value") for a in ((u.get(CUSTOM_EXT) or {}).get("attributes") or []) if a.get("name")}
    mfa = _first(sap, MFA_KEYS)
    if mfa is None:
        mfa = _first(u, MFA_KEYS)
    return {
        "id": u.get("id"), "userName": u.get("userName"), "displayName": u.get("displayName"),
        "userType": u.get("userType"), "active": u.get("active"),
        "email": str(primary.get("value") or "").lower(), "mailVerified": verified,
        "groups": sorted({str(g.get("display") or g.get("value")) for g in u.get("groups") or [] if g}),
        "created": (u.get("meta") or {}).get("created"), "lastModified": (u.get("meta") or {}).get("lastModified"),
        "userId": sap.get("userId"), "status": sap.get("status"),
        "validFrom": sap.get("validFrom"), "validTo": sap.get("validTo"),
        "password": {"status": pwd.get("status"), "setTime": pwd.get("setTime") or pwd.get("changeTime"),
                     "failedLoginAttempts": pwd.get("failedLoginAttempts"), "policy": pwd.get("policy"),
                     "locked": pwd.get("locked") if "locked" in pwd else None},
        "lastLogin": _first(sap, LAST_LOGIN_KEYS) or _first(pwd, LAST_LOGIN_KEYS) or _first(u, LAST_LOGIN_KEYS),
        "mfa": mfa, "custom": custom,
    }


def collect(api: IASClient, log: Callable[[str], None], max_users: int = 200000) -> dict:
    snap: Dict[str, Any] = {"tool": f"IASGuard {__version__}", "vendor": "SAP", "tenant": api.base,
                            "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "users": [], "groups": [], "errors": []}
    try:
        snap["users"] = [_user(u) for u in api.pages("/scim/Users", max_users)]
        log(f"{len(snap['users'])} user(s)")
    except APIError as e:
        snap["errors"].append({"where": "users", "error": str(e)})
        log(f"  ! users: {e}")
    try:
        snap["groups"] = [{"id": g.get("id"), "displayName": g.get("displayName")}
                          for g in api.pages("/scim/Groups", excludedAttributes="members")]
        log(f"{len(snap['groups'])} group(s)")
    except APIError as e:
        snap["errors"].append({"where": "groups", "error": str(e)})
        log(f"  ! groups: {e}")
    fields: Dict[str, int] = {"lastLogin": 0, "mfa": 0}
    for u in snap["users"]:
        fields["lastLogin"] += u["lastLogin"] is not None
        fields["mfa"] += u["mfa"] is not None
    snap["fields_seen"] = fields  # which optional attributes this tenant exposes
    snap["api_stats"] = dict(api.stats)
    return snap


__all__ = ["APIError", "IASClient", "collect"]
