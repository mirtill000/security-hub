"""BeyondTrust PRA client (read-only) and snapshot collection.

Read-only by construction, even though the PRA "Configuration API" permission cannot be read-only:
- only GET requests, without a body, to the Configuration API endpoints listed in CONFIG_PATHS and to the
  Reporting API with the report types in REPORTS;
- the single POST is the OAuth token request (/oauth2/token).
The snapshot keeps what the checks need: no e-mail addresses, IP addresses of users, passwords or recordings.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from ...common import RateLimiter
from .constants import ASSET_TYPES, SESSION_DAYS, USER_AGENT, __version__

CONFIG = "/api/config/v1"
CONFIG_PATHS = {"/user", "/security-provider", "/group-policy", "/vendor", "/jump-policy", "/jumpoint", "/api-account",
                "/vault/account", "/vault/account-policy"} | {f"/jump-item/{t}" for t in ASSET_TYPES}
CONFIG_PATTERNS = (re.compile(r"^/vendor/\d+/user$"), re.compile(r"^/group-policy/\d+/vault-account$"))
REPORTS = {"AccessSessionListing"}
PAGE = 100


class APIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _allowed(path: str) -> bool:
    return path in CONFIG_PATHS or any(p.match(path) for p in CONFIG_PATTERNS)


class PRAClient:
    def __init__(self, site: str, client_id: str, secret: str, timeout: float = 60.0, qps: float = 5.0):
        site = site.strip().rstrip("/")
        if not site.startswith("https://"):
            site = "https://" + site.split("://", 1)[-1]
        self.base = site
        self._basic = "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        self.timeout = timeout
        self.rate = RateLimiter(qps)
        self.ctx = ssl.create_default_context()
        self._token: Optional[str] = None
        self._token_until = 0.0
        self.stats = {"requests": 0, "retries": 0, "errors": 0}

    def _send(self, req: urllib.request.Request) -> urllib.request.addinfourl:
        return urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)

    def token(self) -> str:
        if self._token and time.monotonic() < self._token_until:
            return self._token
        req = urllib.request.Request(f"{self.base}/oauth2/token", data=b"grant_type=client_credentials", method="POST",
                                     headers={"Authorization": self._basic, "Accept": "application/json",
                                              "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT})
        self.stats["requests"] += 1
        try:
            with self._send(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            self.stats["errors"] += 1
            raise APIError(f"HTTP {e.code} on /oauth2/token" + (" (client id / secret not accepted, or the address is not "
                                                                  "in the API account's network allow list)" if e.code in (400, 401, 403) else ""), e.code)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ValueError) as e:
            raise APIError(f"/oauth2/token: {getattr(e, 'reason', e)}")
        self._token = body.get("access_token")
        self._token_until = time.monotonic() + max(60, int(body.get("expires_in") or 3600) - 120)
        return self._token or ""

    def _get(self, url: str, path_label: str) -> tuple:
        for attempt in range(4):
            self.rate.wait()
            self.stats["requests"] += 1
            req = urllib.request.Request(url, method="GET", headers={"Authorization": f"Bearer {self.token()}",
                                                                     "Accept": "application/json", "User-Agent": USER_AGENT})
            try:
                with self._send(req) as resp:
                    return resp.read(), dict(resp.headers or {})
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:   # token revoked or expired: get a new one once
                    self._token = None
                    continue
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(min(30.0, float((e.headers or {}).get("Retry-After") or 2 ** attempt)))
                    continue
                self.stats["errors"] += 1
                hint = " (the API account lacks this permission)" if e.code == 403 else ""
                raise APIError(f"HTTP {e.code} on {path_label}{hint}", e.code)
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                if attempt < 3:
                    self.stats["retries"] += 1
                    time.sleep(2 ** attempt)
                    continue
                self.stats["errors"] += 1
                raise APIError(f"{path_label}: {getattr(e, 'reason', e)}")
        raise APIError(f"{path_label}: too many retries")

    def config(self, path: str, **params: Any) -> Any:
        if not _allowed(path):
            raise ValueError(f"refused: {path} is not a read-only endpoint of this tool")
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        body, _ = self._get(f"{self.base}{CONFIG}{path}" + (f"?{q}" if q else ""), path)
        try:
            return json.loads(body.decode("utf-8") or "null")
        except ValueError as e:
            raise APIError(f"{path}: invalid JSON ({e})")

    def pages(self, path: str, max_items: int = 100000) -> Iterator[dict]:
        page, n = 1, 0
        while True:
            items = self.config(path, per_page=PAGE, current_page=page)
            items = items if isinstance(items, list) else []
            for it in items:
                yield it
                n += 1
                if n >= max_items:
                    return
            if len(items) < PAGE:
                return
            page += 1

    def report(self, name: str, **params: Any) -> ET.Element:
        if name not in REPORTS:
            raise ValueError(f"refused: report {name} is not read by this tool")
        q = urllib.parse.urlencode({"generate_report": name, **params})
        body, _ = self._get(f"{self.base}/api/reporting?{q}", f"report {name}")
        try:
            root = ET.fromstring(body)
        except ET.ParseError as e:
            raise APIError(f"report {name}: invalid XML ({e})")
        for el in root.iter():   # the reports declare a namespace: drop it
            if isinstance(el.tag, str) and "}" in el.tag:
                el.tag = el.tag.split("}", 1)[1]
        err = root.find("error") if root.tag != "error" else root
        if err is not None and (err.text or "").strip():
            raise APIError(f"report {name}: {err.text.strip()}")
        return root


KEEP = {
    "user": ("id", "username", "public_display_name", "security_provider_id", "two_factor_required", "two_factor_type",
             "two_factor_enabled", "fido2_credential_count", "enabled", "last_authentication", "failed_logins", "created_at",
             "perm_admin", "perm_vault", "perm_set_passwords", "perm_endpoint_automation", "perm_access_allowed"),
    "vendor_user": ("id", "username", "public_display_name", "account_expiration", "enabled", "last_authenticated_date",
                    "vendor_administrator", "is_approved", "is_expired", "two_factor_enabled", "fido2_credential_count"),
    "asset": ("id", "name", "hostname", "jump_group_type", "jump_group_id", "jump_policy_id", "session_policy_id",
              "jumpoint_id", "tag", "protocol", "ignore_untrusted", "tunnel_type"),
    "gateway": ("id", "name", "platform", "enabled", "connected", "clustered", "jzp_enabled", "jzp_client_address_restrictions_type"),
    "api_account": ("id", "name", "enabled", "ip_addresses", "client_id", "failed_login_attempts", "perm_command",
                    "perm_reporting_support", "perm_reporting_license", "perm_reporting_vault", "perm_reporting_jump_item",
                    "perm_reporting_duplicate_jump_client", "perm_reporting_syslog", "perm_backup", "perm_vault_backup",
                    "perm_ecm", "perm_scim", "perm_configuration", "perm_configuration_vault_account"),
    "vault_account": ("id", "type", "name", "personal", "account_group_id", "account_policy"),
    "vault_policy": ("id", "name", "code_name", "auto_rotate_credentials", "allow_simultaneous_checkout",
                     "scheduled_password_rotation", "maximum_password_age"),
    "jump_policy": ("id", "display_name", "code_name", "schedule_enabled", "recordings_disabled", "approval_required",
                    "two_factor_challenge_required", "context_requirement", "session_start_notification"),
    "group_policy": ("id", "name", "perm_access_allowed", "access_perm_status", "two_factor_required", "two_factor_type",
                     "perm_protocol_tunnel"),
    "vendor": ("id", "name", "default_policy", "account_expiration", "user_approval_enabled", "network_restrictions"),
    "security_provider": ("id", "type", "name", "enabled", "user_authentication"),
}


def _pick(kind: str, d: dict) -> dict:
    return {k: d.get(k) for k in KEEP[kind]}


def _text(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""


def _session(s: ET.Element) -> dict:
    """Minimal view of an AccessSessionListing <session>: no IP addresses, chat or recording contents."""
    rep = s.find("primary_rep")
    reps = [_text(r.find("username")) for r in s.findall("rep_list/representative")]
    return {"lsid": s.get("lsid"), "start": _text(s.find("start_time")), "end": _text(s.find("end_time")),
            "duration": _text(s.find("duration")), "jump_group": _text(s.find("jump_group")),
            "jump_group_type": (s.find("jump_group").get("type") if s.find("jump_group") is not None else None),
            "gateway": _text(s.find("jumpoint")), "endpoint": _text(s.find("primary_customer")),
            "owner": _text(rep), "users": sorted({r for r in reps if r}),
            "file_transfers": int(_text(s.find("file_transfer_count")) or 0),
            "recorded": s.find("session_recording_view_url") is not None or s.find("command_shell_recordings/*") is not None}


def collect(api: PRAClient, log: Callable[[str], None], session_days: int = SESSION_DAYS,
            now: Optional[datetime] = None) -> dict:
    snap: Dict[str, Any] = {"tool": f"PRAGuard {__version__}", "vendor": "BeyondTrust", "site": api.base,
                            "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"), "errors": []}

    def err(where: str, e: Exception) -> None:
        snap["errors"].append({"where": where, "error": str(e)})
        log(f"  ! {where}: {e}")

    def read(key: str, path: str, kind: str) -> List[dict]:
        try:
            items = [_pick(kind, x) for x in api.pages(path)]
        except APIError as e:
            err(path, e)
            items = []
        snap[key] = items
        return items

    read("users", "/user", "user")
    read("security_providers", "/security-provider", "security_provider")
    groups = read("group_policies", "/group-policy", "group_policy")
    vendors = read("vendors", "/vendor", "vendor")
    read("jump_policies", "/jump-policy", "jump_policy")
    read("gateways", "/jumpoint", "gateway")
    read("api_accounts", "/api-account", "api_account")
    read("vault_accounts", "/vault/account", "vault_account")
    read("vault_policies", "/vault/account-policy", "vault_policy")
    snap["assets"] = []
    for t in ASSET_TYPES:
        try:
            snap["assets"] += [{**_pick("asset", x), "type": t} for x in api.pages(f"/jump-item/{t}")]
        except APIError as e:
            if e.status != 404:   # an asset type this site version does not have is not an error
                err(f"/jump-item/{t}", e)
    snap["vendor_users"] = []
    for v in vendors:
        try:
            snap["vendor_users"] += [{**_pick("vendor_user", x), "vendor_id": v["id"], "vendor": v.get("name")}
                                     for x in api.pages(f"/vendor/{int(v['id'])}/user")]
        except (APIError, TypeError, ValueError) as e:
            err(f"vendor {v.get('name')} users", e)
    snap["vault_roles"] = []
    for g in groups:
        try:
            snap["vault_roles"] += [{"group_policy_id": g["id"], "group_policy": g.get("name"), "account_id": x.get("account_id"),
                                     "role": x.get("role")} for x in api.pages(f"/group-policy/{int(g['id'])}/vault-account")]
        except (APIError, TypeError, ValueError) as e:
            if getattr(e, "status", None) != 404:
                err(f"group policy {g.get('name')} vault roles", e)
    log(f"{len(snap['users'])} user(s), {len(snap['vendor_users'])} vendor user(s), {len(snap['assets'])} asset(s), "
        f"{len(snap['gateways'])} gateway(s), {len(snap['vault_accounts'])} vault account(s)")
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=session_days)
    try:
        root = api.report("AccessSessionListing", start_time=int(start.timestamp()), duration=int(session_days * 86400))
        snap["sessions"] = [_session(s) for s in root.iter("session")]
        snap["session_window"] = {"start": start.isoformat(timespec="seconds"), "days": session_days}
        log(f"{len(snap['sessions'])} session(s) in {session_days} days")
    except APIError as e:
        snap["sessions"] = None
        err("sessions report", e)
    snap["api_stats"] = dict(api.stats)
    return snap
