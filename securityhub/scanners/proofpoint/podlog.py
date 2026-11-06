"""Proofpoint on Demand Log API (PoD Logging): read-only WebSocket client, aggregation and findings.

Endpoint (as used by the Proofpoint connectors of Microsoft Sentinel and Elastic):
    wss://logstream.proofpoint.com:443/v1/stream?cid=<cluster id>&type=<message|audit>&sinceTime=..&toTime=..
with "Authorization: Bearer <token>". The cluster id is shown in the PoD admin interface next to the release number;
Proofpoint provides the token (Remote Syslog Forwarding license). A token accepts ONE session at a time: give this
tool its own token, or it disconnects a SIEM that streams with the same one.

The stream is read for a past window (sinceTime/toTime) and each event is counted as it arrives: no message, header,
subject or address is stored, only totals and the top values the findings name (sending domains, admin accounts).
The WebSocket client is written on the standard library (RFC 6455, client side): no extra dependency.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .constants import USER_AGENT
from .models import Issue, make_issue

POD_HOST = "logstream.proofpoint.com"
WINDOW_HOURS = 4            # one scheduled run every ~4 hours: each run reads the last 4 hours
MAX_EVENTS = 200_000        # safety cap per stream on small devices (the totals then say "sampled")
IDLE_SECONDS = 30.0         # no frame for this long: the window has been sent


class PodError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# minimal WebSocket client (text frames, ping/pong, close; client frames are masked)
# ---------------------------------------------------------------------------

class WebSocket:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _recv(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed by the server")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def _send(self, opcode: int, payload: bytes = b"") -> None:
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", n)
        mask = os.urandom(4)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def messages(self) -> Iterator[str]:
        """Text messages until the server closes the stream."""
        parts: List[bytes] = []
        while True:
            b1, b2 = self._recv(2)
            fin, opcode, n = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._recv(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._recv(8))[0]
            mask = self._recv(4) if b2 & 0x80 else None
            payload = self._recv(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:          # close
                try:
                    self._send(0x8, payload[:2])
                except OSError:
                    pass
                return
            if opcode == 0x9:          # ping
                self._send(0xA, payload)
                continue
            if opcode == 0xA:          # pong
                continue
            parts.append(payload)
            if fin:
                yield b"".join(parts).decode("utf-8", "replace")
                parts = []

    def close(self) -> None:
        try:
            self._send(0x8, struct.pack("!H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def open_stream(cluster: str, token: str, kind: str, since: datetime, until: datetime, host: str = POD_HOST,
                port: int = 443, timeout: float = IDLE_SECONDS, connect: Optional[Callable[..., Any]] = None) -> WebSocket:
    """Open the log stream of one type for a past window. `connect` (tests) returns a connected socket."""
    if kind not in ("message", "audit"):
        raise ValueError(f"not a supported stream type: {kind}")
    q = urllib.parse.urlencode({"cid": cluster, "type": kind, "sinceTime": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "toTime": until.strftime("%Y-%m-%dT%H:%M:%SZ")}, safe=":")
    path = f"/v1/stream?{q}"
    if connect is not None:
        sock = connect()
    else:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    sock.settimeout(timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n"
                  f"User-Agent: {USER_AGENT}\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise PodError("connection closed during the handshake")
        head += chunk
        if len(head) > 65536:
            raise PodError("handshake answer too long")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split()
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if status != 101:
        hint = {401: " (token invalid or expired: ask Proofpoint for the PoD Log API token of this cluster)",
                403: " (token not allowed for this cluster or stream type)",
                409: " (the token is already used by another session, e.g. a SIEM: use a dedicated token)"}.get(status, "")
        raise PodError(f"HTTP {status or '?'} opening the {kind} stream{hint}", status)
    ws = WebSocket(sock)
    ws.buf = head.split(b"\r\n\r\n", 1)[1]
    return ws


# ---------------------------------------------------------------------------
# aggregation (the events are counted, never stored)
# ---------------------------------------------------------------------------

def _dom(addr: Any) -> str:
    a = str(addr or "").strip().lower()
    if "<" in a:
        a = a.rsplit("<", 1)[-1].split(">", 1)[0]
    return a.rsplit("@", 1)[-1].strip(">. ") if "@" in a else ""


def _under(d: str, domains: List[str]) -> bool:
    return any(d == x or d.endswith("." + x) for x in domains)


def _tls_ok(version: Any) -> Optional[bool]:
    v = str(version or "").upper().replace(" ", "")
    if not v:
        return False
    return v in ("TLSV1.2", "TLSV1.3")


class MessageStats:
    """Counters over the 'message' stream (inbound mail only, as seen by the PoD filtering engine)."""

    def __init__(self, own_domains: List[str]):
        self.own = [d.lower() for d in own_domains]
        self.c: Counter = Counter()
        self.disposition: Counter = Counter()
        self.auth_fail_senders: Counter = Counter()
        self.no_tls_senders: Counter = Counter()
        self.spoofed: Counter = Counter()
        self.no_rewrite: Counter = Counter()
        self.quarantine: Counter = Counter()

    def add(self, e: dict) -> None:
        f = e.get("filter") or {}
        if str(f.get("routeDirection") or "").lower() != "inbound":
            self.c["other_direction"] += 1
            return
        self.c["inbound"] += 1
        disp = str(f.get("disposition") or "").lower()
        self.disposition[disp or "?"] += 1
        delivered = disp in ("accept", "continue") and bool((f.get("delivered") or {}).get("rcpts") or not f.get("delivered"))
        if (f.get("quarantine") or {}).get("folder"):
            self.quarantine[str(f["quarantine"]["folder"])] += 1
        mods = f.get("modules") or {}
        hdr = (e.get("msg") or {}).get("normalizedHeader") or (e.get("msg") or {}).get("header") or {}
        from_dom = _dom((hdr.get("from") or [""])[0] if isinstance(hdr.get("from"), list) else hdr.get("from"))
        sender_dom = from_dom or _dom((e.get("envelope") or {}).get("from"))
        # sender authentication (results of the PoD SPF and DMARC modules)
        spf = str((mods.get("spf") or {}).get("result") or "").lower()
        dmarc = str((mods.get("dmarc") or {}).get("filterdResult") or "").lower()
        if spf or dmarc:
            self.c["auth_evaluated"] += 1
        failed = dmarc in ("fail", "reject", "quarantine") or (not dmarc and spf in ("fail", "softfail"))
        if failed:
            self.c["auth_failed"] += 1
            if delivered:
                self.c["auth_failed_delivered"] += 1
                self.auth_fail_senders[sender_dom or "?"] += 1
        # messages that claim to come from our own domains but fail DMARC: spoofing attempts
        if from_dom and self.own and _under(from_dom, self.own) and dmarc in ("fail", "reject", "quarantine"):
            self.c["spoof"] += 1
            self.spoofed[from_dom] += 1
            if delivered:
                self.c["spoof_delivered"] += 1
        # transport: TLS of the inbound SMTP session
        tls = ((e.get("connection") or {}).get("tls") or {}).get("inbound") or {}
        if not _tls_ok(tls.get("version")):
            self.c["no_tls"] += 1
            self.no_tls_senders[_dom((e.get("envelope") or {}).get("from")) or str((e.get("connection") or {}).get("helo") or "?")] += 1
        # URL Defense counts of the message
        ud = ((mods.get("urldefense") or {}).get("counts")) or {}
        if ud:
            self.c["urls"] += int(ud.get("total") or 0)
            self.c["urls_rewritten"] += int(ud.get("rewritten") or 0)
            for k, v in ud.items():
                if k.startswith("noRewrite") and v:
                    self.no_rewrite[k[len("noRewrite"):]] += int(v)
        if (mods.get("sandbox") or {}).get("errorStatus"):
            self.c["sandbox_errors"] += 1
        if (mods.get("av") or {}).get("virusNames"):
            self.c["virus"] += 1

    def result(self) -> dict:
        return {"counts": dict(self.c), "dispositions": dict(self.disposition), "quarantine": dict(self.quarantine),
                "auth_fail_senders": self.auth_fail_senders.most_common(10), "no_tls_senders": self.no_tls_senders.most_common(10),
                "spoofed_domains": self.spoofed.most_common(10), "no_rewrite_reasons": dict(self.no_rewrite)}


class AuditStats:
    """Counters over the 'audit' stream: who administers the PoD console and what changed."""

    def __init__(self):
        self.logins: Dict[str, set] = {}
        self.changes: Counter = Counter()
        self.changes_by: Counter = Counter()
        self.api_keys: List[dict] = []
        self.c: Counter = Counter()

    def add(self, e: dict) -> None:
        a = e.get("audit") or {}
        user = (a.get("user") or {})
        who = str(user.get("email") or user.get("id") or "?").lower()
        action = str(a.get("action") or "").lower()
        tags = {t.get("name"): t.get("value") for t in a.get("tags") or [] if isinstance(t, dict)}
        sub = str(tags.get("eventSubCategory") or a.get("resourceType") or "")
        self.c["events"] += 1
        if action == "login":
            self.logins.setdefault(who, set()).add(str(user.get("ipAddress") or "?"))
        elif action in ("create", "edit", "update", "delete"):
            self.changes[f"{action} {sub}"] += 1
            self.changes_by[who] += 1
            if "apikey" in sub.lower().replace("_", ""):
                self.api_keys.append({"action": action, "by": who, "name": a.get("resourceName"), "time": e.get("ts")})

    def result(self) -> dict:
        return {"counts": dict(self.c), "admins": sorted(self.logins), "login_ips": {u: sorted(ips)[:10] for u, ips in self.logins.items()},
                "changes": self.changes.most_common(20), "changes_by": self.changes_by.most_common(10), "api_keys": self.api_keys[:20]}


def read_stream(ws: WebSocket, sink, max_events: int = MAX_EVENTS) -> Tuple[int, bool]:
    """Feed every event of the stream to `sink.add`; returns (events, truncated)."""
    n = 0
    try:
        for text in ws.messages():
            for line in text.splitlines() or [text]:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict):
                    sink.add(e)
                    n += 1
            if n >= max_events:
                return n, True
    except (socket.timeout, TimeoutError):
        pass   # no more data for the window
    finally:
        ws.close()
    return n, False


def collect(cluster: str, token: str, own_domains: List[str], log: Callable[[str], None], hours: int = WINDOW_HOURS,
            now: Optional[datetime] = None, max_events: int = MAX_EVENTS, connect: Optional[Callable[..., Any]] = None) -> dict:
    until = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    since = until - timedelta(hours=hours)
    out: Dict[str, Any] = {"window": {"start": since.isoformat(), "end": until.isoformat(), "hours": hours}, "errors": []}
    for kind, sink in (("message", MessageStats(own_domains)), ("audit", AuditStats())):
        t0 = time.monotonic()
        try:
            ws = open_stream(cluster, token, kind, since, until, connect=connect)
            n, truncated = read_stream(ws, sink, max_events)
            out[kind] = {**sink.result(), "events": n, "truncated": truncated}
            log(f"PoD {kind} stream: {n} event(s) in {hours}h ({time.monotonic() - t0:.0f}s)" + (" - truncated" if truncated else ""))
        except (PodError, OSError, ValueError) as e:
            out[kind] = None
            out["errors"].append({"where": f"{kind} stream", "error": str(e), "status": getattr(e, "status", None)})
            log(f"  ! PoD {kind} stream: {e}")
            if getattr(e, "status", None) in (401, 403):
                break   # same token for both streams
    return out


NO_REWRITE_LABELS = {"IsExcludedDomain": "Domain excluded from URL Defense", "IsEmail": "Address (mailto)",
                     "IsContentTypeText": "Plain-text part", "IsLargeMsgPartSize": "Message part too large",
                     "IsMaxLengthExceeded": "URL too long", "IsSchemeless": "URL without scheme",
                     "IsUnsupportedScheme": "Unsupported scheme"}
AUTH_FAIL_DELIVERED_SHARE = 1.0   # % of inbound messages: above this, failing authentication is not enforced
NO_TLS_SHARE = 5.0                # % of inbound messages received without TLS 1.2+


def _pct(a: int, b: int) -> Optional[float]:
    return round(100 * a / b, 1) if b else None


def findings(pod: Optional[dict]) -> Tuple[List[Issue], dict]:
    issues: List[Issue] = []
    if not pod:
        return issues, {}
    for e in pod.get("errors") or []:
        issues.append(make_issue("POD_API_ERROR", f"{e.get('where')}: {e.get('error')}"))
    data: Dict[str, Any] = {"window": pod.get("window")}
    m = pod.get("message")
    if m:
        c = m.get("counts") or {}
        inbound = c.get("inbound", 0)
        data["message"] = {
            "events": m.get("events"), "truncated": m.get("truncated"), "inbound": inbound,
            "auth_failed_delivered": c.get("auth_failed_delivered", 0), "auth_failed_delivered_pct": _pct(c.get("auth_failed_delivered", 0), inbound),
            "spoof": c.get("spoof", 0), "spoof_delivered": c.get("spoof_delivered", 0),
            "no_tls": c.get("no_tls", 0), "no_tls_pct": _pct(c.get("no_tls", 0), inbound),
            "tls_pct": _pct(inbound - c.get("no_tls", 0), inbound),
            "urls": c.get("urls", 0), "urls_rewritten": c.get("urls_rewritten", 0), "url_coverage": _pct(c.get("urls_rewritten", 0), c.get("urls", 0)),
            "sandbox_errors": c.get("sandbox_errors", 0), "virus": c.get("virus", 0),
            "dispositions": m.get("dispositions"), "quarantine": m.get("quarantine"),
            "auth_fail_senders": m.get("auth_fail_senders"), "no_tls_senders": m.get("no_tls_senders"),
            "spoofed_domains": m.get("spoofed_domains"),
            "no_rewrite_reasons": {NO_REWRITE_LABELS.get(k, k): v for k, v in (m.get("no_rewrite_reasons") or {}).items()}}
        d = data["message"]
        if inbound and (d["auth_failed_delivered_pct"] or 0) > AUTH_FAIL_DELIVERED_SHARE:
            issues.append(make_issue("POD_AUTH_FAIL_DELIVERED", f"{d['auth_failed_delivered']} of {inbound} inbound messages "
                                     f"({d['auth_failed_delivered_pct']}%) failed SPF/DMARC and were delivered; top senders: "
                                     + ", ".join(f"{s} ({n})" for s, n in (m.get("auth_fail_senders") or [])[:3])))
        if d["spoof_delivered"]:
            issues.append(make_issue("POD_SPOOF_DELIVERED", f"{d['spoof_delivered']} message(s) with your domain as sender failed "
                                     "DMARC and were delivered: " + ", ".join(f"{s} ({n})" for s, n in (m.get("spoofed_domains") or [])[:3])))
        elif d["spoof"]:
            issues.append(make_issue("POD_SPOOF_ATTEMPTS", f"{d['spoof']} message(s) with your domain as sender failed DMARC "
                                     "(not delivered)"))
        if inbound and (d["no_tls_pct"] or 0) > NO_TLS_SHARE:
            issues.append(make_issue("POD_INBOUND_NO_TLS", f"{d['no_tls_pct']}% of inbound messages without TLS 1.2+; top senders: "
                                     + ", ".join(f"{s} ({n})" for s, n in (m.get("no_tls_senders") or [])[:3])))
        excluded = (m.get("no_rewrite_reasons") or {}).get("IsExcludedDomain", 0)
        if excluded:
            issues.append(make_issue("POD_URL_EXCLUDED_DOMAINS", f"{excluded} URL(s) not rewritten because their domain is "
                                     "excluded from URL Defense"))
        if d["sandbox_errors"]:
            issues.append(make_issue("POD_SANDBOX_ERRORS", f"{d['sandbox_errors']} message(s) whose attachments could not be "
                                     "analyzed by Attachment Defense"))
        if m.get("truncated"):
            issues.append(make_issue("POD_SAMPLED", f"first {m.get('events')} events of the window"))
    a = pod.get("audit")
    if a:
        data["audit"] = a
        multi = {u: ips for u, ips in (a.get("login_ips") or {}).items() if len(ips) > 2}
        if multi:
            issues.append(make_issue("POD_ADMIN_MANY_IPS", ", ".join(f"{u} ({len(ips)} IPs)" for u, ips in list(multi.items())[:3])))
        created = [k for k in a.get("api_keys") or [] if k.get("action") == "create"]
        if created:
            issues.append(make_issue("POD_API_KEY_CREATED", ", ".join(f"{k.get('name')} by {k.get('by')}" for k in created[:3])))
        if a.get("changes"):
            issues.append(make_issue("POD_CONFIG_CHANGES", ", ".join(f"{k} ({n})" for k, n in (a.get("changes") or [])[:4])))
    return issues, data
