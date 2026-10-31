"""External probes (opt-in): DNS routing, HTTPS behaviour, legacy TLS, origin exposure."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ._deps import _dns_resolver
from .constants import IMPERVA_DNS_SUFFIXES, USER_AGENT


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _resolve(host: str) -> Tuple[List[str], List[str]]:
    """(cname chain, addresses)."""
    cnames: List[str] = []
    if _dns_resolver is not None:
        try:
            ans = _dns_resolver.resolve(host, "A", raise_on_no_answer=False)
            canon = str(ans.canonical_name).rstrip(".").lower()
            if canon != host.lower():
                cnames.append(canon)
        except Exception:
            pass
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        addrs = []
    return cnames, addrs


def _http_head(host: str, ip: Optional[str], port: int, use_tls: bool, timeout: float, verify: bool) -> dict:
    """Minimal HTTP/1.1 request; returns status, headers and certificate info."""
    out: Dict[str, Any] = {"ok": False}
    target = ip or host
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
    except OSError as e:
        out["error"] = f"connect: {e.strerror or e}"
        return out
    try:
        if use_tls:
            ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            cert = sock.getpeercert() if verify else None
            if cert and cert.get("notAfter"):
                exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                out["cert_days"] = (exp - datetime.now(timezone.utc)).days
            out["tls_version"] = sock.version()
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace").split("\r\n")
        m = re.match(r"HTTP/\d\.\d (\d{3})", head[0] if head else "")
        out["status"] = int(m.group(1)) if m else None
        out["headers"] = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:]) if k}
        out["ok"] = out["status"] is not None
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"certificate: {e.verify_message}"
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _accepts_tls(host: str, version: ssl.TLSVersion, timeout: float) -> Optional[bool]:
    ctx = ssl._create_unverified_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None  # local OpenSSL cannot test this version
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return None


def probe_site(site: dict, timeout: float = 6.0) -> dict:
    """Read-only checks from the Internet. Origin probes only send one GET / per origin address."""
    host = str(site.get("domain", "")).lower()
    res: Dict[str, Any] = {"host": host, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    cnames, addrs = _resolve(host)
    res["cnames"], res["addresses"] = cnames, addrs
    expected = set()
    for rec in site.get("dns") or []:
        for v in rec.get("set_data_to") or []:
            expected.add(str(v).lower().rstrip("."))
    res["expected"] = sorted(expected)
    routed = None
    if addrs:
        routed = any(c.endswith(IMPERVA_DNS_SUFFIXES) or c in expected for c in cnames) or \
                 any(a in expected for a in addrs)
        if not routed and not cnames and _dns_resolver is None and not expected & set(addrs):
            routed = None if not expected else False
    res["routed"] = routed
    if addrs:
        https = _http_head(host, None, 443, True, timeout, True)
        res["https"] = {k: v for k, v in https.items() if k != "headers"}
        hdrs = https.get("headers") or {}
        res["hsts"] = hdrs.get("strict-transport-security")
        res["imperva_edge"] = bool(hdrs.get("x-iinfo") or "imperva" in hdrs.get("x-cdn", "").lower())
        http = _http_head(host, None, 80, False, timeout, False)
        loc = (http.get("headers") or {}).get("location", "")
        res["http_status"] = http.get("status")
        res["redirects_https"] = bool(http.get("status") in (301, 302, 307, 308) and loc.lower().startswith("https://"))
        res["tls10"] = _accepts_tls(host, ssl.TLSVersion.TLSv1, timeout)
        res["tls11"] = _accepts_tls(host, ssl.TLSVersion.TLSv1_1, timeout)
    origins = []
    for origin in (site.get("ips") or [])[:6]:
        origin = str(origin).strip()
        ips = [origin] if re.fullmatch(r"[0-9a-fA-F:.]+", origin) else _resolve(origin)[1][:2]
        for ip in ips:
            if not _is_public(ip):
                origins.append({"origin": origin, "ip": ip, "result": "private"})
                continue
            entry = {"origin": origin, "ip": ip, "result": "closed"}
            for port, tls in ((443, True), (80, False)):
                r = _http_head(host, ip, port, tls, timeout, False)
                if r.get("ok"):
                    entry.update({"result": "serves" if (r["status"] or 0) < 400 else "reachable",
                                  "port": port, "status": r["status"]})
                    break
                if r.get("error", "").startswith("connect") is False and "error" in r:
                    entry.update({"result": "reachable", "port": port})
            origins.append(entry)
    res["origins"] = origins
    return res
