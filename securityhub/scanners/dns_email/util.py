"""Small helpers: DNS tag parsing, DKIM key size, provider matching, cache and HTTP download."""

from __future__ import annotations

import base64
import binascii
import os
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from .constants import PROTECTED_MX_PROVIDERS, USER_AGENT, _MX_SUFFIXES
from .models import Issue, make_issue


def parse_tags(record: str) -> Dict[str, str]:
    """Parse 'k=v; k2=v2' tag lists (DKIM, DMARC, MTA-STS, TLS-RPT, BIMI). First occurrence wins."""
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        if k and k not in tags:
            tags[k] = v.strip()
    return tags


def _der_header(buf: bytes, i: int) -> Tuple[int, int, int]:
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, i, length


def rsa_key_bits(b64: str) -> Optional[int]:
    """Exact RSA modulus size from a DKIM p= value (SubjectPublicKeyInfo or PKCS#1)."""
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None

    def modulus_bits(buf: bytes) -> Optional[int]:
        tag, i, _ = _der_header(buf, 0)
        if tag != 0x30:
            return None
        tag2, j, ln2 = _der_header(buf, i)
        if tag2 == 0x30:  # SPKI: AlgorithmIdentifier, then BIT STRING
            tag3, k, ln3 = _der_header(buf, j + ln2)
            if tag3 != 0x03:
                return None
            return modulus_bits(buf[k + 1:k + ln3])  # skip "unused bits" byte
        if tag2 == 0x02:  # PKCS#1 RSAPublicKey: modulus INTEGER
            return int.from_bytes(buf[j:j + ln2], "big").bit_length()
        return None

    try:
        return modulus_bits(der)
    except (IndexError, ValueError):
        return None


def match_provider(host: str) -> Optional[str]:
    for suffix in _MX_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return PROTECTED_MX_PROVIDERS[suffix]
    return None


def issues_from_problems(problems: List[Tuple[str, str]], max_details: int = 3) -> List[Issue]:
    """Group (code, detail) tuples into one Issue per code."""
    grouped: Dict[str, List[str]] = {}
    for code, detail in problems:
        lst = grouped.setdefault(code, [])
        if detail and detail not in lst:
            lst.append(detail)
    out = []
    for code, details in grouped.items():
        txt = ", ".join(details[:max_details])
        if len(details) > max_details:
            txt += f" (+{len(details) - max_details} more)"
        out.append(make_issue(code, txt or None))
    return out


def cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    path = os.path.join(base, "mailguard")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = os.path.join(os.getcwd(), ".mailguard-cache")
        os.makedirs(path, exist_ok=True)
    return path


def http_get(url: str, timeout: float, accept: str = "*/*", max_bytes: int = 8 * 1024 * 1024) -> Tuple[int, bytes]:
    """Plain HTTPS GET for well-known public endpoints (PSL, IANA bootstrap, RDAP)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            return resp.status, resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        return e.code, b""
