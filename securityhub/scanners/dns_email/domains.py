"""Domain names: Public Suffix List (organizational domain), IDNA, normalization, tiers."""

from __future__ import annotations

import importlib.util
import os
import time
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

from ._deps import _idna
from .constants import DOMAIN_RE, TIER_WEIGHTS
from .util import cache_dir, http_get

PSL_URLS = [
    "https://publicsuffix.org/list/public_suffix_list.dat",
    "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",
]


class PublicSuffixList:
    def __init__(self, text: str, source: str = ""):
        self.rules: Set[str] = set()
        self.wildcards: Set[str] = set()
        self.exceptions: Set[str] = set()
        self.source = source
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            try:
                if rule.startswith("!"):
                    self.exceptions.add(to_ascii(rule[1:]))
                elif rule.startswith("*."):
                    self.wildcards.add(to_ascii(rule[2:]))
                else:
                    self.rules.add(to_ascii(rule))
            except UnicodeError:
                continue
        if len(self.rules) < 1000:
            raise ValueError("public suffix list looks truncated")

    def registrable(self, domain: str) -> Optional[str]:
        """eTLD+1 (e.g. comune.milano.it -> comune.milano.it, a.b.example.co.uk -> example.co.uk)."""
        labels = domain.lower().rstrip(".").split(".")
        suffix_len = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exceptions:
                suffix_len = len(labels) - i - 1
                break
            if cand in self.rules or (i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wildcards):
                suffix_len = len(labels) - i
                break
        if suffix_len >= len(labels):
            return None  # the name itself is a public suffix
        return ".".join(labels[-(suffix_len + 1):])

    @classmethod
    def load(cls, path: Optional[str] = None, allow_download: bool = True, timeout: float = 10.0,
             max_age_days: int = 7) -> Tuple[Optional["PublicSuffixList"], str]:
        if path:
            with open(path, encoding="utf-8") as f:
                return cls(f.read(), path), f"Public Suffix List: {path}"
        cached = os.path.join(cache_dir(), "public_suffix_list.dat")
        fresh = os.path.exists(cached) and time.time() - os.path.getmtime(cached) < max_age_days * 86400
        if fresh:
            try:
                with open(cached, encoding="utf-8") as f:
                    return cls(f.read(), cached), "Public Suffix List: cached"
            except (OSError, ValueError):
                pass
        if allow_download:
            for url in PSL_URLS:
                try:
                    status, body = http_get(url, timeout)
                    if status == 200:
                        psl = cls(body.decode("utf-8"), url)
                        try:
                            with open(cached, "wb") as f:
                                f.write(body)
                        except OSError:
                            pass
                        return psl, "Public Suffix List: downloaded"
                except Exception:
                    continue
        if os.path.exists(cached):
            try:
                with open(cached, encoding="utf-8") as f:
                    return cls(f.read(), cached), "Public Suffix List: stale cache"
            except (OSError, ValueError):
                pass
        if importlib.util.find_spec("tldextract") is not None:  # tldextract ships an offline snapshot
            return None, "Public Suffix List: tldextract snapshot"
        else:
            return None, ("WARNING: Public Suffix List unavailable - organizational domains are guessed "
                          "(use --psl-file or install tldextract)")


_PSL: Optional[PublicSuffixList] = None
_TLD_EXTRACT = None
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar", "com.tr", "co.za",
    "com.cn", "com.hk", "com.sg", "co.in", "co.il", "com.tw", "co.kr", "gov.it",
}


def set_psl(psl: Optional[PublicSuffixList]) -> None:
    global _PSL, _TLD_EXTRACT
    _PSL = psl
    if psl is None and _TLD_EXTRACT is None:
        try:
            import tldextract
            _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            _TLD_EXTRACT = None


def org_domain(domain: str) -> str:
    """Organizational (registrable) domain via the Public Suffix List."""
    domain = domain.lower().rstrip(".")
    if _PSL is not None:
        return _PSL.registrable(domain) or domain
    if _TLD_EXTRACT is not None:
        try:
            ext = _TLD_EXTRACT(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def to_ascii(host: str) -> str:
    """IDNA 2008 / UTS-46 (non-transitional): 'straße.de' stays 'xn--strae-oqa.de'."""
    host = host.strip().rstrip(".").lower()
    if host.isascii():
        return host
    if _idna is not None:
        return _idna.encode(host, uts46=True, transitional=False).decode("ascii")
    if any(ch in host for ch in "ßς\u200c\u200d"):
        raise UnicodeError("this name needs IDNA 2008 - pip install idna")
    return host.encode("idna").decode("ascii")


def normalize_domain(raw: str) -> Optional[str]:
    """Accepts domains, URLs, e-mail addresses; returns an ASCII (IDNA) lowercase domain or None."""
    s = raw.split("#", 1)[0].strip().strip(",;\"'")
    if not s:
        return None
    if "://" in s:
        s = urlparse(s).hostname or ""
    s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = s.strip().rstrip(".").lower()
    if s.startswith("*."):
        s = s[2:]
    try:
        s = to_ascii(s)
    except (UnicodeError, ValueError, Exception):
        return None
    return s if DOMAIN_RE.fullmatch(s) else None


def tier_weight(tier: str) -> int:
    return TIER_WEIGHTS.get(tier, 2)
