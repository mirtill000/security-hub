"""Optional dependencies (dnspython, idna, defusedxml)."""

from __future__ import annotations

try:  # optional: CNAME resolution for the DNS routing check
    import dns.resolver as _dns_resolver
except ImportError:  # pragma: no cover
    _dns_resolver = None

__all__ = ['_dns_resolver']
