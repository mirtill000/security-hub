"""Optional dependencies (dnspython, idna, defusedxml)."""

from __future__ import annotations

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
except ImportError:  # pragma: no cover
    raise ImportError("The DNS / e-mail module needs dnspython: pip install dnspython")

try:  # IDNA 2008 / UTS-46 (Python's built-in codec is IDNA 2003)
    import idna as _idna
except ImportError:  # pragma: no cover
    _idna = None

try:  # hardened XML parsing for DMARC reports
    from defusedxml import ElementTree as _SafeET
except ImportError:  # pragma: no cover
    _SafeET = None

__all__ = ['_SafeET', '_idna', 'dns']
