"""DNS client: shared cache, in-flight coalescing, retry, rate limit, CD for bogus zones; resolver preflight."""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ...common import RateLimiter
from ._deps import dns


@dataclass
class DNSAnswer:
    status: str  # ok, nodata, nxdomain, error
    records: list = field(default_factory=list)
    ad: bool = False
    canonical: Optional[str] = None  # CNAME target (also set on NXDOMAIN = dangling CNAME)
    error: Optional[str] = None


class DNSClient:
    """Thread-safe resolver wrapper.
    - answers are memoized for the run; concurrent identical queries are coalesced
    - errors are retried once and only cached for ERROR_TTL seconds, so a transient
      timeout on a shared include does not poison every other domain
    - zones marked bogus (broken DNSSEC) are queried with the CD bit"""

    ERROR_TTL = 60.0

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 5.0,
                 use_system: bool = False, qps: float = 0):
        self.timeout = timeout
        self.resolver = self._make_resolver(nameservers, use_system, timeout, cd=False)
        self.resolver_cd = self._make_resolver(nameservers, use_system, timeout, cd=True)
        self.nameservers = [str(n) for n in self.resolver.nameservers]
        self.validating: Optional[bool] = None  # set by preflight()
        self._memo: Dict[tuple, Tuple[DNSAnswer, float]] = {}
        self._inflight: Dict[tuple, threading.Event] = {}
        self._bogus: Set[str] = set()
        self._lock = threading.Lock()
        self._rate = RateLimiter(qps) if qps and qps > 0 else None
        self.stats = Counter()

    @staticmethod
    def _make_resolver(nameservers, use_system, timeout, cd):
        if use_system or not nameservers:
            r = dns.resolver.Resolver(configure=True)
        else:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = list(nameservers)
        # Total budget per query = timeout; each attempt gets half of it so a lost UDP
        # packet fails over to the next resolver.
        r.lifetime = timeout
        r.timeout = max(1.0, timeout / 2)
        # AD in the query (RFC 6840 §5.7) instead of DO: DNSSEC status without RRSIG bloat,
        # so answers stay small (no truncation, no TCP retries).
        r.flags = dns.flags.RD | (dns.flags.CD if cd else dns.flags.AD)
        r.use_edns(0, 0, 1232)
        return r

    def mark_bogus(self, zone: str) -> None:
        with self._lock:
            self._bogus.add(zone.lower().rstrip("."))
            # drop cached SERVFAILs for that zone so they are re-queried with CD
            for key in [k for k, (a, _) in self._memo.items() if a.status == "error" and self._in_zone(k[0], zone)]:
                del self._memo[key]

    @staticmethod
    def _in_zone(name: str, zone: str) -> bool:
        return name == zone or name.endswith("." + zone)

    def _cd_for(self, name: str) -> bool:
        return any(self._in_zone(name, z) for z in self._bogus)

    def query(self, name: str, rdtype: str, fresh: bool = False, cd: Optional[bool] = None) -> DNSAnswer:
        name = name.lower().rstrip(".")
        if cd is None:
            with self._lock:
                cd = self._cd_for(name)
        key = (name, rdtype, bool(cd))
        while True:
            with self._lock:
                if not fresh:
                    hit = self._memo.get(key)
                    if hit is not None:
                        ans, ts = hit
                        if ans.status != "error" or time.monotonic() - ts < self.ERROR_TTL:
                            self.stats["cache_hits"] += 1
                            return ans
                event = self._inflight.get(key)
                if event is None:
                    event = self._inflight[key] = threading.Event()
                    break
                self.stats["coalesced"] += 1
            event.wait()
            fresh = False
        ans = DNSAnswer("error", error="internal error")
        try:
            resolver = self.resolver_cd if cd else self.resolver
            ans = self._resolve(name, rdtype, resolver)
            if ans.status == "error":  # one immediate retry before giving up
                self.stats["retries"] += 1
                ans = self._resolve(name, rdtype, resolver)
        finally:
            with self._lock:
                self._memo[key] = (ans, time.monotonic())
                self.stats["queries"] += 1
                if ans.status == "error":
                    self.stats["errors"] += 1
                del self._inflight[key]
            event.set()
        return ans

    def _resolve(self, name: str, rdtype: str, resolver) -> DNSAnswer:
        if self._rate:
            self._rate.wait()
        try:
            a = resolver.resolve(name, rdtype, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN as e:
            canonical = None
            try:
                c = str(e.canonical_name).rstrip(".").lower()
                canonical = c if c != name else None
            except Exception:
                pass
            return DNSAnswer("nxdomain", canonical=canonical)
        except dns.resolver.NoNameservers:
            return DNSAnswer("error", error="SERVFAIL")
        except dns.exception.Timeout:
            return DNSAnswer("error", error="timeout")
        except dns.exception.DNSException as e:
            return DNSAnswer("error", error=type(e).__name__)
        except Exception as e:  # defensive: malformed names etc.
            return DNSAnswer("error", error=str(e) or type(e).__name__)

        ad = bool(a.response.flags & dns.flags.AD)
        canonical = str(a.canonical_name).rstrip(".").lower()
        canonical = canonical if canonical != name else None
        if a.rrset is None:
            return DNSAnswer("nodata", ad=ad, canonical=canonical)
        records: list = []
        for r in a.rrset:
            if rdtype == "TXT":
                records.append(b"".join(r.strings).decode("utf-8", errors="replace"))
            elif rdtype == "MX":
                records.append((int(r.preference), str(r.exchange).rstrip(".").lower()))
            elif rdtype in ("NS", "CNAME", "PTR"):
                records.append(str(r.target).rstrip(".").lower())
            else:
                records.append(r.to_text())
        return DNSAnswer("ok", records, ad, canonical)

    def has_address(self, host: str) -> Optional[bool]:
        """True if A or AAAA exists, False if neither, None on DNS error."""
        a = self.query(host, "A")
        if a.status == "ok":
            return True
        aaaa = self.query(host, "AAAA")
        if aaaa.status == "ok":
            return True
        if "error" in (a.status, aaaa.status):
            return None
        return False

    def addresses(self, host: str) -> List[str]:
        out: List[str] = []
        for rdtype in ("A", "AAAA"):
            ans = self.query(host, rdtype)
            if ans.status == "ok":
                out.extend(ans.records)
        return out

    def ptr(self, ip: str) -> Optional[str]:
        try:
            rev = dns.reversename.from_address(ip).to_text()
        except Exception:
            return None
        ans = self.query(rev, "PTR")
        return ans.records[0] if ans.status == "ok" and ans.records else None

    def axfr(self, server: str, zone: str) -> Tuple[str, int]:
        """Ask `server` (an IP address) for a full zone transfer of `zone`.

        Returns ("open", records in the first message), ("refused", 0) or ("unreachable", 0). Only the first
        message is read: enough to prove the zone is exposed, without downloading or storing it.
        """
        if self._rate:
            self._rate.wait()
        try:
            for msg in dns.query.xfr(server, zone, timeout=self.timeout, lifetime=self.timeout * 2):
                n = sum(len(rrset) for rrset in msg.answer)
                return ("open", n) if n else ("refused", 0)
            return "refused", 0
        except (OSError, EOFError, dns.exception.Timeout):
            return "unreachable", 0
        except Exception:  # TransferError (REFUSED / NOTAUTH), FormError, malformed answers
            return "refused", 0

    def query_server(self, name: str, rdtype: str, server: str, recursion: bool = True) -> Tuple[str, List[str]]:
        """Uncached query sent to one server (consistency checks)."""
        q = dns.message.make_query(name, rdtype)
        if not recursion:
            q.flags &= ~dns.flags.RD
        if self._rate:
            self._rate.wait()
        try:
            r = dns.query.udp(q, server, timeout=self.timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(q, server, timeout=self.timeout)
        except Exception as e:
            return "error", [type(e).__name__]
        rcode = r.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return "nxdomain", []
        if rcode != dns.rcode.NOERROR:
            return "error", [dns.rcode.to_text(rcode)]
        want = dns.rdatatype.from_text(rdtype)
        values = set()
        for rrset in r.answer:
            if rrset.rdtype != want:
                continue
            for rd in rrset:
                if rdtype == "TXT":
                    values.add(b"".join(rd.strings).decode("utf-8", errors="replace"))
                elif rdtype == "MX":
                    values.add(f"{rd.preference} {str(rd.exchange).rstrip('.').lower()}")
                elif rdtype == "NS":
                    values.add(str(rd.target).rstrip(".").lower())
                else:
                    values.add(rd.to_text())
        return ("ok" if values else "nodata"), sorted(values)


def preflight(client: DNSClient) -> Tuple[bool, str]:
    """Check that the resolver answers and whether it validates DNSSEC (AD on the root zone)."""
    try:
        a = client.resolver.resolve(dns.name.root, "SOA", raise_on_no_answer=False)
    except Exception as e:
        return False, (f"the resolver(s) {', '.join(client.nameservers)} do not answer "
                       f"({type(e).__name__}). Outbound DNS may be blocked: try --system-resolver "
                       f"or --nameservers <internal resolver>")
    if a.rrset is None:
        return False, "the resolver returned an empty answer for the root zone"
    client.validating = bool(a.response.flags & dns.flags.AD)
    if not client.validating:
        return True, ("WARNING: the resolver does not validate DNSSEC - DNSSEC results will be 'unknown'. "
                      "Use a validating resolver (e.g. 1.1.1.1, 8.8.8.8, 9.9.9.9) for DNSSEC checks.")
    return True, "Resolver OK (DNSSEC-validating)"
