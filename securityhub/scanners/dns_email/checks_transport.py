"""MailGuard DNS analyzer mixin: MTA-STS, TLS-RPT and BIMI: transport security and brand indicators."""

from __future__ import annotations

import http.client
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple

from .constants import USER_AGENT
from .fetch import _PinnedHTTPSConnection, is_public_ip
from .models import BIMIResult, DMARCResult, MTASTSResult, TLSRPTResult, make_issue
from .util import parse_tags


class TransportChecks:
    """MTA-STS, TLS-RPT and BIMI: transport security and brand indicators."""

    # ------------------------------------------------------------------
    # MTA-STS (RFC 8461), TLS-RPT (RFC 8460), BIMI
    # ------------------------------------------------------------------

    @staticmethod
    def _mx_matches(host: str, pattern: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return host.endswith(suffix) and "." not in host[: -len(suffix)]
        return host == pattern

    def _analyze_mta_sts(self, domain: str, mx_hosts: List[str], applicable: bool) -> MTASTSResult:
        result = MTASTSResult()
        ans = self.dns.query(f"_mta-sts.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=STSv1\s*(;|$)", r.strip())]
        if not recs:
            result.status = "missing" if applicable else "na"
            if applicable:
                result.issues.append(make_issue("MTASTS_MISSING"))
            return result

        result.txt_record = recs[0]
        result.policy_id = parse_tags(recs[0]).get("id")
        if len(recs) > 1:
            result.status = "error"
            result.policy_error = "multiple _mta-sts TXT records"
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", result.policy_error))
            return result
        if not self.http_checks:
            result.status = "partial"
            return result

        # The policy only changes together with its id (RFC 8461): a recent copy for the same id is reused.
        stored = self.cache.get("mta-sts", domain, self.discovery_max_age, result.policy_id or "") if self.cache else None
        if isinstance(stored, list) and len(stored) == 2:
            body, note = stored
        else:
            body, note = self._fetch_policy(f"mta-sts.{domain}", "/.well-known/mta-sts.txt")
            if body is not None and self.cache is not None:
                self.cache.put("mta-sts", domain, [body, note], result.policy_id or "")
        if body is None:
            result.status = "error"
            result.policy_error = note
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", note))
            return result

        policy: Dict[str, str] = {}
        for line in body.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "mx":
                    result.mx_patterns.append(v)
                else:
                    policy.setdefault(k, v)
        result.mode = policy.get("mode", "").lower() or None
        try:
            result.max_age = int(policy.get("max_age", ""))
        except ValueError:
            result.max_age = None

        errors = []
        if note:
            errors.append(note)
        if policy.get("version") != "STSv1":
            errors.append("missing 'version: STSv1'")
        if result.mode not in ("enforce", "testing", "none"):
            errors.append(f"invalid mode '{result.mode}'")
        if result.max_age is None:
            errors.append("missing/invalid max_age")
        if result.mode != "none" and not result.mx_patterns:
            errors.append("no mx: lines")
        if errors:
            result.policy_error = "; ".join(errors)
            result.issues.append(make_issue("MTASTS_POLICY_ERROR", result.policy_error))

        unmatched = [h for h in mx_hosts if not any(self._mx_matches(h, p) for p in result.mx_patterns)]
        if unmatched and result.mode in ("enforce", "testing"):
            sev = "critical" if result.mode == "enforce" else "warning"
            result.issues.append(make_issue("MTASTS_MX_MISMATCH", ", ".join(unmatched), severity=sev))

        if result.mode == "enforce" and not errors and not unmatched:
            result.status = "valid"
        elif result.mode == "testing":
            result.status = "warning"
            result.issues.append(make_issue("MTASTS_TESTING"))
        elif result.mode == "none":
            result.status = "warning"
            result.issues.append(make_issue("MTASTS_NONE"))
        else:
            result.status = "error" if (errors or unmatched) else "warning"
        return result

    def _analyze_tls_rpt(self, domain: str, applicable: bool) -> TLSRPTResult:
        result = TLSRPTResult()
        ans = self.dns.query(f"_smtp._tls.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=TLSRPTv1\s*(;|$)", r.strip())]
        if not recs:
            result.status = "missing" if applicable else "na"
            if applicable:
                result.issues.append(make_issue("TLSRPT_MISSING"))
            return result
        result.record = recs[0]
        result.rua = parse_tags(recs[0]).get("rua")
        uris = [u.strip().lower() for u in (result.rua or "").split(",") if u.strip()]
        if len(recs) > 1 or not uris or not all(u.startswith(("mailto:", "https:")) for u in uris):
            result.status = "error"
            result.issues.append(make_issue("TLSRPT_INVALID", "multiple records" if len(recs) > 1 else result.rua))
        else:
            result.status = "valid"
        return result

    def _analyze_bimi(self, domain: str, dmarc: DMARCResult) -> BIMIResult:
        result = BIMIResult()
        ans = self.dns.query(f"default._bimi.{domain}", "TXT")
        if ans.status == "error":
            result.status = "dns_error"
            return result
        recs = [r.strip() for r in ans.records if re.match(r"^v=BIMI1\s*(;|$)", r.strip(), re.I)]
        if not recs:
            return result
        tags = parse_tags(recs[0])
        result.record = recs[0]
        result.logo_url = tags.get("l") or None
        result.vmc_url = tags.get("a") or None
        enforcing = (dmarc.policy in ("quarantine", "reject") and dmarc.pct == 100
                     and dmarc.subdomain_policy != "none")
        if enforcing:
            result.status = "valid"
        else:
            result.status = "warning"
            result.issues.append(make_issue("BIMI_NO_ENFORCEMENT"))
        return result


    # ------------------------------------------------------------------
    # SSRF-safe policy fetch (MTA-STS)
    # ------------------------------------------------------------------

    def _fetch_policy(self, host: str, path: str) -> Tuple[Optional[str], Optional[str]]:
        """GET https://host/path with redirects refused (RFC 8461 §3.3), the target IP validated
        as public (no requests into internal networks) and pinned for the connection."""
        ips = self.dns.addresses(host)
        if not ips:
            return None, f"{host} does not resolve"
        if not self.allow_private:
            blocked = [ip for ip in ips if not is_public_ip(ip)]
            if blocked:
                return None, (f"{host} resolves to non-public address {blocked[0]} - fetch blocked "
                              f"(SSRF protection, see --allow-private)")
        ip = next((i for i in ips if ":" not in i), ips[0])
        conn = _PinnedHTTPSConnection(host, ip, self.timeout, self._ssl_ctx)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "text/plain"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                return None, f"redirect not allowed (HTTP {resp.status})"
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            body = resp.read(65537)
            if len(body) > 65536:
                return None, "policy larger than 64 KB"
            ctype = (resp.getheader("Content-Type") or "").lower()
            note = None if ctype.startswith("text/plain") else f"Content-Type '{ctype or 'missing'}' (expected text/plain)"
            return body.decode("utf-8", errors="replace"), note
        except ssl.SSLCertVerificationError as e:
            return None, f"invalid TLS certificate ({e.verify_message})"
        except (socket.timeout, TimeoutError):
            return None, "timeout"
        except (OSError, http.client.HTTPException) as e:
            return None, f"{type(e).__name__}: {e}"
        finally:
            conn.close()
