"""MailGuard DNS analyzer mixin: MX, SPF, DKIM and DMARC: who may send mail for the domain and how it is authenticated."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .constants import DKIM_FIRST_ROUND, DKIM_PROVIDER_SELECTORS, DMARC_RE, SPF_MECHANISMS, SPF_RE, SPF_TERM_RE
from .domains import org_domain
from .models import DKIMResult, DKIMSelector, DMARCResult, MXRecord, MXResult, SPFResult, make_issue
from .util import issues_from_problems, match_provider, parse_tags, rsa_key_bits


@dataclass
class _SPFEval:
    lookups: int = 0
    voids: int = 0
    nodes: List[dict] = field(default_factory=list)
    problems: List[Tuple[str, str]] = field(default_factory=list)
    all_q: Optional[str] = None


class AuthChecks:
    """MX, SPF, DKIM and DMARC: who may send mail for the domain and how it is authenticated."""

    # ------------------------------------------------------------------
    # MX
    # ------------------------------------------------------------------

    def _analyze_mx(self, domain: str, resolve_hosts: bool = True) -> MXResult:
        result = MXResult()
        ans = self.dns.query(domain, "MX")

        if ans.status == "error":
            result.status = "dns_error"
            result.issues.append(make_issue("DNS_ERROR", f"MX ({ans.error})"))
            return result

        if ans.status != "ok" or not ans.records:
            has_addr = self.dns.has_address(domain)
            result.status = "missing"
            if has_addr:
                result.implicit = True
                result.issues.append(make_issue("MX_IMPLICIT"))
            elif has_addr is False:
                result.issues.append(make_issue("MX_MISSING"))
            else:
                result.status = "dns_error"
                result.issues.append(make_issue("DNS_ERROR", "A/AAAA lookup failed while checking implicit MX"))
            return result

        mx_list = sorted(ans.records)
        null_entries = [m for m in mx_list if m[1] in ("", ".")]
        if null_entries:
            if len(mx_list) == 1:
                result.status = "null"
                result.null_mx = True
                result.records.append(MXRecord(priority=mx_list[0][0], host=""))
                result.issues.append(make_issue("MX_NULL"))
                return result
            result.issues.append(make_issue("MX_NULL_MIXED"))
            mx_list = [m for m in mx_list if m[1] not in ("", ".")]

        providers: List[str] = []
        dangling: List[str] = []
        cnames: List[str] = []
        for prio, host in mx_list:
            provider = match_provider(host)
            rec = MXRecord(priority=prio, host=host, is_protected=provider is not None, provider=provider)
            if resolve_hosts:
                a = self.dns.query(host, "A")
                rec.is_cname = a.canonical is not None
                rec.resolves = True if a.status == "ok" else self.dns.has_address(host)
            if rec.resolves is False:
                dangling.append(host)
            if rec.is_cname:
                cnames.append(host)
            if provider:
                result.protected_count += 1
                if provider not in providers:
                    providers.append(provider)
            result.records.append(rec)

        result.total_count = len(result.records)
        result.providers = providers
        if dangling:
            result.issues.append(make_issue("MX_DANGLING", ", ".join(dangling)))
        if cnames:
            result.issues.append(make_issue("MX_CNAME", ", ".join(cnames)))

        if result.protected_count == result.total_count:
            result.status = "valid"
        elif result.protected_count > 0:
            result.status = "partial"
            result.issues.append(make_issue("MX_PARTIAL", f"{result.protected_count}/{result.total_count} protected"))
        else:
            result.status = "warning"
            result.issues.append(make_issue("MX_UNPROTECTED"))
        return result

    # ------------------------------------------------------------------
    # SPF (RFC 7208)
    # ------------------------------------------------------------------

    def _fetch_spf(self, domain: str) -> Tuple[str, List[str], Optional[str]]:
        ans = self.dns.query(domain, "TXT")
        if ans.status == "error":
            return "dns_error", [], ans.error
        if ans.status != "ok":
            return ans.status, [], None  # nxdomain / nodata -> void lookup
        recs = [r.strip() for r in ans.records if SPF_RE.match(r.strip())]
        return ("ok" if recs else "nospf"), recs, None

    def _spf_follow(self, target: str, stack: Tuple[str, ...]) -> _SPFEval:
        """Evaluate an include/redirect target. Returned nodes are relative (target at depth 0)."""
        target = target.lower().rstrip(".")
        if target in stack:
            return _SPFEval(problems=[("SPF_LOOP", " -> ".join(stack + (target,)))])
        if len(stack) > 10:
            return _SPFEval(problems=[("SPF_LOOP", f"nesting too deep at {target}")])
        with self._spf_lock:
            cached = self._spf_memo.get(target)
        if cached is not None:
            return cached

        ev = _SPFEval()
        status, recs, err = self._fetch_spf(target)
        node = {"domain": target, "depth": 0, "lookups": 0, "status": "ok"}
        if status == "dns_error":
            node["status"] = "dns error"
            ev.problems.append(("SPF_DNS_ERROR", f"{target} ({err})"))
        elif status in ("nxdomain", "nodata", "nospf"):
            node["status"] = "no SPF"
            if status in ("nxdomain", "nodata"):
                ev.voids += 1
            ev.problems.append(("SPF_INCLUDE_NO_SPF", target))
        else:
            if len(recs) > 1:
                ev.problems.append(("SPF_MULTIPLE", target))
            sub = self._spf_eval(target, recs[0], stack + (target,), top=False)
            ev.lookups, ev.voids, ev.all_q = sub.lookups, sub.voids, sub.all_q
            ev.problems.extend(sub.problems)
            node["lookups"] = sub.lookups
            ev.nodes = [{**n, "depth": n["depth"] + 1} for n in sub.nodes]
        ev.nodes.insert(0, node)

        if not any(code in ("SPF_LOOP", "SPF_DNS_ERROR") for code, _ in ev.problems):
            with self._spf_lock:
                self._spf_memo[target] = ev
        return ev

    def _spf_eval(self, domain: str, record: str, stack: Tuple[str, ...], top: bool = True) -> _SPFEval:
        ev = _SPFEval()
        seen_all = False
        redirect: Optional[str] = None

        def merge(sub: _SPFEval):
            ev.lookups += sub.lookups
            ev.voids += sub.voids
            ev.nodes.extend(sub.nodes)
            ev.problems.extend(sub.problems)

        for term in record.split()[1:]:
            m = SPF_TERM_RE.fullmatch(term)
            if not m:
                ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                continue
            qual, name, sep, val = m.group(1), m.group(2).lower(), m.group(3), m.group(4) or ""

            if sep == "=":  # modifier
                if qual:
                    ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                elif name == "redirect":
                    redirect = val
                continue  # exp= and unknown modifiers are ignored (RFC 7208 §6)
            if name not in SPF_MECHANISMS:
                ev.problems.append(("SPF_SYNTAX", f"unknown mechanism '{term}' in {domain}"))
                continue
            if seen_all:
                continue  # evaluation never goes past 'all'

            if name == "all":
                if sep:
                    ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                ev.all_q = qual or "+"
                seen_all = True
                continue

            if name in ("ip4", "ip6"):
                try:
                    if sep != ":":
                        raise ValueError
                    net = ipaddress.ip_network(val, strict=False)
                    if (net.version == 4) != (name == "ip4"):
                        raise ValueError
                    if top and qual in ("", "+") and (
                            (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32)):
                        ev.problems.append(("SPF_BROAD_IP", f"{name}:{val}"))
                except ValueError:
                    ev.problems.append(("SPF_SYNTAX", f"invalid '{term}' in {domain}"))
                continue

            # DNS-querying mechanisms: include, a, mx, ptr, exists
            ev.lookups += 1
            if sep == ":":
                target = val.split("/", 1)[0]
            else:
                target = domain
            if name in ("include", "exists") and (sep != ":" or not target):
                ev.problems.append(("SPF_SYNTAX", f"'{term}' in {domain}"))
                continue
            if "%" in target:
                ev.problems.append(("SPF_MACROS", term))
                continue

            if name == "ptr":
                ev.problems.append(("SPF_PTR", domain))
            elif name == "include":
                merge(self._spf_follow(target, stack))
            elif name == "a":
                if self.dns.has_address(target) is False:
                    ev.voids += 1
                    ev.problems.append(("SPF_VOID", f"a:{target}"))
            elif name == "mx":
                mx = self.dns.query(target, "MX")
                if mx.status in ("nxdomain", "nodata"):
                    ev.voids += 1
                    ev.problems.append(("SPF_VOID", f"mx:{target}"))
                elif mx.status == "ok" and len(mx.records) > 10:
                    ev.problems.append(("SPF_MX_TOO_MANY", target))

        if redirect and not seen_all:
            ev.lookups += 1
            if "%" in redirect:
                ev.problems.append(("SPF_MACROS", f"redirect={redirect}"))
            else:
                sub = self._spf_follow(redirect, stack)
                merge(sub)
                ev.all_q = sub.all_q
        return ev

    def _analyze_spf(self, domain: str, mail_enabled: bool = True) -> SPFResult:
        result = SPFResult()
        status, recs, err = self._fetch_spf(domain)

        if status == "dns_error":
            result.status = "dns_error"
            result.issues.append(make_issue("SPF_DNS_ERROR", err))
            return result
        if status != "ok":
            if not mail_enabled:  # no MX: no SPF is not a finding
                result.status = "na"
                return result
            result.status = "missing"
            result.issues.append(make_issue("SPF_MISSING"))
            return result

        problems: List[Tuple[str, str]] = []
        if len(recs) > 1:
            problems.append(("SPF_MULTIPLE", f"{len(recs)} records"))

        record = recs[0]
        result.record = record
        result.records = recs
        ev = self._spf_eval(domain, record, (domain,))
        problems.extend(ev.problems)
        result.lookups = ev.lookups
        result.void_lookups = ev.voids
        result.include_tree = ev.nodes
        result.includes = [n["domain"] for n in ev.nodes if n["depth"] == 0]
        result.mechanism = {"-": "-all", "~": "~all", "?": "?all", "+": "+all"}.get(ev.all_q or "")

        if result.lookups > 10:
            problems.append(("SPF_LOOKUP_LIMIT", f"{result.lookups}/10"))
        elif result.lookups >= 8:
            problems.append(("SPF_LOOKUP_NEAR", f"{result.lookups}/10"))
        if result.void_lookups > 2:
            problems.append(("SPF_VOID_LIMIT", f"{result.void_lookups}/2"))

        if result.mechanism == "+all":
            problems.append(("SPF_PASS_ALL", ""))
        elif result.mechanism == "?all":
            problems.append(("SPF_NEUTRAL", ""))
        elif result.mechanism == "~all":
            problems.append(("SPF_SOFTFAIL", ""))
        elif result.mechanism is None:
            problems.append(("SPF_NO_ALL", ""))

        result.issues = issues_from_problems(problems)
        codes = {c for c, _ in problems}
        permerror_codes = {"SPF_MULTIPLE", "SPF_SYNTAX", "SPF_LOOKUP_LIMIT", "SPF_VOID_LIMIT",
                           "SPF_INCLUDE_NO_SPF", "SPF_LOOP", "SPF_MX_TOO_MANY"}
        result.permerror = bool(codes & permerror_codes)

        if result.permerror or result.mechanism in ("+all", "?all"):
            result.status = "error"
        elif codes & {"SPF_LOOKUP_NEAR", "SPF_SOFTFAIL", "SPF_NO_ALL", "SPF_PTR", "SPF_BROAD_IP",
                      "SPF_VOID", "SPF_DNS_ERROR"}:
            result.status = "warning"
        else:
            result.status = "valid"
        return result

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    def _probe_selector(self, domain: str, selector: str) -> Tuple[Optional[DKIMSelector], bool, Optional[dict]]:
        name = f"{selector}._domainkey.{domain}"
        ans = self.dns.query(name, "TXT")
        if ans.status == "error":
            return None, True, None
        if ans.status == "nxdomain" and ans.canonical:
            return None, False, {"name": name, "target": ans.canonical}
        if ans.status != "ok":
            return None, False, None
        for txt in ans.records:
            tags = parse_tags(txt)
            if "p" not in tags:
                continue
            if "v" in tags and tags["v"] != "DKIM1":
                continue
            algo = tags.get("k", "rsa").lower()
            key = re.sub(r"\s+", "", tags["p"])
            sel = DKIMSelector(name=selector, algorithm=algo, cname=ans.canonical)
            if not key:
                sel.status = "revoked"
            elif algo == "ed25519":
                try:
                    raw = base64.b64decode(key + "=" * (-len(key) % 4), validate=True)
                    sel.key_size, sel.status = 256, ("valid" if len(raw) == 32 else "invalid")
                except (binascii.Error, ValueError):
                    sel.status = "invalid"
            elif algo == "rsa":
                bits = rsa_key_bits(key)
                sel.key_size = bits
                sel.status = "invalid" if bits is None else ("valid" if bits >= 2000 else "weak")
            else:
                sel.status = "invalid"
            sel.testing = "y" in [f.strip().lower() for f in tags.get("t", "").split(":")]
            if "h" in tags:
                sel.hash_algorithms = tags["h"].lower().replace(" ", "")
            return sel, False, None
        return None, False, None

    def _analyze_dkim(self, domain: str, mail_enabled: bool = True, providers: Sequence[str] = ()) -> DKIMResult:
        result = DKIMResult()
        declared = self.domain_selectors.get(domain, [])  # from dkim.csv

        if self.fast_dkim and not declared:
            # RFC 8020: NXDOMAIN on _domainkey means no selector can exist below it
            base = self.dns.query(f"_domainkey.{domain}", "TXT")
            if base.status == "nxdomain":
                result.status = "missing" if mail_enabled else "na"
                if mail_enabled:
                    result.issues.append(make_issue("DKIM_NOT_FOUND", "_domainkey does not exist"))
                return result

        # Selectors are probed in parallel on the shared pool. Circuit breaker: once
        # DKIM_MAX_ERRORS probes of this domain fail (zone not answering), the probes
        # still queued are skipped instead of each waiting for the full timeout.
        state = {"errors": 0, "skipped": 0}
        state_lock = threading.Lock()

        def probe(selector: str):
            with state_lock:
                if state["errors"] >= self.DKIM_MAX_ERRORS:
                    state["skipped"] += 1
                    return None, False, None
            return self._probe_selector(domain, selector)

        def run(batch: List[str]) -> None:
            for fut in [self._pool.submit(probe, s) for s in batch]:
                sel, err, dangling = fut.result()
                if err:
                    with state_lock:
                        state["errors"] += 1
                if sel:
                    if sel.name in declared:
                        sel.source = "declared"
                    elif sel.name in from_reports:
                        sel.source = "report"
                    result.selectors.append(sel)
                if dangling:
                    result.dangling.append(dangling)

        from_reports = self.report_selectors.get(domain, [])
        selectors = list(dict.fromkeys(declared + from_reports + self.selectors))
        # Selector search done recently (cache): only the selectors found then (or, when none was found, the
        # common ones) are probed again; the full search is redone when it is older than the cache period,
        # or at once if a known selector disappeared.
        known = None
        if self.cache is not None and not self.full_dkim:
            known = self.cache.get("dkim", domain, self.discovery_max_age, str(len(self.selectors)))
            known = known if isinstance(known, list) else None
        if known == [] and not from_reports and not self.extra_selectors and not declared:
            # nothing found by the recent full search: if _domainkey still does not exist (RFC 8020: NXDOMAIN
            # means nothing below it), no selector can have appeared - one query instead of a probing round
            base = self.dns.query(f"_domainkey.{domain}", "TXT")
            if base.status == "nxdomain":
                result.full_search = self.cache.stored_at("dkim", domain)
                result.probed = 1
                result.status = "missing" if mail_enabled else "na"
                if mail_enabled:
                    result.issues.append(make_issue("DKIM_NOT_FOUND", "_domainkey does not exist; full search of "
                                                    f"{len(self.selectors)} selectors on {str(result.full_search)[:10]}"))
                return result
        if self.full_dkim:
            first, rest = selectors, []
        else:
            hinted = [x for p in providers for k, v in DKIM_PROVIDER_SELECTORS.items() if k in p.lower() for x in v]
            common = hinted + DKIM_FIRST_ROUND
            first = list(dict.fromkeys(declared + from_reports + self.extra_selectors + (known if known else common)))
            first = [x for x in first if x in selectors]
            rest = [x for x in selectors if x not in first]
        run(first)
        found = any(x.status in ("valid", "weak") for x in result.selectors)
        reuse = known is not None and (found or not known) and state["errors"] == 0
        if reuse:  # same answer as the recent full search: skip it
            result.full_search = self.cache.stored_at("dkim", domain)
            rest = []
        # Parked domains (no mail) need no DKIM: the first round only looks for dangling selector CNAMEs.
        if rest and mail_enabled and not found:
            if state["errors"] < self.DKIM_MAX_ERRORS:
                run(rest)
            else:  # the zone does not answer: the second round counts as skipped (status dns_error, not missing)
                state["skipped"] += len(rest)
        result.stopped_early = bool(rest) and (found or not mail_enabled)
        selectors = first + (rest if not result.stopped_early else [])
        if self.cache is not None and not reuse and not self.full_dkim and state["errors"] == 0:
            self.cache.put("dkim", domain, sorted({s.name for s in result.selectors}), str(len(self.selectors)))
        dns_errors = state["errors"]
        aborted = state["skipped"] > 0
        probed = len(selectors) - state["skipped"]
        result.probed = probed
        result.total_selectors = len(result.selectors)

        problems: List[Tuple[str, str]] = []
        strong = weak = 0
        for s in result.selectors:
            label = f"{s.name} ({s.key_size} bit)" if s.key_size else s.name
            if s.status == "valid":
                strong += 1
            elif s.status == "weak":
                weak += 1
                problems.append(("DKIM_BROKEN_KEY" if (s.key_size or 0) < 1000 else "DKIM_WEAK", label))
            elif s.status == "invalid":
                problems.append(("DKIM_INVALID", s.name))
            elif s.status == "revoked":
                problems.append(("DKIM_REVOKED", s.name))
            if s.testing:
                problems.append(("DKIM_TESTING", s.name))
            if s.hash_algorithms and "sha256" not in s.hash_algorithms:
                problems.append(("DKIM_SHA1", s.name))
        result.valid_selectors = strong + weak
        result.weak_keys = weak
        if declared and dns_errors == 0:
            found_names = {s.name for s in result.selectors}
            for name in declared:
                if name not in found_names:
                    problems.append(("DKIM_DECLARED_MISSING", name))
        result.declared = list(declared)
        result.issues = issues_from_problems(problems)

        if result.valid_selectors == 0:
            if aborted or dns_errors > probed // 2:
                result.status = "dns_error"
                detail = f"{dns_errors}/{probed} probes failed" + (", probing aborted" if aborted else "")
                result.issues.append(make_issue("DKIM_DNS_ERROR", detail))
            elif any(s.status == "invalid" for s in result.selectors):
                result.status = "error"
            elif not mail_enabled:
                result.status = "na"
            else:
                result.status = "missing"
                result.issues.append(make_issue("DKIM_NOT_FOUND", f"{len(selectors)} selectors probed" + (
                    f"; full search of {len(self.selectors)} selectors on {str(result.full_search)[:10]}"
                    if result.full_search else "")))
        elif weak or any(i.code == "DKIM_DECLARED_MISSING" for i in result.issues):
            result.status = "partial"
        else:
            result.status = "valid"
        return result

    # ------------------------------------------------------------------
    # DMARC (RFC 7489)
    # ------------------------------------------------------------------

    def _fetch_dmarc(self, name: str) -> Tuple[str, List[str], Optional[str]]:
        ans = self.dns.query(f"_dmarc.{name}", "TXT")
        if ans.status == "error":
            return "dns_error", [], ans.error
        if ans.status != "ok":
            return "missing", [], None
        recs = [r.strip() for r in ans.records if DMARC_RE.match(r.strip())]
        return ("ok" if recs else "missing"), recs, None

    @staticmethod
    def _same_org(a: str, b: str) -> bool:
        return a == b or a.endswith("." + b) or b.endswith("." + a) or org_domain(a) == org_domain(b)

    def _analyze_dmarc(self, domain: str) -> DMARCResult:
        result = DMARCResult()
        source = domain
        status, recs, err = self._fetch_dmarc(domain)

        if status == "missing":
            org = org_domain(domain)
            if org != domain:
                st2, recs2, err2 = self._fetch_dmarc(org)
                if st2 == "ok":
                    status, recs, source = st2, recs2, org
                    result.inherited_from = org
                elif st2 == "dns_error":
                    status, err = st2, err2

        if status == "dns_error":
            result.status = "dns_error"
            result.issues.append(make_issue("DMARC_DNS_ERROR", err))
            return result
        if status != "ok":
            result.status = "missing"
            result.issues.append(make_issue("DMARC_MISSING"))
            return result

        result.record = recs[0]
        if len(recs) > 1:
            result.status = "misconfigured"
            result.issues.append(make_issue("DMARC_MULTIPLE", f"{len(recs)} records"))
            return result
        if result.inherited_from:
            result.issues.append(make_issue("DMARC_INHERITED", result.inherited_from))

        tags = parse_tags(result.record)
        valid_policies = ("none", "quarantine", "reject")
        p = tags.get("p", "").lower()
        sp = tags.get("sp", "").lower() or None
        np_ = tags.get("np", "").lower() or None
        rua_raw = tags.get("rua")
        if p not in valid_policies:
            result.status = "misconfigured"
            result.issues.append(make_issue("DMARC_INVALID", f"p={p}" if p else "p= missing"))
            if not rua_raw:
                return result
            p = "none"  # RFC 7489 §6.6.3: with a valid rua, treat as p=none

        record_sp = sp if sp in valid_policies else p
        result.policy = record_sp if result.inherited_from else p
        result.subdomain_policy = record_sp
        result.nonexistent_policy = np_ if np_ in valid_policies else record_sp

        bad_tags = []
        pct_raw = tags.get("pct", "100").strip()
        if pct_raw.isdigit() and 0 <= int(pct_raw) <= 100:
            result.pct = int(pct_raw)
        else:
            result.pct = 100
            bad_tags.append(f"pct={pct_raw}")
        for key in ("aspf", "adkim"):
            val = tags.get(key, "r").strip().lower()
            if val not in ("r", "s"):
                bad_tags.append(f"{key}={val}")
        if bad_tags:
            result.issues.append(make_issue("DMARC_BAD_TAG", ", ".join(bad_tags)))
        result.aspf = "strict" if tags.get("aspf", "r").strip().lower() == "s" else "relaxed"
        result.adkim = "strict" if tags.get("adkim", "r").strip().lower() == "s" else "relaxed"
        result.rua = rua_raw
        result.ruf = tags.get("ruf")

        # Policy
        if result.status != "misconfigured":
            if result.policy == "reject":
                result.status = "valid" if result.pct == 100 else "warning"
            elif result.policy == "quarantine":
                result.status = "warning"
                result.issues.append(make_issue("DMARC_QUARANTINE"))
            else:
                result.status = "misconfigured"
                result.issues.append(make_issue("DMARC_NONE"))
        if result.policy in ("quarantine", "reject"):
            if result.pct < 100:
                result.issues.append(make_issue("DMARC_PCT", f"pct={result.pct}"))
            weaker = [f"{k}=none" for k, v in (("sp", sp), ("np", np_)) if v == "none"]
            if weaker and not result.inherited_from:
                result.issues.append(make_issue("DMARC_SP_NONE", ", ".join(weaker)))

        # Aggregate reporting
        if not rua_raw:
            result.issues.append(make_issue("DMARC_NO_RUA"))
        else:
            bad, unauthorized = [], []
            for uri in (u.strip() for u in rua_raw.split(",") if u.strip()):
                if not uri.lower().startswith("mailto:") or "@" not in uri:
                    bad.append(uri)
                    continue
                addr = uri[7:].split("!", 1)[0].strip()
                result.rua_destinations.append(addr)
                rdomain = addr.rsplit("@", 1)[1].lower().rstrip(".")
                if not self._same_org(source, rdomain):
                    auth = self.dns.query(f"{source}._report._dmarc.{rdomain}", "TXT")
                    if auth.status in ("ok", "nodata", "nxdomain") and not any(
                            DMARC_RE.match(r.strip()) for r in auth.records):
                        unauthorized.append(rdomain)
            if bad:
                result.issues.append(make_issue("DMARC_RUA_INVALID", ", ".join(bad)))
            if unauthorized:
                result.issues.append(make_issue("DMARC_RUA_UNAUTHORIZED", ", ".join(sorted(set(unauthorized)))))
            if not result.rua_destinations and not bad:
                result.issues.append(make_issue("DMARC_NO_RUA"))
        return result
