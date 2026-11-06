"""Per-domain checks: routing (DNS) and exposure (TAP: delivered threats, permitted clicks, URL Defense, people)."""

from __future__ import annotations

from collections import Counter
from typing import List, Optional

from .constants import CHECKS, MALICIOUS, SAFE_ROUTE_WORDS
from .models import CheckResult, Issue, make_issue


def _finish(c: CheckResult, weight_key: str) -> CheckResult:
    """valid = full points, warning = half, error = none (unknown / na are not scored)."""
    c.max = CHECKS[weight_key]
    sev = {i.severity for i in c.issues}
    if c.status in ("unknown", "na", "skipped"):
        return c
    c.status = "error" if "critical" in sev else "warning" if "warning" in sev else "valid"
    c.got = {"valid": 1.0, "warning": 0.5, "error": 0.0}[c.status] * c.max
    return c


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def check_routing(dns: Optional[dict]) -> CheckResult:
    c = CheckResult(status="valid")
    if not dns:
        c.status = "unknown"
        return _finish(c, "routing")
    mx = dns.get("mx") or []
    c.data = {"mx": mx, "mx_status": dns.get("mx_status")}
    if dns.get("mx_status") == "error":
        c.status = "unknown"
        c.issues.append(make_issue("MX_DNS_ERROR", dns.get("mx_error") or ""))
        return _finish(c, "routing")
    if not mx:
        c.status = "na"
        return _finish(c, "routing")
    # Which MX hosts are Proofpoint is shown, but not reported: domains whose mail does not (only) go through
    # Proofpoint can be legitimate (other gateway, parked or third-party mail) and are not findings.
    pp = [m for m in mx if m.get("proofpoint")]
    c.data["via_proofpoint"] = "all" if len(pp) == len(mx) else "some" if pp else "none"
    if not pp:
        c.status = "na"
    return _finish(c, "routing")


def check_direct(dns: Optional[dict]) -> CheckResult:
    c = CheckResult(status="valid")
    if not dns or dns.get("mx_status") == "error":
        c.status = "unknown"
        return _finish(c, "direct")
    mx = dns.get("mx") or []
    if not mx or not any(m.get("proofpoint") for m in mx):
        c.status = "na"  # nothing to bypass
        return _finish(c, "direct")
    m365 = dns.get("m365") or {}
    c.data = {"m365_host": m365.get("host"), "m365_resolves": m365.get("resolves"), "m365_verified": dns.get("m365_verified")}
    if m365.get("resolves"):
        c.issues.append(make_issue("DIRECT_DELIVERY", f"{m365['host']} resolves (Microsoft 365): make sure it rejects "
                                                     "mail that does not come from Proofpoint"))
    elif m365.get("resolves") is None and m365:
        c.status = "unknown"
    return _finish(c, "direct")


def check_spf(dns: Optional[dict]) -> CheckResult:
    c = CheckResult(status="valid")
    if not dns or dns.get("spf") is None:
        c.status = "unknown"
        return _finish(c, "spf")
    spf = dns.get("spf") or ""
    c.data = {"record": spf, "proofpoint": dns.get("spf_proofpoint")}
    if not spf:
        c.issues.append(make_issue("SPF_MISSING"))
    elif spf.split()[1:] in (["-all"], ["~all"]):
        c.status = "na"  # the domain sends no mail
    elif not dns.get("spf_proofpoint") and any(m.get("proofpoint") for m in dns.get("mx") or []):
        c.issues.append(make_issue("SPF_NO_PROOFPOINT"))
    return _finish(c, "spf")


def _malicious(m: dict) -> List[dict]:
    return [t for t in m.get("threats") or [] if t.get("classification") in MALICIOUS and t.get("status") not in ("cleared", "falsepositive")]


def check_threats(msgs: Optional[List[dict]], covered: bool) -> CheckResult:
    c = CheckResult(status="valid")
    if msgs is None:
        c.status = "unknown"
        return _finish(c, "threats")
    if not covered:
        c.status = "na"  # mail does not go through Proofpoint: TAP cannot see it
        return _finish(c, "threats")
    bad = [m for m in msgs if _malicious(m)]
    imp = [m for m in msgs if not _malicious(m) and any(t.get("classification") == "impostor" for t in m.get("threats") or [])]
    safe = [m for m in bad if any(w in str(r).lower() for r in m.get("policy_routes") or [] for w in SAFE_ROUTE_WORDS)]
    names = Counter(t.get("classification") for m in bad for t in _malicious(m))
    users = {r for m in bad for r in m.get("recipients") or []}
    c.data = {"delivered": len(msgs), "malicious": len(bad), "impostor": len(imp), "safelisted": len(safe),
              "recipients": len(users), "classifications": dict(names),
              "messages": [{"time": m.get("time"), "recipients": (m.get("recipients") or [])[:3], "from_domain": m.get("from_domain"),
                            "threats": [{"classification": t.get("classification"), "type": t.get("type"), "status": t.get("status"),
                                         "url": t.get("url"), "campaign": t.get("campaign")} for t in (m.get("threats") or [])[:3]],
                            "routes": (m.get("policy_routes") or [])[:4], "quarantine": m.get("quarantine")}
                           for m in sorted(bad + imp, key=lambda x: str(x.get("time")), reverse=True)[:25]]}
    if bad:
        c.issues.append(make_issue("THREAT_DELIVERED", f"{_plural(len(bad), 'message')} to {_plural(len(users), 'user')} ("
                                   + ", ".join(f"{k} {v}" for k, v in names.most_common()) + ")"))
    if safe:
        routes = sorted({str(r) for m in safe for r in m.get("policy_routes") or [] if any(w in str(r).lower() for w in SAFE_ROUTE_WORDS)})
        c.issues.append(make_issue("SAFELIST_DELIVERY", f"{_plural(len(safe), 'message')} via {', '.join(routes[:3])}"))
    if imp:
        c.issues.append(make_issue("IMPOSTOR_DELIVERED", _plural(len(imp), "message")))
    return _finish(c, "threats")


def check_clicks(clicks: Optional[List[dict]], covered: bool) -> CheckResult:
    c = CheckResult(status="valid")
    if clicks is None:
        c.status = "unknown"
        return _finish(c, "clicks")
    if not covered:
        c.status = "na"
        return _finish(c, "clicks")
    bad = [k for k in clicks if k.get("classification") in MALICIOUS and k.get("status") not in ("cleared", "falsepositive")]
    users = sorted({k.get("recipient") for k in bad if k.get("recipient")})
    c.data = {"permitted": len(clicks), "malicious": len(bad), "users": users[:50],
              "clicks": [{k2: k.get(k2) for k2 in ("recipient", "classification", "time", "threat_time", "url", "campaign")}
                         for k in sorted(bad, key=lambda x: str(x.get("time")), reverse=True)[:25]]}
    if bad:
        c.issues.append(make_issue("CLICK_PERMITTED", f"{_plural(len(bad), 'click')} by {_plural(len(users), 'user')}: "
                                   + ", ".join(users[:3]) + (" and others" if len(users) > 3 else "")))
    return _finish(c, "clicks")


def check_rewrite(msgs: Optional[List[dict]], covered: bool) -> CheckResult:
    c = CheckResult(status="valid")
    if msgs is None or not covered:
        c.status = "unknown" if msgs is None else "na"
        return _finish(c, "rewrite")
    url_msgs = [m for m in msgs if any(t.get("type") == "url" for t in m.get("threats") or [])]
    if not url_msgs:
        c.status = "na"  # no delivered message with URL threats: nothing to measure
        return _finish(c, "rewrite")
    partial = [m for m in url_msgs if m.get("rewritten") is False]
    c.data = {"url_messages": len(url_msgs), "not_rewritten": len(partial)}
    if partial:
        c.issues.append(make_issue("URL_NOT_REWRITTEN", f"{len(partial)} of {len(url_msgs)}"))
    return _finish(c, "rewrite")


def check_people(vap: Optional[List[dict]], clickers: Optional[List[dict]], covered: bool) -> CheckResult:
    c = CheckResult(status="valid")
    if vap is None:
        c.status = "unknown"
        return _finish(c, "people")
    if not covered and not vap:
        c.status = "na"
        return _finish(c, "people")
    vips = [p for p in vap if p.get("vip")]
    c.data = {"vap": [{k: p.get(k) for k in ("name", "emails", "department", "title", "vip", "attack_index", "families")} for p in vap[:20]],
              "vap_count": len(vap), "top_clickers": len(clickers or [])}
    if vap:
        c.issues.append(make_issue("VAP_PRESENT", f"{_plural(len(vap), 'user')}: " + ", ".join(
            (p.get("name") or (p.get("emails") or ["?"])[0]) for p in vap[:3]) + (" and others" if len(vap) > 3 else "")))
    if vips:
        c.issues.append(make_issue("VAP_VIP", ", ".join((p.get("name") or (p.get("emails") or ["?"])[0]) for p in vips[:3])))
    return _finish(c, "people")


__all__ = ["Issue", "check_clicks", "check_direct", "check_people", "check_rewrite", "check_routing", "check_spf", "check_threats"]
