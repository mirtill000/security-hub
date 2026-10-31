"""Asset inventory: one view per organization domain across e-mail/DNS, WAF, certificates and tenant.

The reports are produced by independent tools; this module joins them on the domain name:

  - every domain assessed by the DNS module is an asset root (subdomains in the list are
    grouped under the shortest listed parent, e.g. mail.contoso.com under contoso.com);
  - every website protected by the WAF joins the longest listed domain it belongs to, or
    an asset of its own (registrable domain) when the DNS module does not cover it;
  - the Zero Trust tenant joins the asset of its primary domain.

For each asset the module derives cross-area *signals*: problems that only appear when the
areas are seen together (a website not protected by the WAF on a domain that can be spoofed
by e-mail, websites whose domain is not monitored, certificates and registrations expiring...).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .common import grade

TIER_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_RANK = {"critical": 0, "warning": 1, "info": 2}
# second-level labels that are part of the public suffix under a ccTLD (co.uk, com.au, gov.it...)
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go", "mil", "nic", "ltd", "plc", "sch"}
CERT_WARN_DAYS, CERT_CRIT_DAYS = 30, 7
REG_WARN_DAYS, REG_CRIT_DAYS = 60, 14
WAF_BYPASS_CODES = {"ORIGIN_EXPOSED", "DNS_NOT_ROUTED", "WAF_POLICY_DISABLED", "ALLOW_BROAD_IP", "WAF_NO_POLICY"}


# ---------------------------------------------------------------------------
# What was actually measured. A control that was not run, or whose query failed, is UNKNOWN:
# it must never be reported as an exposure (a resolver outage is not "every domain is spoofable").
# ---------------------------------------------------------------------------

UNMEASURED_DNS_PROFILES = {"nonexistent", "unreachable"}
UNKNOWN_STATUSES = {"dns_error", "skipped", "unknown", "error", None, ""}


def dns_measured(r: dict) -> bool:
    """The domain answered: its results describe its configuration."""
    return r.get("profile") not in UNMEASURED_DNS_PROFILES


def dmarc_state(r: dict) -> str:
    """'enforced', 'spoofable' or 'unknown' (not checked, DNS error, domain unreachable)."""
    d = r.get("dmarc") or {}
    if not dns_measured(r) or d.get("status") in UNKNOWN_STATUSES:
        return "unknown"
    enforced = d.get("policy") in ("quarantine", "reject") and int(d.get("pct") or 100) == 100
    return "enforced" if enforced else "spoofable"


def waf_measured(r: dict) -> bool:
    return r.get("profile") != "error"


def waf_protected(r: dict) -> Optional[bool]:
    """True / False when known; None when the WAF rules were not checked or could not be read."""
    if r.get("profile") == "bypass":
        return False
    codes = {i.get("code") for i in r.get("issues") or []}
    if codes & WAF_BYPASS_CODES:
        return False
    owasp = (r.get("compliance") or {}).get("owasp_block")
    if owasp == "pass":
        return True
    if owasp == "fail" and waf_measured(r):
        return False
    return None


def registrable(host: str) -> str:
    """Best-effort registrable domain without the Public Suffix List (used only for unmatched websites)."""
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _days_until(date: str, now: datetime) -> Optional[int]:
    try:
        d = datetime.fromisoformat(str(date)[:10]).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (d - now).days


def _tier(*tiers: str) -> str:
    best = max((t for t in tiers if t in TIER_RANK), key=lambda t: TIER_RANK[t], default="medium")
    return best


def _first(issues: List[dict]) -> str:
    i = next((x for x in issues or [] if x.get("severity") == "critical"), (issues or [None])[0])
    return (i or {}).get("message", "")


def _dns_item(r: dict, report: str) -> dict:
    dmarc = r.get("dmarc") or {}
    state = dmarc_state(r)
    measured = dns_measured(r)
    policy = (dmarc.get("policy") or "missing") if state != "unknown" else (
        "not checked" if dmarc.get("status") == "skipped" else "unknown")
    score = r.get("overall_score") if measured else None
    return {"domain": r.get("domain"), "score": score, "grade": grade(score), "measured": measured,
            "profile": r.get("profile"), "tier": r.get("tier", "medium"), "owner": r.get("owner", ""), "bu": r.get("bu", ""),
            "dmarc": policy, "dmarc_state": state, "enforced": state == "enforced", "spoofable": state == "spoofable",
            "caa": (r.get("caa") or {}).get("status"), "axfr": (r.get("axfr") or {}).get("status"),
            "axfr_open": [s.get("ns") for s in (r.get("axfr") or {}).get("servers") or [] if s.get("result") == "open"],
            "spf": (r.get("spf") or {}).get("status"), "mta_sts": (r.get("mta_sts") or {}).get("status"),
            "dnssec": (r.get("dnssec") or {}).get("status"), "takeover": (r.get("takeover") or {}).get("status"),
            "registration_expires": (r.get("takeover") or {}).get("domain_expires"),
            "critical": sum(i.get("severity") == "critical" for i in r.get("issues") or []),
            "main": _first(r.get("issues")), "report": report, "hash": "#/domains?d=" + str(r.get("domain"))}


def _waf_item(r: dict, report: str) -> dict:
    codes = {i.get("code") for i in r.get("issues") or []}
    tls = ((r.get("checks") or {}).get("tls") or {}).get("data") or {}
    score = r.get("overall_score") if waf_measured(r) else None
    return {"domain": str(r.get("domain") or ""), "site_id": r.get("site_id"), "score": score, "measured": waf_measured(r),
            "grade": grade(score), "profile": r.get("profile"), "tier": r.get("tier", "medium"),
            "owner": r.get("owner", ""), "bu": r.get("bu", ""), "protected": waf_protected(r),
            "origin_exposed": "ORIGIN_EXPOSED" in codes, "account": r.get("account_name") or r.get("account_id"),
            "cert": tls.get("certificate"), "cert_expires": tls.get("expires"), "cert_days": tls.get("days_left"),
            "served_cert_days": tls.get("served_cert_days"),
            "critical": sum(i.get("severity") == "critical" for i in r.get("issues") or []),
            "main": _first(r.get("issues")), "report": report, "hash": "#/domains?d=" + str(r.get("domain"))}


def _signal(sev: str, code: str, text: str, report: Optional[str] = None, hash_: str = "") -> dict:
    return {"severity": sev, "code": code, "text": text, "report": report, "hash": hash_}


def _signals(asset: dict, now: datetime) -> List[dict]:
    out: List[dict] = []
    dns, web = asset["dns"], asset["web"]
    spoofable = [d for d in dns if d["spoofable"]]
    unprotected = [w for w in web if w["protected"] is False]
    if spoofable and unprotected:
        w = unprotected[0]
        out.append(_signal("critical", "WEB_AND_MAIL_EXPOSED",
                           f"{w['domain']} is not effectively protected by the WAF and {spoofable[0]['domain']} "
                           f"can be impersonated by e-mail (DMARC {spoofable[0]['dmarc']})", w["report"], w["hash"]))
    for w in web:
        if w["profile"] == "bypass":
            out.append(_signal("critical", "WEB_BYPASS", f"{w['domain']}: WAF in bypass, traffic is not inspected", w["report"], w["hash"]))
        elif w["origin_exposed"]:
            out.append(_signal("critical", "WEB_ORIGIN_EXPOSED", f"{w['domain']}: origin reachable bypassing the WAF", w["report"], w["hash"]))
        elif w["protected"] is False:
            out.append(_signal("warning", "WEB_NOT_BLOCKING", f"{w['domain']}: WAF does not block the core attacks (OWASP)", w["report"], w["hash"]))
    for d in dns:
        if d["axfr_open"]:
            out.append(_signal("critical", "DNS_AXFR_OPEN", f"{d['domain']}: zone transfer allowed by {', '.join(d['axfr_open'])}",
                               d["report"], d["hash"]))
        if d["takeover"] == "error":
            out.append(_signal("critical", "DNS_TAKEOVER", f"{d['domain']}: a dependency can be taken over (unregistered or dangling)", d["report"], d["hash"]))
        if d in spoofable and not (unprotected and d is spoofable[0]):
            sev = "critical" if d["tier"] in ("critical", "high") and d["profile"] == "mail" else "warning"
            out.append(_signal(sev, "MAIL_SPOOFABLE", f"{d['domain']} can be impersonated by e-mail (DMARC {d['dmarc']})", d["report"], d["hash"]))
    for e in asset["expiries"]:
        days = e["days"]
        if days is None:
            continue
        crit, warn = (CERT_CRIT_DAYS, CERT_WARN_DAYS) if e["kind"] == "certificate" else (REG_CRIT_DAYS, REG_WARN_DAYS)
        if days < 0:
            out.append(_signal("critical", "EXPIRED", f"{e['name']}: {e['kind']} expired {-days} days ago", e["report"], e["hash"]))
        elif days <= warn:
            out.append(_signal("critical" if days <= crit else "warning", "EXPIRING",
                               f"{e['name']}: {e['kind']} expires in {days} days ({e['date']})", e["report"], e["hash"]))
    if web and any(d["caa"] == "missing" for d in dns):
        d = next(d for d in dns if d["caa"] == "missing")
        out.append(_signal("warning", "WEB_NO_CAA", f"{d['domain']} publishes websites but no CAA record: any certificate "
                                                    "authority may issue certificates for it", d["report"], d["hash"]))
    unknown = [d["domain"] for d in dns if not d["measured"] or d["dmarc_state"] == "unknown"] + \
              [w["domain"] for w in web if not w["measured"] or w["protected"] is None]
    if unknown:
        out.append(_signal("info", "DATA_INCOMPLETE", f"Not verified: {', '.join(unknown[:3])}{' and others' if len(unknown) > 3 else ''} "
                                                      "(control not run, DNS or API error) - not counted as exposed",
                           (dns[0] if dns else web[0])["report"], ""))
    if web and not dns and asset["dns_assessed"]:
        out.append(_signal("warning", "DNS_NOT_MONITORED",
                           f"{asset['key']} hosts {len(web)} website{'s' if len(web) > 1 else ''} but is not in the DNS / e-mail assessment",
                           web[0]["report"], web[0]["hash"]))
    out.sort(key=lambda s: SEV_RANK.get(s["severity"], 9))
    return out


def build(reports: List[dict], now: Optional[datetime] = None) -> dict:
    """Join the latest DNS, WAF and Zero Trust reports into assets.

    `reports` are the portal's report dicts with their parsed `payload`.
    """
    now = now or datetime.now(timezone.utc)
    dns_rows: List[Tuple[dict, str]] = []
    waf_rows: List[Tuple[dict, str]] = []
    tenants: List[Tuple[dict, dict]] = []
    for r in reports:
        p = r.get("payload")
        if not isinstance(p, dict):
            continue
        if r["type"] == "dns":
            dns_rows += [(x, r["id"]) for x in p.get("results") or [] if x.get("domain")]
        elif r["type"] == "waf":
            waf_rows += [(x, r["id"]) for x in p.get("results") or [] if x.get("domain")]
        elif r["type"] == "zta":
            tenants.append((p.get("tenant") or {}, r))
    if not dns_rows and not waf_rows:
        return {"assets": [], "summary": {"total": 0}}

    listed = sorted({str(x["domain"]).lower() for x, _ in dns_rows}, key=lambda d: (d.count("."), d))
    roots: Dict[str, str] = {}
    for d in listed:  # shortest listed parent wins
        roots[d] = next((p for p in listed if _under(d, p) and p.count(".") < d.count(".")), d)

    assets: Dict[str, dict] = {}

    def asset(key: str) -> dict:
        return assets.setdefault(key, {"key": key, "dns": [], "web": [], "tenant": None, "expiries": []})

    for x, rid in dns_rows:
        asset(roots[str(x["domain"]).lower()])["dns"].append(_dns_item(x, rid))
    for x, rid in waf_rows:
        host = str(x["domain"]).lower()
        match = max((d for d in listed if _under(host, d)), key=len, default=None)
        asset(roots[match] if match else registrable(host))["web"].append(_waf_item(x, rid))
    for t, r in tenants:
        dom = str(t.get("domain") or "").lower()
        key = next((k for k in assets if dom and _under(dom, k)), None)
        if key:
            assets[key]["tenant"] = {"name": t.get("name") or dom, "domain": dom, "score": r.get("score"),
                                     "grade": r.get("grade"), "report": r["id"], "hash": "#/overview"}

    out = []
    for a in assets.values():
        for w in a["web"]:
            if w["cert_expires"] or w["cert_days"] is not None:
                days = w["cert_days"] if w["cert_days"] is not None else _days_until(w["cert_expires"], now)
                a["expiries"].append({"kind": "certificate", "name": w["domain"], "date": w["cert_expires"] or "",
                                      "days": days, "source": "WAF", "report": w["report"], "hash": w["hash"]})
            elif w["served_cert_days"] is not None:
                a["expiries"].append({"kind": "certificate", "name": w["domain"], "date": "", "days": w["served_cert_days"],
                                      "source": "served (probe)", "report": w["report"], "hash": w["hash"]})
        for d in a["dns"]:
            if d["registration_expires"]:
                a["expiries"].append({"kind": "registration", "name": d["domain"], "date": str(d["registration_expires"])[:10],
                                      "days": _days_until(d["registration_expires"], now), "source": "RDAP",
                                      "report": d["report"], "hash": d["hash"]})
        a["expiries"].sort(key=lambda e: (e["days"] is None, e["days"] if e["days"] is not None else 0))
        a["dns_assessed"] = bool(dns_rows)
        a["signals"] = _signals(a, now)
        items = a["dns"] + a["web"]
        a["tier"] = _tier(*(i["tier"] for i in items))
        a["owners"] = sorted({i["owner"] for i in items if i.get("owner")})
        a["bus"] = sorted({i["bu"] for i in items if i.get("bu")})
        scores = [i["score"] for i in items if i.get("score") is not None]
        a["score"] = min(scores) if scores else None
        a["dns_score"] = min((d["score"] for d in a["dns"] if d["score"] is not None), default=None)
        a["web_score"] = min((w["score"] for w in a["web"] if w["score"] is not None), default=None)
        sev = {s["severity"] for s in a["signals"]}
        incomplete = any(s["code"] == "DATA_INCOMPLETE" for s in a["signals"])
        a["status"] = ("bad" if "critical" in sev or (a["score"] is not None and a["score"] < 50) else
                       "warn" if "warning" in sev or (a["score"] is not None and a["score"] < 80) else
                       "good" if a["score"] is not None and not incomplete else "unknown")  # never "on track" on partial data
        a["coverage_gap"] = any(s["code"] == "DNS_NOT_MONITORED" for s in a["signals"])
        a["incomplete"] = any(s["code"] == "DATA_INCOMPLETE" for s in a["signals"])
        a["next_expiry"] = next((e for e in a["expiries"] if e["days"] is not None), None)
        del a["dns_assessed"]
        out.append(a)
    rank = {"bad": 0, "warn": 1, "unknown": 2, "good": 3}
    out.sort(key=lambda a: (rank[a["status"]], -TIER_RANK.get(a["tier"], 2),
                            -sum(s["severity"] == "critical" for s in a["signals"]),
                            a["score"] if a["score"] is not None else 101, a["key"]))
    summary = {"total": len(out), "at_risk": sum(a["status"] == "bad" for a in out),
               "attention": sum(a["status"] == "warn" for a in out), "on_track": sum(a["status"] == "good" for a in out),
               "coverage_gaps": sum(a["coverage_gap"] for a in out), "incomplete": sum(a["incomplete"] for a in out),
               "unknown": sum(a["status"] == "unknown" for a in out),
               "websites": sum(len(a["web"]) for a in out), "domains": sum(len(a["dns"]) for a in out),
               "expiring": sum(1 for a in out for e in a["expiries"] if e["days"] is not None and e["days"] <= CERT_WARN_DAYS)}
    return {"assets": out, "summary": summary}
