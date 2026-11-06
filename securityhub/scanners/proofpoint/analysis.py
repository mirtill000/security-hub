"""Snapshot analysis: one result per mail domain (routing + TAP exposure), account findings, people and threat views."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..edr.analysis import compute_diff  # same result shape: keyed by site_id (here the domain)
from .checks import (_malicious, check_clicks, check_direct, check_people, check_rewrite, check_routing, check_spf,
                     check_threats)
from .constants import CHECKS, FINDINGS, MALICIOUS, SCORE_CAPS, SEVERITY_RANK, TIER_WEIGHTS
from .models import CheckResult, Issue, MailDomainResult, make_issue
from .podlog import findings as pod_findings
from .tpapi import findings as tp_findings

__all__ = ["analyze_snapshot", "compute_diff"]


def _in(addr_domain: str, domain: str) -> bool:
    return addr_domain == domain or addr_domain.endswith("." + domain)


def _dom(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


LATE_VERDICT_HOURS = 1.0


def _ts(v) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _exposure_hours(msgs: List[dict]) -> Optional[dict]:
    """Time between delivery (messageTime) and the TAP verdict (threatTime) of the malicious messages delivered:
    how long the threat sat in the mailbox before it was known (SIEM API fields)."""
    delays = []
    for m in msgs:
        t0 = _ts(m.get("time"))
        times = [_ts(t.get("time")) for t in _malicious(m)]
        times = [t for t in times if t is not None]
        if t0 is not None and times:
            delays.append(max(0.0, (min(times) - t0).total_seconds() / 3600))
    if not delays:
        return None
    delays.sort()
    mid = len(delays) // 2
    median = delays[mid] if len(delays) % 2 else (delays[mid - 1] + delays[mid]) / 2
    return {"messages": len(delays), "median": round(median, 1), "max": round(delays[-1], 1)}


def score_domain(r: MailDomainResult, checks: List[str]) -> None:
    weighted = [(c, CHECKS[c]) for c in checks if CHECKS[c] and r.checks.get(c) and r.checks[c].max > 0
                and r.checks[c].status not in ("unknown", "na", "skipped")]
    total = sum(w for _, w in weighted)
    comps, score = {}, 0.0
    for c, w in weighted:
        frac = max(0.0, min(1.0, r.checks[c].got / r.checks[c].max))
        comps[c] = {"got": round(frac * w, 1), "max": w}
        score += frac * w
    if total:
        score = 100 * score / total
    else:
        sev = Counter(i.severity for i in r.issues)
        score = max(0, 100 - 40 * sev["critical"] - 15 * sev["warning"])
    score = int(round(score))
    cap = None
    for i in r.issues:
        limit = SCORE_CAPS.get(i.code)
        if limit is not None and score > limit and (cap is None or limit < cap[0]):
            cap = (limit, FINDINGS[i.code][2])
    if cap:
        score = cap[0]
    r.overall_score = score
    r.score_breakdown = {"components": comps, "max": total, "normalized": total != 100,
                         "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None,
                         "note": None if total else "No measurable weighted check: score from findings"}


def evaluate_compliance(r: MailDomainResult, checks: List[str]) -> Dict[str, str]:
    st = lambda c: (r.checks.get(c) or CheckResult()).status
    out = {}
    if {"routing", "direct"} <= set(checks) and st("routing") != "na":
        if st("routing") == "error":
            out["gateway_enforced"] = "fail"
        elif st("routing") == "valid" and st("direct") in ("valid", "na"):
            out["gateway_enforced"] = "pass"
        else:
            out["gateway_enforced"] = "unknown"  # direct delivery to verify, or DNS not readable
    if {"threats", "clicks"} <= set(checks):
        s = {st("threats"), st("clicks")}
        out["no_exposure"] = ("n/a" if s <= {"na", "skipped"} else "fail" if "error" in s else
                              "unknown" if "unknown" in s else "pass")
    return out


REMEDIATION = {
    "DIRECT_DELIVERY": ("Block direct delivery to Microsoft 365", "Exchange admin center",
                        "Mail flow > Connectors: inbound 'Partner organization' connector from Proofpoint, restricted to the "
                        "Proofpoint IPs or certificate; then a mail flow rule (or 'reject direct send') that rejects inbound "
                        "mail not received through that connector"),
    "THREAT_DELIVERED": ("Remove the delivered threats", "TAP dashboard / mailbox",
                         "TAP > Threats: open each threat; pull the messages with TRAP (Threat Response Auto-Pull) or "
                         "Microsoft 365 Threat Explorer / content search and purge; check who opened them"),
    "SAFELIST_DELIVERY": ("Narrow the safelist", "Proofpoint admin portal",
                          "Email Protection > Spam Detection > Organizational Safe List (and sender lists of the policy route "
                          "in the finding): remove or restrict the entry that let the threat through"),
    "CLICK_PERMITTED": ("Respond to the permitted clicks", "TAP dashboard / identity",
                        "TAP > Clicks: for each user reset the password and revoke sessions, check the endpoint with the EDR; "
                        "consider URL isolation for these users"),
    "URL_NOT_REWRITTEN": ("Rewrite every URL", "Proofpoint admin portal",
                          "Targeted Attack Protection > URL Defense: apply URL rewriting to all inbound messages "
                          "(no exceptions by sender or route)"),
    "IMPOSTOR_DELIVERED": ("Tune impostor protection", "Proofpoint admin portal",
                           "Email Protection > Impostor Classifier: review the delivered messages, tighten the policy; "
                           "consider Email Fraud Defense for supplier impersonation"),
    "SPF_NO_PROOFPOINT": ("Authorize Proofpoint in SPF", "DNS",
                          "If outbound mail is relayed by Proofpoint, add the SPF include given for your cluster (*.pphosted.com)"),
    "VAP_VIP": ("Protect the attacked VIPs", "Proofpoint / identity",
                "Apply browser isolation and stricter policies to the VIPs listed, enforce phishing-resistant MFA"),
}


def suggest_remediation(r: MailDomainResult) -> List[dict]:
    seen, out = set(), []
    for i in r.issues:
        if i.code in REMEDIATION and i.code not in seen:
            seen.add(i.code)
            title, where, steps = REMEDIATION[i.code]
            out.append({"title": title, "type": where, "name": r.domain, "value": steps, "note": i.message})
    return out


def analyze_snapshot(snap: dict, checks: List[str], metadata: Dict[str, dict]
                     ) -> Tuple[List[MailDomainResult], List[Issue], List[dict], dict]:
    dns_data: Dict[str, dict] = snap.get("dns") or {}
    tap = "messages_delivered" in snap and not snap.get("siem_failed")
    msgs = snap.get("messages_delivered") or []
    clicks = snap.get("clicks_permitted") or []
    vap = snap.get("vap") if "vap" in snap else None
    clickers = snap.get("top_clickers") if "top_clickers" in snap else None
    listed = [str(d).lower() for d in snap.get("domains") or []]
    seen = set()
    for m in msgs:
        seen |= {_dom(r) for r in m.get("recipients") or []}
    seen |= {_dom(k.get("recipient") or "") for k in clicks}
    # domains the PoD gateway received mail for (message log): handled by Proofpoint whatever their MX says
    pod_msg = ((snap.get("pod") or {}).get("message")) or {}
    seen |= {str(d).lower() for d, _ in pod_msg.get("recipient_domains") or []}
    seen.discard("")
    extra_domains = sorted(d for d in seen if not any(_in(d, x) for x in listed))
    domains = listed + extra_domains
    scan_date = snap.get("collected", "")
    results: List[MailDomainResult] = []
    no_mail: List[str] = []
    not_managed: List[dict] = []   # in the domain list, but Proofpoint does not handle their mail: not assessed
    for d in domains:
        dns = dns_data.get(d)
        mine = [m for m in msgs if any(_in(_dom(r), d) for r in m.get("recipients") or [])] if tap else None
        my_clicks = [k for k in clicks if _in(_dom(k.get("recipient") or ""), d)] if tap else None
        my_vap = [p for p in vap if any(_in(_dom(e), d) for e in p.get("emails") or [])] if vap is not None else None
        my_clickers = [p for p in clickers if any(_in(_dom(e), d) for e in p.get("emails") or [])] if clickers is not None else None
        mx = (dns or {}).get("mx") or []
        if dns and not mx and dns.get("mx_status") != "error" and not mine and not my_clicks:
            no_mail.append(d)  # no MX and no TAP event: the domain does not receive mail
            continue
        covered = any(m.get("proofpoint") for m in mx) if dns else True
        handled = any(_in(x, d) for x in seen)   # Proofpoint saw mail for it (TAP events or PoD log)
        if dns and not handled and (not covered or dns.get("mx_status") == "error"):
            # KPIs are about the domains Proofpoint manages: a listed domain whose MX does not point to Proofpoint
            # (or could not be read) and for which Proofpoint saw no mail is listed apart, not assessed
            not_managed.append({"domain": d, "reason": "MX not readable" if dns.get("mx_status") == "error" else "MX not Proofpoint",
                                "mx": sorted({m.get("platform") or m.get("host") for m in mx if m.get("host")})[:3]})
            continue
        r = MailDomainResult(site_id=d, domain=d, scan_date=scan_date,
                             source="list+tap" if d in listed and d in seen else "list" if d in listed else "tap")
        meta = metadata.get(d) or {}
        r.tier, r.owner, r.bu, r.tags = meta.get("tier", "medium"), meta.get("owner", ""), meta.get("bu", ""), list(meta.get("tags", []))
        plats = sorted({m.get("platform") for m in mx if m.get("platform")})
        if dns and (dns.get("m365") or {}).get("resolves") and "Microsoft 365" not in plats:
            plats.append("Microsoft 365")
        r.account_name = ", ".join(plats)
        r.account_id = r.account_name or None
        r.gateway = "" if not dns else "Proofpoint" if mx and all(m.get("proofpoint") for m in mx) else \
            "Proofpoint + other" if covered else "other" if mx else "none"
        builders = {
            "routing": lambda: check_routing(dns),
            "direct": lambda: check_direct(dns),
            "spf": lambda: check_spf(dns),
            "threats": lambda: check_threats(mine, covered),
            "clicks": lambda: check_clicks(my_clicks, covered),
            "rewrite": lambda: check_rewrite(mine, covered),
            "people": lambda: check_people(my_vap, my_clickers, covered),
        }
        for c in checks:
            try:
                r.checks[c] = builders[c]()
            except Exception as e:  # never lose a domain because of unexpected data
                r.checks[c] = CheckResult(status="unknown", issues=[make_issue("API_ERROR", f"{c}: {type(e).__name__}: {e}")])
        r.issues = sorted((i for c in checks for i in r.checks[c].issues), key=lambda i: SEVERITY_RANK.get(i.severity, 9))
        codes = {i.code for i in r.issues}
        via = ((r.checks.get("routing") or CheckResult()).data or {}).get("via_proofpoint")
        r.profile = ("clicked" if "CLICK_PERMITTED" in codes else "delivered" if "THREAT_DELIVERED" in codes
                     else "unprotected" if via == "none" else "bypass" if via == "some" else "protected")  # routing: informational
        score_domain(r, checks)
        r.compliance = evaluate_compliance(r, checks)
        r.remediation = suggest_remediation(r)
        crit = sum(1 for i in r.issues if i.severity == "critical")
        r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
        results.append(r)
    results.sort(key=lambda x: (-x.priority, x.domain))

    account: List[Issue] = [make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}") for e in snap.get("errors") or []]
    repeat = [p for p in clickers or [] if (p.get("clicks") or 0) >= 2] or list(clickers or [])
    if repeat:
        account.append(make_issue("TOP_CLICKERS", f"{len(repeat)}: " + ", ".join(
            f"{p.get('name') or (p.get('emails') or ['?'])[0]} ({p.get('clicks')})" for p in repeat[:3])
            + (" and others" if len(repeat) > 3 else "")))
    # permitted malicious clicks per user: a second click means the first one was not acted upon
    per_user = Counter(k.get("recipient") for k in clicks
                       if k.get("classification") in MALICIOUS and k.get("status") not in ("cleared", "falsepositive"))
    repeat_users = sorted((u for u, n in per_user.items() if u and n > 1), key=lambda u: -per_user[u])
    if repeat_users:
        account.append(make_issue("CLICK_REPEAT", ", ".join(f"{u} ({per_user[u]})" for u in repeat_users[:5])
                                  + (" and others" if len(repeat_users) > 5 else "")))
    exposure = _exposure_hours(msgs)
    if exposure and exposure["median"] >= LATE_VERDICT_HOURS:
        account.append(make_issue("THREAT_LATE_VERDICT", f"median {exposure['median']:g} h between delivery and verdict "
                                                         f"over {exposure['messages']} malicious message(s), longest {exposure['max']:g} h"))
    if extra_domains and listed:
        account.append(make_issue("TAP_DOMAINS_NOT_LISTED", f"{len(extra_domains)}: {', '.join(extra_domains[:5])}"
                                  + (" and others" if len(extra_domains) > 5 else "")))
    if tap and not msgs and not clicks and not snap.get("blocked"):
        account.append(make_issue("TAP_NO_EVENTS", f"{(snap.get('window') or {}).get('hours', '?')} hours"))
    tp_issues, tp_data = tp_findings(snap.get("tp"))
    pod_issues, pod_data = pod_findings(snap.get("pod"))
    account += tp_issues + pod_issues
    account.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))

    # threats across the whole organization (what the SOC looks at)
    agg: Dict[str, dict] = {}
    for m in msgs:
        for t in _malicious(m) + [t for t in m.get("threats") or [] if t.get("classification") == "impostor"]:
            key = str(t.get("url") or t.get("campaign") or t.get("classification"))
            a = agg.setdefault(key, {"classification": t.get("classification"), "type": t.get("type"), "url": t.get("url"),
                                     "campaign": t.get("campaign"), "messages": 0, "recipients": set(), "clicks": 0})
            a["messages"] += 1
            a["recipients"] |= set(m.get("recipients") or [])
    by_url = defaultdict(int)
    for k in clicks:
        by_url[str(k.get("url"))] += 1
    threats = sorted(({**a, "recipients": len(a["recipients"]), "clicks": by_url.get(str(a["url"]), 0)} for a in agg.values()),
                     key=lambda a: (-a["clicks"], -a["messages"]))[:100]
    blocked = Counter()
    for c in (snap.get("blocked") or {}).values():
        blocked.update(c)
    people = {"vap": vap, "top_clickers": clickers, "window_days": snap.get("people_window_days"),
              "threshold": snap.get("vap_threshold")}
    extra = {"people": people, "threats": threats, "no_mail": no_mail, "not_managed": not_managed, "tap": tap, "window": snap.get("window"),
             "tp": tp_data, "pod": pod_data,
             "totals": {"delivered": len(msgs), "malicious": sum(1 for m in msgs if _malicious(m)), "clicks_permitted": len(clicks),
                        "blocked_messages": blocked.get("messages", 0), "blocked_clicks": blocked.get("clicks", 0),
                        "malicious_clicks_permitted": sum(per_user.values()), "repeat_clickers": len(repeat_users),
                        # share of the clicks on malicious URLs that URL Defense blocked
                        "click_block_rate": (round(100 * blocked.get("clicks", 0) / (blocked.get("clicks", 0) + sum(per_user.values())))
                                             if tap and blocked.get("clicks", 0) + sum(per_user.values()) else None),
                        "exposure_hours": exposure}}
    return results, account, [], extra
