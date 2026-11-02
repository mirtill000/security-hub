"""Per-website checks: onboarding, WAF rules, allow-lists, bots, DDoS, TLS, origin."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .constants import (ACTION_LABELS, BLOCKING_ACTIONS, CORE_RULES, DDOS_DEFAULT_THRESHOLD, DDOS_FACTOR, DDOS_FLOOR,
                        DDOS_HIGH_RATIO, DDOS_LOW_RATIO, DDOS_THRESHOLDS, V1_ACTIONS, V1_RULE_IDS)
from .models import CheckResult, Issue, make_issue


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "on")


def _broad_cidr(value: str, v4_prefix: int, v6_prefix: int) -> bool:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return net.prefixlen <= (v4_prefix if net.version == 4 else v6_prefix)


# Policy exception conditions (Imperva "exceptionType"). The conditions of one exception apply TOGETHER (AND):
# the exception is broad only when no condition narrows it to specific requests.
ASSET_CONDITIONS = {"SITE_ID", "ASSET_ID", "SITE", "ASSET", "ASSETS"}
GEO_CONDITIONS = {"COUNTRY", "CONTINENT", "GEO"}
CONDITION_LABELS = {"URL": "URL is", "IP": "IPs", "COUNTRY": "Countries", "CONTINENT": "Continents", "GEO": "Countries",
                    "SITE_ID": "Assets", "ASSET_ID": "Assets", "SITE": "Assets", "ASSET": "Assets", "ASSETS": "Assets",
                    "CLIENT_ID": "Client", "CLIENT_APP_TYPE": "Client type", "PARAMETER": "Parameter", "COOKIE": "Cookie",
                    "USER_AGENT": "User agent", "HEADER": "Header", "HEADER_NAME": "Header"}
ANY_URL = ("", "/", "*", "/*")


def assess_exception(exc: dict, site_id: Any = None) -> Optional[dict]:
    """One policy exception as seen by `site_id`: None when its asset condition excludes that website."""
    conds = []
    for d in exc.get("data") or []:
        etype = str(d.get("exceptionType") or "").upper()
        values = [str(v).strip() for v in d.get("values") or []]
        conds.append((etype, values))
    assets = [v for t, vals in conds if t in ASSET_CONDITIONS for v in vals]
    if assets and site_id is not None and str(site_id) not in assets:
        return None
    narrowing, why = [], []
    for t, vals in conds:
        if t in ASSET_CONDITIONS:
            continue
        if t.startswith("URL"):
            if vals and not any(v in ANY_URL for v in vals):
                narrowing.append(t)
            else:
                why.append("any URL")
        elif t == "IP":
            if vals and not any(_broad_cidr(v, 16, 32) for v in vals):
                narrowing.append(t)
            else:
                why.append("very broad IP range")
        elif t in GEO_CONDITIONS:
            why.append("whole " + ("continent" if t == "CONTINENT" else "country"))
        elif vals:  # parameter, cookie, header, user agent, client: specific requests only
            narrowing.append(t)
    if not conds or (not narrowing and not why):
        why.append("no condition" if not [c for c in conds if c[0] not in ASSET_CONDITIONS] else "no specific condition")
    labels = []
    for t, _ in conds:
        lab = CONDITION_LABELS.get(t, t.replace("_", " ").capitalize() or "Any")
        if lab not in labels:
            labels.append(lab)
    return {"type": " + ".join(labels) or "Any request",
            "values": [f"{CONDITION_LABELS.get(t, t)}: {', '.join(vals[:5])}{' ...' if len(vals) > 5 else ''}" for t, vals in conds],
            "scope": f"asset {', '.join(assets)}" if assets else "all assets using the policy",
            "comment": exc.get("comment") or "", "broad": not narrowing,
            "why": ", ".join(why) if not narrowing else ""}


def _status_from(issues: List[Issue], default: str = "valid") -> str:
    sev = {i.severity for i in issues}
    return "error" if "critical" in sev else "warning" if "warning" in sev else default


def _legacy_rules(site: dict) -> Dict[str, dict]:
    rules = ((site.get("security") or {}).get("waf") or {}).get("rules") or []
    return {str(r.get("id")): r for r in rules if isinstance(r, dict)}


def _legacy_acls(site: dict) -> Dict[str, dict]:
    rules = ((site.get("security") or {}).get("acls") or {}).get("rules") or []
    return {str(r.get("id")): r for r in rules if isinstance(r, dict)}


def _enrich_policies(applied: Optional[list], account_policies: Dict[Any, dict]) -> List[dict]:
    out = []
    for p in applied or []:
        full = dict(account_policies.get(p.get("id"), {}))
        full.update({k: v for k, v in p.items() if v not in (None, [], "")})
        out.append(full)
    return out


def check_onboarding(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=20)
    active = str(site.get("active", "")).lower()
    status = str(site.get("status", "")).lower()
    if active == "bypass":
        c.issues.append(make_issue("SITE_BYPASS"))
    else:
        c.got += 12
    if status.replace("-", "_") == "fully_configured":
        c.got += 8
    else:
        c.issues.append(make_issue("SITE_NOT_CONFIGURED", status or "unknown status"))
    warnings = site.get("warnings") or []
    if warnings:
        first = warnings[0] if isinstance(warnings[0], str) else json.dumps(warnings[0])[:120]
        c.issues.append(make_issue("SITE_WARNINGS", f"{len(warnings)}: {first}"))
    c.data = {"status": site.get("status"), "active": site.get("active"), "display_name": site.get("display_name"),
              "dns": [{"name": d.get("dns_record_name"), "type": d.get("set_type_to"), "value": d.get("set_data_to")}
                      for d in site.get("dns") or []]}
    if probe:
        c.data["probe"] = {k: probe.get(k) for k in ("cnames", "addresses", "expected", "routed", "imperva_edge")}
        if not probe.get("addresses"):
            c.issues.append(make_issue("DNS_UNRESOLVED", probe.get("host")))
        elif probe.get("routed") is False:
            c.issues.append(make_issue("DNS_NOT_ROUTED", ", ".join((probe.get("cnames") or []) + probe["addresses"][:3])))
    c.status = _status_from(c.issues)
    return c


def check_waf(site: dict, policies: List[dict]) -> CheckResult:
    c = CheckResult(max=36)
    waf = [p for p in policies if p.get("policyType") == "WAF_RULES"]
    legacy = _legacy_rules(site)
    rules: Dict[str, dict] = {}
    exceptions: List[dict] = []
    data_leak = None
    policy_info = None
    if waf:
        if len(waf) > 1:
            c.issues.append(make_issue("WAF_MULTIPLE_POLICIES", ", ".join(str(p.get("name")) for p in waf)))
        enabled = [p for p in waf if p.get("enabled") is not False]
        p = enabled[0] if enabled else waf[0]
        policy_info = {"id": p.get("id"), "name": p.get("name"), "enabled": p.get("enabled") is not False}
        if not enabled:
            c.issues.append(make_issue("WAF_POLICY_DISABLED", str(p.get("name"))))
        for s in p.get("policySettings") or []:
            t = s.get("policySettingType")
            act = str(s.get("settingsAction") or "").upper() or None
            excs = s.get("policyDataExceptions") or []
            if t in CORE_RULES:
                rules[t] = {"action": act if policy_info["enabled"] else "IGNORE", "source": f"policy '{p.get('name')}'",
                            "exceptions": len(excs)}
            elif t == "RESP_DATA_LEAK":
                data_leak = act
            applied = [e for e in (assess_exception(x, site.get("site_id")) for x in excs) if e]
            if t in CORE_RULES:
                rules[t]["exceptions"] = len(applied)
            for e in applied:
                exceptions.append({"rule": CORE_RULES.get(t, t), **e})
    else:
        for rid, core in V1_RULE_IDS.items():
            r = legacy.get(rid)
            if r:
                rules[core] = {"action": V1_ACTIONS.get(r.get("action"), str(r.get("action") or "").upper() or None),
                               "source": "legacy site settings", "exceptions": len(r.get("exceptions") or [])}
        if rules:
            c.issues.append(make_issue("WAF_LEGACY_RULES"))
        else:
            c.issues.append(make_issue("WAF_NO_POLICY"))

    no_policy = any(i.code == "WAF_NO_POLICY" for i in c.issues)
    disabled = any(i.code == "WAF_POLICY_DISABLED" for i in c.issues)
    if not no_policy:
        missing, ignored, alert = [], [], []
        for core, name in CORE_RULES.items():
            act = (rules.get(core) or {}).get("action")
            if not act:
                missing.append(name)
            elif act in BLOCKING_ACTIONS:
                c.got += 0 if disabled else 8
            elif act == "ALERT":
                alert.append(name)
                c.got += 4
            else:
                ignored.append(name)
        if missing:
            c.issues.append(make_issue("WAF_RULE_MISSING", ", ".join(missing)))
        if ignored and not disabled:
            c.issues.append(make_issue("WAF_RULE_IGNORED", ", ".join(ignored)))
        if alert:
            c.issues.append(make_issue("WAF_RULE_ALERT", ", ".join(alert)))

    backdoor = legacy.get("api.threats.backdoor")
    backdoor_action = None
    if backdoor:
        c.max += 4
        backdoor_action = V1_ACTIONS.get(backdoor.get("action"), str(backdoor.get("action") or "").upper())
        if backdoor_action in BLOCKING_ACTIONS:
            c.got += 4
        else:
            c.got += 2 if backdoor_action == "ALERT" else 0
            c.issues.append(make_issue("WAF_BACKDOOR_WEAK", ACTION_LABELS.get(backdoor_action, backdoor_action)))

    if not no_policy:
        broad = [e for e in exceptions if e["broad"]]
        c.max += 4
        c.got += max(0, 4 - 2 * len(broad))
        if broad:
            c.issues.append(make_issue("WAF_BROAD_EXCEPTION", ", ".join(
                f"{e['rule']}: {e['why']}" + (f" ({'; '.join(e['values'][:2])})" if e['values'] else "") for e in broad[:3])))
        undocumented = [e for e in exceptions if not e["comment"]]
        if undocumented:
            c.issues.append(make_issue("WAF_EXCEPTION_NO_COMMENT", f"{len(undocumented)} of {len(exceptions)}"))
        if len(exceptions) > 20:
            c.issues.append(make_issue("WAF_MANY_EXCEPTIONS", str(len(exceptions))))
    if data_leak and data_leak not in BLOCKING_ACTIONS:
        c.issues.append(make_issue("WAF_DATA_LEAK_OFF", ACTION_LABELS.get(data_leak, data_leak)))

    c.data = {"policy": policy_info, "legacy": not waf and bool(rules),
              "rules": [{"rule": name, "action": (rules.get(core) or {}).get("action"),
                         "label": ACTION_LABELS.get((rules.get(core) or {}).get("action"), "Not set"),
                         "source": (rules.get(core) or {}).get("source", ""),
                         "exceptions": (rules.get(core) or {}).get("exceptions", 0)} for core, name in CORE_RULES.items()],
              "backdoor": ACTION_LABELS.get(backdoor_action, backdoor_action) if backdoor else None,
              "data_leak": ACTION_LABELS.get(data_leak, data_leak) if data_leak else None,
              "exceptions": exceptions[:60], "exception_count": len(exceptions)}
    c.status = _status_from(c.issues)
    return c


def check_allowlist(site: dict, policies: List[dict]) -> CheckResult:
    c = CheckResult(max=0)
    ips: List[Tuple[str, str]] = []
    urls: List[Tuple[str, str]] = []
    blocked = {"countries": set(), "continents": set(), "ips": 0, "urls": 0}
    for p in policies:
        ptype = p.get("policyType")
        if p.get("enabled") is False:
            continue
        for s in p.get("policySettings") or []:
            data = s.get("data") or {}
            act = str(s.get("settingsAction") or "").upper()
            if ptype == "WHITELIST" or act == "ALLOW":
                for ip in data.get("ips") or []:
                    ips.append((str(ip), f"policy '{p.get('name')}'"))
                for u in data.get("urls") or []:
                    urls.append((f"{u.get('pattern', '')} {u.get('url', '')}".strip() if isinstance(u, dict) else str(u),
                                 f"policy '{p.get('name')}'"))
            elif ptype == "ACL" and act == "BLOCK":
                geo = data.get("geo") or {}
                blocked["countries"] |= set(geo.get("countries") or [])
                blocked["continents"] |= set(geo.get("continents") or [])
                blocked["ips"] += len(data.get("ips") or [])
                blocked["urls"] += len(data.get("urls") or [])
    acls = _legacy_acls(site)
    for ip in (acls.get("api.acl.whitelisted_ips") or {}).get("ips") or []:
        ips.append((str(ip), "legacy whitelist"))
    for rid, key in (("api.acl.blacklisted_countries", "countries"),):
        geo = (acls.get(rid) or {}).get("geo") or {}
        blocked["countries"] |= set(geo.get("countries") or [])
        blocked["continents"] |= set(geo.get("continents") or [])
    blocked["ips"] += len((acls.get("api.acl.blacklisted_ips") or {}).get("ips") or [])
    broad_ips = [f"{ip} ({src})" for ip, src in ips if _broad_cidr(ip.split("-")[0], 16, 32)]
    if broad_ips:
        c.issues.append(make_issue("ALLOW_BROAD_IP", ", ".join(broad_ips[:4])))
    broad_urls = [f"{u} ({src})" for u, src in urls if re.fullmatch(r"(PREFIX|CONTAINS)?\s*/?\*?", u.strip(), re.I)
                  or u.strip().upper().endswith(" /")]
    if broad_urls:
        c.issues.append(make_issue("ALLOW_BROAD_URL", ", ".join(broad_urls[:4])))
    if len(ips) > 50:
        c.issues.append(make_issue("ALLOW_MANY_IPS", str(len(ips))))
    c.data = {"allowed_ips": [f"{ip} ({src})" for ip, src in ips[:80]], "allowed_ip_count": len(ips),
              "allowed_urls": [f"{u} ({src})" for u, src in urls[:40]],
              "blocked_countries": sorted(blocked["countries"]), "blocked_continents": sorted(blocked["continents"]),
              "blocked_ips": blocked["ips"], "blocked_urls": blocked["urls"]}
    c.status = _status_from(c.issues)
    return c


def check_bots(site: dict) -> CheckResult:
    c = CheckResult(max=10)
    r = _legacy_rules(site).get("api.threats.bot_access_control")
    if not r:
        c.issues.append(make_issue("BOT_RULE_MISSING"))
        c.status = "missing"
        return c
    bad, suspected = _truthy(r.get("block_bad_bots")), _truthy(r.get("challenge_suspected_bots"))
    c.got = (6 if bad else 0) + (4 if suspected else 0)
    if not bad:
        c.issues.append(make_issue("BOT_BAD_NOT_BLOCKED"))
    if not suspected:
        c.issues.append(make_issue("BOT_SUSPECTED_NOT_CHALLENGED"))
    c.data = {"block_bad_bots": bad, "challenge_suspected_bots": suspected}
    c.status = _status_from(c.issues) if bad else "warning"
    return c


def traffic_profile(traffic: Optional[dict]) -> Optional[dict]:
    """Peak / p95 / average requests per second from hits_timeseries (human + bot = legitimate,
    blocked counted separately). Values are bucket averages, so short bursts are smoothed."""
    if not traffic or traffic.get("error") or not traffic.get("hits_timeseries"):
        return None
    gran_s = (traffic.get("granularity") or 0) / 1000 or None
    if not gran_s:  # default granularity: infer the bucket size from the timestamps
        for s in traffic["hits_timeseries"]:
            ts = sorted(int(p[0]) for p in s.get("data") or [] if isinstance(p, (list, tuple)) and p)
            if len(ts) > 1:
                gaps = sorted(b - a for a, b in zip(ts, ts[1:]) if b > a)
                gran_s = gaps[len(gaps) // 2] / 1000 if gaps else None
                break

    def series(kind: str, per_second: bool) -> Optional[Dict[int, float]]:
        for s in traffic["hits_timeseries"]:
            label = f"{s.get('id', '')} {s.get('name', '')}".lower()
            ps = "_ps" in label or "per second" in label or "per_second" in label
            if kind in label and ps == per_second:
                return {int(p[0]): float(p[1] or 0) for p in s.get("data") or [] if isinstance(p, (list, tuple)) and len(p) >= 2}
        return None

    parts = {}
    for kind in ("human", "bot", "blocked"):
        data = series(kind, True)
        if data is None and gran_s:
            counts = series(kind, False)
            data = {t: v / gran_s for t, v in counts.items()} if counts else None
        parts[kind] = data or {}
    stamps = sorted(set(parts["human"]) | set(parts["bot"]) | set(parts["blocked"]))
    if not stamps:
        return None
    legit = [(t, parts["human"].get(t, 0.0) + parts["bot"].get(t, 0.0)) for t in stamps]
    blocked = [parts["blocked"].get(t, 0.0) for t in stamps]
    values = sorted(v for _, v in legit)
    peak_t, peak = max(legit, key=lambda x: x[1])
    p95 = values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))]
    step = max(1, -(-len(legit) // 120))  # at most ~120 points for the chart (bucket maximum)
    chart = [[legit[i][0], round(max(v for _, v in legit[i:i + step]), 2), round(max(blocked[i:i + step]), 2)]
             for i in range(0, len(legit), step)]
    ddos_incidents = sum(int(t.get("incidents") or 0) for t in traffic.get("threats") or []
                         if "ddos" in str(t.get("id", "")).lower())
    return {"peak": round(peak, 2), "peak_at": datetime.fromtimestamp(peak_t / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "p95": round(p95, 2), "avg": round(sum(values) / len(values), 2), "blocked_peak": round(max(blocked), 2),
            "days": traffic.get("days"), "granularity_s": int(gran_s) if gran_s else None, "points": len(legit),
            "ddos_incidents": ddos_incidents, "chart": chart}


def recommend_threshold(peak: float, factor: float, floor: int, origin_max: Optional[float]) -> Tuple[int, str]:
    target = max(floor, factor * peak)
    rec = next((v for v in DDOS_THRESHOLDS if v >= target), DDOS_THRESHOLDS[-1])
    why = f"{factor:g} x peak {peak:g} rps, minimum {floor}" + (", capped at the highest value Imperva accepts" if target > DDOS_THRESHOLDS[-1] else "")
    if origin_max and rec > origin_max:
        below = [v for v in DDOS_THRESHOLDS if v <= origin_max]
        if below:
            rec = below[-1]
            why += f", limited by origin capacity {origin_max:g} rps"
    return rec, why


def _adaptive_value(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    t = str(v).strip().lower()
    if t in ("", "none", "null"):
        return None
    if "adaptive" in t or t in ("true", "1", "yes", "on", "enabled", "enable"):
        return True
    if t in ("false", "0", "no", "off", "disabled", "disable"):
        return False
    return None


def ddos_adaptive(site: dict) -> Optional[bool]:
    """True when the DDoS threshold is adaptive (Imperva tunes it from the site's own traffic), False when a fixed
    threshold is set, None when the snapshot does not say. Read from the DDoS rule (an 'adaptive' parameter,
    or 'adaptive' in the activation mode or threshold value) and from DDoS settings elsewhere in the site."""
    r = _legacy_rules(site).get("api.threats.ddos") or {}
    for k, v in r.items():
        if "adaptive" in str(k).lower():
            got = _adaptive_value(v)
            if got is not None:
                return got
    for k in ("activation_mode", "activation_mode_text", "ddos_traffic_threshold", "ddos_traffic_threshold_text"):
        if "adaptive" in str(r.get(k) or "").lower():
            return True

    def walk(node: Any, path: str, depth: int) -> Optional[bool]:
        if depth > 4:
            return None
        if isinstance(node, dict):
            for k, v in node.items():
                key = f"{path}.{k}".lower()
                if "adaptive" in str(k).lower() and "ddos" in key and not isinstance(v, (dict, list)):
                    got = _adaptive_value(v)
                    if got is not None:
                        return got
                got = walk(v, key, depth + 1)
                if got is not None:
                    return got
        elif isinstance(node, list):
            for v in node:
                got = walk(v, path, depth + 1)
                if got is not None:
                    return got
        return None
    found = walk({k: v for k, v in site.items() if k != "security"}, "site", 0)
    if found is not None:
        return found
    return False if r.get("ddos_traffic_threshold") not in (None, "") else None


def check_ddos(site: dict, traffic: Optional[dict] = None, origin_max: Optional[float] = None,
               factor: float = DDOS_FACTOR, floor: int = DDOS_FLOOR) -> CheckResult:
    c = CheckResult(max=10)
    r = _legacy_rules(site).get("api.threats.ddos")
    if not r:
        c.issues.append(make_issue("DDOS_RULE_MISSING"))
        c.status = "missing"
        return c
    mode = str(r.get("activation_mode") or "").lower()
    label = r.get("activation_mode_text") or mode.rsplit(".", 1)[-1]
    adaptive = ddos_adaptive(site) is True
    try:
        threshold = 0 if adaptive else int(r.get("ddos_traffic_threshold") or 0)
    except (TypeError, ValueError):
        threshold = 0
    mode_off = mode.endswith(".off") or mode == "off"
    if mode_off:
        c.issues.append(make_issue("DDOS_OFF"))
    else:
        c.got = 10
    c.data = {"mode": label, "threshold": threshold or None, "origin_max_rps": origin_max, "adaptive": adaptive}
    if adaptive:
        # Imperva sets the threshold from the site's own traffic: comparing it with a fixed value makes no sense.
        profile = traffic_profile(traffic)
        if profile is not None:
            c.data["traffic"] = profile
            if profile["ddos_incidents"]:
                c.issues.append(make_issue("DDOS_ACTIVATIONS", f"{profile['ddos_incidents']} incident(s) in {profile['days']} days"))
        c.status = _status_from(c.issues)
        return c
    profile = traffic_profile(traffic)
    if profile is None:
        if traffic is not None:
            c.issues.append(make_issue("DDOS_TRAFFIC_UNAVAILABLE", (traffic or {}).get("error")))
        elif threshold > 2000:
            c.issues.append(make_issue("DDOS_HIGH_THRESHOLD", f"{threshold} requests/s"))
    else:
        rec, why = recommend_threshold(profile["peak"], factor, floor, origin_max)
        c.data.update({"traffic": profile, "recommended": rec, "recommended_why": why})
        c.max += 5
        tuning = 5
        # Coarse buckets (a day or more) average peaks away: be stricter when comparing with the threshold.
        coarse = not profile["granularity_s"] or profile["granularity_s"] >= 86400
        low_ratio = 0.5 if coarse else DDOS_LOW_RATIO
        c.data["coarse"] = coarse
        if threshold:
            ratio = profile["peak"] / threshold
            c.data["peak_ratio"] = round(ratio * 100)
            if ratio >= low_ratio:
                tuning = 0
                c.issues.append(make_issue("DDOS_THRESHOLD_LOW", f"peak {profile['peak']:g} rps on {profile['peak_at']} UTC "
                                                                f"is {ratio:.0%} of the threshold {threshold}"
                                                                + (" (multi-day averages: real peaks are higher)" if coarse else "")
                                                                + f"; recommended {rec}"))
            elif threshold > DDOS_HIGH_RATIO * rec:
                tuning = 2
                c.issues.append(make_issue("DDOS_THRESHOLD_HIGH", f"threshold {threshold}, peak {profile['peak']:g} rps, recommended {rec}"))
            elif threshold == DDOS_DEFAULT_THRESHOLD and rec != DDOS_DEFAULT_THRESHOLD:
                tuning = 4
                c.issues.append(make_issue("DDOS_DEFAULT_THRESHOLD", f"recommended {rec} for a peak of {profile['peak']:g} rps"))
            if origin_max and threshold > origin_max:
                tuning = min(tuning, 1)
                c.issues.append(make_issue("DDOS_ABOVE_ORIGIN", f"threshold {threshold}, origin capacity {origin_max:g} rps"))
        c.got += 0 if mode_off else tuning
        if profile["ddos_incidents"]:
            c.issues.append(make_issue("DDOS_ACTIVATIONS", f"{profile['ddos_incidents']} incident(s) in {profile['days']} days"))
    c.status = _status_from(c.issues)
    return c


def check_tls(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=12)
    ssl_info = site.get("ssl") or {}
    custom = ssl_info.get("custom_certificate") or {}
    generated = ssl_info.get("generated_certificate") or {}
    origin = ssl_info.get("origin_server") or {}
    data: Dict[str, Any] = {}
    has_cert = False
    if custom and _truthy(custom.get("active", True)) and custom.get("expirationDate"):
        has_cert = True
        try:
            exp = datetime.fromtimestamp(int(custom["expirationDate"]) / 1000, timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            data.update({"certificate": "custom", "expires": exp.strftime("%Y-%m-%d"), "days_left": days})
            if days < 0:
                c.issues.append(make_issue("CERT_EXPIRED", exp.strftime("%Y-%m-%d")))
            elif days <= 30:
                c.issues.append(make_issue("CERT_EXPIRING", f"{days} days, {exp:%Y-%m-%d}"))
                c.got += 3
            else:
                c.got += 6
        except (TypeError, ValueError, OSError):
            data["certificate"] = "custom (expiry unreadable)"
        errors = [k for k in ("validityError", "chainError", "hostnameMismatchError", "revocationError") if _truthy(custom.get(k))]
        if errors:
            c.issues.append(make_issue("CERT_ERROR", ", ".join(errors)))
        else:
            c.got += 3
    elif generated:
        has_cert = True
        vstatus = str(generated.get("validation_status") or "").lower()
        data.update({"certificate": f"Imperva-generated ({generated.get('ca', 'CA')})", "validation": vstatus,
                     "san": generated.get("san")})
        if vstatus in ("done", "valid", "completed"):
            c.got += 9
        else:
            c.got += 3
            c.issues.append(make_issue("CERT_VALIDATION_PENDING", vstatus or "unknown"))
    if not has_cert:
        c.issues.append(make_issue("TLS_NOT_ENABLED"))
    if origin:
        detected = _truthy(origin.get("detected"))
        data["origin_tls"] = detected
        if detected:
            c.got += 3
        elif has_cert:
            c.issues.append(make_issue("ORIGIN_NO_TLS", origin.get("detectionStatus")))
    else:
        c.max -= 3
    if probe and probe.get("addresses"):
        c.max += 3
        data.update({"hsts": probe.get("hsts"), "redirects_https": probe.get("redirects_https"),
                     "tls10": probe.get("tls10"), "tls11": probe.get("tls11"),
                     "served_tls": (probe.get("https") or {}).get("tls_version"),
                     "served_cert_days": (probe.get("https") or {}).get("cert_days")})
        if probe.get("hsts"):
            c.got += 1
        elif has_cert:
            c.issues.append(make_issue("TLS_NO_HSTS"))
        if probe.get("redirects_https"):
            c.got += 1
        elif probe.get("http_status") is not None and has_cert:
            c.issues.append(make_issue("TLS_NO_REDIRECT", f"HTTP {probe.get('http_status')}"))
        if probe.get("tls10") or probe.get("tls11"):
            c.issues.append(make_issue("TLS_LEGACY", ", ".join(v for v, k in (("TLS 1.0", "tls10"), ("TLS 1.1", "tls11")) if probe.get(k))))
        else:
            c.got += 1
        days = (probe.get("https") or {}).get("cert_days")
        if days is not None and days <= 14:
            c.issues.append(make_issue("TLS_LIVE_CERT_EXPIRING", f"{days} days"))
    c.data = data
    c.status = _status_from(c.issues)
    return c


def check_origin(site: dict, probe: Optional[dict]) -> CheckResult:
    c = CheckResult(max=0)
    c.data = {"origins": site.get("ips") or []}
    if not probe:
        c.status = "na"
        c.data["note"] = "Run with --probe to test direct access to the origin"
        return c
    c.data["results"] = probe.get("origins") or []
    serves = [o for o in c.data["results"] if o.get("result") == "serves"]
    reach = [o for o in c.data["results"] if o.get("result") == "reachable"]
    if serves:
        c.issues.append(make_issue("ORIGIN_EXPOSED", ", ".join(f"{o['ip']}:{o.get('port')} HTTP {o.get('status')}" for o in serves[:3])))
    if reach:
        c.issues.append(make_issue("ORIGIN_REACHABLE", ", ".join(f"{o['ip']}:{o.get('port')}" for o in reach[:3])))
    c.status = _status_from(c.issues) if c.data["results"] else "unknown"
    return c
