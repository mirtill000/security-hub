"""Snapshot analysis: per-endpoint results, console findings, policies view, baseline comparison, metadata."""

from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .checks import (assess_exclusion, check_health, check_policy, check_protection, check_scan, check_threats,
                     check_version, check_vulnerabilities, version_tuple)
from .constants import (CHECKS, ENGINES, FINDINGS, SCORE_CAPS, SEVERITY_RANK, STALE_DAYS, THREAT_SLA_DAYS, TIER_ALIASES,
                        TIER_WEIGHTS)
from .models import CheckResult, EndpointResult, Issue, make_issue


def latest_ga(packages: List[dict]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in packages or []:
        os_type, v = str(p.get("osType") or "").lower(), p.get("version")
        if os_type and v and str(p.get("status") or "ga").lower() == "ga":
            if os_type not in out or version_tuple(v) > version_tuple(out[os_type]):
                out[os_type] = v
    return out


def effective_policy(a: dict, policies: Dict[str, dict], groups: Dict[str, dict]) -> Tuple[Optional[dict], Optional[str]]:
    """The policy that applies to an agent: its group's when the group does not inherit, else its site's."""
    g = groups.get(str(a.get("groupId")))
    if g and g.get("inherits") is False:
        p = policies.get(f"group:{g.get('id')}")
        return p, f"group {g.get('name')}" if p else None
    p = policies.get(f"site:{a.get('siteId')}")
    return p, (f"site {a.get('siteName')}" if p else None)


def score_endpoint(r: EndpointResult, checks: List[str]) -> None:
    weighted = [(c, CHECKS[c]) for c in checks if CHECKS[c] and r.checks.get(c) and r.checks[c].max > 0
                and r.checks[c].status not in ("unknown", "na", "skipped")]
    total = sum(w for _, w in weighted)
    comps, score = {}, 0.0
    for c, w in weighted:
        ch = r.checks[c]
        frac = max(0.0, min(1.0, ch.got / ch.max))
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


def evaluate_compliance(r: EndpointResult, checks: List[str]) -> Dict[str, str]:
    st = lambda c: (r.checks.get(c) or CheckResult()).status
    out = {}
    need = ["health", "protection", "policy", "version"]
    if set(need) <= set(checks):
        if any(st(c) in ("unknown", "skipped") for c in need):
            out["edr_baseline"] = "unknown"
        else:
            out["edr_baseline"] = "pass" if all(st(c) == "valid" for c in need) else "fail"
    if {"protection", "policy"} <= set(checks):
        if r.os_type != "windows":
            out["ransomware_ready"] = "n/a"
        elif st("policy") == "unknown" or st("protection") == "unknown":
            out["ransomware_ready"] = "unknown"
        else:
            snaps = (r.checks["policy"].data or {}).get("snapshots")
            out["ransomware_ready"] = "pass" if st("protection") == "valid" and snaps is not False else "fail"
    return out


REMEDIATION = {
    "MODE_DETECT": ("Switch the policy to Protect", "Sentinels > Policy (site or group) > Mitigation mode > Malicious threats: Protect"),
    "ANTI_TAMPER_OFF": ("Enable anti-tamper", "Sentinels > Policy > Agent configuration > Anti tampering: On"),
    "ENGINE_OFF": ("Enable the detection engines", "Sentinels > Policy > Engines: turn on every engine listed in the finding"),
    "SNAPSHOTS_OFF": ("Enable VSS snapshots", "Sentinels > Policy > Agent configuration > Snapshots: On (needed for rollback)"),
    "AGENT_STALE": ("Investigate or decommission the stale agent", "Sentinels > Endpoints: filter by Last active; decommission retired machines"),
    "AGENT_DISABLED": ("Re-enable the agent", "Sentinels > Endpoints > Actions > Agent actions > Enable agent"),
    "AGENT_ACTION_NEEDED": ("Complete the pending action", "Sentinels > Endpoints > Pending actions (reboot or upgrade)"),
    "AGENT_OUTDATED": ("Upgrade the agent", "Sentinels > Endpoints > Actions > Update agent (or an upgrade policy)"),
    "AGENT_VERY_OLD": ("Upgrade the agent now", "Sentinels > Endpoints > Actions > Update agent"),
    "THREAT_ACTIVE": ("Mitigate and investigate the threat", "Incidents > Threats: open the threat > Mitigation actions; isolate the endpoint if needed"),
    "THREAT_UNRESOLVED": ("Close the incident", "Incidents > Threats: set the analyst verdict and resolve"),
    "APPS_VULNERABLE": ("Patch vulnerable applications", "Singularity Vulnerability Management / Applications: patch the listed versions"),
    "NO_FULL_SCAN": ("Run a full disk scan", "Sentinels > Endpoints > Actions > Full disk scan"),
}


def suggest_remediation(r: EndpointResult) -> List[dict]:
    seen, out = set(), []
    for i in r.issues:
        if i.code in REMEDIATION and i.code not in seen:
            seen.add(i.code)
            title, steps = REMEDIATION[i.code]
            out.append({"title": title, "type": "SentinelOne console", "name": r.domain, "value": steps,
                        "note": i.message})
    return out


def analyze_snapshot(snap: dict, checks: List[str], metadata: Dict[str, dict], inventory: Optional[List[str]] = None,
                     stale_days: int = STALE_DAYS, sla_days: int = THREAT_SLA_DAYS, now: Optional[datetime] = None
                     ) -> Tuple[List[EndpointResult], List[Issue], List[dict], dict]:
    # ages are measured at collection time: re-analyzing a saved snapshot gives the same answer
    collected = None
    try:
        collected = datetime.fromisoformat(str(snap.get("collected") or "").replace("Z", "+00:00"))
        collected = collected if collected.tzinfo else collected.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    now = now or collected or datetime.now(timezone.utc)
    policies = snap.get("policies") or {}
    groups = {str(g.get("id")): g for g in snap.get("groups") or []}
    latest = latest_ga(snap.get("packages") or [])
    threats_by_agent: Dict[str, List[dict]] = defaultdict(list)
    for t in snap.get("threats") or []:
        threats_by_agent[str(t.get("agent_id") or "")].append(t)
    scan_date = snap.get("collected", "")
    results: List[EndpointResult] = []
    usage: Counter = Counter()
    agents = [a for a in snap.get("agents") or [] if not (a.get("isDecommissioned") or a.get("isUninstalled"))]
    for a in agents:
        host = str(a.get("computerName") or a.get("id") or "?")
        r = EndpointResult(site_id=str(a.get("id") or ""), domain=host.lower(), account_id=str(a.get("siteId") or ""),
                           account_name=str(a.get("siteName") or ""), group_name=str(a.get("groupName") or ""),
                           os=str(a.get("osName") or a.get("osType") or ""), os_type=str(a.get("osType") or "").lower(),
                           machine_type=str(a.get("machineType") or ""), agent_version=str(a.get("agentVersion") or ""),
                           scan_date=scan_date)
        meta = metadata.get(r.domain) or metadata.get(r.domain.split(".")[0]) or metadata.get(r.group_name.lower()) \
            or metadata.get(r.account_name.lower()) or {}
        r.tier, r.owner, r.bu, r.tags = meta.get("tier", "medium"), meta.get("owner", ""), meta.get("bu", ""), list(meta.get("tags", []))
        policy, scope = effective_policy(a, policies, groups)
        if scope:
            pid = f"group:{a.get('groupId')}" if scope.startswith("group") else f"site:{a.get('siteId')}"
            r.policies = [{"id": pid, "name": scope, "type": scope.split()[0], "enabled": True}]
            usage[pid] += 1
        builders = {
            "health": lambda: check_health(a, now, stale_days),
            "protection": lambda: check_protection(a),
            "policy": lambda: check_policy(a, policy, scope),
            "version": lambda: check_version(a, latest),
            "threats": lambda: check_threats(a, threats_by_agent.get(r.site_id, []), now, sla_days),
            "vulnerabilities": lambda: check_vulnerabilities(a),
            "scan": lambda: check_scan(a),
        }
        for c in checks:
            try:
                r.checks[c] = builders[c]()
            except Exception as e:  # never lose an endpoint because of unexpected data
                r.checks[c] = CheckResult(status="unknown", issues=[make_issue("API_ERROR", f"{c}: {type(e).__name__}: {e}")])
        health = r.checks.get("health")
        if health is not None and any(i.code == "AGENT_STALE" for i in health.issues):
            # The agent has not reported for stale_days: what the console shows for it is its last known state, which may
            # change when it comes back online. Only the stale agent is reported; the other checks are not evaluated.
            health.issues = [i for i in health.issues if i.code == "AGENT_STALE"]
            for c in checks:
                if c != "health":
                    ch = r.checks[c]
                    r.checks[c] = CheckResult(status="unknown", max=ch.max, data={**(ch.data or {}), "not_evaluated":
                                              f"agent not seen for {(health.data or {}).get('last_seen_days')} days"})
        r.issues = sorted((i for c in checks for i in r.checks[c].issues), key=lambda i: SEVERITY_RANK.get(i.severity, 9))
        codes = {i.code for i in r.issues}
        r.profile = ("disabled" if "AGENT_DISABLED" in codes else "stale" if "AGENT_STALE" in codes
                     else "threat" if "THREAT_ACTIVE" in codes else "detect" if "MODE_DETECT" in codes else "protected")
        score_endpoint(r, checks)
        r.compliance = evaluate_compliance(r, checks)
        r.remediation = suggest_remediation(r)
        crit = sum(1 for i in r.issues if i.severity == "critical")
        r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
        results.append(r)
    results.sort(key=lambda x: (-x.priority, x.domain))

    account: List[Issue] = []
    for e in snap.get("errors") or []:
        account.append(make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}"))
    exclusions = []
    for x in snap.get("exclusions") or []:
        risk = assess_exclusion(x)
        exclusions.append({**{k: x.get(k) for k in ("id", "type", "value", "mode", "pathExclusionType", "osType", "description",
                                                     "scopeName", "scope", "userName", "createdAt")},
                           "risk": FINDINGS[risk[0]][0] if risk else None, "risk_code": risk[0] if risk else None,
                           "reason": risk[1] if risk else ""})
    for code in ("EXCLUSION_BROAD", "EXCLUSION_ALL_MONITORS", "EXCLUSION_RISKY"):
        hits = [x for x in exclusions if x["risk_code"] == code]
        if hits:
            account.append(make_issue(code, f"{len(hits)}: " + "; ".join(x["reason"] for x in hits[:3])
                                      + (" and others" if len(hits) > 3 else "")))
    undocumented = [x for x in exclusions if not (x.get("description") or "").strip()]
    if undocumented:
        account.append(make_issue("EXCLUSION_NO_DESCRIPTION", f"{len(undocumented)} of {len(exclusions)}"))

    policy_rows = []
    site_names = {str(s.get("id")): s.get("name") for s in snap.get("sites") or []}
    for pid, p in policies.items():
        kind, _, ident = pid.partition(":")
        name = site_names.get(ident) if kind == "site" else (groups.get(ident) or {}).get("name")
        off = [ENGINES.get(k, k) for k, v in (p.get("engines") or {}).items() if str(v).lower() == "off"]
        row = {"id": pid, "name": name or ident, "type": kind, "mode": p.get("mitigationMode"),
               "suspicious_mode": p.get("mitigationModeSuspicious"), "anti_tamper": p.get("antiTamperingOn"),
               "snapshots": p.get("snapshotsOn"), "engines_off": off, "auto_mitigation": p.get("autoMitigationAction"),
               "in_scan": usage.get(pid, 0)}
        policy_rows.append(row)
        if str(p.get("mitigationMode") or "").lower() == "detect":
            account.append(make_issue("POLICY_DETECT", f"{kind} {row['name']} ({usage.get(pid, 0)} endpoints)"))
        if p.get("antiTamperingOn") is False:
            account.append(make_issue("POLICY_ANTI_TAMPER_OFF", f"{kind} {row['name']}"))

    names = Counter(r.domain for r in results)
    dup = [n for n, k in names.items() if k > 1]
    if dup:
        account.append(make_issue("AGENTS_DUPLICATE", f"{len(dup)}: {', '.join(sorted(dup)[:5])}"))
    very_stale = [r for r in results if (((r.checks.get("health") or CheckResult()).data or {}).get("last_seen_days") or 0) > 90]
    if very_stale:
        account.append(make_issue("AGENTS_STALE_MANY", f"{len(very_stale)} not seen for more than 90 days"))
    coverage = None
    if inventory is not None:
        have = {r.domain for r in results} | {r.domain.split(".")[0] for r in results}
        missing = sorted(h for h in inventory if h not in have and h.split(".")[0] not in have)
        coverage = {"inventory": len(inventory), "covered": len(inventory) - len(missing), "missing": missing}
        if missing:
            account.append(make_issue("COVERAGE_GAP", f"{len(missing)} of {len(inventory)}: {', '.join(missing[:5])}"
                                      + (" and others" if len(missing) > 5 else "")))
    account.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
    return results, account, policy_rows, {"coverage": coverage, "exclusions": exclusions}


def compute_diff(results: List[EndpointResult], baseline_path: str) -> dict:
    with open(baseline_path, encoding="utf-8") as f:
        raw = json.load(f)
    items = raw.get("results", raw) if isinstance(raw, dict) else raw
    base = {str(d.get("site_id") or d.get("domain")): d for d in items if isinstance(d, dict)}
    summary = {"baseline": os.path.basename(baseline_path), "baseline_date": max((str(d.get("scan_date", "")) for d in base.values()), default=""),
               "improved": 0, "worsened": 0, "unchanged": 0, "new_domains": [], "removed_domains": [], "new_critical": 0}
    current = set()
    for r in results:
        key = r.site_id or r.domain
        current.add(key)
        b = base.get(key)
        if b is None:
            r.change = {"new": True, "changed": True, "score_delta": None, "status_changes": [], "new_issues": [], "resolved_issues": []}
            summary["new_domains"].append(r.domain)
            continue
        delta = r.overall_score - int(b.get("overall_score") or 0)
        status_changes = []
        for c, ch in r.checks.items():
            before = ((b.get("checks") or {}).get(c) or {}).get("status")
            if before and before != ch.status and "skipped" not in (before, ch.status):
                status_changes.append({"check": c, "from": before, "to": ch.status})
        now_codes, old_codes = {i.code for i in r.issues}, {i.get("code") for i in b.get("issues") or []}
        new, resolved = sorted(now_codes - old_codes), sorted(old_codes - now_codes - {None})
        summary["new_critical"] += len({i.code for i in r.issues if i.severity == "critical"} & set(new))
        changed = bool(delta or status_changes or new or resolved)
        r.change = {"new": False, "changed": changed, "score_delta": delta, "previous_score": b.get("overall_score"),
                    "status_changes": status_changes, "new_issues": new, "resolved_issues": resolved}
        summary["improved" if delta > 0 else "worsened" if delta < 0 else "unchanged"] += 1
    summary["removed_domains"] = sorted(str(base[k].get("domain")) for k in set(base) - current)[:200]
    return summary


def _read_table(path: str) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        return []
    try:
        dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO("\n".join(lines)), dialect=dialect))
    head = [h.strip().lower() for h in rows[0]]
    hosts = {"hostname", "host", "computer", "computername", "name", "device", "endpoint", "fqdn", "group", "site"}
    if not set(head) & hosts:  # no header: one host per line
        return [{"hostname": r[0].strip()} for r in rows if r and r[0].strip()]
    return [{h: (r[i].strip() if i < len(r) else "") for i, h in enumerate(head)} for r in rows[1:]]


def load_inventory(path: str) -> List[str]:
    """Host names expected to have an agent (CMDB / AD export): CSV with a hostname column, or one per line."""
    out: Set[str] = set()
    for row in _read_table(path):
        h = next((row[k] for k in ("hostname", "host", "computer", "computername", "name", "device", "endpoint", "fqdn")
                  if row.get(k)), "")
        if h:
            out.add(h.strip().lower())
    return sorted(out)


def load_metadata(path: str) -> Dict[str, dict]:
    """hostname / group / site -> tier, owner, bu, tags."""
    out: Dict[str, dict] = {}
    for row in _read_table(path):
        key = next((row[k] for k in ("hostname", "host", "computer", "computername", "name", "group", "site") if row.get(k)), "")
        if not key:
            continue
        tier = (row.get("tier") or "medium").strip().lower()
        out[key.lower()] = {"tier": TIER_ALIASES.get(tier, tier if tier in TIER_WEIGHTS else "medium"),
                            "owner": row.get("owner", ""), "bu": row.get("bu", ""),
                            "tags": [t.strip() for t in (row.get("tags") or "").split("|") if t.strip()]}
    return out

