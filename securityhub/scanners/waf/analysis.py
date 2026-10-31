"""Snapshot analysis, baseline comparison and website metadata."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter
from typing import Dict, List, Tuple

from .checks import (_enrich_policies, check_allowlist, check_bots, check_ddos, check_onboarding, check_origin,
                     check_tls, check_waf)
from .constants import ACTION_LABELS, CORE_RULES, DDOS_FACTOR, DDOS_FLOOR, SEVERITY_RANK, TIER_ALIASES, TIER_WEIGHTS
from .models import CheckResult, Issue, SiteResult, make_issue
from .remediation import suggest_remediation
from .scoring import evaluate_compliance, score_site


def analyze_snapshot(snap: dict, checks: List[str], probes: Dict[str, dict], metadata: Dict[str, dict],
                     ddos_factor: float = DDOS_FACTOR, ddos_floor: int = DDOS_FLOOR
                     ) -> Tuple[List[SiteResult], List[Issue], List[dict]]:
    results: List[SiteResult] = []
    account_issues: List[Issue] = []
    policy_rows: List[dict] = []
    scan_date = snap.get("collected", "")
    for acc in snap.get("accounts", []):
        acc_policies = {p.get("id"): p for p in acc.get("policies") or []}
        usage = Counter()
        sites_without_policy = []
        for site in acc.get("sites") or []:
            sid = str(site.get("site_id"))
            applied_raw = (acc.get("asset_policies") or {}).get(sid)
            policies = _enrich_policies(applied_raw, acc_policies)
            for p in policies:
                usage[p.get("id")] += 1
            r = SiteResult(site_id=int(site.get("site_id") or 0), domain=str(site.get("domain") or site.get("display_name") or sid).lower(),
                           account_id=acc.get("account_id"), account_name=acc.get("name") or "",
                           status_text=str(site.get("status") or ""), active=str(site.get("active") or ""), scan_date=scan_date)
            meta = metadata.get(sid) or metadata.get(r.domain) or {}
            r.tier, r.owner, r.bu, r.tags = meta.get("tier", "medium"), meta.get("owner", ""), meta.get("bu", ""), list(meta.get("tags", []))
            r.policies = [{"id": p.get("id"), "name": p.get("name"), "type": p.get("policyType"),
                           "enabled": p.get("enabled") is not False} for p in policies]
            if applied_raw == [] or (applied_raw is not None and not policies):
                sites_without_policy.append(r.domain)
            probe = probes.get(sid)
            r.probed = probe is not None
            builders = {"onboarding": lambda: check_onboarding(site, probe), "waf": lambda: check_waf(site, policies),
                        "allowlist": lambda: check_allowlist(site, policies), "bots": lambda: check_bots(site),
                        "ddos": lambda: check_ddos(site, (acc.get("traffic") or {}).get(sid), meta.get("max_rps"),
                                                   ddos_factor, ddos_floor),
                        "tls": lambda: check_tls(site, probe),
                        "origin": lambda: check_origin(site, probe)}
            for cname in checks:
                try:
                    r.checks[cname] = builders[cname]()
                except Exception as e:  # never lose a site because of unexpected data
                    r.checks[cname] = CheckResult(status="unknown", issues=[make_issue("API_ERROR", f"{cname}: {type(e).__name__}: {e}")])
            problem = (acc.get("site_errors") or {}).get(sid)
            r.issues = [i for cname in checks for i in r.checks[cname].issues]
            if problem:
                r.error = problem
                r.issues.append(make_issue("API_ERROR", problem))
            r.issues.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
            r.profile = ("bypass" if r.active.lower() == "bypass" else
                         "error" if r.error else
                         "onboarding" if r.status_text.lower().replace("-", "_") != "fully_configured" else "protected")
            score_site(r, checks)
            r.compliance = evaluate_compliance(r, checks)
            r.remediation = suggest_remediation(r)
            crit = sum(1 for i in r.issues if i.severity == "critical")
            r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
            results.append(r)

        # account-level hygiene
        waf_policies = [p for p in acc_policies.values() if p.get("policyType") == "WAF_RULES"]
        if waf_policies and not any(p.get("isMarkedAsDefault") or p.get("defaultPolicyConfig") for p in waf_policies):
            account_issues.append(make_issue("ACCOUNT_NO_DEFAULT_WAF", f"account {acc.get('account_id')}"))
        disabled = [str(p.get("name")) for p in acc_policies.values() if p.get("enabled") is False]
        if disabled:
            account_issues.append(make_issue("ACCOUNT_DISABLED_POLICIES", ", ".join(disabled[:5]) + (" ..." if len(disabled) > 5 else "")))
        unused = [str(p.get("name")) for p in acc_policies.values()
                  if (p.get("numberOfAssets") == 0 if p.get("numberOfAssets") is not None else usage[p.get("id")] == 0)]
        if unused:
            account_issues.append(make_issue("ACCOUNT_UNUSED_POLICIES", f"{len(unused)}: " + ", ".join(unused[:5])))
        if sites_without_policy:
            account_issues.append(make_issue("ACCOUNT_SITES_WITHOUT_POLICY", f"{len(sites_without_policy)}: " + ", ".join(sites_without_policy[:5])))
        for p in acc_policies.values():
            settings = p.get("policySettings") or []
            summary = ", ".join(f"{CORE_RULES.get(s.get('policySettingType'), s.get('policySettingType'))} "
                                f"{ACTION_LABELS.get(str(s.get('settingsAction') or '').upper(), s.get('settingsAction'))}"
                                for s in settings[:6])
            policy_rows.append({"id": p.get("id"), "name": p.get("name"), "type": p.get("policyType"),
                                "enabled": p.get("enabled") is not False,
                                "default": bool(p.get("isMarkedAsDefault") or p.get("defaultPolicyConfig")),
                                "assets": p.get("numberOfAssets") if p.get("numberOfAssets") is not None else usage[p.get("id")],
                                "in_scan": usage[p.get("id")], "settings": summary,
                                "exceptions": sum(len(s.get("policyDataExceptions") or []) for s in settings),
                                "modified": str(p.get("lastModified") or "")[:10], "modified_by": p.get("lastUserModified") or "",
                                "account": acc.get("account_id")})
    for e in snap.get("errors") or []:
        account_issues.append(make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}"))
    seen, unique = set(), []
    for i in account_issues:  # sub-accounts that inherit the parent's policies report the same items
        if (i.code, i.message) not in seen:
            seen.add((i.code, i.message))
            unique.append(i)
    account_issues = sorted(unique, key=lambda i: SEVERITY_RANK.get(i.severity, 9))
    seen_p, rows = set(), []
    for p in policy_rows:
        if p["id"] not in seen_p:
            seen_p.add(p["id"])
            rows.append(p)
    policy_rows = rows
    return results, account_issues, policy_rows


def compute_diff(results: List[SiteResult], baseline_path: str) -> dict:
    with open(baseline_path, encoding="utf-8") as f:
        raw = json.load(f)
    items = raw.get("results", raw) if isinstance(raw, dict) else raw
    base = {str(d.get("site_id") or d.get("domain")): d for d in items if isinstance(d, dict)}
    summary = {"baseline": os.path.basename(baseline_path), "baseline_date": max((str(d.get("scan_date", "")) for d in base.values()), default=""),
               "improved": 0, "worsened": 0, "unchanged": 0, "new_domains": [], "removed_domains": [], "new_critical": 0}
    seen = set()
    for r in results:
        key = str(r.site_id)
        seen.add(key)
        b = base.get(key)
        if b is None:
            r.change = {"new": True, "changed": True, "score_delta": None, "status_changes": [], "new_issues": [], "resolved_issues": []}
            summary["new_domains"].append(r.domain)
            continue
        delta = r.overall_score - int(b.get("overall_score") or 0)
        changes = []
        for cname, ch in r.checks.items():
            before = ((b.get("checks") or {}).get(cname) or {}).get("status")
            if before and before != ch.status and "skipped" not in (before, ch.status):
                changes.append({"check": cname, "from": before, "to": ch.status})
        now = {i.code for i in r.issues}
        old = {i.get("code") for i in b.get("issues") or []}
        new_i, res_i = sorted(now - old), sorted(old - now)
        summary["new_critical"] += len({i.code for i in r.issues if i.severity == "critical"} & set(new_i))
        r.change = {"new": False, "changed": bool(delta or changes or new_i or res_i), "score_delta": delta,
                    "previous_score": b.get("overall_score"), "status_changes": changes, "new_issues": new_i, "resolved_issues": res_i}
        summary["improved" if delta > 0 else "worsened" if delta < 0 else "unchanged"] += 1
    summary["removed_domains"] = sorted(str(base[k].get("domain", k)) for k in set(base) - seen)
    return summary


def load_metadata(path: str) -> Dict[str, dict]:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0], delimiters=",;\t")
    except (csv.Error, IndexError):
        dialect = csv.excel
    out: Dict[str, dict] = {}
    for row in csv.DictReader(io.StringIO(text), dialect=dialect):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        key = row.get("site_id") or row.get("domain") or row.get("dominio") or ""
        if not key:
            continue
        try:
            max_rps = float(row.get("max_rps") or row.get("origin_max_rps") or 0) or None
        except ValueError:
            max_rps = None
        out[key.lower()] = {"max_rps": max_rps,
                            "tier": TIER_ALIASES.get(row.get("tier", row.get("criticality", "")).lower(), "medium"),
                            "owner": row.get("owner", row.get("referente", "")), "bu": row.get("bu", row.get("business_unit", "")),
                            "tags": [t.strip() for t in re.split(r"[|,;]", row.get("tags", "")) if t.strip()]}
    return out
