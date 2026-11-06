"""PRA analysis: one result per object (users, vendor users, assets, gateways, API accounts, vault accounts)
with the checks that apply to its kind, site-level findings and session statistics."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..edr.analysis import compute_diff
from ..sap_ias.analysis import parse_time
from .constants import (ALL_OBJECTS_LIMIT, ASSET_TYPES, CHECKS, FINDINGS, INACTIVE_DAYS, KINDS, NEVER_USED_GRACE_DAYS,
                        SCORE_CAPS, SEVERITY_RANK, TIER_WEIGHTS)
from .models import CheckResult, Issue, ObjectResult, make_issue

__all__ = ["analyze_snapshot", "compute_diff"]

TUNNELS = {t for t in ASSET_TYPES if "tunnel" in t}
SAML_LIKE = {"saml", "ldap", "kerberos", "radius", "scim"}


def _days(v, now: datetime) -> Optional[int]:
    t = parse_time(v)
    return None if t is None else (now - t).days


def _check(issues: List[Issue], key: str, applicable: bool = True, data: Optional[dict] = None) -> CheckResult:
    c = CheckResult(status="valid" if applicable else "na", max=CHECKS[key], data=data or {}, issues=issues if applicable else [])
    if applicable:
        sev = {i.severity for i in issues}
        c.status = "error" if "critical" in sev else "warning" if "warning" in sev else "valid"
        c.got = {"valid": 1.0, "warning": 0.5, "error": 0.0}[c.status] * c.max
    return c


def _score(r: ObjectResult) -> None:
    weighted = [(c, CHECKS[c]) for c in r.checks if r.checks[c].status not in ("na", "unknown", "skipped")]
    total = sum(w for _, w in weighted)
    comps, score = {}, 0.0
    for c, w in weighted:
        frac = r.checks[c].got / r.checks[c].max if r.checks[c].max else 1.0
        comps[c] = {"got": round(frac * w, 1), "max": w}
        score += frac * w
    score = int(round(100 * score / total)) if total else 100
    cap = None
    for i in r.issues:
        limit = SCORE_CAPS.get(i.code)
        if limit is not None and score > limit and (cap is None or limit < cap[0]):
            cap = (limit, FINDINGS[i.code][2])
    if cap:
        score = cap[0]
    r.overall_score = score
    r.score_breakdown = {"components": comps, "max": total, "normalized": total != 100,
                         "cap": f"Capped at {cap[0]}: {cap[1]}" if cap else None, "note": None}


REMEDIATION = {
    "ADMIN_NO_MFA": ("Require MFA for the administrator", "/login > Users & Security > Users (or the group policy): Two-Factor Authentication: Require FIDO2 / TOTP"),
    "USER_NO_MFA": ("Require MFA", "/login > Users & Security > Group Policies > policy > Account settings: Two-Factor Authentication required"),
    "VENDOR_NO_MFA": ("Require MFA for vendors", "/login > Users & Security > Vendors > vendor group > Group Policy: Two-Factor Authentication required"),
    "VENDOR_NO_EXPIRY": ("Set vendor account expiration", "/login > Users & Security > Vendors > vendor group: Account Expiration"),
    "ASSET_RECORDING_OFF": ("Record the sessions", "/login > Jump > Jump Policies > policy: uncheck 'Disable Session Recordings'"),
    "ASSET_NO_POLICY": ("Assign an asset policy", "Access Console > asset > Properties: Jump Policy"),
    "ASSET_TELNET": ("Use SSH instead of Telnet", "Access Console > asset > Properties: Protocol SSH"),
    "ASSET_RDP_UNTRUSTED": ("Verify server certificates", "Access Console > asset > Properties: uncheck 'Ignore Untrusted Certificate'"),
    "API_NO_IP_WRITE": ("Restrict the API account", "/login > Management > API Configuration > account: Network Restrictions"),
    "API_NO_IP": ("Restrict the API account", "/login > Management > API Configuration > account: Network Restrictions"),
    "API_WRITE": ("Reduce the API account permissions", "/login > Management > API Configuration > account: Permissions"),
    "API_SELF_EXCESS": ("Reduce this tool's permissions", "/login > Management > API Configuration > account: keep Configuration API, "
                        "Session Reports and Vault Account Activity Reports only"),
    "VAULT_NO_ROTATION": ("Rotate the credential automatically", "/login > Vault > Account Policies: rotate after check-in and on a schedule"),
    "VAULT_CHECKOUT": ("Inject instead of checkout", "/login > Users & Security > Group Policies > policy > Vault Accounts: role Inject"),
    "USER_INACTIVE": ("Disable the inactive account", "/login > Users & Security > Users > user: uncheck Account Active"),
    "USER_NEVER_USED": ("Disable the unused account", "/login > Users & Security > Users > user: uncheck Account Active"),
    "VENDOR_INACTIVE": ("Expire the vendor account", "/login > Users & Security > Vendors > vendor group > user: disable or expire"),
}


def _remediation(r: ObjectResult) -> List[dict]:
    seen, out = set(), []
    for i in r.issues:
        if i.code in REMEDIATION and i.code not in seen:
            seen.add(i.code)
            title, steps = REMEDIATION[i.code]
            out.append({"title": title, "type": "BeyondTrust PRA", "name": r.domain, "value": steps, "note": i.message})
    return out


def analyze_snapshot(snap: dict, checks: List[str], inactive_days: int = INACTIVE_DAYS, self_client_id: Optional[str] = None,
                     limit: int = ALL_OBJECTS_LIMIT, now: Optional[datetime] = None
                     ) -> Tuple[List[ObjectResult], List[Issue], List[dict], dict]:
    now = now or parse_time(snap.get("collected")) or datetime.now(timezone.utc)
    providers = {p.get("id"): p for p in snap.get("security_providers") or []}
    jump_policies = {p.get("id"): p for p in snap.get("jump_policies") or []}
    vault_policies = {p.get("code_name"): p for p in snap.get("vault_policies") or []}
    gateways = {g.get("id"): g.get("name") for g in snap.get("gateways") or []}
    checkout_by = defaultdict(list)
    for v in snap.get("vault_roles") or []:
        if v.get("role") == "inject_and_checkout":
            checkout_by[v.get("account_id")].append(v.get("group_policy"))
    scan_date = snap.get("collected", "")
    results: List[ObjectResult] = []

    def add(kind: str, oid, name: str, detail: str, per_check: Dict[str, Tuple[bool, List[Issue], dict]], tier: str = "medium"):
        r = ObjectResult(site_id=f"{kind}:{oid}", domain=name or f"{kind} {oid}", account_id=kind, account_name=KINDS[kind],
                         kind=kind, detail=detail, scan_date=scan_date, tier=tier)
        for c in checks:
            applicable, issues, data = per_check.get(c, (False, [], {}))
            r.checks[c] = _check(issues, c, applicable, data)
        r.issues = sorted((i for c in checks for i in r.checks[c].issues), key=lambda i: SEVERITY_RANK.get(i.severity, 9))
        codes = {i.code for i in r.issues}
        r.profile = "critical" if any(i.severity == "critical" for i in r.issues) else "attention" if codes - {
            c for c in codes if FINDINGS[c][0] == "info"} else "ok"
        _score(r)
        if kind in ("user", "vendor_user", "api_account") and "authentication" in r.checks:
            r.compliance["strong_auth"] = "fail" if codes & {"USER_NO_MFA", "ADMIN_NO_MFA", "VENDOR_NO_MFA", "API_NO_IP", "API_NO_IP_WRITE"} else "pass"
        if kind == "asset" and "access_policy" in r.checks:
            r.compliance["governed_access"] = "fail" if codes & {"ASSET_NO_POLICY", "ASSET_RECORDING_OFF"} else "pass"
        r.remediation = _remediation(r)
        crit = sum(1 for i in r.issues if i.severity == "critical")
        r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
        results.append(r)
        return r

    # users
    for u in snap.get("users") or []:
        if u.get("enabled") is False:
            continue
        prov = providers.get(u.get("security_provider_id")) or {}
        ptype = str(prov.get("type") or "local").lower()
        admin = bool(u.get("perm_admin"))
        mfa = bool(u.get("two_factor_required") or u.get("two_factor_enabled") or (u.get("fido2_credential_count") or 0) > 0)
        auth: List[Issue] = []
        if not mfa and ptype not in ("saml",):   # SAML users get MFA from the IdP
            auth.append(make_issue("ADMIN_NO_MFA" if admin else "USER_NO_MFA", f"provider {prov.get('name') or ptype}"))
        if admin and ptype == "local":
            auth.append(make_issue("ADMIN_LOCAL"))
        if (u.get("failed_logins") or 0) >= 5:
            auth.append(make_issue("FAILED_LOGINS", str(u.get("failed_logins"))))
        priv = ([make_issue("USER_ADMIN")] if admin else []) + ([make_issue("USER_VAULT_ADMIN")] if u.get("perm_vault") else [])
        life: List[Issue] = []
        last = _days(u.get("last_authentication"), now)
        if last is None and (_days(u.get("created_at"), now) or 0) > NEVER_USED_GRACE_DAYS:
            life.append(make_issue("USER_NEVER_USED", f"created {str(u.get('created_at'))[:10]}"))
        elif last is not None and last > inactive_days:
            life.append(make_issue("USER_INACTIVE", f"last sign-in {last} days ago"))
        add("user", u.get("id"), u.get("username"), f"{u.get('public_display_name') or ''} · {prov.get('name') or ptype}".strip(" ·"),
            {"authentication": (True, auth, {"provider": prov.get("name") or ptype, "provider_type": ptype, "mfa": mfa,
                                             "two_factor_type": u.get("two_factor_type")}),
             "privileges": (True, priv, {"admin": admin, "vault_admin": bool(u.get("perm_vault"))}),
             "lifecycle": (True, life, {"last_sign_in": u.get("last_authentication"), "days": last, "created": u.get("created_at")})},
            tier="critical" if admin else "medium")

    # vendor users
    for v in snap.get("vendor_users") or []:
        if v.get("enabled") is False:
            continue
        mfa = bool(v.get("two_factor_enabled") or (v.get("fido2_credential_count") or 0) > 0)
        auth = [] if mfa else [make_issue("VENDOR_NO_MFA", v.get("vendor"))]
        life: List[Issue] = []
        if not v.get("account_expiration"):
            life.append(make_issue("VENDOR_NO_EXPIRY", v.get("vendor")))
        last = _days(v.get("last_authenticated_date"), now)
        if last is not None and last > inactive_days:
            life.append(make_issue("VENDOR_INACTIVE", f"last sign-in {last} days ago"))
        add("vendor_user", v.get("id"), v.get("username"), f"{v.get('public_display_name') or ''} · vendor {v.get('vendor') or ''}".strip(" ·"),
            {"authentication": (True, auth, {"mfa": mfa}),
             "privileges": (True, [make_issue("VENDOR_ADMIN")] if v.get("vendor_administrator") else [], {"vendor_admin": v.get("vendor_administrator")}),
             "lifecycle": (True, life, {"expires": v.get("account_expiration"), "last_sign_in": v.get("last_authenticated_date"),
                                        "days": last, "vendor": v.get("vendor")})},
            tier="high")

    # assets
    for a in snap.get("assets") or []:
        pol = jump_policies.get(a.get("jump_policy_id"))
        acc: List[Issue] = []
        if not pol:
            acc.append(make_issue("ASSET_NO_POLICY"))
        else:
            if pol.get("recordings_disabled"):
                acc.append(make_issue("ASSET_RECORDING_OFF", pol.get("display_name")))
            if not pol.get("approval_required"):
                acc.append(make_issue("ASSET_NO_APPROVAL", pol.get("display_name")))
            if not pol.get("two_factor_challenge_required"):
                acc.append(make_issue("ASSET_NO_MFA_CHALLENGE", pol.get("display_name")))
            if not pol.get("schedule_enabled"):
                acc.append(make_issue("ASSET_NO_SCHEDULE", pol.get("display_name")))
        if a.get("jump_group_type") == "personal":
            acc.append(make_issue("ASSET_PERSONAL"))
        exp: List[Issue] = []
        if str(a.get("protocol") or "").lower() == "telnet":
            exp.append(make_issue("ASSET_TELNET", a.get("hostname")))
        if a.get("ignore_untrusted"):
            exp.append(make_issue("ASSET_RDP_UNTRUSTED", a.get("hostname")))
        if a.get("type") in TUNNELS:
            exp.append(make_issue("ASSET_TUNNEL", ASSET_TYPES.get(a.get("type"))))
        add("asset", f"{a.get('type')}:{a.get('id')}", a.get("name"),
            f"{ASSET_TYPES.get(a.get('type'), a.get('type'))} · {a.get('hostname') or ''} · gateway {gateways.get(a.get('jumpoint_id'), '-')}",
            {"access_policy": (True, acc, {"policy": (pol or {}).get("display_name"), "recording": not (pol or {}).get("recordings_disabled") if pol else None,
                                           "approval": (pol or {}).get("approval_required"), "schedule": (pol or {}).get("schedule_enabled"),
                                           "mfa_challenge": (pol or {}).get("two_factor_challenge_required"), "group_type": a.get("jump_group_type")}),
             "exposure": (True, exp, {"type": ASSET_TYPES.get(a.get("type")), "host": a.get("hostname"), "protocol": a.get("protocol"),
                                      "tag": a.get("tag")})})

    # gateways
    for g in snap.get("gateways") or []:
        if g.get("enabled") is False:
            continue
        exp = []
        if g.get("connected") is False:
            exp.append(make_issue("GATEWAY_OFFLINE"))
        if g.get("clustered") is False:
            exp.append(make_issue("GATEWAY_SINGLE_NODE"))
        if g.get("jzp_enabled") and g.get("jzp_client_address_restrictions_type") in ("no_restriction", "allow_all"):
            exp.append(make_issue("GATEWAY_PROXY_OPEN"))
        add("gateway", g.get("id"), g.get("name"), f"{g.get('platform') or ''} · {'connected' if g.get('connected') else 'not connected'}",
            {"exposure": (True, exp, {"connected": g.get("connected"), "clustered": g.get("clustered"), "proxy": g.get("jzp_enabled")})},
            tier="high")

    # API accounts
    for k in snap.get("api_accounts") or []:
        if k.get("enabled") is False:
            continue
        write = [p for p, on in (("Command API full access", k.get("perm_command") == "full_access"), ("Backup API", k.get("perm_backup")),
                                 ("Vault encryption key", k.get("perm_vault_backup")), ("Manage Vault Accounts", k.get("perm_configuration_vault_account")),
                                 ("SCIM API", k.get("perm_scim")), ("Endpoint Credential Manager", k.get("perm_ecm"))) if on]
        writes_config = bool(k.get("perm_configuration")) or bool(write)
        auth = []
        if not str(k.get("ip_addresses") or "").strip():
            auth.append(make_issue("API_NO_IP_WRITE" if writes_config else "API_NO_IP"))
        priv = [make_issue("API_WRITE", ", ".join(write))] if write else []
        if self_client_id and k.get("client_id") == self_client_id:
            extra = [n for n, on in (("License Usage Reports", k.get("perm_reporting_license")), ("Syslog Reports", k.get("perm_reporting_syslog")),
                                     ("Duplicate Jump Client Reports", k.get("perm_reporting_duplicate_jump_client"))) if on] + write
            if extra:
                priv.append(make_issue("API_SELF_EXCESS", ", ".join(extra)))
        add("api_account", k.get("id"), k.get("name"), "this tool" if self_client_id and k.get("client_id") == self_client_id else "API account",
            {"authentication": (True, auth, {"allow_list": k.get("ip_addresses") or ""}),
             "privileges": (True, priv, {"command": k.get("perm_command"), "configuration": k.get("perm_configuration"),
                                         "sensitive": write})}, tier="high")

    # vault accounts
    for va in snap.get("vault_accounts") or []:
        pol = vault_policies.get(va.get("account_policy"))
        life: List[Issue] = []
        if pol is not None:
            if not pol.get("auto_rotate_credentials") and not pol.get("scheduled_password_rotation"):
                life.append(make_issue("VAULT_NO_ROTATION", pol.get("name")))
            elif pol.get("scheduled_password_rotation") and (pol.get("maximum_password_age") or 0) > 90:
                life.append(make_issue("VAULT_LONG_ROTATION", f"{pol.get('maximum_password_age')} days"))
            if pol.get("allow_simultaneous_checkout"):
                life.append(make_issue("VAULT_SHARED_USE"))
        priv = [make_issue("VAULT_CHECKOUT", ", ".join(sorted(set(checkout_by[va.get("id")]))))] if checkout_by.get(va.get("id")) else []
        add("vault_account", va.get("id"), va.get("name"), f"{va.get('type') or ''}{' · personal' if va.get('personal') else ''}",
            {"lifecycle": (pol is not None, life, {"policy": (pol or {}).get("name") or va.get("account_policy") or "default"}),
             "privileges": (True, priv, {"checkout_groups": checkout_by.get(va.get("id"), [])})})

    # site level
    account: List[Issue] = [make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}") for e in snap.get("errors") or []]
    idp = [p for p in providers.values() if p.get("enabled") and p.get("user_authentication") and str(p.get("type")).lower() in SAML_LIKE]
    if providers and not idp:
        account.append(make_issue("LOCAL_AUTH_ONLY"))
    weak = [g.get("name") for g in snap.get("group_policies") or []
            if g.get("perm_access_allowed") and g.get("access_perm_status") != "not_defined" and g.get("two_factor_type") in (None, "optional")]
    if weak:
        account.append(make_issue("POLICY_MFA_OPTIONAL", f"{len(weak)}: {', '.join(weak[:4])}"))
    noexp = [v.get("name") for v in snap.get("vendors") or [] if not v.get("account_expiration")]
    if noexp:
        account.append(make_issue("VENDOR_GROUP_NO_EXPIRY", ", ".join(noexp[:5])))
    noappr = [v.get("name") for v in snap.get("vendors") or [] if v.get("user_approval_enabled") is False]
    if noappr:
        account.append(make_issue("VENDOR_GROUP_NO_APPROVAL", ", ".join(noappr[:5])))
    sessions = snap.get("sessions")
    sess_stats = None
    if sessions is not None:
        vendors = {v.get("username") for v in snap.get("vendor_users") or []}
        unrec = [s for s in sessions if not s.get("recorded")]
        ft = [s for s in sessions if s.get("file_transfers")]
        sess_stats = {"total": len(sessions), "unrecorded": len(unrec), "file_transfers": len(ft),
                      "by_vendors": sum(1 for s in sessions if set(s.get("users") or []) & vendors),
                      "days": (snap.get("session_window") or {}).get("days"),
                      "top_users": Counter(s.get("owner") for s in sessions if s.get("owner")).most_common(10),
                      "top_endpoints": Counter(s.get("endpoint") for s in sessions if s.get("endpoint")).most_common(10)}
        if unrec:
            account.append(make_issue("SESSIONS_UNRECORDED", f"{len(unrec)} of {len(sessions)}"))
        if ft:
            account.append(make_issue("SESSIONS_FILE_TRANSFER", f"{len(ft)} session{'s' if len(ft) != 1 else ''}"))
    account.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
    results.sort(key=lambda x: (-x.priority, x.domain))
    kinds = Counter(r.kind for r in results)
    limited = len(results) > limit
    if limited:
        results = [r for r in results if any(i.severity in ("critical", "warning") for i in r.issues)]
    totals = {"objects": dict(kinds), "listed": len(results), "limited": limited, "sessions": sess_stats,
              "users_disabled": sum(1 for u in snap.get("users") or [] if u.get("enabled") is False)}
    return results, account, [], {"totals": totals}
