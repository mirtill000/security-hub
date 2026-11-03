"""Per-user identity checks and tenant-level findings for SAP Cloud Identity Services."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Set, Tuple

from ..edr.analysis import compute_diff  # same result shape: keyed by site_id (here the SCIM user id)
from .constants import (ALL_USERS_LIMIT, CHECKS, FAILED_LOGIN_ALERT, FINDINGS, INACTIVE_DAYS, NEVER_USED_GRACE_DAYS,
                        PASSWORD_MAX_DAYS, SCORE_CAPS, SEVERITY_RANK, TIER_WEIGHTS)
from .models import CheckResult, Issue, UserResult, make_issue

__all__ = ["analyze_snapshot", "compute_diff", "parse_time"]

PASSWORD_ON = {"enabled", "initial", "active", "new"}
PASSWORD_OFF = {"disabled", "inactive", "deleted", "none"}


def parse_time(v) -> Optional[datetime]:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):  # epoch milliseconds
        return datetime.fromtimestamp(v / 1000, timezone.utc)
    try:
        t = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _days(v, now: datetime) -> Optional[int]:
    t = parse_time(v)
    return None if t is None else (now - t).days


def password_state(u: dict) -> Optional[bool]:
    st = str((u.get("password") or {}).get("status") or "").lower()
    return True if st in PASSWORD_ON else False if st in PASSWORD_OFF else None


def _finish(c: CheckResult, key: str) -> CheckResult:
    c.max = CHECKS[key]
    if c.status in ("unknown", "na", "skipped"):
        return c
    sev = {i.severity for i in c.issues}
    c.status = "error" if "critical" in sev else "warning" if "warning" in sev else "valid"
    c.got = {"valid": 1.0, "warning": 0.5, "error": 0.0}[c.status] * c.max
    return c


def check_signin(u: dict, privileged: bool, password_types: Set[str]) -> CheckResult:
    c = CheckResult(status="valid")
    pw = password_state(u)
    c.data = {"password_status": (u.get("password") or {}).get("status"), "privileged": privileged}
    if pw is None:
        c.status = "unknown"
    elif pw and privileged:
        c.issues.append(make_issue("PASSWORD_LOGIN_PRIVILEGED", ", ".join(u.get("privileged_groups") or [])))
    elif pw and str(u.get("userType") or "").lower() not in password_types:
        c.issues.append(make_issue("PASSWORD_LOGIN", f"password {c.data['password_status']}"))
    elif pw:
        c.data["expected"] = True  # user type that is expected to use IAS passwords (e.g. suppliers)
    return _finish(c, "signin")


def check_mfa(u: dict) -> CheckResult:
    c = CheckResult(status="valid")
    pw = password_state(u)
    mfa = u.get("mfa")
    c.data = {"mfa": mfa}
    if pw is False:
        c.status = "na"   # signs in through the corporate IdP: MFA is enforced there
    elif mfa is None:
        c.status = "unknown"
    elif str(mfa).lower() in ("false", "0", "no", "disabled", "none"):
        c.issues.append(make_issue("PASSWORD_NO_MFA"))
    return _finish(c, "mfa")


def check_password(u: dict, now: datetime, max_days: int) -> CheckResult:
    c = CheckResult(status="valid")
    p = u.get("password") or {}
    if password_state(u) is not True:
        c.status = "na" if password_state(u) is False else "unknown"
        return _finish(c, "password")
    age = _days(p.get("setTime"), now)
    policy = str(p.get("policy") or "")
    failed = p.get("failedLoginAttempts")
    c.data = {"age_days": age, "policy": policy, "failed": failed, "status": p.get("status")}
    if str(p.get("status") or "").lower() == "initial" and (_days(u.get("created"), now) or 0) > NEVER_USED_GRACE_DAYS:
        c.issues.append(make_issue("PASSWORD_INITIAL", f"account created {str(u.get('created'))[:10]}"))
    elif age is not None and age > max_days:
        c.issues.append(make_issue("PASSWORD_OLD", f"{age} days"))
    low = policy.lower()
    if low and "enterprise" not in low and ("/web/" in low or "standard" in low):
        c.issues.append(make_issue("PASSWORD_STANDARD_POLICY", policy.rsplit("/", 2)[-2] if "/" in policy else policy))
    try:
        if failed is not None and int(failed) >= FAILED_LOGIN_ALERT:
            c.issues.append(make_issue("FAILED_LOGINS", str(failed)))
    except (TypeError, ValueError):
        pass
    if p.get("locked") is True or str(u.get("status") or "").lower() == "locked":
        c.issues.append(make_issue("LOCKED"))
    return _finish(c, "password")


def check_activity(u: dict, now: datetime, inactive_days: int, last_login_visible: bool) -> CheckResult:
    c = CheckResult(status="valid")
    last = _days(u.get("lastLogin"), now)
    c.data = {"last_login": u.get("lastLogin"), "days": last, "created": u.get("created")}
    if last is None and not last_login_visible:
        c.status = "unknown"
    elif last is None:
        created = _days(u.get("created"), now)
        if created is not None and created > NEVER_USED_GRACE_DAYS:
            c.issues.append(make_issue("NEVER_USED", f"created {str(u.get('created'))[:10]}"))
    elif last > inactive_days:
        c.issues.append(make_issue("INACTIVE", f"last sign-in {last} days ago"))
    return _finish(c, "activity")


def check_lifecycle(u: dict, now: datetime) -> CheckResult:
    c = CheckResult(status="valid")
    end = parse_time(u.get("validTo"))
    c.data = {"valid_from": u.get("validFrom"), "valid_to": u.get("validTo")}
    if end is not None and end < now:
        c.issues.append(make_issue("EXPIRED_ACTIVE", f"valid until {end:%Y-%m-%d}"))
    return _finish(c, "lifecycle")


def check_email(u: dict, shared: int) -> CheckResult:
    c = CheckResult(status="valid")
    c.data = {"email": u.get("email"), "verified": u.get("mailVerified"), "shared_with": max(0, shared - 1)}
    if u.get("mailVerified") is False:
        c.issues.append(make_issue("EMAIL_UNVERIFIED"))
    if shared > 1:
        c.issues.append(make_issue("EMAIL_SHARED", f"{shared} accounts use {u.get('email')}"))
    return _finish(c, "email")


def score_user(r: UserResult, checks: List[str]) -> None:
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


REMEDIATION = {
    "PASSWORD_LOGIN": ("Disable the IAS password", "Administration Console > Users & Authorizations > User Management > "
                       "user > Authentication: set the password status to Disabled (the user signs in through the corporate IdP)"),
    "PASSWORD_LOGIN_PRIVILEGED": ("Disable the IAS password of the privileged user", "Administration Console > User Management > "
                                  "user > Authentication: password Disabled; the application must delegate to the corporate IdP"),
    "PASSWORD_NO_MFA": ("Require a second factor", "Administration Console > Applications > application > Authentication "
                        "and Access > Risk-Based Authentication: Two-Factor Authentication for this user group or user type"),
    "PASSWORD_OLD": ("Enforce password expiry", "Administration Console > Password Policies: assign a policy with expiry "
                     "(Enterprise) to the applications"),
    "PASSWORD_INITIAL": ("Force or remove the initial password", "Deactivate the account if unused, or require the change at first sign-in"),
    "PASSWORD_STANDARD_POLICY": ("Use the Enterprise password policy", "Administration Console > Applications > application > "
                                 "Password Policy: Enterprise (or a stricter custom policy)"),
    "INACTIVE": ("Deactivate the inactive account", "Administration Console > User Management > user > Deactivate "
                 "(or let the corporate leaver process do it through provisioning)"),
    "NEVER_USED": ("Deactivate the unused account", "Administration Console > User Management > user > Deactivate"),
    "EXPIRED_ACTIVE": ("Deactivate the expired account", "Administration Console > User Management > user > Deactivate"),
    "EMAIL_SHARED": ("Give each person their own account", "Merge or deactivate the duplicate accounts"),
}


def suggest_remediation(r: UserResult) -> List[dict]:
    seen, out = set(), []
    for i in r.issues:
        if i.code in REMEDIATION and i.code not in seen:
            seen.add(i.code)
            title, steps = REMEDIATION[i.code]
            out.append({"title": title, "type": "SAP Cloud Identity Services", "name": r.domain, "value": steps, "note": i.message})
    return out


def analyze_snapshot(snap: dict, checks: List[str], privileged_groups: Iterable[str] = (),
                     password_types: Iterable[str] = (), inactive_days: int = INACTIVE_DAYS,
                     password_max_days: int = PASSWORD_MAX_DAYS, all_users_limit: int = ALL_USERS_LIMIT,
                     now: Optional[datetime] = None) -> Tuple[List[UserResult], List[Issue], List[dict], dict]:
    now = now or parse_time(snap.get("collected")) or datetime.now(timezone.utc)
    priv = {g.strip().lower() for g in privileged_groups if g.strip()}
    pw_types = {t.strip().lower() for t in password_types if t.strip()}
    users = snap.get("users") or []
    seen = snap.get("fields_seen") or {}
    last_login_visible = bool(seen.get("lastLogin")) or any(u.get("lastLogin") for u in users)
    mfa_visible = bool(seen.get("mfa")) or any(u.get("mfa") is not None for u in users)
    active = [u for u in users if u.get("active") is not False]
    emails = Counter(u.get("email") for u in active if u.get("email"))
    scan_date = snap.get("collected", "")
    results: List[UserResult] = []
    for u in active:
        groups = list(u.get("groups") or [])
        pgroups = [g for g in groups if g.lower() in priv]
        u = {**u, "privileged_groups": pgroups}
        utype = str(u.get("userType") or "")
        r = UserResult(site_id=str(u.get("id") or u.get("userName")), domain=str(u.get("userName") or u.get("id") or "?"),
                       account_id=utype or None, account_name=utype, display_name=str(u.get("displayName") or ""),
                       user_id=str(u.get("userId") or ""), email=str(u.get("email") or ""), groups=groups,
                       password=str((u.get("password") or {}).get("status") or ""), scan_date=scan_date,
                       tier="critical" if pgroups else "medium")
        builders = {
            "signin": lambda: check_signin(u, bool(pgroups), pw_types),
            "mfa": lambda: check_mfa(u),
            "password": lambda: check_password(u, now, password_max_days),
            "activity": lambda: check_activity(u, now, inactive_days, last_login_visible),
            "lifecycle": lambda: check_lifecycle(u, now),
            "email": lambda: check_email(u, emails.get(u.get("email"), 0) if u.get("email") else 0),
        }
        for c in checks:
            try:
                r.checks[c] = builders[c]()
            except Exception as e:  # never lose a user because of unexpected data
                r.checks[c] = CheckResult(status="unknown", issues=[make_issue("API_ERROR", f"{c}: {type(e).__name__}: {e}")])
        r.issues = sorted((i for c in checks for i in r.checks[c].issues), key=lambda i: SEVERITY_RANK.get(i.severity, 9))
        codes = {i.code for i in r.issues}
        r.profile = ("expired" if "EXPIRED_ACTIVE" in codes else "privileged" if "PASSWORD_LOGIN_PRIVILEGED" in codes
                     else "password" if password_state(u) else "inactive" if codes & {"INACTIVE", "NEVER_USED"} else "federated")
        score_user(r, checks)
        st = lambda c: (r.checks.get(c) or CheckResult()).status
        if "signin" in checks:
            r.compliance["federated_only"] = "unknown" if st("signin") == "unknown" else "fail" if password_state(u) else "pass"
        if {"activity", "lifecycle", "email"} <= set(checks):
            states = {st("activity"), st("lifecycle"), st("email")}
            r.compliance["account_hygiene"] = ("fail" if states & {"error", "warning"} else
                                               "unknown" if "unknown" in states else "pass")
        r.remediation = suggest_remediation(r)
        crit = sum(1 for i in r.issues if i.severity == "critical")
        r.priority = TIER_WEIGHTS.get(r.tier, 2) * (100 - r.overall_score + 15 * crit)
        results.append(r)

    totals = {"users": len(users), "active": len(active), "inactive_accounts": len(users) - len(active),
              "groups": len(snap.get("groups") or []),
              "by_type": dict(Counter(str(u.get("userType") or "(none)") for u in active).most_common()),
              "password_enabled": sum(1 for u in active if password_state(u)),
              "password_unexpected": sum(1 for r in results if r.checks.get("signin") and r.checks["signin"].issues),
              "federated": sum(1 for u in active if password_state(u) is False),
              "privileged": sum(1 for r in results if r.tier == "critical"),
              "with_findings": sum(1 for r in results if any(i.severity in ("critical", "warning") for i in r.issues)),
              "last_login_visible": last_login_visible, "mfa_visible": mfa_visible}
    account: List[Issue] = [make_issue("API_ERROR", f"{e.get('where')}: {e.get('error')}") for e in snap.get("errors") or []]
    if active and totals["password_unexpected"] / len(active) > 0.2:
        account.append(make_issue("PASSWORD_SHARE_HIGH", f"{totals['password_unexpected']} of {len(active)} active users "
                                                          f"({100 * totals['password_unexpected'] // len(active)}%)"))
    if "mfa" in checks and not mfa_visible and totals["password_enabled"]:
        account.append(make_issue("MFA_NOT_VISIBLE", f"{totals['password_enabled']} users with a local password"))
    if "activity" in checks and not last_login_visible and active:
        account.append(make_issue("LAST_LOGIN_NOT_VISIBLE"))
    account.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 9))
    results.sort(key=lambda x: (-x.priority, x.domain))
    limited = len(results) > all_users_limit
    if limited:  # very large directories: list the users that need action, count everyone
        results = [r for r in results if any(i.severity in ("critical", "warning") for i in r.issues)]
    totals["listed"] = len(results)
    totals["limited"] = limited
    return results, account, [], {"totals": totals}
