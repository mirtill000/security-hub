"""Per-endpoint checks: agent health, protection mode, policy hardening, version, threats, vulnerabilities, scan."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .constants import ENGINE_FINDING, ENGINES, EXECUTABLE_TYPES, MITIGATED, OPTIONAL_ENGINES
from .models import CheckResult, make_issue


def _when(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def days_since(value, now: datetime) -> Optional[int]:
    d = _when(value)
    return None if d is None else max(0, (now - d).days)


def _status(c: CheckResult, default: str = "valid") -> str:
    sev = {i.severity for i in c.issues}
    return "error" if "critical" in sev else "warning" if "warning" in sev else default


def version_tuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4])


def check_health(a: dict, now: datetime, stale_days: int) -> CheckResult:
    c = CheckResult(max=20)
    age = days_since(a.get("lastActiveDate"), now)
    state = str(a.get("operationalState") or "").lower()
    actions = [str(x) for x in a.get("userActionsNeeded") or [] if x]
    perms = [str(x) for x in a.get("missingPermissions") or [] if x]
    c.data = {"last_seen": a.get("lastActiveDate"), "last_seen_days": age, "network": a.get("networkStatus"),
              "operational_state": a.get("operationalState"), "actions_needed": actions, "missing_permissions": perms,
              "registered": a.get("registeredAt")}
    if age is None:
        c.status = "unknown"
        return c
    if "disabled" in state:
        c.issues.append(make_issue("AGENT_DISABLED", state))
    if age > stale_days:
        c.issues.append(make_issue("AGENT_STALE", f"last seen {age} days ago"))
    if actions:
        c.issues.append(make_issue("AGENT_ACTION_NEEDED", ", ".join(actions)))
    if perms:
        c.issues.append(make_issue("AGENT_MISSING_PERMISSIONS", ", ".join(perms)))
    crit = any(i.severity == "critical" for i in c.issues)
    c.got = 0 if crit else 20 - 5 * min(2, len([i for i in c.issues if i.severity == "warning"]))
    c.status = _status(c)
    return c


def check_protection(a: dict) -> CheckResult:
    c = CheckResult(max=30)
    mode, susp = str(a.get("mitigationMode") or "").lower(), str(a.get("mitigationModeSuspicious") or "").lower()
    c.data = {"mode": mode or None, "suspicious_mode": susp or None}
    if not mode:
        c.status = "unknown"
        return c
    if mode != "protect":
        c.issues.append(make_issue("MODE_DETECT", mode))
    else:
        c.got = 30
    if susp and susp != "protect":
        c.issues.append(make_issue("MODE_SUSPICIOUS_DETECT"))
    c.status = _status(c)
    return c


def check_policy(a: dict, policy: Optional[dict], scope: Optional[str]) -> CheckResult:
    c = CheckResult(max=25)
    if not policy:
        c.status = "unknown"  # policy not readable: not counted as failed
        c.data = {"scope": scope}
        return c
    engines = policy.get("engines") or {}
    off = [k for k, v in engines.items() if str(v).lower() == "off"]
    tamper = policy.get("antiTamperingOn")
    snapshots = policy.get("snapshotsOn")
    action = str(policy.get("autoMitigationAction") or "")
    c.data = {"scope": scope, "anti_tamper": tamper, "snapshots": snapshots, "auto_mitigation": action or None,
              "mode": policy.get("mitigationMode"), "engines": {ENGINES.get(k, k): v for k, v in engines.items()},
              "engines_off": [ENGINES.get(k, k) for k in off]}
    got = 25.0
    if tamper is False:
        c.issues.append(make_issue("ANTI_TAMPER_OFF"))
        got -= 12
    for k in off:   # one finding per engine: the engine is named in the finding title
        if k in ENGINE_FINDING:
            issue = make_issue(ENGINE_FINDING[k])
            if scope:
                issue.message += f" (policy: {scope})"
            c.issues.append(issue)
        else:
            c.issues.append(make_issue("ENGINE_OFF", k))
    required_off = [k for k in off if k not in OPTIONAL_ENGINES]
    if required_off:
        got -= min(8, 3 * len(required_off))
    if snapshots is False and str(a.get("osType") or "").lower() == "windows":
        c.issues.append(make_issue("SNAPSHOTS_OFF"))
        got -= 5
    if action.endswith("killThreat"):
        c.issues.append(make_issue("AUTO_MITIGATION_KILL_ONLY"))
    c.got = max(0.0, got)
    c.status = _status(c)
    return c


def check_version(a: dict, latest: Dict[str, str]) -> CheckResult:
    c = CheckResult(max=10)
    v, os_type = a.get("agentVersion"), str(a.get("osType") or "").lower()
    newest = latest.get(os_type)
    c.data = {"agent_version": v, "latest_ga": newest, "up_to_date": a.get("isUpToDate")}
    if not v:
        c.status = "unknown"
        return c
    cur, ga = version_tuple(v), version_tuple(newest) if newest else ()
    if ga and cur and cur[0] <= ga[0] - 2:
        c.issues.append(make_issue("AGENT_VERY_OLD", f"{v}, latest GA {newest}"))
    elif a.get("isUpToDate") is False or (ga and cur and cur < ga):
        c.issues.append(make_issue("AGENT_OUTDATED", f"{v}" + (f", latest GA {newest}" if newest else "")))
        c.got = 5
    else:
        c.got = 10
    c.status = _status(c)
    return c


def check_threats(a: dict, threats: List[dict], now: datetime, sla_days: int) -> CheckResult:
    c = CheckResult(max=15)
    active = [t for t in threats if str(t.get("mitigation") or "").lower() not in MITIGATED]
    open_ = [t for t in threats if t not in active]
    late = [t for t in threats if (days_since(t.get("created"), now) or 0) > sla_days]
    c.data = {"open": len(threats), "active": len(active), "infected": a.get("infected"),
              "agent_active_threats": a.get("activeThreats"),
              "threats": [{k: t.get(k) for k in ("name", "classification", "confidence", "mitigation", "incident", "verdict", "created")}
                          for t in threats[:20]]}
    if active or (not threats and (a.get("infected") or (a.get("activeThreats") or 0) > 0)):
        names = ", ".join(sorted({str(t.get("name")) for t in active if t.get("name")})[:3])
        c.issues.append(make_issue("THREAT_ACTIVE", names or f"{a.get('activeThreats') or 1} active"))
    if open_:
        c.issues.append(make_issue("THREAT_UNRESOLVED", f"{len(open_)} open"))
    if late:
        c.issues.append(make_issue("THREAT_SLA", f"{len(late)} older than {sla_days} days"))
    c.got = 0 if any(i.severity == "critical" for i in c.issues) else 15 - 5 * min(2, len(c.issues))
    c.status = _status(c)
    return c


def check_vulnerabilities(a: dict) -> CheckResult:
    c = CheckResult()
    st = str(a.get("appsVulnerabilityStatus") or "").lower()
    c.data = {"status": st or None}
    if not st or st in ("not_applicable", "na"):
        c.status = "na"
    elif st in ("patch_required", "vulnerable"):
        c.issues.append(make_issue("APPS_VULNERABLE"))
        c.status = "warning"
    else:
        c.status = "valid"
    return c


def check_scan(a: dict) -> CheckResult:
    c = CheckResult()
    st = str(a.get("scanStatus") or "").lower()
    c.data = {"status": st or None, "finished": a.get("scanFinishedAt")}
    if not st:
        c.status = "na"
    elif st in ("none", "aborted") and not a.get("scanFinishedAt"):
        c.issues.append(make_issue("NO_FULL_SCAN"))
        c.status = "warning"
    else:
        c.status = "valid"
    return c


# ---------------------------------------------------------------------------
# Exclusions (console level)
# ---------------------------------------------------------------------------

_BROAD_PATH = re.compile(r"^(\*|[a-z]:\\?\*?|[\\/]\*?|\*[\\/].*|.*[\\/]\*[\\/]?\*?)$", re.I)
_WRITABLE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\programdata\\", "\\windows\\temp",
             "/tmp", "/var/tmp", "/users/shared", "/dev/shm", "\\public\\")


def assess_exclusion(x: dict) -> Optional[Tuple[str, str]]:
    """(finding code, reason) for a risky exclusion, or None."""
    typ, val = str(x.get("type") or "").lower(), str(x.get("value") or "").strip().strip('"')
    mode = str(x.get("mode") or "").lower()
    win = val.lower().replace("/", "\\")   # one separator for the checks; Unix paths become \\tmp\\...
    if typ == "path":
        if val.startswith("*") and len(val.strip("*\\/")) > 0:
            return "EXCLUSION_BROAD", f"{val} (leading wildcard: matches the name in any location)"
        if _BROAD_PATH.match(val) or win.rstrip("\\*") in ("", "c:", "d:"):
            return "EXCLUSION_BROAD", f"{val} (whole drive, root or wildcard)"
        writable = any(w.replace("/", "\\") in win for w in _WRITABLE)
        folder = str(x.get("pathExclusionType") or "").lower() in ("folder", "subfolders", "") or val.endswith(("*", "\\", "/"))
        if writable and folder:
            return "EXCLUSION_BROAD", f"{val} (user-writable folder)"
    if typ == "file_type" and val.lower().lstrip(".*") in EXECUTABLE_TYPES:
        return "EXCLUSION_BROAD", f"file type .{val.lower().lstrip('.*')} (executable or script)"
    if typ in ("browser", "certificate"):
        return "EXCLUSION_RISKY", f"{typ} {val}"
    if "disable_all_monitors" in mode:
        return "EXCLUSION_ALL_MONITORS", val
    return None
