"""Finding history across runs: since when each finding is open and how long fixes take (MTTR).

The state lives in <output_dir>/findings_state.json and is updated by `securityhub run` from the latest report of each
area. A finding is (area, item, code) with severity critical or warning: it is opened the first time a report shows it
and resolved when a newer report of the same area no longer shows it. Only data dates are used (the date of the
report), so re-reading the same report changes nothing.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Dict, List, Optional

from .common import atomic_write

STATE_FILE = "findings_state.json"
KEEP_RESOLVED_DAYS = 180     # resolved findings kept for the MTTR
MTTR_WINDOW_DAYS = 90        # MTTR over the findings resolved in the last 90 days
MAX_OPEN = 50000             # safety cap on very large estates
ORG_ITEM = "(organization)"


def finding_list(kind: str, payload: dict, limit: int = 20000) -> List[dict]:
    """Critical and warning findings of a report: one entry per (item, code), organization-level ones included."""
    out, seen = [], set()
    rows = payload.get("results") if isinstance(payload, dict) else None
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        item = str(r.get("domain") or r.get("email") or r.get("host") or "")
        for i in r.get("issues") or []:
            if not isinstance(i, dict) or i.get("severity") not in ("critical", "warning"):
                continue
            key = (item, i.get("code"))
            if key in seen or not i.get("code"):
                continue
            seen.add(key)
            out.append({"item": item, "code": i["code"], "severity": i["severity"], "message": i.get("message") or ""})
            if len(out) >= limit:
                return out
    for i in (payload.get("account_issues") if isinstance(payload, dict) else None) or []:
        if isinstance(i, dict) and i.get("severity") in ("critical", "warning") and i.get("code") \
                and (ORG_ITEM, i["code"]) not in seen:
            seen.add((ORG_ITEM, i["code"]))
            out.append({"item": ORG_ITEM, "code": i["code"], "severity": i["severity"], "message": i.get("message") or "",
                        "org": True})
    return out


def _key(area: str, item: str, code: str) -> str:
    return f"{area}|{item}|{code}"


def _day(text: str) -> Optional[datetime]:
    from .portal import parse_date      # report dates: "2026-11-06T10:00:00Z" and older formats
    return parse_date(str(text or ""))


def load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        if isinstance(st, dict) and isinstance(st.get("open"), dict):
            st.setdefault("resolved", [])
            st.setdefault("areas", {})
            return st
    except (OSError, ValueError):
        pass
    return {"version": 1, "open": {}, "resolved": [], "areas": {}}


def update(state: dict, reports: List[dict], now: Optional[datetime] = None) -> dict:
    """Apply the latest report of each area to the state. Reports carry `type`, `date` and `open_findings`."""
    now = now or datetime.now(timezone.utc)
    by_area: Dict[str, List[dict]] = {}
    for r in reports:
        if r.get("open_findings") is not None and r.get("type") not in (None, "other"):
            by_area.setdefault(r["type"], [])
            by_area[r["type"]].extend(r["open_findings"])
            state["areas"].setdefault(r["type"], {})["date_raw"] = r.get("date") or ""
    for area, findings in by_area.items():
        info = state["areas"][area]
        when = _day(info.get("date_raw", "")) or now
        stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        if info.get("applied") == stamp:            # same report as last time: nothing new
            continue
        info["applied"] = stamp
        info.setdefault("since", stamp)             # tracking started: older findings are "open since at least"
        current = {_key(area, f["item"], f["code"]): f for f in findings}
        for k, f in current.items():
            o = state["open"].get(k)
            if o:
                o.update(last_seen=stamp, severity=f["severity"])
            elif len(state["open"]) < MAX_OPEN:
                state["open"][k] = {"area": area, "item": f["item"], "code": f["code"], "severity": f["severity"],
                                    "first_seen": stamp, "last_seen": stamp}
        for k in [k for k, o in state["open"].items() if o["area"] == area and k not in current]:
            o = state["open"].pop(k)
            first = _day(o["first_seen"])
            state["resolved"].append({"area": area, "item": o["item"], "code": o["code"], "severity": o["severity"],
                                      "first_seen": o["first_seen"], "resolved": stamp,
                                      "days": round(((when - first).total_seconds() / 86400) if first else 0, 1),
                                      "since_start": o["first_seen"] == info["since"]})
    cutoff = now - timedelta(days=KEEP_RESOLVED_DAYS)
    state["resolved"] = [x for x in state["resolved"] if (_day(x["resolved"]) or now) >= cutoff]
    state["updated"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return state


def save(path: str, state: dict) -> None:
    atomic_write(path, json.dumps(state, separators=(",", ":")))


def age_days(first_seen: str, now: Optional[datetime] = None) -> Optional[float]:
    first = _day(first_seen)
    return round(((now or datetime.now(timezone.utc)) - first).total_seconds() / 86400, 1) if first else None


def summary(state: dict, now: Optional[datetime] = None) -> Dict[str, dict]:
    """Per area: open findings and their age, findings open for more than 30 days, MTTR of the last 90 days."""
    now = now or datetime.now(timezone.utc)
    out: Dict[str, dict] = {}
    for area, info in state.get("areas", {}).items():
        opened = [o for o in state["open"].values() if o["area"] == area]
        ages = [a for a in (age_days(o["first_seen"], now) for o in opened) if a is not None]
        since = info.get("since")
        window = now - timedelta(days=MTTR_WINDOW_DAYS)
        fixed = [x for x in state["resolved"] if x["area"] == area and (_day(x["resolved"]) or now) >= window]
        exact = [x["days"] for x in fixed if not x.get("since_start")]   # opened while tracked: real duration
        out[area] = {
            "open": len(opened), "open_critical": sum(o["severity"] == "critical" for o in opened),
            "median_age_days": round(median(ages), 1) if ages else None, "oldest_days": max(ages) if ages else None,
            "over_30_days": sum(a > 30 for a in ages),
            "resolved_90d": len(fixed), "mttr_days": round(median(exact), 1) if exact else None,
            "mttr_critical_days": round(median([x["days"] for x in fixed if not x.get("since_start") and x["severity"] == "critical"]), 1)
            if any(not x.get("since_start") and x["severity"] == "critical" for x in fixed) else None,
            "tracked_since": since,
        }
    return out


def annotate(reports: List[dict], state: dict, now: Optional[datetime] = None) -> None:
    """Add first_seen / age to each open finding of the reports and the per-area summary (r["finding_age"])."""
    now = now or datetime.now(timezone.utc)
    per_area = summary(state, now)
    for r in reports:
        area = r.get("type")
        info = state.get("areas", {}).get(area) or {}
        for f in r.get("open_findings") or []:
            o = state["open"].get(_key(area, f["item"], f["code"]))
            if o:
                f["first_seen"] = o["first_seen"]
                f["age_days"] = age_days(o["first_seen"], now)
                f["since_start"] = o["first_seen"] == info.get("since")
        if area in per_area:
            r["finding_age"] = per_area[area]


def track(out_dir: str, reports: List[dict], write: bool = True, now: Optional[datetime] = None) -> dict:
    """Update (when `write`) and apply the state of `out_dir` to `reports`; returns the per-area summary."""
    path = os.path.join(out_dir, STATE_FILE)
    state = load(path)
    if write:
        update(state, reports, now)
        save(path, state)
    annotate(reports, state, now)
    return summary(state, now)
