"""Cross-module risks: problems that only appear when the reports of different tools are joined.

The domain view (e-mail, DNS, WAF, Proofpoint routing) lives in `inventory`. This module joins
the other two axes the tools share:

  people     by e-mail address: Proofpoint (Very Attacked People, top clickers, permitted
             malicious clicks), SAP Cloud Identity Services users, BeyondTrust PRA users;
  endpoints  by host name: BeyondTrust PRA jump targets and SentinelOne agents.

A rule fires only on data that was measured: a person missing from a report is "not known",
never "unprotected", and a PRA target given by IP address is not compared with EDR host names.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

SEV_RANK = {"critical": 0, "warning": 1, "info": 2}

# What each rule means and what to do, shown next to the risk in the portal.
RULES = {
    "CLICKER_PRIVILEGED": ("critical", "Malicious click permitted for a privileged user",
                           "Reset the user's credentials and sessions, check the endpoint, review recent privileged sessions"),
    "ATTACKED_NO_MFA": ("critical", "Targeted user can sign in without a second factor",
                        "Require MFA for this user first: phishing is aimed at them and a password alone protects the account"),
    "ATTACKED_PRIVILEGED": ("warning", "Very Attacked Person with privileged access",
                            "Keep privileged access separate from the mailbox identity (dedicated admin account), require phishing-resistant MFA"),
    "PRIVILEGED_NO_MFA_ELSEWHERE": ("warning", "Privileged in one system, without MFA in another",
                                    "Enforce MFA on every account of the person: the weakest one is the way in"),
    "PRA_TARGET_THREAT": ("critical", "Privileged access target with an active threat",
                          "Suspend remote access to the endpoint until the threat is resolved"),
    "PRA_TARGET_EDR_WEAK": ("warning", "Privileged access target weakly protected by the EDR",
                            "Set the agent to protect mode and make sure it reports to the console"),
    "PRA_TARGET_NO_EDR": ("warning", "Privileged access target without an EDR agent",
                          "Install the SentinelOne agent, or document why the target cannot have one (appliance, OT)"),
}


def _link(code: str, subject: str, text: str, refs: List[dict], severity: Optional[str] = None) -> dict:
    sev, title, fix = RULES[code]
    return {"severity": severity or sev, "code": code, "title": title, "subject": subject, "text": text, "fix": fix, "refs": refs}


def _ref(report: dict, label: str, hash_: str = "") -> dict:
    return {"report": report["id"], "area": report["type"], "label": label, "hash": hash_}


def _row_hash(name: str) -> str:
    return "#/domains?d=" + str(name)


def _email(v) -> str:
    v = str(v or "").strip().lower()
    return v if "@" in v else ""


def _short_host(h: str) -> str:
    """Host name without the domain: endpoints are named 'dc01' in one tool and 'dc01.contoso.local' in another."""
    h = str(h or "").strip().lower().rstrip(".")
    return h.split(".")[0] if h else ""


def _is_address(h: str) -> bool:
    try:
        ipaddress.ip_address(str(h).strip())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# people
# ---------------------------------------------------------------------------

def _people(reports: List[dict]) -> Dict[str, dict]:
    """e-mail -> what each module knows about the person."""
    people: Dict[str, dict] = {}

    def person(email: str) -> dict:
        return people.setdefault(email, {"email": email, "name": "", "pp": {}, "ias": None, "pra": []})

    for r in reports:
        p = r.get("payload")
        if not isinstance(p, dict):
            continue
        if r["type"] == "proofpoint" and p.get("tap"):
            pe = p.get("people") or {}
            for kind in ("vap", "top_clickers"):
                for x in pe.get(kind) or []:
                    for e in x.get("emails") or []:
                        e = _email(e)
                        if e:
                            pp = person(e)
                            pp["name"] = pp["name"] or x.get("name") or ""
                            pp["pp"][kind] = x
                            pp["pp"]["report"] = r
            for row in p.get("results") or []:
                for c in ((row.get("checks") or {}).get("clicks") or {}).get("data", {}).get("clicks") or []:
                    e = _email(c.get("recipient"))
                    if e:
                        pp = person(e)
                        pp["pp"].setdefault("clicks", []).append(c)
                        pp["pp"]["report"] = r
                        pp["pp"]["domain"] = row.get("domain")
        elif r["type"] == "ias":
            for row in p.get("results") or []:
                e = _email(row.get("email") or ((row.get("checks") or {}).get("email") or {}).get("data", {}).get("email"))
                if not e:
                    continue
                ck = row.get("checks") or {}
                signin = (ck.get("signin") or {}).get("data") or {}
                mfa = (ck.get("mfa") or {})
                pw = signin.get("password_status")
                person(e)["ias"] = {
                    "row": row, "report": r, "privileged": bool(signin.get("privileged")),
                    # a local IAS password that works: the corporate IdP (and its MFA) can be skipped
                    "password_login": pw not in (None, "", "disabled"),
                    "mfa": (mfa.get("data") or {}).get("mfa") if mfa.get("status") not in ("unknown", "skipped", "na") else None,
                }
                person(e)["name"] = person(e)["name"] or row.get("display_name") or ""
        elif r["type"] == "pra":
            for row in p.get("results") or []:
                if row.get("kind") not in ("user", "vendor_user"):
                    continue
                e = _email(row.get("email")) or _email(row.get("domain"))
                if not e:
                    continue
                ck = row.get("checks") or {}
                auth = (ck.get("authentication") or {}).get("data") or {}
                priv = (ck.get("privileges") or {}).get("data") or {}
                person(e)["pra"].append({
                    "row": row, "report": r, "vendor": row.get("kind") == "vendor_user",
                    "admin": bool(priv.get("admin") or priv.get("vault_admin") or priv.get("vendor_admin")),
                    # None for SSO / directory users: MFA is enforced by their identity provider, not "without MFA"
                    "mfa": auth.get("mfa"),
                })
    return people


def _people_links(people: Dict[str, dict]) -> List[dict]:
    out: List[dict] = []
    for e, x in sorted(people.items()):
        pp, ias, pra = x["pp"], x["ias"], x["pra"]
        who = f"{x['name']} ({e})" if x["name"] else e
        clicked = pp.get("clicks") or []
        vap = pp.get("vap")
        clicker = pp.get("top_clickers")
        pp_ref = []
        if pp.get("report"):
            pp_ref = [_ref(pp["report"], "Proofpoint: " + ("permitted click" if clicked else "Very Attacked Person" if vap else "top clicker"),
                           _row_hash(pp["domain"]) if clicked and pp.get("domain") else "#/policies")]
        ias_ref = [_ref(ias["report"], "SAP Cloud Identity user", _row_hash(ias["row"].get("domain")))] if ias else []
        pra_refs = [_ref(a["report"], "PRA " + ("vendor user" if a["vendor"] else "user"), _row_hash(a["row"].get("domain"))) for a in pra]
        privileged_where = (["PRA administrator"] if any(a["admin"] for a in pra) else []) + \
                           (["PRA access"] if pra and not any(a["admin"] for a in pra) else []) + \
                           (["SAP IAS privileged group"] if ias and ias["privileged"] else [])
        no_mfa_where = (["SAP IAS (local password, no second factor)"] if ias and ias["password_login"] and ias["mfa"] is False else []) + \
                       [f"PRA {'vendor ' if a['vendor'] else ''}user" for a in pra if a["mfa"] is False]

        if clicked and privileged_where:
            out.append(_link("CLICKER_PRIVILEGED", e, f"{who} allowed a malicious click ({clicked[-1].get('classification') or 'threat'}, "
                                                      f"{str(clicked[-1].get('time') or '')[:10]}) and has {', '.join(privileged_where)}",
                             pp_ref + pra_refs + ias_ref))
        if (vap or clicker or clicked) and no_mfa_where:
            why = "clicked a malicious link" if clicked else "is a Very Attacked Person" if vap else "is a top clicker"
            out.append(_link("ATTACKED_NO_MFA", e, f"{who} {why} and can sign in without MFA: {', '.join(no_mfa_where)}", pp_ref + ias_ref + pra_refs))
        elif vap and privileged_where and not clicked:
            out.append(_link("ATTACKED_PRIVILEGED", e, f"{who} is among the Very Attacked People (attack index "
                                                       f"{vap.get('attack_index')}) and has {', '.join(privileged_where)}", pp_ref + pra_refs + ias_ref))
        if not (vap or clicker or clicked):
            admin_somewhere = (ias and ias["privileged"]) or any(a["admin"] for a in pra)
            if admin_somewhere and no_mfa_where and ias and pra:
                out.append(_link("PRIVILEGED_NO_MFA_ELSEWHERE", e, f"{who} is privileged ({', '.join(privileged_where)}) "
                                                                   f"and has no MFA on: {', '.join(no_mfa_where)}", ias_ref + pra_refs))
    return out


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

def _endpoint_links(reports: List[dict]) -> Tuple[List[dict], dict]:
    edr = [r for r in reports if r["type"] == "edr" and isinstance(r.get("payload"), dict)]
    pra = [r for r in reports if r["type"] == "pra" and isinstance(r.get("payload"), dict)]
    stats = {"pra_targets": 0, "matched": 0, "by_address": 0}
    if not edr or not pra:
        return [], stats
    agents: Dict[str, Tuple[dict, dict]] = {}
    for r in edr:
        for row in r["payload"].get("results") or []:
            h = _short_host(row.get("domain"))
            if h:
                agents[h] = (row, r)
    out: List[dict] = []
    for r in pra:
        for row in r["payload"].get("results") or []:
            if row.get("kind") != "asset":
                continue
            host = str(row.get("host") or ((row.get("checks") or {}).get("exposure") or {}).get("data", {}).get("host") or "").strip().lower()
            if not host:
                continue
            stats["pra_targets"] += 1
            if _is_address(host):  # EDR reports host names: an address cannot be compared
                stats["by_address"] += 1
                continue
            pra_ref = _ref(r, "PRA jump target", _row_hash(row.get("domain")))
            name = row.get("domain") or host
            hit = agents.get(_short_host(host))
            if not hit:
                out.append(_link("PRA_TARGET_NO_EDR", host, f"{name} ({host}) is reachable through privileged remote access "
                                                            "but no SentinelOne agent with this name reports to the console", [pra_ref]))
                continue
            stats["matched"] += 1
            agent, er = hit
            edr_ref = _ref(er, "SentinelOne endpoint", _row_hash(agent.get("domain")))
            prof = agent.get("profile")
            if prof == "threat":
                out.append(_link("PRA_TARGET_THREAT", host, f"{name} ({host}) has an active threat in SentinelOne and is "
                                                            "reachable through privileged remote access", [edr_ref, pra_ref]))
            elif prof in ("detect", "stale", "disabled"):
                state = {"detect": "detect mode only (threats are not stopped)", "stale": "agent not seen recently",
                         "disabled": "agent disabled"}[prof]
                out.append(_link("PRA_TARGET_EDR_WEAK", host, f"{name} ({host}) is reachable through privileged remote access; "
                                                              f"SentinelOne: {state}", [edr_ref, pra_ref]))
    return out, stats


def build(reports: List[dict]) -> dict:
    """Cross-module risks from the latest reports (portal report dicts with their parsed `payload`)."""
    people = _people(reports)
    links = _people_links(people)
    ep, stats = _endpoint_links(reports)
    links += ep
    links.sort(key=lambda x: (SEV_RANK.get(x["severity"], 9), x["code"], x["subject"]))
    areas = sorted({r["type"] for r in reports if isinstance(r.get("payload"), dict)} & {"proofpoint", "ias", "pra", "edr"})
    joined = {e: x for e, x in people.items() if sum(bool(v) for v in (x["pp"], x["ias"], x["pra"])) > 1}
    return {"links": links, "summary": {
        "total": len(links), "critical": sum(x["severity"] == "critical" for x in links),
        "warning": sum(x["severity"] == "warning" for x in links), "areas": areas,
        "people_joined": len(joined), "pra_targets": stats["pra_targets"], "pra_targets_matched": stats["matched"],
        "pra_targets_by_address": stats["by_address"]}}
