"""Mail routing seen from the Internet (DNS): MX through Proofpoint, direct delivery to the mailbox service, SPF.

The DNS answers are stored in the snapshot, so a saved snapshot is re-analyzed offline with the same result.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from .constants import PROOFPOINT_HOSTS, SPF_PROOFPOINT

SPF_RE = re.compile(r"^v=spf1(\s|$)", re.I)
PLATFORMS = (("mail.protection.outlook.com", "Microsoft 365"), ("mx.microsoft", "Microsoft 365"),
             ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
             ("mimecast.com", "Mimecast"), ("messagelabs.com", "Broadcom Email Security"),
             ("iphmx.com", "Cisco Secure Email"), ("barracudanetworks.com", "Barracuda"))


def _ends(host: str, suffixes: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in suffixes)


def platform_of(host: str) -> str:
    for suffix, name in PLATFORMS:
        if _ends(host, (suffix,)):
            return name
    return ""


def m365_direct_host(domain: str) -> str:
    """Microsoft 365 inbound endpoint of a domain: contoso.com -> contoso-com.mail.protection.outlook.com."""
    return domain.replace(".", "-") + ".mail.protection.outlook.com"


def classify_mx(client, host: str, gateways: Sequence[str]) -> dict:
    """Is an MX host a Proofpoint gateway? By name, by CNAME target, or by the reverse DNS of its addresses."""
    if _ends(host, gateways):
        return {"host": host, "proofpoint": True, "how": "name"}
    a = client.query(host, "A")
    if a.canonical and _ends(a.canonical, gateways):
        return {"host": host, "proofpoint": True, "how": f"CNAME {a.canonical}"}
    for ip in client.addresses(host)[:2]:
        name = client.ptr(ip)
        if name and _ends(name, gateways):
            return {"host": host, "proofpoint": True, "how": f"reverse DNS of {ip}: {name}"}
    return {"host": host, "proofpoint": False, "platform": platform_of(host), "resolves": bool(client.addresses(host))}


def _spf_has(client, record: str, gateways: Sequence[str], depth: int = 0, seen: Optional[set] = None) -> bool:
    """True if the SPF record (or an include up to 2 levels down) authorizes a Proofpoint host."""
    seen = seen if seen is not None else set()
    for term in record.split()[1:]:
        m = re.match(r"^[+~?-]?(include|redirect)[:=](\S+)$", term, re.I)
        if not m:
            continue
        target = m.group(2).lower().rstrip(".")
        if _ends(target, gateways):
            return True
        if depth < 2 and target not in seen and len(seen) < 8 and "%" not in target:
            seen.add(target)
            ans = client.query(target, "TXT")
            for rec in (ans.records if ans.status == "ok" else []):
                if SPF_RE.match(rec.strip()) and _spf_has(client, rec.strip(), gateways, depth + 1, seen):
                    return True
    return False


def lookup_domain(client, domain: str, gateways: Sequence[str]) -> dict:
    out: dict = {"mx_status": "ok", "mx": [], "spf": None, "spf_proofpoint": None, "m365": None}
    mx = client.query(domain, "MX")
    if mx.status == "error":
        out["mx_status"] = "error"
        out["mx_error"] = mx.error
    elif mx.status != "ok" or not mx.records:
        out["mx_status"] = mx.status if mx.status != "ok" else "nodata"
    elif all(h in ("", ".") for _, h in mx.records):
        out["mx_status"] = "null"  # RFC 7505: the domain accepts no mail
    else:
        out["mx"] = [{"preference": p, **classify_mx(client, h, gateways)} for p, h in sorted(mx.records) if h not in ("", ".")]
    txt = client.query(domain, "TXT")
    if txt.status == "ok":
        spf = [r.strip() for r in txt.records if SPF_RE.match(r.strip())]
        out["spf"] = spf[0] if spf else ""
        out["spf_proofpoint"] = _spf_has(client, spf[0], SPF_PROOFPOINT + tuple(g for g in gateways if g not in PROOFPOINT_HOSTS)) if spf else None
        out["m365_verified"] = any(r.strip().lower().startswith("ms=") for r in txt.records)
    elif txt.status != "error":
        out["spf"] = ""
    if out["mx"]:
        host = m365_direct_host(domain)
        out["m365"] = {"host": host, "resolves": client.has_address(host)}
    return out


def collect_dns(domains: List[str], client, gateways: Sequence[str], workers: int = 8,
                log: Callable[[str], None] = lambda m: None) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="mx") as ex:
        for d, res in zip(domains, ex.map(lambda d: lookup_domain(client, d, gateways), domains)):
            out[d] = res
    log(f"{len(out)} domain(s) resolved")
    return out
