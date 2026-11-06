"""Input (plain list or CSV with metadata) and configuration files."""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from .constants import TIER_ALIASES
from .domains import normalize_domain
from .models import DomainInput

CSV_COLUMNS = {
    "domain": ("domain", "dominio", "domains", "fqdn"),
    "tier": ("tier", "criticality", "criticita", "criticità", "priority", "priorita"),
    "owner": ("owner", "referente", "responsabile"),
    "bu": ("bu", "business_unit", "business unit", "unit", "department", "dipartimento"),
    "tags": ("tags", "tag", "labels"),
}


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read().lstrip("\ufeff")
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


POSITIONAL = ("domain", "tier", "owner", "bu", "tags")
FIELD_SPLIT = re.compile(r"\s*[;,\t]\s*")


def _header_map(fields: List[str]) -> Dict[str, int]:
    """Column index of each known field when `fields` is a header row (needs a domain column)."""
    colmap: Dict[str, int] = {}
    for idx, col in enumerate(fields):
        key = col.strip().strip('"').strip().lower()
        for target, aliases in CSV_COLUMNS.items():
            if key in aliases and target not in colmap:
                colmap[target] = idx
    return colmap if "domain" in colmap else {}


def _domain_input(d: str, row: Dict[str, str]) -> DomainInput:
    tier_raw = (row.get("tier") or "").strip().lower()
    tags = [t.strip() for t in re.split(r"[|,;]", row.get("tags") or "") if t.strip()]
    return DomainInput(domain=d, tier=TIER_ALIASES.get(tier_raw, "medium"), owner=(row.get("owner") or "").strip(),
                       bu=(row.get("bu") or "").strip(), tags=tags)


def load_domains(path: str) -> Tuple[List[DomainInput], List[str]]:
    """Domains to assess, from any of these forms (the extension does not matter):

    - a plain list: one domain per line, or several per line separated by commas, semicolons or spaces;
    - a CSV with a header: columns recognized by name (domain/dominio, tier, owner, bu, tags), only domain required;
    - a CSV without a header: columns by position - domain, tier, owner, bu, tags - all optional except the first.
    Lines starting with # and text after # are ignored. Tiers: critical, high, medium (default), low.
    """
    text = _read_input(path)
    lines = [l.split("#", 1)[0].rstrip() for l in text.splitlines()]
    lines = [l for l in lines if l.strip()]
    inputs: Dict[str, DomainInput] = {}
    invalid: List[str] = []

    def add(raw: str, row: Dict[str, str]) -> None:
        raw = raw.strip().strip('"').strip()
        d = normalize_domain(raw)
        if not d:
            if raw:
                invalid.append(raw)
        elif d not in inputs:
            inputs[d] = _domain_input(d, row)

    if not lines:
        return [], []
    header = _header_map(FIELD_SPLIT.split(lines[0].strip()))
    if header:
        try:
            dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        for cells in csv.reader(io.StringIO("\n".join(lines[1:])), dialect=dialect):
            row = {k: (cells[i] if i < len(cells) else "") for k, i in header.items()}
            add(row.get("domain", ""), row)
        return list(inputs.values()), invalid

    tiers = set(TIER_ALIASES) | set(TIER_ALIASES.values())
    for line in lines:
        cells = [c.strip().strip('"').strip() for c in FIELD_SPLIT.split(line.strip())]
        # "example.com;critical;owner..." (or with the tier left empty) is a row with metadata;
        # anything else is a list of domains ("a.com, b.com" or "a.com b.com")
        if len(cells) > 1 and (cells[1].lower() in tiers or cells[1] == "") and " " not in cells[0]:
            add(cells[0], dict(zip(POSITIONAL, cells)))
            continue
        for token in re.split(r"[,\s;]+", line.strip()):
            if token:
                add(token, {})
    return list(inputs.values()), invalid


def load_config(path: str, profile: Optional[str]) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ValueError("YAML config needs PyYAML (pip install pyyaml) - or use a .json config")
        cfg = yaml.safe_load(text) or {}
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise ValueError("config must be a mapping of option: value")
    profiles = cfg.pop("profiles", {}) or {}
    if profile:
        if profile not in profiles:
            raise ValueError(f"profile '{profile}' not found (available: {', '.join(profiles) or 'none'})")
        cfg.update(profiles[profile] or {})
    out = {}
    for k, v in cfg.items():
        key = str(k).replace("-", "_")
        if isinstance(v, list) and key in ("checks", "skip", "selectors", "nameservers", "lookalike_tiers"):
            v = ",".join(str(x) for x in v)
        out[key] = v
    return out


# ---------------------------------------------------------------------------
# DKIM selectors per domain (dkim.csv)
# ---------------------------------------------------------------------------

DKIM_FILE = "dkim.csv"
DKIM_COLUMNS = {"domain": ("domain", "dominio", "domains", "fqdn"),
                "selector": ("selector", "selectors", "selettore", "selettori", "dkim", "record")}
SELECTOR_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]{0,61}[a-z0-9_])?$")
# DNS zone-file line: <selector>._domainkey.<domain>[.] [TTL] [IN] TXT|CNAME <data>
ZONE_LINE = re.compile(r"^(?P<name>\S+?\._domainkey\.\S+?)\.?\s+(?:\d+\s+)?(?:IN\s+)?(?P<type>TXT|CNAME)\s+(?P<data>.*)$", re.I)
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")


def dkim_key_id(p: str) -> str:
    """Short fingerprint of a DKIM public key (the p= value): compares keys without copying them into reports."""
    import hashlib
    return hashlib.sha256(re.sub(r"\s+", "", p).encode()).hexdigest()[:16]


def _zone_entry(line: str) -> Optional[Tuple[str, str, dict]]:
    """(domain, selector, expected) from a zone-file line, None when the line is not one."""
    m = ZONE_LINE.match(line)
    if not m:
        return None
    sel, dom = m.group("name").lower().split("._domainkey.", 1)
    data = m.group("data").strip()
    expected: dict = {}
    if m.group("type").upper() == "TXT":
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
        txt = "".join(parts) if parts else data
        tags = {}
        for item in txt.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                tags[k.strip().lower()] = re.sub(r"\s+", "", v)
        p = tags.get("p", "")
        if KEY_RE.match(p):  # a real key (not a placeholder like p=xxx): the published one must be the same
            expected["key_id"] = dkim_key_id(p)
        if tags.get("k"):
            expected["algorithm"] = tags["k"].lower()
    else:
        expected["cname"] = data.split()[0].rstrip(".").lower() if data else ""
    return dom.rstrip("."), sel, expected


def load_dkim_file(path: str) -> Tuple[Dict[str, List[str]], List[str], Dict[Tuple[str, str], dict]]:
    """DKIM records each domain publishes, for selectors that are not the providers' defaults.

    Accepted lines (mixed in the same file; '#' starts a comment):

        1m-mm._domainkey.uk.example.com.  1  IN  TXT  "v=DKIM1;k=rsa;p=MIIB..."    DNS zone-file line
        s1._domainkey.example.com  IN  CNAME  s1.dkim.provider.net.                  delegated selector
        example.com;s1-2024        or  example.com;mktg|crm                          domain;selector (CSV)
        s2._domainkey.example.com                                                    record name only

    Returns ({domain: [selectors]}, invalid lines, {(domain, selector): expected}) where expected may hold
    'key_id' (fingerprint of the p= key in the file), 'algorithm' and 'cname'.
    """
    out: Dict[str, List[str]] = {}
    expected: Dict[Tuple[str, str], dict] = {}
    invalid: List[str] = []
    col = {"domain": 0, "selector": 1}
    first = True

    def add(dom_raw: str, sels: List[str], line: str, exp: Optional[dict] = None) -> None:
        domain = normalize_domain(dom_raw)
        if not domain or not sels:
            invalid.append(line)
            return
        for s in sels:
            if not SELECTOR_RE.match(s):
                invalid.append(f"{domain}: {s}")
                continue
            if s not in out.setdefault(domain, []):
                out[domain].append(s)
            if exp:
                expected[(domain, s)] = exp

    for raw in _read_input(path).splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", ";")):
            continue
        zone = _zone_entry(line)
        if zone:  # before splitting on ';': the TXT data contains it
            first = False
            add(zone[0], [zone[1]], line, zone[2])
            continue
        line = line.split("#", 1)[0].strip()
        fields = [f.strip().strip('"').strip() for f in FIELD_SPLIT.split(line)]
        if first:
            first = False
            low = [f.lower() for f in fields]
            hdr = {k: next((i for i, f in enumerate(low) if f in names), None) for k, names in DKIM_COLUMNS.items()}
            if hdr["domain"] is not None:
                col = {"domain": hdr["domain"], "selector": hdr["selector"] if hdr["selector"] is not None else 1}
                continue
        dom_raw = fields[col["domain"]] if col["domain"] < len(fields) else ""
        sel_raw = fields[col["selector"]] if col["selector"] < len(fields) else ""
        if "._domainkey." in dom_raw.lower() and not sel_raw:   # record name only
            sel_raw, dom_raw = dom_raw.lower().rstrip(".").split("._domainkey.", 1)
        add(dom_raw, [s.lower().split("._domainkey.", 1)[0] for s in re.split(r"[|\s]+", sel_raw) if s], line)
    return {d: s for d, s in out.items() if s}, invalid, expected


def find_dkim_file(input_file: Optional[str]) -> Optional[str]:
    """dkim.csv next to the domain list, else in the current folder (None when there is none)."""
    folders = ([os.path.dirname(os.path.abspath(input_file))] if input_file and input_file != "-" else []) + [os.getcwd()]
    for folder in dict.fromkeys(folders):
        p = os.path.join(folder, DKIM_FILE)
        if os.path.isfile(p):
            return p
    return None
