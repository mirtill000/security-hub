"""Input (plain list or CSV with metadata) and configuration files."""

from __future__ import annotations

import csv
import io
import json
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
