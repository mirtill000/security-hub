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


def load_domains(path: str) -> Tuple[List[DomainInput], List[str]]:
    text = _read_input(path)
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    first = lines[0].lower() if lines else ""
    is_csv = path.lower().endswith((".csv", ".tsv")) or bool(
        re.match(r"^\s*\"?(domain|dominio|domains|fqdn)\"?\s*[,;\t]", first))
    inputs: Dict[str, DomainInput] = {}
    invalid: List[str] = []
    if is_csv:
        try:
            dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO("\n".join(lines)), dialect=dialect)
        colmap = {}
        for col in reader.fieldnames or []:
            key = col.strip().lower()
            for target, aliases in CSV_COLUMNS.items():
                if key in aliases:
                    colmap[target] = col
        if "domain" not in colmap:
            raise ValueError("CSV input needs a 'domain' column")
        for row in reader:
            raw = (row.get(colmap["domain"]) or "").strip()
            d = normalize_domain(raw)
            if not d:
                if raw:
                    invalid.append(raw)
                continue
            if d in inputs:
                continue
            tier_raw = (row.get(colmap.get("tier", ""), "") or "").strip().lower()
            tags = [t.strip() for t in re.split(r"[|,;]", row.get(colmap.get("tags", ""), "") or "") if t.strip()]
            inputs[d] = DomainInput(domain=d, tier=TIER_ALIASES.get(tier_raw, "medium"),
                                    owner=(row.get(colmap.get("owner", ""), "") or "").strip(),
                                    bu=(row.get(colmap.get("bu", ""), "") or "").strip(), tags=tags)
    else:
        for line in lines:
            for token in re.split(r"[,\s;]+", line.split("#", 1)[0].strip()):
                if not token:
                    continue
                d = normalize_domain(token)
                if not d:
                    invalid.append(token)
                elif d not in inputs:
                    inputs[d] = DomainInput(domain=d)
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
