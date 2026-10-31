"""Lookalike / typosquatting candidate generation."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List

from .domains import to_ascii

_QWERTY_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
KEYBOARD_NEIGHBOURS: Dict[str, str] = {}
for _r, _row in enumerate(_QWERTY_ROWS):
    for _c, _ch in enumerate(_row):
        _near = []
        for _dr in (-1, 0, 1):
            _rr = _r + _dr
            if 0 <= _rr < len(_QWERTY_ROWS):
                for _dc in (-1, 0, 1):
                    _cc = _c + _dc
                    if (_dr or _dc) and 0 <= _cc < len(_QWERTY_ROWS[_rr]):
                        _near.append(_QWERTY_ROWS[_rr][_cc])
        KEYBOARD_NEIGHBOURS[_ch] = "".join(_near)

ASCII_HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
                    "e": ["3"], "a": ["4"], "s": ["5"], "g": ["q", "9"], "b": ["6"], "z": ["2"], "t": ["7"]}
MULTI_HOMOGLYPHS = [("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl"), ("nn", "m")]
IDN_HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ"}
LOOKALIKE_TLDS = ["com", "net", "org", "it", "eu", "co", "io", "info", "biz", "online", "site", "shop",
                  "app", "de", "fr", "es", "ch", "nl", "us", "co.uk"]
COMBO_WORDS = ["mail", "secure", "login", "account", "support", "online", "group", "web", "portal", "it"]
LOOKALIKE_PRIORITY = ["homoglyph", "idn-homoglyph", "tld-swap", "omission", "transposition", "repetition",
                      "hyphenation", "combo", "replacement", "vowel-swap", "insertion"]


def generate_lookalikes(reg_domain: str, limit: int = 150) -> Dict[str, str]:
    """Typosquatting candidates for a registrable domain -> technique. Ordered by likelihood."""
    name, _, suffix = reg_domain.partition(".")
    buckets: Dict[str, List[str]] = defaultdict(list)
    seen = {reg_domain}

    def add(label: str, kind: str, sfx: str = suffix) -> None:
        label = label.strip("-")
        if not label or len(label) > 63:
            return
        if not label.startswith("xn--") and not re.fullmatch(r"[a-z0-9-]+", label):
            return
        cand = f"{label}.{sfx}"
        if cand not in seen:
            seen.add(cand)
            buckets[kind].append(cand)

    n = len(name)
    for i, ch in enumerate(name):
        for rep in ASCII_HOMOGLYPHS.get(ch, []):
            add(name[:i] + rep + name[i + 1:], "homoglyph")
    for a, b in MULTI_HOMOGLYPHS:
        idx = name.find(a)
        while idx >= 0:
            add(name[:idx] + b + name[idx + len(a):], "homoglyph")
            idx = name.find(a, idx + 1)
    for i, ch in enumerate(name):
        if ch in IDN_HOMOGLYPHS:
            try:
                add(to_ascii(name[:i] + IDN_HOMOGLYPHS[ch] + name[i + 1:]), "idn-homoglyph")
            except Exception:
                pass
    for t in LOOKALIKE_TLDS:
        if t != suffix:
            add(name, "tld-swap", t)
    for i in range(n):
        add(name[:i] + name[i + 1:], "omission")
    for i in range(n - 1):
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
    for i in range(n):
        add(name[:i] + name[i] + name[i:], "repetition")
    for i in range(1, n):
        add(name[:i] + "-" + name[i:], "hyphenation")
    for w in COMBO_WORDS:
        add(f"{name}-{w}", "combo")
        add(f"{name}{w}", "combo")
        add(f"{w}-{name}", "combo")
    for i, ch in enumerate(name):
        for k in KEYBOARD_NEIGHBOURS.get(ch, ""):
            add(name[:i] + k + name[i + 1:], "replacement")
    for i, ch in enumerate(name):
        if ch in "aeiou":
            for v in "aeiou":
                if v != ch:
                    add(name[:i] + v + name[i + 1:], "vowel-swap")
    for i, ch in enumerate(name):
        for k in KEYBOARD_NEIGHBOURS.get(ch, ""):
            add(name[:i] + k + name[i:], "insertion")

    out: Dict[str, str] = {}
    pointers = {k: 0 for k in LOOKALIKE_PRIORITY}
    while len(out) < limit and any(pointers[k] < len(buckets[k]) for k in LOOKALIKE_PRIORITY):
        for k in LOOKALIKE_PRIORITY:  # round-robin across techniques, in priority order
            if pointers[k] < len(buckets[k]) and len(out) < limit:
                out[buckets[k][pointers[k]]] = k
                pointers[k] += 1
    return out
