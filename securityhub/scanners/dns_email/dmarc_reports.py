"""DMARC aggregate reports (RFC 7489 appendix C): .xml/.gz/.zip/.eml ingestion."""

from __future__ import annotations

import email
import email.policy
import gzip
import io
import os
import xml.etree.ElementTree as _ET
import zipfile
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Set, Tuple

from ._deps import _SafeET

MAX_REPORT_BYTES = 50 * 1024 * 1024


def _safe_xml(data: bytes):
    if _SafeET is not None:
        return _SafeET.fromstring(data, forbid_dtd=True)
    head = data.lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise ValueError("DTD/entities are not allowed in DMARC reports")
    return _ET.fromstring(data)


def _report_payloads(name: str, data: bytes, depth: int = 0) -> Iterable[Tuple[str, bytes]]:
    """Yield (label, xml bytes) from xml / gz / zip / eml content, with decompression limits."""
    if depth > 3:
        return
    low = name.lower()
    if data[:2] == b"\x1f\x8b" or low.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            raw = g.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("decompressed report too large")
        yield from _report_payloads(low[:-3] if low.endswith(".gz") else low + ".xml", raw, depth + 1)
    elif data[:4] == b"PK\x03\x04" or low.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_REPORT_BYTES:
                    continue
                yield from _report_payloads(info.filename, z.read(info), depth + 1)
    elif low.endswith((".eml", ".msg")) or data[:5] in (b"Retur", b"Recei", b"From ", b"Deliv", b"MIME-"):
        msg = email.message_from_bytes(data, policy=email.policy.default)
        for part in msg.walk():
            fname = part.get_filename() or ""
            ctype = part.get_content_type()
            if fname or ctype in ("application/zip", "application/gzip", "application/x-gzip", "text/xml",
                                  "application/xml"):
                payload = part.get_payload(decode=True) or b""
                if payload:
                    yield from _report_payloads(fname or ("x.zip" if "zip" in ctype else "x.xml"), payload, depth + 1)
    elif data.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] == b"<":
        yield name, data.lstrip(b"\xef\xbb\xbf")


def load_dmarc_reports(paths: List[str]) -> Tuple[Dict[str, dict], List[str], int]:
    """Aggregate DMARC reports by header_from domain. Returns (data, errors, report_count)."""
    files: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files.extend(os.path.join(root, n) for n in sorted(names))
        elif os.path.exists(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)

    data: Dict[str, dict] = {}
    errors: List[str] = []
    seen_ids: Set[Tuple[str, str]] = set()

    def new_domain():
        return {"reports": 0, "messages": 0, "passed": 0, "begin": "", "end": "", "reporters": Counter(),
                "sources": {}, "selector_pairs": set()}

    for path in files:
        try:
            if os.path.getsize(path) > MAX_REPORT_BYTES:
                raise ValueError("file too large")
            with open(path, "rb") as f:
                blob = f.read()
            for label, xml in _report_payloads(os.path.basename(path), blob):
                root = _safe_xml(xml)
                if root.tag != "feedback":
                    continue
                org = (root.findtext("report_metadata/org_name") or "unknown").strip()
                rid = (root.findtext("report_metadata/report_id") or label).strip()
                if (org, rid) in seen_ids:
                    continue
                seen_ids.add((org, rid))
                begin = root.findtext("report_metadata/date_range/begin") or ""
                end = root.findtext("report_metadata/date_range/end") or ""
                touched = set()
                for rec in root.findall("record"):
                    hdr = (rec.findtext("identifiers/header_from") or
                           root.findtext("policy_published/domain") or "").strip().lower().rstrip(".")
                    if not hdr:
                        continue
                    d = data.setdefault(hdr, new_domain())
                    touched.add(hdr)
                    try:
                        count = int(rec.findtext("row/count") or 0)
                    except ValueError:
                        count = 0
                    ip = (rec.findtext("row/source_ip") or "?").strip()
                    pe_dkim = (rec.findtext("row/policy_evaluated/dkim") or "").lower()
                    pe_spf = (rec.findtext("row/policy_evaluated/spf") or "").lower()
                    disp = (rec.findtext("row/policy_evaluated/disposition") or "none").lower()
                    auth_pass = False
                    dkim_domains = set()
                    for dk in rec.findall("auth_results/dkim"):
                        dom = (dk.findtext("domain") or "").lower()
                        sel = (dk.findtext("selector") or "").strip()
                        res = (dk.findtext("result") or "").lower()
                        if res == "pass":
                            auth_pass = True
                            dkim_domains.add(dom)
                            if sel and dom:
                                d["selector_pairs"].add((dom, sel))
                    for sp in rec.findall("auth_results/spf"):
                        if (sp.findtext("result") or "").lower() == "pass":
                            auth_pass = True
                    src = d["sources"].setdefault(ip, {"count": 0, "passed": 0, "unaligned": 0, "spoofed": 0,
                                                       "envelope_from": set(), "dkim_domains": set(),
                                                       "disposition": Counter()})
                    src["count"] += count
                    src["disposition"][disp] += count
                    src["dkim_domains"] |= dkim_domains
                    env = (rec.findtext("identifiers/envelope_from") or "").strip().lower()
                    if env:
                        src["envelope_from"].add(env)
                    d["messages"] += count
                    if pe_dkim == "pass" or pe_spf == "pass":
                        src["passed"] += count
                        d["passed"] += count
                    elif auth_pass:
                        src["unaligned"] += count
                    else:
                        src["spoofed"] += count
                for hdr in touched:
                    d = data[hdr]
                    d["reports"] += 1
                    d["reporters"][org] += 1
                    if begin and (not d["begin"] or begin < d["begin"]):
                        d["begin"] = begin
                    if end and end > d["end"]:
                        d["end"] = end
        except Exception as e:
            errors.append(f"{os.path.basename(path)}: {type(e).__name__}: {e}")

    for d in data.values():
        for key in ("begin", "end"):
            if d[key].isdigit():
                d[key] = datetime.fromtimestamp(int(d[key]), timezone.utc).strftime("%Y-%m-%d")
        d["selector_pairs"] = sorted(d["selector_pairs"])
    return data, errors, len(seen_ids)
