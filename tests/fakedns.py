"""Offline DNS for tests: answers from tests/fixtures/dns_zones.json instead of the network."""

import json
import os
from contextlib import contextmanager

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load_zones(path: str = os.path.join(FIXTURES, "dns_zones.json")) -> dict:
    with open(path, encoding="utf-8") as f:
        return {k.lower(): v for k, v in json.load(f).items()}


@contextmanager
def fake_dns(zones: dict = None):
    """Patch DNSClient so every query is answered from `zones` (name -> {rdtype: [records]})."""
    from securityhub.scanners import dns_email
    zones = load_zones() if zones is None else zones
    Answer = dns_email.DNSAnswer

    def resolve(self, name, rdtype, resolver=None):
        name = name.lower().rstrip(".")
        node = zones.get(name)
        if node is None:
            return Answer("nxdomain")
        if rdtype not in node and "CNAME" in node and rdtype != "CNAME":
            target = node["CNAME"][0]
            sub = resolve(self, target, rdtype)
            return Answer(sub.status, sub.records, False, target, sub.error)
        if rdtype not in node:
            return Answer("nodata")
        recs = node[rdtype]
        if rdtype == "MX":
            recs = [(int(p), h) for p, h in recs]
        return Answer("ok", list(recs), False, None)

    original = dns_email.DNSClient._resolve
    dns_email.DNSClient._resolve = resolve
    try:
        yield
    finally:
        dns_email.DNSClient._resolve = original


# Options that keep the DNS module fully offline (with fake_dns active).
OFFLINE_ARGS = ["--skip-preflight", "--offline", "--no-rdap", "--no-http", "--nameservers", "127.0.0.1", "-t", "1", "-q"]
