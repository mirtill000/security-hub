"""Proofpoint Threat Protection API (reports) and PoD Log API (WebSocket streams): read-only clients, aggregation, findings."""

import io
import json
import socket
import struct
import threading
import unittest
import urllib.parse
from datetime import datetime, timezone
from unittest import mock

from securityhub.scanners.proofpoint import podlog, tpapi

from .helpers import TempDirTest

NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)

# Shapes of the documented sample responses (Dash Reports API)
TP_ANSWERS = {
    "/effectiveness-reports/threat-response-quarantines": {"total": {
        "numberOfTapMessages": 100, "numberOfMessageCopiesQuarantinedUnread": 80, "numberOfMessageCopiesQuarantinedRead": 15,
        "numberOfMessageCopiesSkippedSkiplisted": 3, "numberOfMessageCopiesSkippedExternal": 2}},
    "/effectiveness-reports/url-rewritten-summary": {
        "rewrittenURLs": {"countURLs": 15000, "countMessages": 12000, "reasons": []},
        "nonRewrittenURLsDueToPPS": {"countURLs": 500, "countMessages": 400, "reasons": [{"reason": "Excluded domain", "countURLs": 450}]},
        "nonRewrittenURLs": {"countURLs": 600, "countMessages": 150, "reasons": []}},
    "/bec-reports/vips-targeted-by-bec-threats": {"users": [
        {"person": "John CEO", "title": "Chief Executive Officer", "vip": True, "ato": False, "riskExposure": "HIGH",
         "isPrivileged": True, "attackIndex": 95.5, "becEmailThreats": 25},
        {"person": "Ann CFO", "vip": True, "ato": False, "riskExposure": "LOW", "isPrivileged": False, "becEmailThreats": 2}]},
    "/executive-summary/industry-comparison": {"customer": {"attackIndex": 85}, "verticals": [{"name": "TECHNOLOGY", "attackIndex": 75}]},
    "/mail-bomb-events": {"data": [{"name": None, "email": "Bob@Contoso.com", "eventCount": 412}], "total": 1},
}


class FakeHTTP(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ThreatProtectionTest(TempDirTest):
    def fake(self, seen):
        def urlopen(req, timeout=None, context=None):
            url = urllib.parse.urlsplit(req.full_url)
            seen.append((req.get_method(), url.netloc, url.path, dict(urllib.parse.parse_qsl(url.query))))
            if url.netloc == "auth.proofpoint.com":
                return FakeHTTP(json.dumps({"access_token": "tok", "token_type": "Bearer", "expires_in": 3600}).encode())
            assert req.headers["Authorization"] == "Bearer tok"
            return FakeHTTP(json.dumps(TP_ANSWERS[url.path.split("/dash/reports", 1)[1]]).encode())
        return urlopen

    def test_reads_are_gets_on_a_closed_list_and_findings(self):
        seen = []
        api = tpapi.ThreatProtectionAPI("key", "secret")
        api.rate.wait = lambda: None
        with mock.patch("urllib.request.urlopen", self.fake(seen)):
            tp = tpapi.collect(api, lambda m: None, 30, now=NOW)
        self.assertEqual(seen[0][:3], ("POST", "auth.proofpoint.com", "/v1/token"))      # the only POST: the token
        reports = seen[1:]
        self.assertTrue(all(m == "GET" and h == "threatprotection-api.proofpoint.com" for m, h, _, _ in reports))
        self.assertEqual({p.split("/dash/reports", 1)[1] for _, _, p, _ in reports}, set(tpapi.READ_ONLY_PATHS))
        self.assertEqual(reports[0][3]["start"], "2026-10-07T12:00:00Z")                   # documented ISO 8601 UTC
        industry = next(q for _, _, p, q in reports if p.endswith("industry-comparison"))
        self.assertEqual(industry["startMonth"], "2026-07")    # within the accepted range (13 to 3 months ago), a complete quarter
        with self.assertRaises(ValueError):
            api.get("/effectiveness-reports/custom-blocklist-activity")                      # not on the list

        issues, data = tpapi.findings(tp)
        codes = {i.code for i in issues}
        self.assertEqual(codes, {"TR_PULLED_AFTER_READ", "TR_SKIPPED", "URL_REWRITE_GAP", "BEC_VIP_TARGETED_RISK",
                                 "ATTACK_INDEX_ABOVE_INDUSTRY", "MAIL_BOMB_TARGETED"})
        self.assertEqual(data["quarantines"]["read_share"], 16)                               # 15 of 95 pulled after reading
        self.assertEqual(data["url_rewrite"]["coverage"], 93.2)
        self.assertEqual(data["mail_bomb"]["users"][0]["email"], "bob@contoso.com")

    def test_daily_cache_keeps_within_the_rate_limits(self):
        from securityhub.cache import Store
        seen = []
        store = Store("proofpoint", path=self.path("c.json"), now=NOW)
        api = tpapi.ThreatProtectionAPI("key", "secret")
        api.rate.wait = lambda: None
        with mock.patch("urllib.request.urlopen", self.fake(seen)):
            tpapi.collect(api, lambda m: None, 30, now=NOW, store=store)
            n = len(seen)
            again = tpapi.collect(api, lambda m: None, 30, now=NOW, store=store)
        self.assertEqual(len(seen), n)                                   # second run: no call at all
        self.assertEqual(len(again["reused"]), 5)

    def test_bad_key_is_explained(self):
        import urllib.error
        api = tpapi.ThreatProtectionAPI("key", "bad")
        api.rate.wait = lambda: None
        err = urllib.error.HTTPError("u", 401, "x", {}, io.BytesIO(b""))
        with mock.patch("urllib.request.urlopen", side_effect=err):
            tp = tpapi.collect(api, lambda m: None, 30, now=NOW)
        self.assertIn("API Key Management", tp["errors"][0]["error"])
        self.assertIn("TP_API_ERROR", {i.code for i in tpapi.findings(tp)[0]})


def ev_message(direction="inbound", disp="accept", spf="pass", dmarc="pass", hdr_from="news@partner.com", tls="TLSv1.2",
               urls=None, sandbox=None):
    e = {"connection": {"helo": "mx.sender.example", "ip": "192.0.2.1",
                        "tls": {"inbound": {"version": tls}} if tls else {}},
         "envelope": {"from": hdr_from, "rcpts": ["user@contoso.com"]},
         "filter": {"routeDirection": direction, "disposition": disp, "delivered": {"rcpts": ["user@contoso.com"]} if disp == "accept" else {},
                    "modules": {"spf": {"result": spf}, "dmarc": {"filterdResult": dmarc}}},
         "msg": {"normalizedHeader": {"from": [f"\"Sender\" <{hdr_from}>"], "subject": ["secret subject"]}}, "ts": "2026-11-06T10:00:00Z"}
    if urls:
        e["filter"]["modules"]["urldefense"] = {"counts": urls}
    if sandbox:
        e["filter"]["modules"]["sandbox"] = {"errorStatus": sandbox}
    return e


def ev_audit(action, user, ip, sub="authorization", name=None):
    return {"audit": {"action": action, "resourceName": name, "tags": [{"name": "eventSubCategory", "value": sub}],
                      "user": {"email": user, "ipAddress": ip}}, "ts": "2026-11-06T09:00:00Z"}


MESSAGES = ([ev_message() for _ in range(80)]
            + [ev_message(spf="fail", dmarc="fail", hdr_from="invoice@bad.example") for _ in range(5)]            # delivered
            + [ev_message(disp="reject", spf="fail", dmarc="fail", hdr_from="ceo@contoso.com")]                     # spoof blocked
            + [ev_message(spf="fail", dmarc="fail", hdr_from="it@contoso.com")]                                     # spoof delivered
            + [ev_message(tls="") for _ in range(10)]                                                               # no TLS
            + [ev_message(tls="TLSv1.0") for _ in range(2)]
            + [ev_message(urls={"total": 10, "rewritten": 7, "noRewriteIsExcludedDomain": 3})]
            + [ev_message(sandbox="timeout")]
            + [ev_message(direction="outbound") for _ in range(4)])
AUDIT = [ev_audit("login", "admin@contoso.com", ip) for ip in ("198.51.100.1", "198.51.100.2", "203.0.113.9")] + \
        [ev_audit("login", "ops@contoso.com", "198.51.100.1"),
         ev_audit("create", "admin@contoso.com", "198.51.100.1", "threatProtectionApiKeys", "siem-key"),
         ev_audit("edit", "ops@contoso.com", "198.51.100.1", "spamDetection.policies")]


def ws_frame(payload: bytes, opcode=0x1) -> bytes:
    n = len(payload)
    head = bytes([0x80 | opcode]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack("!H", n) if n < 65536
                                     else bytes([127]) + struct.pack("!Q", n))
    return head + payload


def fake_server(events_by_type, requests, status=101):
    """A connect() for open_stream: a socketpair whose other end answers like the PoD log service."""
    def connect():
        client, server = socket.socketpair()

        def serve():
            req = b""
            while b"\r\n\r\n" not in req:
                req += server.recv(4096)
            line = req.split(b"\r\n", 1)[0].decode()
            requests.append((line, req.decode()))
            if status != 101:
                server.sendall(f"HTTP/1.1 {status} Unauthorized\r\n\r\n".encode())
                server.close()
                return
            kind = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(line.split()[1]).query))["type"]
            server.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            server.sendall(ws_frame(b"", 0x9))                                       # a ping first
            for e in events_by_type[kind]:
                data = json.dumps(e).encode()
                server.sendall(ws_frame(data[:20], 0x1)[:0] + bytes([0x01, len(data[:20])]) + data[:20]   # fragmented frame
                               + ws_frame(data[20:], 0x0))
            server.sendall(ws_frame(struct.pack("!H", 1000), 0x8))
            try:
                server.recv(4096)
            except OSError:
                pass
            server.close()
        threading.Thread(target=serve, daemon=True).start()
        return client
    return connect


class PodLogTest(unittest.TestCase):
    def test_streams_are_read_and_only_counted(self):
        requests = []
        pod = podlog.collect("pphosted_contoso_hosted", "tok", ["contoso.com"], lambda m: None, 4, now=NOW,
                             connect=fake_server({"message": MESSAGES, "audit": AUDIT}, requests))
        self.assertEqual(len(requests), 2)
        line, raw = requests[0]
        self.assertTrue(line.startswith("GET /v1/stream?cid=pphosted_contoso_hosted&type=message&sinceTime=2026-11-06T08:00:00Z"
                                        "&toTime=2026-11-06T12:00:00Z HTTP/1.1"))
        self.assertIn("Authorization: Bearer tok", raw)
        self.assertNotIn("secret subject", json.dumps(pod))                       # nothing of the messages is kept
        m = pod["message"]
        self.assertEqual((m["events"], m["counts"]["inbound"], m["counts"]["other_direction"]), (105, 101, 4))
        self.assertEqual(m["recipient_domains"], [("contoso.com", 101)])          # domains only, no addresses

        issues, data = podlog.findings(pod)
        codes = {i.code for i in issues}
        self.assertEqual(codes, {"POD_AUTH_FAIL_DELIVERED", "POD_SPOOF_DELIVERED", "POD_INBOUND_NO_TLS", "POD_URL_EXCLUDED_DOMAINS",
                                 "POD_SANDBOX_ERRORS", "POD_ADMIN_MANY_IPS", "POD_API_KEY_CREATED", "POD_CONFIG_CHANGES"})
        d = data["message"]
        self.assertEqual((d["auth_failed_delivered"], d["spoof"], d["spoof_delivered"], d["no_tls"]), (6, 2, 1, 12))
        self.assertEqual(tuple(d["auth_fail_senders"][0]), ("bad.example", 5))
        self.assertEqual(d["url_coverage"], 70.0)
        self.assertEqual(data["audit"]["admins"], ["admin@contoso.com", "ops@contoso.com"])

    def test_token_rejected(self):
        pod = podlog.collect("c", "bad", [], lambda m: None, 4, now=NOW, connect=fake_server({}, [], status=401))
        self.assertIsNone(pod["message"])
        self.assertNotIn("audit", pod)                                           # same token: not tried again
        self.assertIn("token invalid", pod["errors"][0]["error"])
        self.assertEqual({i.code for i in podlog.findings(pod)[0]}, {"POD_API_ERROR"})

    def test_only_message_and_audit_streams(self):
        with self.assertRaises(ValueError):
            podlog.open_stream("c", "t", "maillog", NOW, NOW, connect=lambda: None)


if __name__ == "__main__":
    unittest.main()
