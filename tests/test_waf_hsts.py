"""WAF HSTS check: header through same-host redirects, unverifiable answers are not failures."""

import unittest

from securityhub.scanners.waf.checks import check_tls
from securityhub.scanners.waf.probe import check_hsts


def resp(status, headers=None, body=""):
    return {"ok": True, "status": status, "headers": {k.lower(): v for k, v in (headers or {}).items()}, "body": body}


class HstsTest(unittest.TestCase):
    def test_states(self):
        h = check_hsts("www.example", resp(200, {"Strict-Transport-Security": "max-age=31536000"}), 5)
        self.assertEqual((h["state"], h["max_age"], h["include_subdomains"], h["preload"]), ("present", 31536000, False, False))
        self.assertEqual(check_hsts("www.example", resp(200), 5)["state"], "missing")
        self.assertEqual(check_hsts("www.example", resp(200, {"Strict-Transport-Security": "max-age=0"}), 5)["state"], "disabled")
        self.assertEqual(check_hsts("www.example", {"ok": False, "error": "timeout"}, 5)["state"], "unknown")
        self.assertEqual(check_hsts("www.example", resp(403), 5)["state"], "unknown")
        challenge = resp(200, body="<html><script src=/_Incapsula_Resource?x=1></script>")
        self.assertEqual(check_hsts("www.example", challenge, 5)["state"], "unknown")

    def test_follows_same_host_redirects_only(self):
        pages = {"/it/": resp(200, {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"})}
        h = check_hsts("www.example", resp(301, {"Location": "https://www.example/it/"}), 5, fetch=lambda p: pages[p])
        self.assertEqual((h["state"], h["path"]), ("present", "/it/"))
        h = check_hsts("www.example", resp(302, {"Location": "/it/"}), 5, fetch=lambda p: pages[p])
        self.assertEqual(h["state"], "present")
        h = check_hsts("www.example", resp(301, {"Location": "https://other.example/"}), 5, fetch=lambda p: pages[p])
        self.assertEqual(h["state"], "missing")                     # another host's header does not protect this one
        loop = check_hsts("www.example", resp(302, {"Location": "/a"}), 5, fetch=lambda p: resp(302, {"Location": "/a"}))
        self.assertEqual(loop["state"], "missing")

    def test_check_tls(self):
        site = {"ssl": {"generated_certificate": {"ca": "GS", "validation_status": "done"}}}
        base = {"addresses": ["203.0.113.1"], "https": {"ok": True}, "redirects_https": True, "tls10": False, "tls11": False}
        codes = lambda probe: {i.code for i in check_tls(site, {**base, **probe}).issues}
        self.assertNotIn("TLS_NO_HSTS", codes({"hsts_check": {"state": "present", "header": "max-age=1"}}))
        self.assertNotIn("TLS_NO_HSTS", codes({"hsts_check": {"state": "unknown", "reason": "timeout"}}))
        self.assertIn("TLS_NO_HSTS", codes({"hsts_check": {"state": "missing"}}))
        self.assertIn("TLS_NO_HSTS", codes({"hsts_check": {"state": "disabled", "max_age": 0}}))
        self.assertNotIn("TLS_NO_HSTS", codes({"hsts": None, "https": {"ok": False, "error": "timeout"}}))   # older probe
        self.assertIn("TLS_NO_HSTS", codes({"hsts": None}))
