import json
import re
import unittest
from datetime import datetime, timezone

from securityhub import cli, inventory

from .fakedns import OFFLINE_ARGS, fake_dns
from .helpers import TempDirTest, fixture, silenced

NOW = datetime(2026, 10, 31, tzinfo=timezone.utc)


def dns_row(domain, policy="reject", tier="medium", profile="mail", takeover="valid", expires=None, score=90):
    return {"domain": domain, "overall_score": score, "profile": profile, "tier": tier, "owner": "", "bu": "",
            "dmarc": {"policy": policy, "pct": 100}, "spf": {"status": "valid"}, "mta_sts": {"status": "missing"},
            "dnssec": {"status": "missing"}, "takeover": {"status": takeover, "domain_expires": expires}, "issues": []}


def waf_row(domain, profile="protected", blocking=True, days=400, codes=(), score=80):
    return {"domain": domain, "site_id": 1, "overall_score": score, "profile": profile, "tier": "medium",
            "compliance": {"owasp_block": "pass" if blocking else "fail"},
            "checks": {"tls": {"data": {"certificate": "custom", "expires": "2027-12-01", "days_left": days}}},
            "issues": [{"code": c, "severity": "critical", "message": c} for c in codes]}


def reports(dns=(), waf=(), tenant=None):
    out = [{"id": "r0", "type": "dns", "payload": {"results": list(dns)}},
           {"id": "r1", "type": "waf", "payload": {"results": list(waf)}}]
    if tenant:
        out.append({"id": "r2", "type": "zta", "score": 61, "grade": "C", "payload": {"tenant": tenant}})
    return out


def codes(asset):
    return [s["code"] for s in asset["signals"]]


class InventoryTest(unittest.TestCase):
    def test_websites_join_the_longest_listed_domain(self):
        inv = inventory.build(reports([dns_row("contoso.com"), dns_row("mail.contoso.com"), dns_row("contoso.co.uk")],
                                      [waf_row("www.contoso.com"), waf_row("shop.contoso.co.uk"), waf_row("app.mail.contoso.com")]), NOW)
        a = {x["key"]: x for x in inv["assets"]}
        self.assertEqual(sorted(a), ["contoso.co.uk", "contoso.com"])  # mail.contoso.com grouped under its parent
        self.assertEqual(sorted(w["domain"] for w in a["contoso.com"]["web"]), ["app.mail.contoso.com", "www.contoso.com"])
        self.assertEqual(len(a["contoso.com"]["dns"]), 2)

    def test_unlisted_website_is_a_coverage_gap(self):
        inv = inventory.build(reports([dns_row("contoso.com")], [waf_row("portal.northwind.co.uk")]), NOW)
        a = {x["key"]: x for x in inv["assets"]}
        self.assertIn("northwind.co.uk", a)  # registrable domain, ccTLD second level handled
        self.assertIn("DNS_NOT_MONITORED", codes(a["northwind.co.uk"]))
        self.assertTrue(a["northwind.co.uk"]["coverage_gap"])
        self.assertEqual(inv["summary"]["coverage_gaps"], 1)

    def test_cross_area_signal_web_and_mail(self):
        inv = inventory.build(reports([dns_row("fabrikam.com", policy="none", tier="high")],
                                      [waf_row("www.fabrikam.com", blocking=False)]), NOW)
        a = inv["assets"][0]
        self.assertEqual(codes(a)[0], "WEB_AND_MAIL_EXPOSED")
        self.assertEqual(a["status"], "bad")
        self.assertEqual(a["signals"][0]["report"], "r1")

    def test_spoofable_domain_without_websites(self):
        a = inventory.build(reports([dns_row("x.com", policy="none", tier="critical")]), NOW)["assets"][0]
        self.assertEqual([(s["code"], s["severity"]) for s in a["signals"]], [("MAIL_SPOOFABLE", "critical")])

    def test_bypass_origin_and_takeover(self):
        a = inventory.build(reports([dns_row("x.com", takeover="error")],
                                    [waf_row("a.x.com", profile="bypass"), waf_row("b.x.com", codes=("ORIGIN_EXPOSED",))]), NOW)["assets"][0]
        self.assertTrue({"WEB_BYPASS", "WEB_ORIGIN_EXPOSED", "DNS_TAKEOVER"} <= set(codes(a)))

    def test_expiries(self):
        a = inventory.build(reports([dns_row("x.com", expires="2026-11-10T00:00:00Z")],
                                    [waf_row("a.x.com", days=20), waf_row("b.x.com", days=-3), waf_row("c.x.com", days=500)]), NOW)["assets"][0]
        sig = {(s["code"], s["severity"]) for s in a["signals"]}
        self.assertIn(("EXPIRING", "warning"), sig)   # certificate in 20 days, registration in 10 days (<= 14: critical)
        self.assertIn(("EXPIRED", "critical"), sig)
        self.assertIn(("EXPIRING", "critical"), sig)
        self.assertEqual(a["next_expiry"]["days"], -3)
        self.assertEqual([e["days"] for e in a["expiries"]], [-3, 10, 20, 500])

    def test_tenant_joins_its_domain_and_healthy_asset(self):
        inv = inventory.build(reports([dns_row("contoso.com"), dns_row("old.net", profile="non-mail")], [waf_row("www.contoso.com")],
                                      tenant={"name": "Contoso", "domain": "contoso.com"}), NOW)
        a = {x["key"]: x for x in inv["assets"]}
        self.assertEqual(a["contoso.com"]["tenant"]["score"], 61)
        self.assertEqual(a["contoso.com"]["status"], "good")
        self.assertEqual(a["contoso.com"]["signals"], [])

    def test_no_dns_or_waf(self):
        self.assertEqual(inventory.build([{"id": "r0", "type": "zta", "payload": {"tenant": {}}}])["assets"], [])

    def test_sorting_puts_assets_at_risk_first(self):
        inv = inventory.build(reports([dns_row("ok.com"), dns_row("bad.com", takeover="error")]), NOW)
        self.assertEqual([a["key"] for a in inv["assets"]], ["bad.com", "ok.com"])


class PortalAssetsTest(TempDirTest):
    def test_portal_and_posture_carry_the_inventory(self):
        with silenced():
            with fake_dns():
                cli.main(["dns", fixture("domains.csv"), "-o", self.path("dns.html")] + OFFLINE_ARGS)
            cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("waf.html")])
            cli.main(["zta", fixture("ZeroTrustAssessmentReport.json"), "-o", self.path("zta.html")])
            cli.main(["portal", self.tmp, "-o", self.path("hub.html"), "--summary-json", self.path("p.json")])
        with open(self.path("hub.html"), encoding="utf-8") as f:
            page = f.read()
        data = json.loads(re.search(r'id="hub-data">(.*?)</script>', page, re.S).group(1))
        assets = {a["key"]: a for a in data["meta"]["inventory"]["assets"]}
        self.assertEqual(sorted(assets), ["contoso-old.example", "contoso.example", "fabrikam.example", "northwind.example"])
        self.assertEqual(assets["contoso.example"]["tenant"]["name"], "Contoso")
        self.assertIn("WEB_AND_MAIL_EXPOSED", codes(assets["fabrikam.example"]))
        self.assertNotIn('"payload"', page[:page.index('id="rep-')])  # parsed payloads are not duplicated in the index
        with open(self.path("p.json"), encoding="utf-8") as f:
            posture = json.load(f)
        self.assertEqual(posture["assets"]["summary"]["coverage_gaps"], 1)
        self.assertEqual(posture["assets"]["items"][0]["status"], "bad")


if __name__ == "__main__":
    unittest.main()
