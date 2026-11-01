"""CAA and zone transfer (AXFR) checks of the DNS module."""

import unittest
from unittest import mock

from securityhub import cli, inventory, portal
from securityhub.scanners import dns_email
from securityhub.scanners.dns_email import parse_checks

from .fakedns import OFFLINE_ARGS, fake_dns, load_zones
from .helpers import TempDirTest, fixture, load_results, silenced


class Answer:
    def __init__(self, n):
        self.answer = [[object()] * n]


class DnsHygieneTest(TempDirTest):
    def scan(self, checks="all,axfr", zones=None):
        with silenced(), fake_dns(zones):
            cli.main(["dns", fixture("domains.csv"), "-o", self.path("dns.html"), "--json", "--csv", "--checks", checks] + OFFLINE_ARGS)
        return {r["domain"]: r for r in load_results(self.path("dns.json"))}

    def test_checks_selection(self):
        self.assertIn("caa", parse_checks("all"))
        self.assertNotIn("axfr", parse_checks("all"))  # active test: opt-in
        self.assertIn("axfr", parse_checks("all,zone-transfer"))

    def test_caa(self):
        r = self.scan()
        c = r["contoso.example"]["caa"]
        self.assertEqual((c["status"], c["issuers"], c["iodef"]), ("valid", ["digicert.com", "letsencrypt.org"],
                                                                    ["mailto:security@contoso.example"]))
        self.assertEqual(r["contoso-old.example"]["caa"]["issuers"], [";"])
        self.assertEqual([i["code"] for i in r["contoso-old.example"]["caa"]["issues"]], [])  # ";" needs no iodef
        f = r["fabrikam.example"]
        self.assertEqual(f["caa"]["status"], "missing")
        self.assertIn("CAA_MISSING", [i["code"] for i in f["issues"]])
        self.assertTrue(any(x["type"] == "CAA" for x in f["remediation"]))

    def test_caa_inherited_invalid_and_error(self):
        zones = load_zones()
        zones["mail.contoso.example"] = {"A": ["203.0.113.25"], "SOA": ["x"]}
        zones["fabrikam.example"]["CAA"] = ['128 tbs "x"', '0 issue "digicert.com"']
        zones["contoso-old.example"]["CAA"] = ["garbage"]
        with open(self.path("d.txt"), "w") as f:
            f.write("mail.contoso.example\nfabrikam.example\ncontoso-old.example\n")
        with silenced(), fake_dns(zones):
            cli.main(["dns", self.path("d.txt"), "-o", self.path("dns.html"), "--json", "--checks", "caa"] + OFFLINE_ARGS)
        r = {x["domain"]: x for x in load_results(self.path("dns.json"))}
        self.assertEqual(r["mail.contoso.example"]["caa"]["inherited_from"], "contoso.example")
        self.assertEqual(r["fabrikam.example"]["caa"]["status"], "warning")
        self.assertIn("CAA_INVALID", [i["code"] for i in r["fabrikam.example"]["caa"]["issues"]])
        self.assertIn("CAA_INVALID", [i["code"] for i in r["contoso-old.example"]["caa"]["issues"]])

    def test_axfr(self):
        r = self.scan()
        self.assertEqual(r["fabrikam.example"]["axfr"]["status"], "error")
        self.assertIn("AXFR_OPEN", [i["code"] for i in r["fabrikam.example"]["issues"]])
        self.assertEqual(r["contoso.example"]["axfr"]["status"], "valid")
        self.assertEqual({s["result"] for s in r["contoso.example"]["axfr"]["servers"]}, {"refused"})
        # the e-mail score does not depend on DNS checks
        email = lambda: {x["domain"]: x["overall_score"] for x in load_results(self.path("email.json"))}
        before = email()
        self.scan("all")
        self.assertEqual(email(), before)

    def test_axfr_probe_reads_only_the_first_message(self):
        client = dns_email.DNSClient(["127.0.0.1"], timeout=1)
        with mock.patch.object(dns_email.dnsclient.dns.query, "xfr", return_value=iter([Answer(5), Answer(500)])):
            self.assertEqual(client.axfr("192.0.2.1", "x.example"), ("open", 5))
        with mock.patch.object(dns_email.dnsclient.dns.query, "xfr", side_effect=dns_email.dnsclient.dns.exception.FormError()):
            self.assertEqual(client.axfr("192.0.2.1", "x.example"), ("refused", 0))
        with mock.patch.object(dns_email.dnsclient.dns.query, "xfr", side_effect=ConnectionRefusedError()):
            self.assertEqual(client.axfr("192.0.2.1", "x.example"), ("unreachable", 0))

    def test_portal_and_assets(self):
        self.scan()
        with silenced():
            cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("waf.html")])
        reps = portal.collect([self.path("dns.html"), self.path("waf.html")])[0]
        dns = next(r for r in reps if r["type"] == "dns")
        side = {k: v for k, v, _ in dns["exec"]["side"]}
        self.assertEqual(side["Zone transfer open to anyone"], "1 domain")
        kpi = {k["key"]: k for k in dns["exec"]["kpis"]}
        self.assertEqual((kpi["caa"]["value"], kpi["caa"]["detail"]), (67, "2 of 3 verified domains"))
        signals = {a["key"]: {s["code"] for s in a["signals"]} for a in inventory.build(reps)["assets"]}
        self.assertIn("DNS_AXFR_OPEN", signals["fabrikam.example"])
        self.assertIn("WEB_NO_CAA", signals["fabrikam.example"])
        with open(self.path("dns.csv"), encoding="utf-8-sig") as f:
            header = f.readline()
        self.assertIn("caa;caa_issuers;takeover;axfr", header)


if __name__ == "__main__":
    unittest.main()
