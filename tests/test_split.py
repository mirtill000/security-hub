"""One scan, two reports: e-mail security and DNS security."""

import json
import os
import re

from securityhub import cli, inventory, orchestrator as orch, portal
from securityhub.common import EXIT_OK
from securityhub.scanners.dns_email.views import VIEWS, email_output

from .fakedns import OFFLINE_ARGS, fake_dns
from .helpers import TempDirTest, fixture, load_results, silenced


def payload(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(re.search(r'id="mg-data">(.*?)</script>', f.read(), re.S).group(1))


class SplitTest(TempDirTest):
    def scan(self, *extra, out="dns.html"):
        with silenced(), fake_dns():
            both = [] if "--combined" in extra else ["--email-output", self.path(out.replace("dns", "email"))]
            code = cli.main(["dns", fixture("domains.csv"), "-o", self.path(out)] + both + ["--json", "--csv",
                             "--checks", "all,axfr"] + OFFLINE_ARGS + list(extra))
        self.assertEqual(code, EXIT_OK)

    def test_two_reports_with_their_own_checks_and_findings(self):
        self.scan()
        self.assertEqual(sorted(os.listdir(self.tmp)), ["dns.csv", "dns.html", "dns.json", "email.csv", "email.html", "email.json"])
        email, dns = payload(self.path("email.html")), payload(self.path("dns.html"))
        self.assertEqual(email["checks"], ["mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt"])
        self.assertEqual(dns["checks"], ["dkim", "dnssec", "caa", "takeover", "axfr"])
        self.assertEqual((email["meta"]["view"], dns["meta"]["view"]), ("email", "dns"))
        self.assertEqual(dns["compliance"], {})          # sender requirements belong to the e-mail report
        protos = lambda p: {p["findings"][i["code"]][1] for r in p["results"] for i in r["issues"]}
        self.assertTrue(protos(email) <= VIEWS["email"]["protocols"] | {"DNS"})
        self.assertTrue(protos(dns) <= VIEWS["dns"]["protocols"] | {"DNS"})
        self.assertIn("AXFR_OPEN", {i["code"] for r in dns["results"] for i in r["issues"]})
        self.assertNotIn("AXFR_OPEN", {i["code"] for r in email["results"] for i in r["issues"]})
        e = {r["domain"]: r for r in load_results(self.path("email.json"))}
        d = {r["domain"]: r for r in load_results(self.path("dns.json"))}
        self.assertEqual(e["fabrikam.example"]["dnssec"]["status"], "skipped")
        self.assertEqual(d["fabrikam.example"]["dmarc"]["status"], "skipped")
        self.assertEqual(set(d["fabrikam.example"]["score_breakdown"]["components"]), {"dnssec", "caa", "takeover", "axfr"})
        self.assertEqual(d["fabrikam.example"]["overall_score"], 30)  # takeover ok 30/100; DNSSEC, CAA, AXFR failing

    def test_csv_columns_follow_the_report(self):
        self.scan()
        with open(self.path("email.csv"), encoding="utf-8-sig") as f:
            email = f.readline().strip().split(";")
        with open(self.path("dns.csv"), encoding="utf-8-sig") as f:
            dns = f.readline().strip().split(";")
        self.assertIn("dmarc_policy", email)
        self.assertNotIn("caa", email)
        self.assertIn("axfr", dns)
        self.assertNotIn("spf_status", dns)

    def test_combined_report_as_before(self):
        self.scan("--combined", out="all.html")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["all.csv", "all.html", "all.json"])
        self.assertIn("dmarc", payload(self.path("all.html"))["checks"])
        self.assertIn("caa", payload(self.path("all.html"))["checks"])

    def test_email_report_name(self):
        self.assertEqual(email_output("/r/dns.html"), "/r/email.html")
        self.assertEqual(email_output("dns_report.html"), "email_report.html")
        self.assertEqual(email_output("mailguard_dns_report.html"), "mailguard_email_report.html")
        self.assertEqual(email_output("report.html"), "report_email.html")

    def test_baseline_from_an_older_combined_export(self):
        self.scan("--combined", out="old.html")
        self.scan("--baseline", self.path("old.json"))
        email = payload(self.path("email.html"))
        self.assertEqual(email["diff"]["improved"] + email["diff"]["worsened"], 0)  # different scale: no score delta
        changes = [r["change"] for r in email["results"]]
        self.assertTrue(all(c["score_delta"] is None for c in changes))
        self.assertTrue(all(not c["resolved_issues"] for c in changes))  # DNS findings are not "resolved" e-mail findings
        self.scan("--baseline", self.path("dns.json"))  # same view: scores compared
        self.assertTrue(all(r["change"]["score_delta"] == 0 for r in payload(self.path("dns.html"))["results"]))

    def test_portal_areas_and_assets(self):
        self.scan()
        with silenced():
            cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("waf.html")])
            cli.main(["portal", self.path("email.html"), self.path("dns.html"), self.path("waf.html"), "-o", self.path("hub.html")])
        reports = portal.collect([self.path("email.html"), self.path("dns.html"), self.path("waf.html")])[0]
        self.assertEqual([(r["type"], r["label"]) for r in reports],
                         [("email", "Email security"), ("dns", "DNS security"), ("waf", "Imperva Cloud WAF")])
        kpis = {r["type"]: [k["key"] for k in r["exec"]["kpis"]] for r in reports}
        self.assertEqual((kpis["email"], kpis["dns"]), (["spoof"], ["dnssec", "caa"]))
        ids = {r["type"]: r["id"] for r in reports}
        assets = {a["key"]: a for a in inventory.build(reports)["assets"]}
        sig = {s["code"]: s for s in assets["fabrikam.example"]["signals"]}
        self.assertEqual(sig["DNS_AXFR_OPEN"]["report"], ids["dns"])       # links to the DNS report
        self.assertEqual(sig["WEB_AND_MAIL_EXPOSED"]["report"], ids["waf"])
        dom = assets["fabrikam.example"]["dns"][0]
        self.assertEqual((dom["report"], dom["dns_report"], dom["dmarc"], dom["caa"]), (ids["email"], ids["dns"], "none", "missing"))

    def test_legacy_combined_report_reads_as_email(self):
        self.scan("--combined", out="old.html")
        r = portal.collect([self.path("old.html")])[0][0]
        self.assertEqual(r["type"], "email")

    def test_run_writes_both_and_the_portal_shows_both(self):
        cfg = self.path("c.json")
        with open(cfg, "w") as f:
            json.dump({"output_dir": "out", "modules": {"dns": {"input": fixture("domains.csv"), "options": {
                "skip_preflight": True, "offline": True, "no_http": True, "nameservers": ["127.0.0.1"], "timeout": 0.3}}}}, f)
        with silenced():
            orch.run(cfg, log=lambda m: None)
        run = orch.list_runs(self.path("out"))[0]
        self.assertTrue({"email.report.json", "dns.report.json", "email.json", "dns.json", "dns.log"} <= set(os.listdir(run)))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            self.assertEqual([a["area"] for a in json.load(f)["areas"]], ["email", "dns"])
