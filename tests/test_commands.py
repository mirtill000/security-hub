"""Four single commands (email, dns, waf, zta) and one scan for e-mail + DNS in 'securityhub run'."""

import json
import os
import re

from securityhub import cli, orchestrator as orch
from securityhub.common import EXIT_OK, EXIT_USAGE

from .fakedns import OFFLINE_ARGS, fake_dns
from .helpers import TempDirTest, fixture, silenced


def checks_of(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(re.search(r'id="mg-data">(.*?)</script>', f.read(), re.S).group(1))["checks"]


class CommandsTest(TempDirTest):
    def run_cmd(self, *argv):
        with silenced() as (out, err), fake_dns():
            code = cli.main(list(argv) + OFFLINE_ARGS)
        return code, err.getvalue()

    def test_help_lists_four_commands(self):
        with silenced() as (out, _):
            cli.main(["--help"])
        for c in ("email", "dns", "waf", "zta"):
            self.assertRegex(out.getvalue(), rf"\n  {c} ")

    def test_email_command_writes_one_email_report(self):
        code, _ = self.run_cmd("email", fixture("domains.csv"), "-o", self.path("e.html"), "--json")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["e.html", "e.json"])
        self.assertEqual(checks_of(self.path("e.html")), ["mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt"])

    def test_bimi_only_on_request(self):
        self.run_cmd("email", fixture("domains.csv"), "-o", self.path("e.html"), "--json")
        with open(self.path("e.json"), encoding="utf-8") as f:
            rows = json.load(f)["results"]
        self.assertTrue(all(r["bimi"]["status"] == "skipped" for r in rows))
        self.assertFalse(any(i["code"].startswith("BIMI") for r in rows for i in r["issues"]))
        self.run_cmd("email", fixture("domains.csv"), "-o", self.path("b.html"), "--checks", "all,bimi")
        self.assertEqual(checks_of(self.path("b.html"))[-1], "bimi")

    def test_dns_command_writes_one_dns_report(self):
        code, _ = self.run_cmd("dns", fixture("domains.csv"), "-o", self.path("d.html"), "--checks", "all,axfr")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(os.listdir(self.tmp), ["d.html"])
        self.assertEqual(checks_of(self.path("d.html")), ["dkim", "dnssec", "caa", "takeover", "axfr"])

    def test_checks_of_the_other_command_are_refused(self):
        code, err = self.run_cmd("email", fixture("domains.csv"), "-o", self.path("e.html"), "--checks", "spf,caa")
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("use 'securityhub dns'", err)
        code, err = self.run_cmd("dns", fixture("domains.csv"), "-o", self.path("d.html"), "--checks", "dmarc")
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("use 'securityhub email'", err)

    def test_default_output_names(self):
        from securityhub.scanners.dns_email import build_parser
        self.assertEqual(build_parser("email").parse_args(["x"]).output, "email_report.html")
        self.assertEqual(build_parser("dns").parse_args(["x"]).output, "dns_report.html")


class OneScanTest(TempDirTest):
    OPTS = {"skip_preflight": True, "offline": True, "no_http": True, "nameservers": ["127.0.0.1"], "timeout": 0.3}

    def config(self, email_opts=None, dns_opts=None, email=True):
        mods = {"dns": {"input": fixture("domains.csv"), "options": {**self.OPTS, **(dns_opts or {})}}}
        if email:
            mods["email"] = {"input": fixture("domains.csv"), "options": {**self.OPTS, **(email_opts or {})}}
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": mods}, f)
        return p

    def dry(self, cfg):
        with silenced() as (out, _):
            self.assertEqual(orch.run(cfg, dry_run=True), EXIT_OK)
        return [l for l in out.getvalue().splitlines() if l.startswith("securityhub ")]

    def test_email_and_dns_share_one_scan(self):
        cmds = self.dry(self.config({"checks": "spf,dmarc", "dmarc_reports": [self.tmp]}, {"checks": "all,axfr"}))
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith("securityhub dns "))
        self.assertIn("--email-output", cmds[0])
        self.assertIn("--checks spf,dmarc,dkim,dnssec,caa,takeover,axfr", cmds[0])   # DKIM is in both reports
        self.assertIn("--dmarc-reports", cmds[0])   # e-mail-only options travel with the shared scan

    def test_conflicting_options_keep_two_scans(self):
        cmds = self.dry(self.config({"workers": 2}, {"workers": 8}))
        self.assertEqual([c.split()[1] for c in cmds], ["email", "dns"])

    def test_only_one_of_them(self):
        with silenced() as (out, _):
            orch.run(self.config(), dry_run=True, only=["email"])
        self.assertEqual([l.split()[1] for l in out.getvalue().splitlines() if l.startswith("securityhub ")], ["email"])

    def test_older_configuration_with_dns_only_still_gets_both_reports(self):
        cmds = self.dry(self.config(email=False))
        self.assertEqual(len(cmds), 1)
        self.assertIn("--email-output", cmds[0])

    def test_run_produces_both_reports_and_areas(self):
        with silenced():
            orch.run(self.config(), log=lambda m: None)
        run = orch.list_runs(self.path("out"))[0]
        self.assertTrue({"email.report.json", "dns.report.json"} <= set(os.listdir(run)))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            p = json.load(f)
        self.assertEqual([a["area"] for a in p["areas"]], ["email", "dns"])
        self.assertEqual([m["module"] for m in p["run"]["modules"]], ["dns"])  # one process for both
