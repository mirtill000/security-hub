import json
import os
import unittest

from securityhub import cli
from securityhub.common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE

from .helpers import TempDirTest, fixture, silenced


class CliTest(TempDirTest):
    def test_help_and_version(self):
        with silenced() as (out, _):
            self.assertEqual(cli.main(["--help"]), EXIT_OK)
            self.assertEqual(cli.main(["--version"]), EXIT_OK)
        self.assertIn("securityhub <command>", out.getvalue())

    def test_no_args_and_unknown_command(self):
        with silenced():
            self.assertEqual(cli.main([]), EXIT_USAGE)
            self.assertEqual(cli.main(["nope"]), EXIT_USAGE)

    def test_module_usage_error_is_exit_1(self):
        with silenced() as (_, err):
            self.assertEqual(cli.main(["zta"]), EXIT_USAGE)
        self.assertIn("securityhub zta", err.getvalue())

    def test_zta_report(self):
        out = self.path("zta.html")
        with silenced():
            code = cli.main(["zta", fixture("ZeroTrustAssessmentReport.json"), "-o", out, "--json", "--csv"])
        self.assertEqual(code, EXIT_OK)
        for ext in ("html", "json", "csv"):
            self.assertTrue(os.path.isfile(self.path(f"zta.{ext}")))
        with open(self.path("zta.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["tenant"]["name"], "Contoso")
        self.assertEqual(len(data["tests"]), 8)

    def test_zta_fail_under(self):
        with silenced():
            code = cli.main(["zt", fixture("ZeroTrustAssessmentReport.json"), "-o", self.path("z.html"), "--fail-under", "90"])
        self.assertEqual(code, EXIT_FAIL_UNDER)

    def test_waf_from_snapshot(self):
        out = self.path("waf.html")
        with silenced():
            code = cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", out, "--json"])
        self.assertEqual(code, EXIT_OK)
        with open(self.path("waf.json"), encoding="utf-8") as f:
            data = json.load(f)
        domains = {r["domain"]: r for r in data["results"]}
        self.assertEqual(domains["legacy.contoso.example"]["profile"], "bypass")

    def test_portal_and_status(self):
        with silenced():
            cli.main(["zta", fixture("ZeroTrustAssessmentReport.json"), "-o", self.path("zta.html")])
            cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("waf.html")])
            code = cli.main(["portal", self.tmp, "-o", self.path("hub.html"), "--summary-json", self.path("posture.json")])
        self.assertEqual(code, EXIT_OK)
        with open(self.path("hub.html"), encoding="utf-8") as f:
            page = f.read()
        self.assertIn('id="hub-data"', page)
        with open(self.path("posture.json"), encoding="utf-8") as f:
            posture = json.load(f)
        self.assertEqual(sorted(a["area"] for a in posture["areas"]), ["waf", "zta"])
        with silenced() as (out, _):
            self.assertEqual(cli.main(["status", self.tmp, "--json"]), EXIT_OK)
        self.assertEqual(len(json.loads(out.getvalue())["areas"]), 2)  # the portal file itself is not a report

    def test_init_writes_config_once(self):
        cfg = self.path("securityhub.yaml")
        with silenced():
            self.assertEqual(cli.main(["init", cfg]), EXIT_OK)
            self.assertEqual(cli.main(["init", cfg]), EXIT_USAGE)
            self.assertEqual(cli.main(["init", cfg, "--force"]), EXIT_OK)


if __name__ == "__main__":
    unittest.main()
