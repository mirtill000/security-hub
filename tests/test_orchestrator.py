import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

from securityhub import orchestrator as orch
from securityhub.common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE
from securityhub.scanners import waf

from .helpers import TempDirTest, fixture, silenced

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)


class OptionsTest(unittest.TestCase):
    def setUp(self):
        self.parser = waf.build_parser()

    def test_switches_values_and_lists(self):
        argv = orch.options_to_argv(self.parser, {"account_id": 1, "probe": True, "csv": False, "sites": ["a.com", "b.com"],
                                                  "include-subaccounts": True, "baseline": None})
        self.assertEqual(argv, ["--account-id", "1", "--probe", "--sites", "a.com,b.com", "--include-subaccounts"])

    def test_unknown_reserved_and_secret_options(self):
        for opts in ({"nope": 1}, {"output": "x.html"}, {"api_key": "secret"}, {"probe": "yes"}):
            with self.assertRaises(orch.ConfigError):
                orch.options_to_argv(self.parser, opts)

    def test_append_options_are_repeated(self):
        try:
            from securityhub.scanners import dns_email
        except ImportError:
            self.skipTest("dnspython not installed")
        argv = orch.options_to_argv(dns_email.build_parser(), {"dmarc_reports": ["a", "b"], "nameservers": ["1.1.1.1", "9.9.9.9"]})
        self.assertEqual(argv, ["--dmarc-reports", "a", "--dmarc-reports", "b", "--nameservers", "1.1.1.1,9.9.9.9"])


class ExampleConfigTest(TempDirTest):
    def test_example_file_matches_template_and_loads(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "examples", "securityhub.example.yaml"), encoding="utf-8") as f:
            self.assertEqual(f.read(), orch.EXAMPLE_CONFIG)
        p = self.path("c.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(orch.EXAMPLE_CONFIG)
        cfg = orch.load_config(p)
        self.assertEqual(set(cfg["modules"]), {"dns", "waf", "zta"})

    def test_unknown_module_rejected(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"modules": {"siem": {}}}, f)
        with self.assertRaises(orch.ConfigError):
            orch.load_config(p)


class RunTest(TempDirTest):
    def config(self, **extra):
        cfg = {"title": "Test", "output_dir": "out", "keep_runs": 3, "modules": {
            "waf": {"options": {"from_json": fixture("waf_snapshot.json"), "csv": True}},
            "zta": {"input": fixture("ZeroTrustAssessmentReport.json")}}}
        cfg.update(extra)
        p = self.path("securityhub.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        return p

    def run_hub(self, cfg, when, **kw):
        with silenced():
            return orch.run(cfg, now=when, log=lambda m: None, **kw)

    def test_run_builds_portal_posture_and_history(self):
        cfg = self.config()
        self.assertEqual(self.run_hub(cfg, T0), EXIT_OK)
        self.assertEqual(self.run_hub(cfg, T0 + timedelta(days=7)), EXIT_OK)
        out = self.path("out")
        runs = orch.list_runs(out)
        self.assertEqual(len(runs), 2)
        for name in ("waf.html", "waf.json", "waf.csv", "zta.html", "zta.json"):
            self.assertTrue(os.path.isfile(os.path.join(runs[-1], name)), name)
        self.assertTrue(os.path.isfile(os.path.join(out, "security_hub.html")))
        with open(os.path.join(out, "posture.json"), encoding="utf-8") as f:
            posture = json.load(f)
        self.assertEqual([a["area"] for a in posture["areas"]], ["waf", "zta"])
        self.assertEqual(len(posture["runs"]), 4)  # 2 runs x 2 modules feed the KPI history
        self.assertEqual(posture["run"]["id"], (T0 + timedelta(days=7)).strftime(orch.RUN_FORMAT))
        # the second run was compared with the first one
        with open(os.path.join(runs[-1], "zta.json"), encoding="utf-8") as f:
            self.assertTrue(all("change" in t for t in json.load(f)["tests"]))

    def test_runs_in_the_same_second_do_not_overwrite(self):
        cfg = self.config()
        self.run_hub(cfg, T0)
        self.run_hub(cfg, T0)
        self.assertEqual(len(orch.list_runs(self.path("out"))), 2)

    def test_quiet_hides_module_output(self):
        with silenced() as (out, err):
            orch.run(self.config(), now=T0, quiet=True, log=lambda m: None)
        self.assertNotIn("Report generated", out.getvalue() + err.getvalue())
        self.assertIn("SECURITY POSTURE", out.getvalue())

    def test_keep_runs_prunes_old_runs(self):
        cfg = self.config(keep_runs=2)
        for d in range(4):
            self.run_hub(cfg, T0 + timedelta(days=d))
        runs = orch.list_runs(self.path("out"))
        self.assertEqual([os.path.basename(r) for r in runs],
                         [(T0 + timedelta(days=d)).strftime(orch.RUN_FORMAT) for d in (2, 3)])

    def test_dry_run_writes_nothing(self):
        with silenced() as (out, _):
            code = orch.run(self.config(), dry_run=True, log=lambda m: None)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("securityhub waf", out.getvalue())
        self.assertFalse(os.path.exists(self.path("out")))

    def test_only(self):
        self.assertEqual(self.run_hub(self.config(), T0, only=["zta"]), EXIT_OK)
        files = sorted(os.listdir(orch.list_runs(self.path("out"))[0]))
        self.assertEqual(files, ["zta.html", "zta.json"])
        with self.assertRaises(orch.ConfigError):
            orch.run(self.config(), only=["dns"])

    def test_fail_under(self):
        self.assertEqual(self.run_hub(self.config(fail_under=90), T0), EXIT_FAIL_UNDER)

    def test_failing_module_does_not_stop_the_others(self):
        cfg = self.config()
        with open(cfg, encoding="utf-8") as f:
            data = json.load(f)
        data["modules"]["zta"]["input"] = self.path("missing.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(data, f)
        self.assertEqual(self.run_hub(cfg, T0), EXIT_USAGE)
        self.assertTrue(os.path.isfile(self.path("out", "security_hub.html")))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            posture = json.load(f)
        mods = {m["module"]: m for m in posture["run"]["modules"]}
        self.assertEqual(mods["waf"]["exit_code"], EXIT_OK)
        self.assertEqual(mods["zta"]["exit_code"], EXIT_USAGE)

    def test_relative_paths_resolved_from_config_folder(self):
        os.makedirs(self.path("cfg"))
        p = self.path("cfg", "hub.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"output_dir": "../reports", "modules": {"zta": {"input": "../zta.json"}}}, f)
        with open(fixture("ZeroTrustAssessmentReport.json"), "rb") as src, open(self.path("zta.json"), "wb") as dst:
            dst.write(src.read())
        self.assertEqual(self.run_hub(p, T0), EXIT_OK)
        self.assertTrue(os.path.isfile(self.path("reports", "security_hub.html")))



class DnsRunTest(TempDirTest):
    def test_dns_module_in_run(self):
        if importlib.util.find_spec("dns") is None:
            self.skipTest("dnspython not installed")
        p = self.path("c.json")
        with open(p, "w", encoding="utf-8") as f:  # 127.0.0.1:53 answers nothing: plumbing only, no network
            json.dump({"output_dir": "out", "modules": {"dns": {"input": fixture("domains.csv"), "options": {
                "skip_preflight": True, "offline": True, "no_http": True, "nameservers": ["127.0.0.1"], "timeout": 0.5,
                "checks": "spf,dmarc"}}}}, f)
        with silenced():
            code = orch.run(p, now=T0, log=lambda m: None)
        self.assertIn(code, (EXIT_OK, EXIT_FAIL_UNDER))
        run = orch.list_runs(self.path("out"))[0]
        with open(os.path.join(run, "dns.json"), encoding="utf-8") as f:
            self.assertEqual(sorted(r["domain"] for r in json.load(f)), ["contoso.example", "mail.contoso.example"])


if __name__ == "__main__":
    unittest.main()
