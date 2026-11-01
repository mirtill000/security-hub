"""Unknown is not exposed (B1-B3), concurrent runs (B5), overall status (U1), data freshness (U2)."""

import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone

from securityhub import cli, inventory, orchestrator as orch, portal
from securityhub.common import EXIT_OK, EXIT_USAGE, LockBusy, RunLock, atomic_write

from .fakedns import OFFLINE_ARGS, fake_dns
from .helpers import TempDirTest, fixture, silenced

NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)


def collect(*files):
    return portal.collect(list(files))[0]


class UnknownIsNotExposedTest(TempDirTest):
    """A control that was not run, or whose lookup failed, must never be reported as an exposure."""

    def test_b1_dns_outage_is_not_spoofing(self):
        with silenced():  # resolver that never answers: every domain unreachable
            cli.main(["dns", fixture("domains.csv"), "-o", self.path("dns.html"), "--email-output", self.path("email.html"),
                      "--skip-preflight", "--offline",
                      "--no-http", "--nameservers", "127.0.0.1", "-t", "0.2", "-q"])
        r = collect(self.path("email.html"))[0]
        self.assertIsNone(r["exec"]["headline"])
        self.assertEqual(r["exec"]["status"], "unknown")
        d = collect(self.path("dns.html"))[0]  # the DNS report says the same: nothing verified, nothing exposed
        self.assertEqual((d["type"], d["exec"]["status"], d["exec"]["headline"]), ("dns", "unknown", None))
        self.assertIsNone(r["score"])
        self.assertIsNone(r["exec"]["kpis"][0]["value"])
        self.assertIn("3 not verified", r["exec"]["kpis"][0]["detail"])
        inv = inventory.build([r, d])
        self.assertEqual({a["status"] for a in inv["assets"]}, {"unknown"})
        codes = {s["code"] for a in inv["assets"] for s in a["signals"]}
        self.assertEqual(codes, {"DATA_INCOMPLETE"})

    def test_b2_dmarc_not_checked_is_not_spoofing(self):
        with silenced(), fake_dns():
            cli.main(["email", fixture("domains.csv"), "-o", self.path("email.html"), "--checks", "spf"] + OFFLINE_ARGS)
        r = collect(self.path("email.html"))[0]
        self.assertIsNone(r["exec"]["kpis"][0]["value"])
        self.assertIn("not checked", r["exec"]["kpis"][0]["detail"])
        self.assertIsNone(r["exec"]["headline"])
        signals = {s["code"] for a in inventory.build([r])["assets"] for s in a["signals"]}
        self.assertNotIn("MAIL_SPOOFABLE", signals)

    def test_b3_waf_rules_not_checked_is_not_unprotected(self):
        with silenced():
            cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("waf.html"), "--checks", "onboarding,tls"])
        r = collect(self.path("waf.html"))[0]
        kpi = r["exec"]["kpis"][0]
        self.assertEqual(kpi["value"], 0)              # only the website in bypass is known to be unprotected
        self.assertIn("0 of 1 verified", kpi["detail"])
        self.assertIn("4 not verified", kpi["detail"])
        signals = [s["code"] for a in inventory.build([r])["assets"] for s in a["signals"]]
        self.assertNotIn("WEB_NOT_BLOCKING", signals)
        self.assertIn("WEB_BYPASS", signals)

    def test_waf_protected_tri_state(self):
        self.assertIs(inventory.waf_protected({"profile": "bypass"}), False)
        self.assertIs(inventory.waf_protected({"profile": "protected", "compliance": {"owasp_block": "pass"}}), True)
        self.assertIs(inventory.waf_protected({"profile": "protected", "compliance": {"owasp_block": "fail"}}), False)
        self.assertIsNone(inventory.waf_protected({"profile": "protected", "compliance": {}}))
        self.assertIsNone(inventory.waf_protected({"profile": "error", "compliance": {"owasp_block": "unknown"}}))
        self.assertIs(inventory.waf_protected({"profile": "protected", "compliance": {},
                                               "issues": [{"code": "ORIGIN_EXPOSED"}]}), False)

    def test_dmarc_state(self):
        ok = {"profile": "mail", "dmarc": {"status": "valid", "policy": "reject", "pct": 100}}
        self.assertEqual(inventory.dmarc_state(ok), "enforced")
        self.assertEqual(inventory.dmarc_state({**ok, "dmarc": {"status": "missing"}}), "spoofable")
        self.assertEqual(inventory.dmarc_state({**ok, "dmarc": {"status": "valid", "policy": "reject", "pct": 50}}), "spoofable")
        for st in ("dns_error", "skipped", "unknown"):
            self.assertEqual(inventory.dmarc_state({**ok, "dmarc": {"status": st}}), "unknown")
        self.assertEqual(inventory.dmarc_state({**ok, "profile": "unreachable"}), "unknown")


class OverallStatusTest(unittest.TestCase):
    """U1: no average of scores that are not comparable."""

    def test_worst_known_status(self):
        o = portal.overall_status([{"label": "A", "status": "good"}, {"label": "B", "status": "warn"}, {"label": "C", "status": "bad"}])
        self.assertEqual((o["status"], o["areas"]), ("bad", {"bad": 1, "warn": 1, "good": 1, "unknown": 0}))
        self.assertTrue(o["complete"])

    def test_unknown_and_stale_make_the_picture_incomplete(self):
        o = portal.overall_status([{"label": "DNS", "status": "good"}, {"label": "ZT", "status": "unknown"},
                                   {"label": "WAF", "status": "good", "stale": True}])
        self.assertEqual(o["status"], "good")
        self.assertFalse(o["complete"])
        self.assertEqual((o["not_verified"], o["stale"]), (["ZT"], ["WAF"]))
        self.assertEqual(portal.overall_status([{"label": "X", "status": "unknown"}])["status"], "unknown")

    def test_posture_has_no_average_score(self):
        p = portal.posture([])
        self.assertEqual(p["schema"], 2)
        self.assertNotIn("overall_score", p)
        self.assertIn("overall", p)


class FreshnessTest(TempDirTest):
    """U2: data age per area, stale flag, exit code for monitoring."""

    def test_freshness(self):
        r = {"type": "zta", "date": "2026-09-01T08:00:00Z"}
        f = portal.freshness(r, NOW)
        self.assertEqual((round(f["age_days"]), f["max_age_days"], f["stale"]), (60, 35, True))
        self.assertFalse(portal.freshness(r, NOW, {"zta": 90})["stale"])
        self.assertFalse(portal.freshness({"type": "dns", "date": "2026-10-31T08:00:00Z"}, NOW)["stale"])

    def test_parse_max_age(self):
        self.assertEqual(portal.parse_max_age("dns=1, zta=30"), {"dns": 1.0, "zta": 30.0})
        for bad in ("siem=3", "dns", "dns="):
            with self.assertRaises(ValueError):
                portal.parse_max_age(bad)

    def test_status_fail_stale_and_portal_limits(self):
        with silenced():
            cli.main(["zta", fixture("ZeroTrustAssessmentReport.json"), "-o", self.path("zta.html")])  # executed 2026-10-01
            self.assertEqual(cli.main(["status", self.path("zta.html"), "--fail-stale", "--max-age", "zta=100000"]), EXIT_OK)
            self.assertEqual(cli.main(["status", self.path("zta.html"), "--fail-stale", "--max-age", "zta=1"]), orch.EXIT_STALE)
            self.assertEqual(cli.main(["status", self.path("zta.html"), "--max-age", "nope=1"]), EXIT_USAGE)
            cli.main(["portal", self.path("zta.html"), "-o", self.path("hub.html"), "--max-age", "zta=7"])
        with open(self.path("hub.html"), encoding="utf-8") as f:
            self.assertIn('"max_age_days":{"email":2,"dns":2,"waf":2,"zta":7.0}', f.read())


class ConcurrencyTest(TempDirTest):
    """B5: one run per output folder, never two runs in the same run folder, atomic outputs."""

    def test_lock_is_exclusive_and_released(self):
        with RunLock(self.tmp):
            with self.assertRaises(LockBusy) as cm:
                with RunLock(self.tmp):
                    pass
            self.assertIn("pid", str(cm.exception))
        with RunLock(self.tmp):  # released
            pass

    def test_lock_held_by_another_process(self):
        code = ("import sys, time; sys.path.insert(0, %r); from securityhub.common import RunLock\n"
                "with RunLock(%r): print('locked', flush=True); time.sleep(30)") % (os.getcwd(), self.tmp)
        p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(), "locked")
            cfg = self.path("c.json")
            with open(cfg, "w") as f:
                json.dump({"output_dir": self.tmp, "modules": {"zta": {"input": fixture("ZeroTrustAssessmentReport.json")}}}, f)
            lines = []
            with silenced():
                self.assertEqual(orch.run(cfg, log=lines.append), EXIT_USAGE)
            self.assertIn("another run is using this output folder", "\n".join(lines))
            self.assertEqual(orch.list_runs(self.tmp), [])
        finally:
            p.kill()
            p.wait()

    def test_run_folder_is_never_reused(self):
        when = datetime(2026, 10, 31, 8, tzinfo=timezone.utc)
        os.makedirs(self.path("runs", when.strftime(orch.RUN_FORMAT)))
        run_dir, stamp = orch._claim_run_dir(self.tmp, when.strftime(orch.RUN_FORMAT), when)
        self.assertEqual(stamp, (when + timedelta(seconds=1)).strftime(orch.RUN_FORMAT))
        self.assertTrue(os.path.isdir(run_dir))

    def test_atomic_write(self):
        p = self.path("posture.json")
        atomic_write(p, '{"a": 1}')
        atomic_write(p, '{"a": 2}')
        with open(p) as f:
            self.assertEqual(json.load(f), {"a": 2})
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith(".tmp-")], [])


if __name__ == "__main__":
    unittest.main()
