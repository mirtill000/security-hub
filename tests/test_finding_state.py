"""Finding history: first seen, resolution and MTTR across runs; the "Exposed now" list of the portal."""

import json
import os
import unittest
from datetime import datetime, timezone

from securityhub import finding_state as fs
from securityhub import portal

from .helpers import TempDirTest


def rep(area, date, rows, org=()):
    payload = {"results": [{"domain": d, "issues": [{"code": c, "severity": s, "message": c.lower()} for c, s in issues]}
                           for d, issues in rows],
               "account_issues": [{"code": c, "severity": "critical", "message": c.lower()} for c in org]}
    r = {"id": "r1", "type": area, "label": area.upper(), "date": date}
    r["open_findings"] = fs.finding_list(area, payload)
    for f in r["open_findings"]:
        if f["code"] in portal.EXPOSURE_CODES.get(area, ()):
            f["exposure"] = True
    return r


def day(d):
    return datetime(2026, 11, d, 12, tzinfo=timezone.utc)


class FindingStateTest(unittest.TestCase):
    def test_open_resolve_and_mttr(self):
        st = fs.load("/nonexistent/state.json")
        fs.update(st, [rep("edr", "2026-11-01T06:00:00Z", [("pc1", [("THREAT_ACTIVE", "critical"), ("POLICY_DETECT", "warning")])])], day(1))
        # second run: the threat is still there, a new finding appears on pc2
        fs.update(st, [rep("edr", "2026-11-03T06:00:00Z", [("pc1", [("THREAT_ACTIVE", "critical"), ("POLICY_DETECT", "warning")]),
                                                           ("pc2", [("AGENT_DISABLED", "critical")])])], day(3))
        # third run: pc2 fixed after 4 days, pc1 still open
        fs.update(st, [rep("edr", "2026-11-07T06:00:00Z", [("pc1", [("THREAT_ACTIVE", "critical"), ("POLICY_DETECT", "warning")])])], day(7))
        s = fs.summary(st, day(7))["edr"]
        self.assertEqual((s["open"], s["open_critical"], s["resolved_90d"]), (2, 1, 1))
        self.assertEqual(s["mttr_days"], 4.0)                 # opened and closed while tracked
        self.assertEqual(s["oldest_days"], 6.2)               # pc1 since the first report (01 06:00 -> 07 12:00)
        self.assertEqual(s["tracked_since"], "2026-11-01T06:00:00Z")

    def test_findings_open_when_tracking_starts_do_not_count_in_mttr(self):
        st = fs.load("/nonexistent/state.json")
        fs.update(st, [rep("waf", "2026-11-01T06:00:00Z", [("a.com", [("SITE_BYPASS", "critical")])])], day(1))
        fs.update(st, [rep("waf", "2026-11-02T06:00:00Z", [])], day(2))
        s = fs.summary(st, day(2))["waf"]
        self.assertEqual((s["resolved_90d"], s["mttr_days"]), (1, None))   # its real age is unknown

    def test_same_report_twice_changes_nothing(self):
        st = fs.load("/nonexistent/state.json")
        r = rep("ias", "2026-11-01T06:00:00Z", [("bob", [("PASSWORD_NO_MFA", "critical")])])
        fs.update(st, [r], day(1))
        first = json.dumps(st["open"], sort_keys=True)
        fs.update(st, [r], day(5))
        self.assertEqual(json.dumps(st["open"], sort_keys=True), first)
        self.assertEqual(st["resolved"], [])

    def test_info_findings_are_not_tracked(self):
        r = rep("dns", "2026-11-01T06:00:00Z", [("a.com", [("DNSSEC_MISSING", "info"), ("AXFR_OPEN", "critical")])])
        self.assertEqual([f["code"] for f in r["open_findings"]], ["AXFR_OPEN"])


class TrackAndExposedTest(TempDirTest):
    def test_track_writes_state_and_annotates(self):
        reports = [rep("edr", "2026-11-01T06:00:00Z", [("pc1", [("THREAT_ACTIVE", "critical"), ("POLICY_DETECT", "warning")])],
                       org=["COVERAGE_GAP"])]
        fs.track(self.tmp, reports, now=day(1))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, fs.STATE_FILE)))
        reports = [rep("edr", "2026-11-04T06:00:00Z", [("pc1", [("THREAT_ACTIVE", "critical"), ("POLICY_DETECT", "warning")])],
                       org=["COVERAGE_GAP"])]
        fs.track(self.tmp, reports, now=day(4))
        threat = next(f for f in reports[0]["open_findings"] if f["code"] == "THREAT_ACTIVE")
        self.assertEqual(threat["first_seen"], "2026-11-01T06:00:00Z")
        self.assertEqual(reports[0]["finding_age"]["open"], 3)
        x = portal.exposed_now(reports)
        self.assertEqual([(i["item"], i["code"]) for i in x["items"]],
                         [("(organization)", "COVERAGE_GAP"), ("pc1", "THREAT_ACTIVE")])   # POLICY_DETECT is hygiene
        self.assertTrue(x["items"][0]["org"])
        self.assertEqual(x["items"][1]["hash"], "#/domains?d=pc1")


if __name__ == "__main__":
    unittest.main()
