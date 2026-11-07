"""Area score, grade and status tell the same story in the portal and posture.json."""

import json
import unittest

from securityhub import portal
from securityhub.common import grade


def row(score, mx=1, **k):
    return {"domain": f"d{score}-{mx}", "overall_score": score, "tier": "medium", "profile": "protected", "issues": [],
            "score_breakdown": {"max": mx}, **k}


class AreaScoreTest(unittest.TestCase):
    def test_bands_follow_the_grades(self):
        for score, st in ((90, "good"), (77, "good"), (75, "good"), (74, "warn"), (50, "warn"), (49, "bad")):
            self.assertEqual(portal._status(score, False), st, score)
        self.assertEqual(grade(77), "B")
        self.assertEqual(portal._status(99, True), "warn")             # a critical exposure is never "good"

    def test_rows_with_nothing_measurable_are_not_counted(self):
        # e.g. Proofpoint: mail domains whose mail Proofpoint does not filter have no measurable control
        payload = {"results": [row(40)] + [row(100, mx=0) for _ in range(50)]}
        self.assertEqual(portal.area_score("proofpoint", payload), 40)
        self.assertEqual(portal.summarize_assets("proofpoint", payload)["score"], 40)

    def test_score_is_brought_into_the_band_of_the_status(self):
        s = {"score": 99, "exec": {"status": "warn", "headline": [None, "2 malicious messages reached users"], "actions": []}}
        portal._align_score(s)
        self.assertEqual((s["score"], grade(s["score"]), s["score_uncapped"]), (74, "C", 99))
        self.assertIn("2 malicious messages reached users", s["score_cap"])
        s = {"score": 66, "exec": {"status": "bad", "headline": None,
                                   "actions": [{"severity": "critical", "title": "1 PRA administrator without MFA"}]}}
        portal._align_score(s)
        self.assertEqual((s["score"], grade(s["score"])), (49, "F"))
        ok = {"score": 77, "exec": {"status": "good"}}
        portal._align_score(ok)
        self.assertEqual((ok["score"], grade(ok["score"])), (77, "B"))                         # nothing to align
        self.assertNotIn("score_cap", ok)

    def test_status_and_card_use_the_same_score(self):
        payload = {"results": [row(80), row(70)], "totals": {}}
        self.assertEqual(portal.exec_pra(payload)["status"], portal._status(portal.area_score("pra", payload), False))


if __name__ == "__main__":
    unittest.main()


class ReportMatchesPortalTest(unittest.TestCase):
    def test_report_carries_the_portal_area_score(self):
        import json
        import os
        import tempfile
        from securityhub import cli
        from .helpers import fixture, silenced
        d = tempfile.mkdtemp()
        out = os.path.join(d, "edr.html")
        with silenced():
            cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "-o", out])
        with open(out, encoding="utf-8") as f:
            payload = json.loads(portal.DATA_RE.search(f.read()).group(1))
        card = portal.collect([out])[0][0]
        self.assertEqual((payload["area"]["score"], payload["area"]["grade"]), (card["score"], card["grade"]))
        self.assertTrue(payload["area"]["cap"])                    # an active threat caps the area: the report says so


class PortalAreaInReportTest(unittest.TestCase):
    def test_portal_gives_its_figures_to_a_report_without_area(self):
        import tempfile, os, re as _re
        from securityhub import cli, portal
        from tests.helpers import fixture, silenced
        with tempfile.TemporaryDirectory() as d:
            with silenced():
                cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "-o", os.path.join(d, "edr.html")])
            with open(os.path.join(d, "edr.html"), encoding="utf-8") as f:
                title, payload = portal.extract_report(f.read())
            payload.pop("area")                                    # a report written by an older version
            with open(os.path.join(d, "edr.html"), "w", encoding="utf-8") as f:
                f.write(portal.build_page("edr", title, payload))
            reports, _ = portal.collect([d])
            page = portal.report_page(reports[0])
            m = _re.search(r"window\.HUB_AREA=(\{.*?\});</script>", page)
            self.assertIsNotNone(m)
            area = json.loads(m.group(1))
            self.assertEqual((area["score"], area["grade"]), (reports[0]["score"], reports[0]["grade"]))
            self.assertEqual(area["cap"], reports[0].get("score_cap"))

