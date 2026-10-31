import io
import os
import unittest
from unittest import mock

from securityhub.console import Progress, Style, print_posture


class Tty(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


SUMMARY = {"overall": {"status": "warn", "areas": {"bad": 0, "warn": 1, "good": 0, "unknown": 1}, "stale": ["Microsoft Zero Trust"],
                       "not_verified": [], "complete": False}, "summary": "2 need attention.",
           "areas": [{"label": "Microsoft Zero Trust", "grade": "D", "score": 54, "status": "warn", "date": "2026-09-01T08:00:00Z",
                      "age_days": 60.0, "max_age_days": 35, "stale": True, "kpis": []},
                     {"label": "Imperva Cloud WAF", "grade": "D", "score": 50, "status": "warn", "date": "2026-10-31T08:00:00Z", "age_days": 0.2,
                      "headline": "2 of 3 websites are not protected", "kpis": [{"label": "Protected", "value": 33, "unit": "%"}]}],
           "assets": {"summary": {"total": 4, "at_risk": 3, "coverage_gaps": 1},
                      "items": [{"asset": "fabrikam.example", "status": "bad", "signals": [{"text": "web and mail exposed"}]}]},
           "actions": [{"severity": "critical", "label": "Imperva Cloud WAF", "title": "No WAF policy"}]}


class ConsoleTest(unittest.TestCase):
    def test_plain_output_when_not_a_terminal(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True):
            print_posture(SUMMARY, out)
        text = out.getvalue()
        self.assertNotIn("\033[", text)
        for s in ("SECURITY POSTURE", "ATTENTION", "1 need attention", "1 not verified", "Incomplete picture - stale: Microsoft Zero Trust",
                  "60 days old", "stale (limit 35 days)", "today", "Protected: 33%", "fabrikam.example", "3 at risk", "No WAF policy"):
            self.assertIn(s, text)

    def test_colors_on_a_terminal_and_no_color(self):
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            self.assertTrue(Style(Tty()).color)
        with mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}, clear=True):
            self.assertFalse(Style(Tty()).color)
        with mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=True):
            self.assertTrue(Style(io.StringIO()).color)

    def test_progress_writes_one_line_per_event_in_logs(self):
        out = io.StringIO()
        p = Progress(["dns", "waf"], {"dns": "DNS", "waf": "WAF"}, out)
        with p:
            p.start("dns")
            p.finish("dns", "ok")
            p.start("waf")
            p.finish("waf", "timeout", "timed out after 10s")
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertIn("running", lines[0])
        self.assertIn("done", lines[1])
        self.assertIn("timed out after 10s", lines[3])

    def test_progress_redraws_in_place_on_a_terminal(self):
        out = Tty()
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            p = Progress(["dns"], {"dns": "DNS"}, out)
            with p:
                p.start("dns")
                p.finish("dns", "ok")
        self.assertIn("\033[1F", out.getvalue())  # cursor moved back up to redraw the block

    def test_disabled_progress_is_silent(self):
        out = io.StringIO()
        p = Progress(["dns"], {"dns": "DNS"}, out, enabled=False)
        with p:
            p.start("dns")
            p.finish("dns", "ok")
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
