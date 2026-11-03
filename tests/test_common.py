import json
import unittest

from securityhub.common import EXIT_USAGE, Parser, RateLimiter, csv_safe, grade, json_for_html


class CommonTest(unittest.TestCase):
    def test_csv_safe_neutralizes_formulas(self):
        for v in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "|calc", "%x"):
            self.assertEqual(csv_safe(v), "'" + v)
        self.assertEqual(csv_safe("example.com"), "example.com")
        self.assertEqual(csv_safe(42), 42)

    def test_json_for_html_cannot_break_out_of_script(self):
        payload = {"x": "</script><script>alert(1)</script>& "}
        out = json_for_html(payload)
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)
        self.assertNotIn("&", out)
        self.assertEqual(json.loads(out), payload)

    def test_json_for_html_default(self):
        self.assertEqual(json.loads(json_for_html({"s": {1}}, default=list)), {"s": [1]})

    def test_grade(self):
        self.assertEqual([grade(x) for x in (None, 95, 80, 65, 50, 49)], ["-", "A", "B", "C", "D", "F"])
        self.assertEqual([grade(x) for x in (89, 76, 75, 74.9, 65)], ["B", "B", "B", "C", "C"])

    def test_rate_limiter_unlimited(self):
        r = RateLimiter(0)
        for _ in range(1000):
            r.wait()  # must not sleep

    def test_parser_usage_error_exit_code(self):
        p = Parser(prog="t")
        p.add_argument("--n", type=int)
        with self.assertRaises(SystemExit) as cm, open("/dev/null", "w") as devnull:
            import contextlib
            with contextlib.redirect_stderr(devnull):
                p.parse_args(["--n", "x"])
        self.assertEqual(cm.exception.code, EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
