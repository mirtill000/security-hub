import re
import subprocess
import shutil
import unittest
from importlib import resources

from securityhub import ui


class UiAssetsTest(unittest.TestCase):
    PAGES = ("dns", "waf", "edr", "proofpoint", "zta", "portal")

    def test_includes_are_resolved(self):
        for page in self.PAGES:
            for ext in ("css", "js"):
                text = ui.asset(f"{page}.{ext}")
                self.assertNotIn("@include", text, f"{page}.{ext}")
        for tpl in ("report.html", "portal.html"):
            self.assertIn("__DATA__", ui.asset(tpl))

    def test_shared_design_system_is_used_by_every_page(self):
        base = ui.asset("base.css")
        for page in self.PAGES:
            self.assertTrue(ui.asset(f"{page}.css").startswith(base), page)
            self.assertIn(ui.asset("core.js"), ui.asset(f"{page}.js"), page)
        for page in ("dns", "waf"):
            self.assertIn(ui.asset("asset-report.js"), ui.asset(f"{page}.js"))

    def test_shared_functions_are_not_redefined(self):
        shared = set(re.findall(r"^(?:function |const )(\\w+)", ui.asset("core.js") + ui.asset("report-core.js"), re.M))
        for page in ("dns", "waf", "zta"):
            own = resources.files("securityhub.ui").joinpath(f"{page}.js").read_text(encoding="utf-8")
            self.assertFalse(shared & set(re.findall(r"^(?:function |const )(\\w+)", own, re.M)), page)

    def test_theme_is_shared_by_every_page(self):
        theme = ui.asset("theme.js")
        for page in self.PAGES:
            js = ui.asset(f"{page}.js")
            self.assertIn(theme, js, page)
            self.assertIn("themeControl()", js, page)          # System / Light / Dark selector
            self.assertIn("...themeActions()", js, page)       # theme commands in the search palette
            self.assertEqual(js.count("const isDark"), 1, page)  # one implementation only
        for tpl in ("report.html", "portal.html"):
            head = ui.asset(tpl).split("<style>")[0]
            self.assertIn("securityhub-theme", head, tpl)       # applied before the first paint

    def test_include_loop_is_detected(self):
        with self.assertRaises(ValueError):
            ui.asset("x", _depth=9)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_javascript_parses(self):
        for page in self.PAGES:
            r = subprocess.run(["node", "-e", "new (require('vm').Script)(require('fs').readFileSync(0, 'utf8'))"],
                               input=ui.asset(f"{page}.js"), text=True, capture_output=True)
            self.assertEqual(r.returncode, 0, f"{page}.js: {r.stderr[:500]}")


if __name__ == "__main__":
    unittest.main()
