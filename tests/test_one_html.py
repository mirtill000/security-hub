"""One HTML in the end: runs keep report data, the portal rebuilds the pages."""

import json
import os
import re

from securityhub import cli, orchestrator as orch, portal

from .fakedns import OFFLINE_ARGS, fake_dns
from .helpers import TempDirTest, fixture, silenced

T0 = "2026-10-01T080000Z"


class OneHtmlTest(TempDirTest):
    def config(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": {
                "waf": {"options": {"from_json": fixture("waf_snapshot.json")}},
                "zta": {"input": fixture("ZeroTrustAssessmentReport.json")}}}, f)
        return p

    def htmls(self):
        return sorted(os.path.relpath(os.path.join(r, n), self.path("out")) for r, _, ns in os.walk(self.path("out"))
                      for n in ns if n.endswith(".html"))

    def test_only_the_portal_is_html(self):
        with silenced():
            orch.run(self.config(), log=lambda m: None)
            orch.run(self.config(), log=lambda m: None)
        self.assertEqual(self.htmls(), ["security_hub.html"])
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            mods = json.load(f)["run"]["modules"]
        self.assertTrue(all(m["report"].endswith(".report.json") for m in mods))
        reports, history = portal.collect(orch.list_runs(self.path("out")))
        self.assertEqual(len(history["runs"]), 4)          # trends still built from the data of every run
        self.assertEqual([r["file"] for r in reports], ["waf.html", "zta.html"])  # downloaded as pages

    def test_rebuilt_page_is_the_module_page(self):
        for args, name in ((["waf", "--from-json", fixture("waf_snapshot.json")], "waf"),
                           (["zta", fixture("ZeroTrustAssessmentReport.json")], "zta")):
            with silenced():
                cli.main(args + ["-o", self.path(name + ".html")])
            with open(self.path(name + ".html"), encoding="utf-8") as f:
                page = f.read()
            data = portal.compact_report(self.path(name + ".html"))
            self.assertFalse(os.path.exists(self.path(name + ".html")))
            r = portal.collect([data])[0][0]
            self.assertEqual(r["html"], page, name)

    def test_rebuilt_dns_pages(self):
        with silenced(), fake_dns():
            cli.main(["dns", fixture("domains.csv"), "-o", self.path("dns.html")] + OFFLINE_ARGS)
        pages = {}
        for n in ("email", "dns"):
            with open(self.path(n + ".html"), encoding="utf-8") as f:
                pages[n] = f.read()
            portal.compact_report(self.path(n + ".html"))
        for r in portal.collect([self.path("email.report.json"), self.path("dns.report.json")])[0]:
            self.assertEqual(r["html"], pages[r["type"]], r["type"])

    def test_older_runs_with_pages_are_converted(self):
        with silenced():
            os.makedirs(self.path("out", "runs", T0))
            cli.main(["zta", fixture("ZeroTrustAssessmentReport.json"), "-o", self.path("out", "runs", T0, "zta.html")])
            orch.run(self.config(), log=lambda m: None)
        self.assertEqual(self.htmls(), ["security_hub.html"])
        self.assertTrue(os.path.isfile(self.path("out", "runs", T0, "zta.report.json")))

    def test_portal_embeds_the_rebuilt_pages(self):
        with silenced():
            orch.run(self.config(), log=lambda m: None)
        with open(self.path("out", "security_hub.html"), encoding="utf-8") as f:
            hub = f.read()
        blocks = re.findall(r'<script type="application/json" id="rep-(r\d+)">(.*?)</script>', hub, re.S)
        self.assertEqual(len(blocks), 2)
        self.assertTrue(all("<!DOCTYPE html>" in json.loads(b) for _, b in blocks))

    def test_foreign_html_is_left_alone(self):
        with open(self.path("notes.html"), "w") as f:
            f.write("<html><body>notes</body></html>")
        self.assertIsNone(portal.compact_report(self.path("notes.html")))
        self.assertTrue(os.path.exists(self.path("notes.html")))
