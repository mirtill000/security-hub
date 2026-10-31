"""Publishing the portal to a web server folder after each run."""

import json
import os
import stat

from securityhub import orchestrator as orch
from securityhub.common import EXIT_OK, EXIT_USAGE

from .helpers import TempDirTest, fixture, silenced


class PublishTest(TempDirTest):
    def config(self, publish):
        os.makedirs(self.path("www"), exist_ok=True)
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "publish": publish,
                       "modules": {"zta": {"input": fixture("ZeroTrustAssessmentReport.json")}}}, f)
        return p

    def test_only_the_portal_is_published(self):
        with silenced():
            self.assertEqual(orch.run(self.config(self.path("www")), log=lambda m: None), EXIT_OK)
        self.assertEqual(os.listdir(self.path("www")), ["index.html"])
        with open(self.path("www", "index.html"), encoding="utf-8") as a, open(self.path("out", "security_hub.html"), encoding="utf-8") as b:
            self.assertEqual(a.read(), b.read())
        self.assertEqual(stat.S_IMODE(os.stat(self.path("www", "index.html")).st_mode), 0o644)

    def test_posture_and_mode(self):
        with silenced():
            orch.run(self.config({"dir": "www", "posture": True, "mode": "0640"}), log=lambda m: None)  # relative to the config
        self.assertEqual(sorted(os.listdir(self.path("www"))), ["index.html", "posture.json"])
        self.assertEqual(stat.S_IMODE(os.stat(self.path("www", "posture.json")).st_mode), 0o640)

    def test_invalid_publish_settings(self):
        for bad in ({"dir": "missing"}, {"dir": "www", "mode": "0777"}, {"dir": "www", "mode": "abc"},
                    {"dir": "www", "other": 1}, {"posture": True}, ["www"]):
            with self.assertRaises(orch.ConfigError, msg=bad):
                orch.run(self.config(bad), dry_run=True)

    def test_publish_failure_is_an_error(self):
        cfg = self.config(self.path("www"))
        os.chmod(self.path("www"), 0o500)
        self.addCleanup(os.chmod, self.path("www"), 0o700)
        if os.access(self.path("www"), os.W_OK):  # running as root: permissions are not enforced
            self.skipTest("root ignores folder permissions")
        lines = []
        with silenced():
            self.assertEqual(orch.run(cfg, log=lines.append), EXIT_USAGE)
        self.assertIn("cannot publish", "\n".join(lines))

    def test_dry_run_mentions_publish(self):
        with silenced() as (out, _):
            orch.run(self.config(self.path("www")), dry_run=True)
        self.assertIn("publish the portal to", out.getvalue())
