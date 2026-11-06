"""securityhub doctor: credentials, APIs and inputs of each module, health.json and the Status page."""

import json
import os
from unittest import mock

from securityhub import cli, doctor, portal
from securityhub.scanners.edr import api as s1api
from securityhub.scanners.waf import api as wafapi

from .helpers import TempDirTest, fixture, silenced


class DoctorTest(TempDirTest):
    def config(self, mods):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": self.path("out"), "modules": mods}, f)
        return p

    def test_checks_and_health_file(self):
        cfg = self.config({"edr": {"options": {}}, "waf": {"options": {"account_id": 1}}, "pra": {"options": {}},
                           "zta": {"input": fixture("ZeroTrustAssessmentReport.json")}})
        env = {"S1_CONSOLE_URL": "https://acme.sentinelone.net", "S1_API_TOKEN": "t", "IMPERVA_API_ID": "1", "IMPERVA_API_KEY": "bad"}

        def s1_get(self, path, **params):
            assert (path, params.get("limit")) == ("/sites", 1)            # one small read
            return {"data": [{}], "pagination": {"totalItems": 3}}

        def waf_v1(self, path, **params):
            raise wafapi.APIError("HTTP 401", 401)
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(s1api.SentinelOneAPI, "get", s1_get), \
                mock.patch.object(wafapi.ImpervaAPI, "v1", waf_v1), silenced():
            code = cli.main(["doctor", "-c", cfg])
        self.assertEqual(code, 1)                                         # one module failed
        with open(self.path("out", "health.json")) as f:
            h = json.load(f)
        st = {k: {c["check"]: c["status"] for c in m["checks"]} for k, m in h["modules"].items()}
        self.assertEqual(st["edr"]["SentinelOne API"], "ok")
        self.assertEqual(st["waf"]["Imperva API"], "fail")
        waf_api = next(c for c in h["modules"]["waf"]["checks"] if c["check"] == "Imperva API")
        self.assertIn("read access", waf_api["hint"])                    # 401: the credential, not the network
        self.assertEqual(st["pra"]["Client secret"], "fail")
        self.assertIn(st["zta"]["Zero Trust export"], ("ok", "warn"))
        self.assertNotIn("bad", json.dumps(h))                            # no secret in the health file

    def test_status_page_data_in_the_portal(self):
        with silenced():
            cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "-o", self.path("edr.html")])
        reports, history = portal.collect([self.path("edr.html")])
        r = reports[0]
        self.assertEqual(set(r["coverage"]), {"items", "scored", "not_evaluable", "not_evaluable_by_check", "api_errors", "not_configured"})
        split = r["split"]
        self.assertGreater(split["exposed"], 0)                           # the endpoint with an active threat
        self.assertIsNotNone(split["hygiene"])
        health = {"doctor": {"generated": "2026-11-06T10:00:00Z", "status": "ok", "modules": {}}}
        portal.build_hub(reports, self.path("hub.html"), "t", history, health=health)
        with open(self.path("hub.html"), encoding="utf-8") as f:
            page = f.read()
        self.assertIn('"health":{"doctor"', page)
