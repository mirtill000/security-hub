"""SentinelOne EDR module: analysis, exclusions, API client, CLI, portal and orchestrator."""

import io
import json
import os
import re
import unittest
import urllib.error
from datetime import datetime
from unittest import mock

from securityhub import cli, orchestrator as orch, portal
from securityhub.common import EXIT_OK, EXIT_USAGE
from securityhub.scanners import edr
from securityhub.scanners.edr import api as s1api
from securityhub.scanners.edr.checks import assess_exclusion

from .helpers import TempDirTest, fixture, silenced


def snapshot():
    with open(fixture("s1_snapshot.json"), encoding="utf-8") as f:
        return json.load(f)


def analyze(snap=None, inventory=None):
    return edr.analyze_snapshot(snap or snapshot(), list(edr.CHECKS), {}, inventory)


class AnalysisTest(TempDirTest):
    def test_profiles_and_findings(self):
        results, account, policies, extra = analyze()
        r = {x.domain: x for x in results}
        self.assertNotIn("ws-retired-09", r)                       # decommissioned agents are not assessed
        self.assertEqual({k: v.profile for k, v in r.items()}, {
            "srv-sql-01": "threat", "ws-rome-04": "disabled", "srv-web-02": "detect", "ws-old-07": "stale",
            "ws-milano-02": "protected", "ws-milano-01": "protected", "mac-design-03": "protected"})
        codes = lambda h: {i.code for i in r[h].issues}
        self.assertIn("THREAT_ACTIVE", codes("srv-sql-01"))
        self.assertEqual(r["srv-sql-01"].overall_score, 20)        # capped by the active threat
        self.assertTrue({"MODE_DETECT", "ANTI_TAMPER_OFF"} <= codes("srv-web-02"))
        eng = [i for i in r["srv-web-02"].issues if i.code.startswith("ENGINE_OFF")]
        self.assertTrue(eng and all(i.code != "ENGINE_OFF" for i in eng))            # one finding per named engine
        self.assertTrue(all(i.message.startswith("Detection engine disabled: ") for i in eng))
        self.assertTrue(all("(policy: group Lab)" in i.message for i in eng), [i.message for i in eng])
        self.assertEqual(r["srv-web-02"].checks["policy"].data["scope"], "group Lab")   # group does not inherit
        self.assertEqual(r["ws-milano-01"].checks["policy"].data["scope"], "site EMEA")
        self.assertIn("AGENT_VERY_OLD", codes("ws-milano-02"))
        self.assertLessEqual(r["ws-milano-02"].overall_score, 70)
        self.assertTrue({"THREAT_UNRESOLVED", "THREAT_SLA"} <= codes("ws-milano-01"))  # mitigated, open for 21 days
        self.assertIn("AGENT_STALE", codes("ws-old-07"))            # 71 days at collection time (limit 45)
        # a stale agent reports only that: its other checks show its last known state and are not evaluated
        self.assertEqual({i.code for i in r["ws-old-07"].issues}, {"AGENT_STALE"})
        self.assertEqual({c: x.status for c, x in r["ws-old-07"].checks.items() if c not in ("health", "threats")},
                         {c: "unknown" for c in r["ws-old-07"].checks if c not in ("health", "threats")})
        self.assertEqual(set(r["ws-old-07"].score_breakdown["components"]), {"health", "threats"})
        self.assertEqual(r["mac-design-03"].compliance["ransomware_ready"], "n/a")
        acc = {i.code for i in account}
        self.assertTrue({"EXCLUSION_BROAD", "POLICY_DETECT", "POLICY_ANTI_TAMPER_OFF", "EXCLUSION_NO_DESCRIPTION"} <= acc)
        self.assertEqual({p["id"] for p in policies}, {"site:s1", "site:s2", "group:g3"})
        self.assertEqual(sum(1 for x in extra["exclusions"] if x["risk"] == "critical"), 2)

    def test_unreadable_policy_is_not_a_failure(self):
        snap = snapshot()
        snap["policies"] = {}
        r = {x.domain: x for x in analyze(snap)[0]}["ws-milano-01"]
        self.assertEqual(r.checks["policy"].status, "unknown")
        self.assertNotIn("policy", r.score_breakdown["components"])
        self.assertEqual(r.compliance["edr_baseline"], "unknown")

    def test_coverage_against_inventory(self):
        inv = edr.load_inventory(fixture("s1_inventory.csv"))
        self.assertIn("srv-sql-01.contoso.local", inv)
        extra = analyze(inventory=inv)[3]
        self.assertEqual(extra["coverage"], {"inventory": 9, "covered": 7, "missing": ["srv-backup-01", "ws-reception-02"]})

    def test_plain_inventory_and_metadata(self):
        with open(self.path("inv.txt"), "w") as f:
            f.write("WS-MILANO-01\n# comment\nsrv-new-01\n")
        self.assertEqual(edr.load_inventory(self.path("inv.txt")), ["srv-new-01", "ws-milano-01"])
        with open(self.path("meta.csv"), "w") as f:
            f.write("hostname;tier;owner\nsrv-sql-01;critical;dba\n")
        r = {x.domain: x for x in edr.analyze_snapshot(snapshot(), list(edr.CHECKS), edr.load_metadata(self.path("meta.csv")))[0]}
        self.assertEqual((r["srv-sql-01"].tier, r["srv-sql-01"].owner), ("critical", "dba"))

    def test_exclusions(self):
        risky = {
            ("path", "C:\\*", None): "EXCLUSION_BROAD", ("path", "/", None): "EXCLUSION_BROAD",
            ("path", "C:\\Users\\*\\AppData\\Local\\Temp\\", "subfolders"): "EXCLUSION_BROAD",
            ("path", "/tmp/", "folder"): "EXCLUSION_BROAD", ("path", "*\\veeam\\*", None): "EXCLUSION_BROAD",
            ("file_type", "exe", None): "EXCLUSION_BROAD", ("browser", "Chrome", None): "EXCLUSION_RISKY",
        }
        for (t, v, pt), code in risky.items():
            self.assertEqual(assess_exclusion({"type": t, "value": v, "pathExclusionType": pt})[0], code, v)
        self.assertEqual(assess_exclusion({"type": "path", "value": "D:\\SQL\\Data\\", "pathExclusionType": "folder",
                                           "mode": "disable_all_monitors"})[0], "EXCLUSION_ALL_MONITORS")
        for safe in ({"type": "path", "value": "C:\\Program Files\\Veeam\\VeeamAgent.exe", "pathExclusionType": "file"},
                     {"type": "file_type", "value": "ldf"}, {"type": "white_hash", "value": "ab" * 20}):
            self.assertIsNone(assess_exclusion(safe), safe)

    def test_baseline(self):
        with silenced():
            cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "-o", self.path("a.html"), "--json"])
            cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "-o", self.path("b.html"), "--baseline", self.path("a.json")])
        with open(self.path("b.html"), encoding="utf-8") as f:
            payload = json.loads(re.search(r'id="mg-data">(.*?)</script>', f.read(), re.S).group(1))
        self.assertEqual((payload["diff"]["improved"], payload["diff"]["worsened"], payload["diff"]["unchanged"]), (0, 0, 7))


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, body=b"{}", headers=None):
    return urllib.error.HTTPError("https://x", code, "err", headers or {}, io.BytesIO(body))


class ApiTest(TempDirTest):
    def test_pagination_and_auth_header(self):
        pages = [{"data": [{"id": 1}, {"id": 2}], "pagination": {"nextCursor": "c2"}},
                 {"data": [{"id": 3}], "pagination": {"nextCursor": None}}]
        seen = []

        def fake(req, timeout, context):
            seen.append(req)
            return FakeResponse(json.dumps(pages[len(seen) - 1]).encode())
        a = s1api.SentinelOneAPI("https://c.sentinelone.net", "TOKEN", qps=0)
        with mock.patch.object(s1api.urllib.request, "urlopen", fake):
            self.assertEqual([x["id"] for x in a.paginate("/agents")], [1, 2, 3])
        self.assertEqual(seen[0].get_header("Authorization"), "ApiToken TOKEN")
        self.assertIn("/web/api/v2.1/agents?limit=1000", seen[0].full_url)
        self.assertIn("cursor=c2", seen[1].full_url)

    def test_errors_and_retry(self):
        a = s1api.SentinelOneAPI("https://c.sentinelone.net", "T", qps=0)
        with mock.patch.object(s1api.urllib.request, "urlopen", side_effect=http_error(401)):
            with self.assertRaises(s1api.APIError) as cm:
                a.get("/agents")
        self.assertIn("token invalid or expired", str(cm.exception))
        calls = iter([http_error(429, headers={"Retry-After": "0"}), FakeResponse(b'{"data": []}')])
        with mock.patch.object(s1api.urllib.request, "urlopen", lambda *x, **k: (lambda r: (_ for _ in ()).throw(r) if isinstance(r, Exception) else r)(next(calls))):
            self.assertEqual(a.get("/agents"), {"data": []})
        self.assertEqual(a.stats["retries"], 1)
        with self.assertRaises(ValueError):
            s1api.SentinelOneAPI("http://insecure", "T")

    def test_collect(self):
        class Fake(s1api.SentinelOneAPI):
            def get(self, path, **params):
                if path == "/sites":
                    return {"data": {"sites": [{"id": "s1", "name": "EMEA"}]}}
                if path == "/agents":
                    return {"data": [{"id": "1", "computerName": "WS1", "lastIpToMgmt": "10.0.0.1", "siteId": "s1"}]}
                if path == "/groups":
                    return {"data": [{"id": "g1", "name": "Lab", "inherits": False}]}
                if path.endswith("/policy"):
                    return {"data": {"mitigationMode": "protect"}}
                if path == "/threats":
                    return {"data": [{"id": "t", "threatInfo": {"threatName": "x", "mitigationStatus": "active"},
                                      "agentRealtimeInfo": {"agentId": "1", "agentComputerName": "WS1"}}]}
                if path == "/exclusions":
                    if params.get("type") == "browser":
                        raise s1api.APIError("HTTP 400", 400)
                    return {"data": [{"id": "e", "type": params.get("type"), "value": "v"}]}
                if path == "/update/agent/packages":
                    raise s1api.APIError("HTTP 403 (token scope too narrow)", 403)
                return {"data": []}
        snap = s1api.collect(Fake("https://c.sentinelone.net", "T", qps=0), [], lambda m: None)
        self.assertNotIn("lastIpToMgmt", snap["agents"][0])          # only the fields the checks need
        self.assertEqual(set(snap["policies"]), {"site:s1", "group:g1"})
        self.assertEqual(snap["threats"][0]["agent_id"], "1")
        self.assertEqual(snap["threats"][0]["mitigation"], "active")
        self.assertEqual(len(snap["exclusions"]), 4)                  # 'browser' type unknown to the console: ignored
        self.assertEqual([e["where"] for e in snap["errors"]], ["agent packages"])


class CliPortalTest(TempDirTest):
    def test_cli_outputs_and_credentials(self):
        with silenced():
            code = cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "--inventory", fixture("s1_inventory.csv"),
                             "-o", self.path("edr.html"), "--json", "--csv"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["edr.csv", "edr.html", "edr.json"])
        with mock.patch.dict(os.environ, {}, clear=True), silenced() as (_, err):
            self.assertEqual(cli.main(["edr", "-o", self.path("x.html")]), EXIT_USAGE)
        self.assertIn("S1_API_TOKEN", err.getvalue())
        with silenced():
            self.assertEqual(cli.main(["s1", "--from-json", fixture("s1_snapshot.json"), "-o", self.path("y.html"),
                                       "--fail-under", "50"]), 2)

    def test_portal_area_and_rebuilt_page(self):
        with silenced():
            cli.main(["edr", "--from-json", fixture("s1_snapshot.json"), "--inventory", fixture("s1_inventory.csv"), "-o", self.path("edr.html")])
        with open(self.path("edr.html"), encoding="utf-8") as f:
            page = f.read()
        r = portal.collect([self.path("edr.html")])[0][0]
        self.assertEqual((r["type"], r["label"]), ("edr", "SentinelOne EDR"))
        kpis = {k["key"]: k for k in r["exec"]["kpis"]}
        self.assertEqual((kpis["edr_protect"]["value"], kpis["edr_coverage"]["value"]), (67, 78))   # 4 of 6 in Protect mode (the stale agent is not evaluated); 7 of 9
        self.assertEqual(r["exec"]["headline"][1], "1 endpoint with a threat not mitigated")
        self.assertEqual(r["exec"]["status"], "bad")
        self.assertEqual(r["exec"]["actions"][0]["code"], "THREAT_ACTIVE")
        self.assertTrue(any(a["code"] == "COVERAGE_GAP" for a in r["exec"]["actions"]))
        portal.compact_report(self.path("edr.html"))
        self.assertEqual(portal.report_page(portal.collect([self.path("edr.report.json")])[0][0]), page)

    def test_orchestrator(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": {"edr": {"options": {"from_json": fixture("s1_snapshot.json")}}}}, f)
        with silenced():
            self.assertIn(orch.run(p), (EXIT_OK, 2))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            self.assertEqual([a["area"] for a in json.load(f)["areas"]], ["edr"])
        with open(p, "w") as f:
            json.dump({"modules": {"edr": {"options": {"api_token": "secret"}}}}, f)
        with self.assertRaises(orch.ConfigError):
            orch.run(p, dry_run=True)


class StaleWindowTest(unittest.TestCase):
    def test_default_window_is_45_days(self):
        from datetime import timedelta
        snap = snapshot()
        when = datetime.fromisoformat(snap["collected"])
        for a in snap["agents"]:
            if a["computerName"] == "WS-OLD-07":
                a["lastActiveDate"] = (when - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = {x.domain: x for x in edr.analyze_snapshot(snap, list(edr.CHECKS), {})[0]}
        self.assertNotIn("AGENT_STALE", {i.code for i in r["ws-old-07"].issues})   # 40 days: not stale yet
        self.assertNotEqual(r["ws-old-07"].profile, "stale")

    def test_open_threats_of_a_stale_agent_are_still_reported(self):
        snap = snapshot()
        old = next(a for a in snap["agents"] if a["computerName"] == "WS-OLD-07")
        t = dict(snap["threats"][0], id="t-old", agent_id=old["id"], hostname=old["computerName"])
        snap["threats"].append(t)
        r = {x.domain: x for x in edr.analyze_snapshot(snap, list(edr.CHECKS), {})[0]}["ws-old-07"]
        codes = {i.code for i in r.issues}
        self.assertIn("AGENT_STALE", codes)
        self.assertTrue(codes & {"THREAT_ACTIVE", "THREAT_UNRESOLVED"}, codes)     # the incident is still open
        self.assertEqual(r.checks["protection"].status, "unknown")
