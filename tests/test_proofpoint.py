"""Proofpoint module: DNS routing, TAP client and collection, analysis, CLI, portal and orchestrator."""

import io
import json
import os
import re
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

from securityhub import cli, orchestrator as orch, portal
from securityhub.common import EXIT_OK, EXIT_USAGE
from securityhub.scanners import proofpoint as pp
from securityhub.scanners.dns_email.dnsclient import DNSAnswer
from securityhub.scanners.proofpoint import api as tapapi
from securityhub.scanners.proofpoint.constants import PROOFPOINT_HOSTS

from .helpers import TempDirTest, fixture, silenced


def snapshot():
    with open(fixture("pp_snapshot.json"), encoding="utf-8") as f:
        return json.load(f)


def analyze(snap=None):
    s = snap or snapshot()
    return pp.analyze_snapshot(s, list(pp.CHECKS), s.get("domain_meta") or {})


class FakeDNS:
    """name -> {rdtype: records}; PTR answers keyed by IP."""

    def __init__(self, zones):
        self.zones = zones

    def query(self, name, rdtype):
        node = self.zones.get(name.lower())
        if node is None:
            return DNSAnswer("nxdomain")
        if "CNAME" in node and rdtype != "CNAME":
            sub = self.query(node["CNAME"], rdtype)
            return DNSAnswer(sub.status, sub.records, False, node["CNAME"])
        return DNSAnswer("ok", list(node[rdtype])) if rdtype in node else DNSAnswer("nodata")

    def addresses(self, host):
        a = self.query(host, "A")
        return a.records if a.status == "ok" else []

    def has_address(self, host):
        return bool(self.addresses(host))

    def ptr(self, ip):
        return (self.zones.get("ptr:" + ip) or {}).get("PTR")


ZONES = {
    "contoso.com": {"MX": [(10, "mx0a-1.pphosted.com"), (10, "mx0b-1.pphosted.com")],
                    "TXT": ["v=spf1 include:_spf.contoso.com -all", "MS=ms12345"]},
    "_spf.contoso.com": {"TXT": ["v=spf1 include:spf-1.pphosted.com ~all"]},
    "contoso-com.mail.protection.outlook.com": {"A": ["52.101.0.1"]},
    "fabrikam.com": {"MX": [(10, "mx0a-1.pphosted.com"), (5, "mail.fabrikam.com")], "TXT": ["v=spf1 mx -all"]},
    "mail.fabrikam.com": {"A": ["203.0.113.5"]},
    "tailspin.com": {"MX": [(10, "mail.tailspin.com")], "TXT": ["v=spf1 include:spf-2.pphosted.com -all"]},
    "mail.tailspin.com": {"A": ["67.231.152.1"]},
    "ptr:67.231.152.1": {"PTR": "mx0a-2.pphosted.com"},
    "alias.com": {"MX": [(10, "mx.alias.com")], "TXT": []},
    "mx.alias.com": {"CNAME": "mx0a-3.pphosted.com"},
    "mx0a-3.pphosted.com": {"A": ["67.231.1.1"]},
    "parked.com": {"MX": [(0, "")], "TXT": ["v=spf1 -all"]},
}


class RoutingTest(TempDirTest):
    def test_lookup(self):
        dns = FakeDNS(ZONES)
        c = pp.lookup_domain(dns, "contoso.com", PROOFPOINT_HOSTS)
        self.assertTrue(all(m["proofpoint"] for m in c["mx"]))
        self.assertTrue(c["spf_proofpoint"])                         # through a nested include
        self.assertEqual(c["m365"], {"host": "contoso-com.mail.protection.outlook.com", "resolves": True})
        f = pp.lookup_domain(dns, "fabrikam.com", PROOFPOINT_HOSTS)
        self.assertEqual([m["proofpoint"] for m in f["mx"]], [False, True])  # sorted by preference
        self.assertTrue(pp.lookup_domain(dns, "tailspin.com", PROOFPOINT_HOSTS)["mx"][0]["how"].startswith("reverse DNS"))
        self.assertTrue(pp.lookup_domain(dns, "alias.com", PROOFPOINT_HOSTS)["mx"][0]["how"].startswith("CNAME"))
        self.assertEqual(pp.lookup_domain(dns, "parked.com", PROOFPOINT_HOSTS)["mx_status"], "null")
        self.assertEqual(pp.m365_direct_host("my.co.uk"), "my-co-uk.mail.protection.outlook.com")
        routing = pp.check_routing(f)                             # routing is shown, not reported
        self.assertEqual((routing.issues, routing.data["via_proofpoint"]), ([], "some"))


class AnalysisTest(TempDirTest):
    def test_profiles_scores_and_findings(self):
        results, account, _, extra = analyze()
        r = {x.domain: x for x in results}
        self.assertEqual({k: v.profile for k, v in r.items()}, {
            "contoso.com": "clicked", "fabrikam.com": "delivered", "northwind.com": "unprotected",
            "tailspin.com": "protected", "adatum.com": "protected"})
        codes = lambda d: {i.code for i in r[d].issues}
        self.assertTrue({"CLICK_PERMITTED", "THREAT_DELIVERED", "DIRECT_DELIVERY", "URL_NOT_REWRITTEN", "VAP_VIP"} <= codes("contoso.com"))
        self.assertLessEqual(r["contoso.com"].overall_score, 40)
        self.assertTrue({"SAFELIST_DELIVERY", "SPF_NO_PROOFPOINT"} <= codes("fabrikam.com"))
        self.assertFalse({c for d in r for c in codes(d)} & {"MX_NOT_PROOFPOINT", "MX_BYPASS", "MX_BYPASS_PREFERRED"})
        self.assertEqual(r["northwind.com"].checks["threats"].status, "na")   # TAP cannot see mail it does not filter
        self.assertNotIn("SPF_NO_PROOFPOINT", codes("northwind.com"))
        self.assertEqual(r["tailspin.com"].overall_score, 100)
        self.assertEqual(r["adatum.com"].checks["routing"].status, "unknown")  # seen by TAP only: not resolved
        self.assertEqual(r["adatum.com"].source, "tap")
        self.assertEqual(r["contoso.com"].tier, "critical")
        self.assertEqual(r["contoso.com"].checks["threats"].data["malicious"], 1)  # the false positive is not counted
        self.assertEqual(extra["no_mail"], ["parked.com"])
        self.assertEqual({i.code for i in account}, {"TOP_CLICKERS", "TAP_DOMAINS_NOT_LISTED"})
        self.assertEqual(extra["totals"]["blocked_messages"], 1645)
        self.assertEqual(r["contoso.com"].compliance, {"gateway_enforced": "unknown", "no_exposure": "fail"})
        self.assertEqual(r["tailspin.com"].compliance, {"gateway_enforced": "pass", "no_exposure": "pass"})

    def test_dns_only(self):
        snap = snapshot()
        for k in ("messages_delivered", "clicks_permitted", "vap", "top_clickers", "blocked"):
            snap.pop(k)
        results, account, _, extra = analyze(snap)
        r = {x.domain: x for x in results}
        self.assertNotIn("adatum.com", r)
        self.assertEqual(r["contoso.com"].checks["clicks"].status, "unknown")
        self.assertNotIn("clicks", r["contoso.com"].score_breakdown["components"])
        self.assertFalse(extra["tap"])

    def test_dns_only_report_has_no_tap_controls(self):
        """TAP not configured: its controls are left out of the report, not shown as read errors."""
        snap = snapshot()
        for k in ("messages_delivered", "clicks_permitted", "vap", "top_clickers", "blocked"):
            snap.pop(k)
        p = self.path("dns_only.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(snap, f)
        with silenced():
            self.assertEqual(cli.main(["pp", "--from-json", p, "-o", self.path("d.html"), "--json"]), EXIT_OK)
        with open(self.path("d.json"), encoding="utf-8") as f:
            data = json.load(f)
        rows = data["results"]
        self.assertFalse({c for r in rows for c in r["checks"]} & {"threats", "clicks", "rewrite", "people"})
        self.assertIn("TAP_NOT_CONFIGURED", {i["code"] for i in data["account_issues"]})


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ApiTest(TempDirTest):
    def test_collect_minimizes_and_counts(self):
        calls = []

        def fake(req, timeout, context):
            calls.append(req)
            if "/siem/" in req.full_url:
                body = {"messagesDelivered": [{"GUID": "g", "messageTime": "t", "subject": "SECRET SUBJECT", "recipient": ["A@Contoso.com"],
                                               "fromAddress": ["x@evil.example"], "threatsInfoMap": [{"classification": "PHISH", "threatStatus": "active",
                                                                                                    "threatType": "url", "threatUrl": "https://threatinsight.proofpoint.com/x"}],
                                               "policyRoutes": ["default_inbound"], "completelyRewritten": False}] if len(calls) == 1 else [],
                        "clicksPermitted": [], "clicksBlocked": [{"recipient": "b@contoso.com", "clickIP": "10.1.1.1"}],
                        "messagesBlocked": [{"recipient": ["c@contoso.com"], "subject": "x"}]}
            elif "/people/vap" in req.full_url:
                body = {"users": [{"identity": {"emails": ["A@contoso.com"], "name": "A", "vip": True}, "threatStatistics": {"attackIndex": 900}}],
                        "vapAttackIndexThreshold": 500}
            else:
                raise urllib.error.HTTPError(req.full_url, 403, "no", {}, io.BytesIO(b""))
            return FakeResponse(json.dumps(body).encode())
        a = tapapi.TapAPI("principal", "secret", qps=0)
        with mock.patch.object(tapapi.urllib.request, "urlopen", fake):
            snap = tapapi.collect(a, lambda m: None, hours=3, now=datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc))
        self.assertTrue(calls[0].get_header("Authorization").startswith("Basic "))
        self.assertIn("interval=2026-11-01T03:00:00Z/2026-11-01T04:00:00Z", calls[0].full_url)
        self.assertEqual(sum("/siem/" in c.full_url for c in calls), 3)
        text = json.dumps(snap)
        self.assertNotIn("SECRET SUBJECT", text)
        self.assertNotIn("10.1.1.1", text)
        m = snap["messages_delivered"][0]
        self.assertEqual((m["recipients"], m["from_domain"], m["threats"][0]["classification"]), (["a@contoso.com"], "evil.example", "phish"))
        self.assertEqual(snap["blocked"], {"contoso.com": {"messages": 3, "clicks": 3}})
        self.assertEqual(snap["vap"][0]["attack_index"], 900)
        self.assertIsNone(snap["top_clickers"])                       # 403: not read, not "no clickers"
        self.assertFalse(snap["siem_failed"])

    def test_auth_error_stops(self):
        a = tapapi.TapAPI("p", "s", qps=0)
        err = urllib.error.HTTPError("u", 401, "no", {}, io.BytesIO(b""))
        with mock.patch.object(tapapi.urllib.request, "urlopen", side_effect=err) as m:
            snap = tapapi.collect(a, lambda x: None, hours=24)
        self.assertTrue(snap["siem_failed"])
        self.assertEqual(m.call_count, 3)                             # one SIEM call, then the two People calls
        self.assertIn("service principal or secret invalid", snap["errors"][0]["error"])


class CliPortalTest(TempDirTest):
    def test_cli(self):
        with silenced():
            code = cli.main(["proofpoint", "--from-json", fixture("pp_snapshot.json"), "-o", self.path("pp.html"), "--json", "--csv"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["pp.csv", "pp.html", "pp.json"])
        with mock.patch.dict(os.environ, {}, clear=True), silenced() as (_, err):
            self.assertEqual(cli.main(["pp", "-o", self.path("x.html")]), EXIT_USAGE)
        self.assertIn("PROOFPOINT_PRINCIPAL", err.getvalue())
        with silenced():
            self.assertEqual(cli.main(["tap", "--from-json", fixture("pp_snapshot.json"), "-o", self.path("y.html"), "--fail-under", "50"]), 2)
            self.assertEqual(cli.main(["pp", "--hours", "200", "--domains", "x"]), EXIT_USAGE)
        with open(self.path("d.txt"), "w") as f:
            f.write("contoso.com\n")
        with mock.patch("securityhub.scanners.dns_email.dnsclient.preflight", return_value=(False, "blocked")), \
                silenced() as (_, err):  # a broken resolver must not turn every domain into "no mail"
            self.assertEqual(cli.main(["pp", "--domains", self.path("d.txt"), "--no-tap", "-o", self.path("z.html")]), EXIT_USAGE)
        self.assertIn("DNS not usable", err.getvalue())

    def test_portal_area(self):
        with silenced():
            cli.main(["proofpoint", "--from-json", fixture("pp_snapshot.json"), "-o", self.path("pp.html")])
        with open(self.path("pp.html"), encoding="utf-8") as f:
            page = f.read()
        payload = json.loads(re.search(r'id="mg-data">(.*?)</script>', page, re.S).group(1))
        self.assertEqual(payload["meta"]["tool"], "PPGuard")
        r = portal.collect([self.path("pp.html")])[0][0]
        self.assertEqual((r["type"], r["label"], r["exec"]["status"]), ("proofpoint", "Proofpoint", "bad"))
        kpis = {k["key"]: k["value"] for k in r["exec"]["kpis"]}
        self.assertEqual(kpis, {"pp_clicks": 1, "pp_delivered": 2, "pp_click_block": 75})
        self.assertEqual(r["exec"]["actions"][0]["code"], "CLICK_PERMITTED")
        portal.compact_report(self.path("pp.html"))
        self.assertEqual(portal.report_page(portal.collect([self.path("pp.report.json")])[0][0]), page)

    def test_orchestrator(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": {"proofpoint": {"options": {"from_json": fixture("pp_snapshot.json")}}}}, f)
        with silenced():
            self.assertIn(orch.run(p), (EXIT_OK, 2))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            self.assertEqual([a["area"] for a in json.load(f)["areas"]], ["proofpoint"])
        with open(p, "w") as f:
            json.dump({"modules": {"proofpoint": {"options": {"secret": "x"}}}}, f)
        with self.assertRaises(orch.ConfigError):
            orch.run(p, dry_run=True)


class CollectCacheTest(TempDirTest):
    def test_settled_hours_and_people_reused(self):
        from securityhub.cache import Store
        calls = []

        def fake(req, timeout, context):
            calls.append(req.full_url)
            if "/siem/" in req.full_url:
                body = {"messagesDelivered": [], "clicksPermitted": [], "messagesBlocked": [{"recipient": ["a@contoso.com"]}]}
            else:
                body = {"users": []}
            return FakeResponse(json.dumps(body).encode())
        t0 = datetime(2026, 11, 2, 10, 5, tzinfo=timezone.utc)
        with mock.patch.object(tapapi.urllib.request, "urlopen", fake):
            store1 = Store("pp", path=self.path("c.json"), now=t0)
            first = tapapi.collect(tapapi.TapAPI("p", "s", qps=0), lambda m: None, hours=24, now=t0, store=store1)
            store1.save()
            n1 = len(calls)
            later = t0 + timedelta(hours=4)
            store = Store("pp", path=self.path("c.json"), now=later)
            second = tapapi.collect(tapapi.TapAPI("p", "s", qps=0), lambda m: None, hours=24, now=later, store=store)
        siem2 = sum("/siem/" in c for c in calls[n1:])
        self.assertEqual(n1, 24 + 2)
        self.assertEqual(siem2, 5)                  # 4 new hours + the hour that had not settled at the first run
        self.assertEqual(second["siem_hours_reused"], 19)
        self.assertTrue(second["people_reused"])
        self.assertEqual(first["blocked"]["contoso.com"]["messages"], 24)
        self.assertEqual(second["blocked"]["contoso.com"]["messages"], 24)   # same totals from cache + new hours
