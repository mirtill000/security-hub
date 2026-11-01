"""Scan cost: two-round DKIM probing, cap on concurrent DNS queries, light portal history."""

import os
import threading
import time
from unittest import mock

from securityhub import cli, orchestrator as orch, portal
from securityhub.scanners import dns_email

from .fakedns import OFFLINE_ARGS, fake_dns, load_zones
from .helpers import TempDirTest, fixture, load_results, silenced


class DkimRoundsTest(TempDirTest):
    def scan(self, *extra):
        calls = []
        with fake_dns():
            fake = dns_email.DNSClient._resolve

            def counting(self, name, rdtype, resolver=None):
                calls.append(name)
                return fake(self, name, rdtype, resolver)
            with mock.patch.object(dns_email.DNSClient, "_resolve", counting), silenced():
                cli.main(["email", fixture("domains.csv"), "-o", self.path("d.html"), "--json", "--checks", "dkim"] + OFFLINE_ARGS + list(extra))
        res = {r["domain"]: r["dkim"] for r in load_results(self.path("d.json"))}
        per = lambda d: sum(1 for c in calls if c.endswith("._domainkey." + d))
        return res, per

    def test_stops_after_a_valid_key(self):
        res, per = self.scan()
        self.assertEqual(res["contoso.example"]["status"], "valid")       # selector1 (Microsoft 365 MX)
        self.assertTrue(res["contoso.example"]["stopped_early"])
        self.assertLessEqual(per("contoso.example"), len(dns_email.DKIM_FIRST_ROUND))

    def test_missing_still_means_every_selector(self):
        res, per = self.scan()
        self.assertEqual(res["fabrikam.example"]["status"], "missing")
        self.assertFalse(res["fabrikam.example"]["stopped_early"])
        self.assertEqual(per("fabrikam.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))

    def test_parked_domain_first_round_only(self):
        res, per = self.scan()
        self.assertEqual(res["contoso-old.example"]["status"], "na")
        self.assertLessEqual(per("contoso-old.example"), len(dns_email.DKIM_FIRST_ROUND))

    def test_full_dkim_probes_everything(self):
        res, per = self.scan("--full-dkim")
        self.assertEqual(per("contoso.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))
        self.assertEqual(res["contoso.example"]["status"], "valid")

    def test_custom_selectors_are_in_the_first_round(self):
        zones = load_zones()
        zones["fabrikam.example"]["MX"] = [[10, "mx.fabrikam.example"]]
        zones["corp2026._domainkey.fabrikam.example"] = {"TXT": zones["selector1._domainkey.contoso.example"]["TXT"]}
        with fake_dns(zones), silenced():
            cli.main(["email", fixture("domains.csv"), "-o", self.path("d.html"), "--json", "--checks", "dkim",
                      "--selectors", "corp2026"] + OFFLINE_ARGS)
        r = {x["domain"]: x["dkim"] for x in load_results(self.path("d.json"))}["fabrikam.example"]
        self.assertEqual((r["status"], r["stopped_early"]), ("valid", True))


class InflightCapTest(TempDirTest):
    def test_no_more_than_max_inflight_queries(self):
        state, lock = {"now": 0, "max": 0}, threading.Lock()
        client = dns_email.DNSClient(["127.0.0.1"], timeout=1, max_inflight=3)

        def slow(self, name, rdtype, resolver):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.05)
            with lock:
                state["now"] -= 1
            return dns_email.DNSAnswer("nodata")
        with mock.patch.object(dns_email.DNSClient, "_resolve_now", slow):
            threads = [threading.Thread(target=client.query, args=(f"n{i}.example", "TXT")) for i in range(12)]
            [t.start() for t in threads]
            [t.join() for t in threads]
        self.assertEqual(state["max"], 3)


class LightHistoryTest(TempDirTest):
    def test_history_runs_are_not_kept_in_memory(self):
        with silenced():
            for d in ("2026-10-01T060000Z", "2026-10-02T060000Z", "2026-10-03T060000Z"):
                os.makedirs(self.path("runs", d))
                cli.main(["waf", "--from-json", fixture("waf_snapshot.json"), "-o", self.path("runs", d, "waf.html")])
        loaded = []
        real = portal.load_report
        with mock.patch.object(portal, "load_report", lambda *a, **k: loaded.append(real(*a, **k)) or loaded[-1]):
            reports, history = portal.collect(orch.list_runs(self.tmp))
        self.assertEqual(len(loaded), 3)
        self.assertTrue(all("html" not in r for r in loaded if r is not reports[0]))
        self.assertIn("html", reports[0])
        self.assertIsInstance(reports[0]["payload"], dict)
        self.assertEqual(len(history["runs"]), 3)
