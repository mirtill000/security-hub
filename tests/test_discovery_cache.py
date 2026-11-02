"""Discovery cache: frequent runs reuse slow-changing results without hiding changes."""

import os
from datetime import datetime, timedelta, timezone
from unittest import mock

from securityhub import cli
from securityhub.cache import Store
from securityhub.scanners import dns_email
from securityhub.scanners.dns_email.models import ConsistencyResult, Issue
from securityhub.scanners.dns_email.rdap import RDAPClient

from .fakedns import OFFLINE_ARGS, fake_dns, load_zones
from .helpers import TempDirTest, fixture, load_results, silenced


class StoreTest(TempDirTest):
    def test_age_fingerprint_save_and_prune(self):
        now = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
        s = Store("t", path=self.path("c.json"), now=now)
        s.put("a", "k", [1, 2], "fp1")
        self.assertEqual(s.get("a", "k", 24, "fp1"), [1, 2])
        self.assertIsNone(s.get("a", "k", 24, "fp2"))
        self.assertIsNone(s.get("a", "k", 0, "fp1"))
        s.data["a"]["old"] = {"at": (now - timedelta(days=9)).isoformat(), "v": 1}
        self.assertIsNone(s.save())
        self.assertEqual(oct(os.stat(self.path("c.json")).st_mode & 0o777), "0o600")
        later = Store("t", path=self.path("c.json"), now=now + timedelta(hours=25))
        self.assertIsNone(later.get("a", "k", 24, "fp1"))           # too old now
        self.assertEqual(later.get("a", "k", 48, "fp1"), [1, 2])
        self.assertNotIn("old", later.data["a"])                     # dropped after a week
        with open(self.path("bad.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(Store("t", path=self.path("bad.json")).data, {})   # unreadable cache: start empty


class DkimCacheTest(TempDirTest):
    def scan(self, zones=None, *extra):
        calls = []
        with fake_dns(zones):
            fake = dns_email.DNSClient._resolve

            def counting(self, name, rdtype, resolver=None):
                calls.append(name)
                return fake(self, name, rdtype, resolver)
            with mock.patch.object(dns_email.DNSClient, "_resolve", counting), silenced():
                cli.main(["email", fixture("domains.csv"), "-o", self.path("d.html"), "--json", "--checks", "dkim"]
                         + OFFLINE_ARGS + list(extra))
        res = {r["domain"]: r["dkim"] for r in load_results(self.path("d.json"))}
        return res, lambda d: sum(1 for c in calls if c.endswith("._domainkey." + d))

    def test_second_run_reuses_the_search(self):
        first, per1 = self.scan()
        self.assertEqual(per1("fabrikam.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))
        again, per2 = self.scan()
        self.assertEqual(per2("fabrikam.example"), 0)                      # _domainkey still absent: 1 query in total
        self.assertEqual(again["fabrikam.example"]["status"], "missing")
        self.assertTrue(again["fabrikam.example"]["full_search"])
        self.assertEqual(per2("contoso.example"), 1)                       # only the selector found last time
        self.assertEqual(again["contoso.example"]["status"], "valid")
        self.assertEqual({d: r["status"] for d, r in first.items()}, {d: r["status"] for d, r in again.items()})
        with open(self.path("d.html"), encoding="utf-8") as f:
            self.assertIn("Reused from runs of the last 24 hours", f.read())

    def test_changes_are_not_hidden(self):
        self.scan()
        zones = load_zones()
        del zones["selector1._domainkey.contoso.example"]                  # key removed: full search again
        zones["_domainkey.fabrikam.example"] = {}                            # a selector appeared under fabrikam
        zones["selector1._domainkey.fabrikam.example"] = {"TXT": load_zones()["selector1._domainkey.contoso.example"]["TXT"]}
        res, per = self.scan(zones)
        self.assertEqual(per("contoso.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))
        self.assertEqual(res["contoso.example"]["status"], "missing")
        self.assertEqual(res["fabrikam.example"]["status"], "valid")

    def test_disabled(self):
        self.scan()
        _, per = self.scan(None, "--cache-max-age", "0")
        self.assertEqual(per("fabrikam.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))
        _, per = self.scan(None, "--no-cache")
        self.assertEqual(per("fabrikam.example"), len(dns_email.DEFAULT_DKIM_SELECTORS))


class OtherCachesTest(TempDirTest):
    def test_rdap_keeps_registered_never_unregistered(self):
        store = Store("t", path=self.path("c.json"))
        answers = {"a.example": {"state": "registered", "expires": "2027-01-01"}, "gone.example": {"state": "unregistered"}}
        rd = RDAPClient(store=store)
        with mock.patch.object(RDAPClient, "_lookup", side_effect=lambda d: answers[d]) as m:
            rd.lookup("a.example")
            rd.lookup("gone.example")
            rd2 = RDAPClient(store=store)
            self.assertEqual(rd2.lookup("a.example")["expires"], "2027-01-01")
            rd2.lookup("gone.example")
        self.assertEqual(m.call_count, 3)                                    # gone.example asked again

    def test_check_results_rebuilt(self):
        store = Store("t", path=self.path("c.json"))
        a = dns_email.EmailSecurityAnalyzer(nameservers=["127.0.0.1"], cache=store)
        try:
            made = []

            def compute():
                made.append(1)
                return ConsistencyResult(status="warning", sources=["x"], differences=[{"name": "n"}],
                                         issues=[Issue("warning", "DNS", "m", "r", "DNS_INCONSISTENT")])
            r1 = a._cached("consistency", "d.example", ConsistencyResult, compute, "ns")
            r2 = a._cached("consistency", "d.example", ConsistencyResult, compute, "ns")
            a._cached("consistency", "d.example", ConsistencyResult, compute, "other-resolvers")
        finally:
            a.close()
        self.assertEqual(len(made), 2)
        self.assertEqual(r1, r2)
        self.assertIsInstance(r2.issues[0], Issue)
