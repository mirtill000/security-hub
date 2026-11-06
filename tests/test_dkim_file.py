"""dkim.csv: DKIM selectors per domain, for selectors that are not the providers' defaults."""

import shutil
from unittest import mock

from securityhub import cli
from securityhub.scanners import dns_email
from securityhub.scanners.dns_email.inputs import find_dkim_file, load_dkim_file

from .fakedns import OFFLINE_ARGS, fake_dns, load_zones
from .helpers import TempDirTest, fixture, load_results, silenced


class LoadTest(TempDirTest):
    def write(self, name, text):
        with open(self.path(name), "w", encoding="utf-8") as f:
            f.write(text)
        return self.path(name)

    def test_formats(self):
        p = self.write("dkim.csv", "﻿Dominio;Selettore\ncontoso.com;s1-2024\nContoso.COM;mktg|crm s1-2024\n"
                                   "s2._domainkey.fabrikam.com\n# comment\nbroken;\nfabrikam.com;ok bad!\n")
        sel, bad, _ = load_dkim_file(p)
        self.assertEqual(sel, {"contoso.com": ["s1-2024", "mktg", "crm"], "fabrikam.com": ["s2", "ok"]})
        self.assertEqual(bad, ["broken;", "fabrikam.com: bad!"])

    def test_no_header_and_comma(self):
        sel, bad, _ = load_dkim_file(self.write("x.csv", "contoso.com, s1\ncontoso.com,s2\n"))
        self.assertEqual((sel, bad), ({"contoso.com": ["s1", "s2"]}, []))

    def test_zone_file_lines(self):
        key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "A" * 40
        sel, bad, exp = load_dkim_file(self.write("dkim.csv",
            '1m-mm._domainkey.uk.coachellacontest2025.aperol.com.\t1\tIN\tTXT\t"v=DKIM1;k=rsa;p=xxx"\n'
            f's2._domainkey.aperol.com. 3600 IN TXT "v=DKIM1; k=rsa; " "p={key[:30]}" "{key[30:]}"\n'   # split TXT strings
            's3._domainkey.aperol.com IN CNAME s3.dkim.provider.net.\n'
            '; zone comment\n'))
        self.assertEqual((sel, bad), ({"uk.coachellacontest2025.aperol.com": ["1m-mm"], "aperol.com": ["s2", "s3"]}, []))
        self.assertNotIn("key_id", exp[("uk.coachellacontest2025.aperol.com", "1m-mm")])   # p=xxx is a placeholder
        self.assertEqual(len(exp[("aperol.com", "s2")]["key_id"]), 16)
        self.assertEqual(exp[("aperol.com", "s3")], {"cname": "s3.dkim.provider.net"})

    def test_found_next_to_the_domain_list(self):
        self.write("domains.csv", "contoso.com\n")
        self.assertNotEqual(find_dkim_file(self.path("domains.csv")), self.path("dkim.csv"))
        self.write("dkim.csv", "contoso.com;s1\n")
        self.assertEqual(find_dkim_file(self.path("domains.csv")), self.path("dkim.csv"))


class ScanTest(TempDirTest):
    def scan(self, dkim_csv=None, *extra, command="email", checks="dkim"):
        shutil.copy(fixture("domains.csv"), self.path("domains.csv"))
        if dkim_csv is not None:
            with open(self.path("dkim.csv"), "w", encoding="utf-8") as f:
                f.write(dkim_csv)
        zones = load_zones()
        # a custom selector the default list does not contain
        zones["_domainkey.fabrikam.example"] = {}
        zones["corp2024._domainkey.fabrikam.example"] = {"TXT": zones["selector1._domainkey.contoso.example"]["TXT"]}
        self.queries = []
        with fake_dns(zones):
            fake = dns_email.DNSClient._resolve

            def counting(client, name, rdtype, resolver=None):
                self.queries.append(name.lower())
                return fake(client, name, rdtype, resolver)
            with mock.patch.object(dns_email.DNSClient, "_resolve", counting), silenced():
                cli.main([command, self.path("domains.csv"), "-o", self.path("d.html"), "--json", "--checks", checks, "--no-cache"]
                         + OFFLINE_ARGS + list(extra))
        self.rows = {r["domain"]: r for r in load_results(self.path("d.json"))}
        return {d: r["dkim"] for d, r in self.rows.items()}

    def dkim_queries(self):
        return sorted({q for q in self.queries if "._domainkey." in q})

    def test_only_the_listed_records_are_verified(self):
        res = self.scan("domain;selector\nfabrikam.example;corp2024\ncontoso.example;old2023\nunknown.example;s1\n")
        # no guessing: only the records of dkim.csv are queried
        self.assertEqual(self.dkim_queries(), ["corp2024._domainkey.fabrikam.example", "old2023._domainkey.contoso.example"])
        fab, con = res["fabrikam.example"], res["contoso.example"]
        self.assertEqual((fab["status"], fab["mode"]), ("valid", "dkim.csv"))
        self.assertEqual([(s["name"], s["source"]) for s in fab["selectors"]], [("corp2024", "declared")])
        # selector1 exists in DNS but is not listed: not guessed, so the listed record is simply missing
        self.assertEqual((con["status"], con["declared"]), ("missing", ["old2023"]))
        self.assertIn("DKIM_DECLARED_MISSING", {i["code"] for i in con["issues"]})
        with open(self.path("d.html"), encoding="utf-8") as f:
            self.assertIn("from dkim.csv", f.read())

    def test_domain_not_listed_is_not_verified_nor_counted(self):
        res = self.scan("fabrikam.example;corp2024\n", checks="spf,dkim,dmarc")
        con = res["contoso.example"]
        self.assertEqual(con["status"], "unknown")
        self.assertIn("DKIM_NOT_DECLARED", {i["code"] for i in con["issues"]})
        self.assertNotIn("dkim", self.rows["contoso.example"]["score_breakdown"]["components"])   # not counted
        self.assertIn("dkim", self.rows["fabrikam.example"]["score_breakdown"]["components"])

    def test_key_compared_with_the_zone_line(self):
        import re
        txt = load_zones()["selector1._domainkey.contoso.example"]["TXT"][0]
        good = re.search(r"p=([A-Za-z0-9+/=]+)", txt).group(1)
        res = self.scan(f'selector1._domainkey.contoso.example. 300 IN TXT "v=DKIM1; k=rsa; p={good}"\n'
                        f'corp2024._domainkey.fabrikam.example. 300 IN TXT "v=DKIM1; k=rsa; p={"B" * 60}"\n')
        self.assertEqual(res["contoso.example"]["status"], "valid")                       # same key
        self.assertIn("DKIM_KEY_MISMATCH", {i["code"] for i in res["fabrikam.example"]["issues"]})
        self.assertEqual(res["fabrikam.example"]["status"], "partial")

    def test_dkim_is_an_email_control_only(self):
        self.scan("fabrikam.example;corp2024\n", command="dns", checks="dnssec,caa")
        for r in self.rows.values():
            self.assertEqual(r["dkim"]["status"], "skipped")                      # not in the DNS report
            self.assertNotIn("dkim", r["score_breakdown"]["components"])
            self.assertFalse([i for i in r["issues"] if i["code"].startswith("DKIM")])
        res = self.scan("fabrikam.example;corp2024\n")                          # the e-mail report evaluates it
        self.assertEqual(res["fabrikam.example"]["status"], "valid")

    def test_file_can_be_ignored(self):
        res = self.scan("fabrikam.example;corp2024\n", "--dkim-file", "none")
        self.assertEqual(res["fabrikam.example"]["status"], "missing")             # default search: corp2024 is not a default
        self.assertEqual(res["fabrikam.example"]["mode"], "probe")
