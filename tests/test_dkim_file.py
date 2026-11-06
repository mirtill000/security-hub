"""dkim.csv: DKIM selectors per domain, for selectors that are not the providers' defaults."""

import shutil

from securityhub import cli
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
        sel, bad = load_dkim_file(p)
        self.assertEqual(sel, {"contoso.com": ["s1-2024", "mktg", "crm"], "fabrikam.com": ["s2", "ok"]})
        self.assertEqual(bad, ["broken;", "fabrikam.com: bad!"])

    def test_no_header_and_comma(self):
        sel, bad = load_dkim_file(self.write("x.csv", "contoso.com, s1\ncontoso.com,s2\n"))
        self.assertEqual((sel, bad), ({"contoso.com": ["s1", "s2"]}, []))

    def test_found_next_to_the_domain_list(self):
        self.write("domains.csv", "contoso.com\n")
        self.assertNotEqual(find_dkim_file(self.path("domains.csv")), self.path("dkim.csv"))
        self.write("dkim.csv", "contoso.com;s1\n")
        self.assertEqual(find_dkim_file(self.path("domains.csv")), self.path("dkim.csv"))


class ScanTest(TempDirTest):
    def scan(self, dkim_csv=None, *extra):
        shutil.copy(fixture("domains.csv"), self.path("domains.csv"))
        if dkim_csv is not None:
            with open(self.path("dkim.csv"), "w", encoding="utf-8") as f:
                f.write(dkim_csv)
        zones = load_zones()
        # a custom selector the default list does not contain
        zones["_domainkey.fabrikam.example"] = {}
        zones["corp2024._domainkey.fabrikam.example"] = {"TXT": zones["selector1._domainkey.contoso.example"]["TXT"]}
        with fake_dns(zones), silenced():
            cli.main(["email", self.path("domains.csv"), "-o", self.path("d.html"), "--json", "--checks", "dkim", "--no-cache"]
                     + OFFLINE_ARGS + list(extra))
        return {r["domain"]: r["dkim"] for r in load_results(self.path("d.json"))}

    def test_custom_selector_is_found_and_missing_one_reported(self):
        without = self.scan()
        self.assertEqual(without["fabrikam.example"]["status"], "missing")        # not a default selector

        res = self.scan("domain;selector\nfabrikam.example;corp2024\ncontoso.example;old2023\nunknown.example;s1\n")
        fab, con = res["fabrikam.example"], res["contoso.example"]
        self.assertEqual(fab["status"], "valid")
        self.assertEqual([(s["name"], s["source"]) for s in fab["selectors"]], [("corp2024", "declared")])
        self.assertEqual(con["declared"], ["old2023"])
        self.assertEqual(con["status"], "partial")                                # selector1 valid, old2023 missing
        self.assertIn("DKIM_DECLARED_MISSING", {i["code"] for i in con["issues"]})
        with open(self.path("d.html"), encoding="utf-8") as f:
            self.assertIn("from dkim.csv", f.read())

    def test_file_can_be_ignored(self):
        res = self.scan("fabrikam.example;corp2024\n", "--dkim-file", "none")
        self.assertEqual(res["fabrikam.example"]["status"], "missing")
