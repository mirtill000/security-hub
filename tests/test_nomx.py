"""Domains without MX records: missing SPF or DKIM is not a finding (they do not handle mail)."""

from securityhub import cli

from .fakedns import OFFLINE_ARGS, fake_dns, load_zones
from .helpers import TempDirTest, load_results, silenced


class NoMxTest(TempDirTest):
    def scan(self, zones, domains):
        with open(self.path("d.txt"), "w") as f:
            f.write("\n".join(domains))
        with fake_dns(zones), silenced():
            cli.main(["email", self.path("d.txt"), "-o", self.path("e.html"), "--json"] + OFFLINE_ARGS)
        return {r["domain"]: r for r in load_results(self.path("e.json"))}

    def test_missing_spf_dkim_not_findings_without_mx(self):
        zones = load_zones()
        zones["website-only.example"] = {"SOA": ["ns. host. 1 2 3 4 5"], "A": ["203.0.113.20"]}           # no MX, A only
        zones["nothing.example"] = {"SOA": ["ns. host. 1 2 3 4 5"]}                                        # no MX, no A
        zones["loose.example"] = {"SOA": ["ns. host. 1 2 3 4 5"], "TXT": ["v=spf1 include:x.example ~all"]}  # no MX, loose SPF
        zones["mail-nospf.example"] = {"SOA": ["ns. host. 1 2 3 4 5"], "MX": [[10, "mx.mail-nospf.example"]]}
        zones["mx.mail-nospf.example"] = {"A": ["203.0.113.30"]}
        r = self.scan(zones, ["website-only.example", "nothing.example", "loose.example", "mail-nospf.example"])
        codes = lambda d: {i["code"] for i in r[d]["issues"]}
        for d in ("website-only.example", "nothing.example"):
            self.assertEqual(r[d]["profile"], "non-mail", d)
            self.assertFalse(codes(d) & {"SPF_MISSING", "DKIM_NOT_FOUND", "SPF_PARKED_NOT_STRICT"}, d)
            self.assertEqual((r[d]["spf"]["status"], r[d]["dkim"]["status"]), ("na", "na"), d)
            self.assertEqual(r[d]["score_breakdown"]["components"]["spf"]["got"], 25, d)   # not penalized
            self.assertIn("DMARC_PARKED_NOT_REJECT", codes(d))                           # spoofing protection still checked
        self.assertIn("MX_IMPLICIT", codes("website-only.example"))
        self.assertIn("SPF_PARKED_NOT_STRICT", codes("loose.example"))                    # a loose record is still flagged
        self.assertIn("SPF_MISSING", codes("mail-nospf.example"))                          # with MX: still a finding
        self.assertEqual(r["mail-nospf.example"]["profile"], "mail")
