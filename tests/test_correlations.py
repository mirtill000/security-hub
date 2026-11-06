"""Cross-module risks: people (Proofpoint, SAP IAS, PRA), endpoints (PRA, EDR) and mail domains (Proofpoint, DNS)."""

import unittest

from securityhub import correlations, inventory


def rep(rid, kind, payload):
    return {"id": rid, "type": kind, "payload": payload}


def pp(vap=(), clickers=(), clicks=(), results=None, no_mail=()):
    rows = results if results is not None else [{"domain": "contoso.com", "profile": "clicked", "checks": {
        "clicks": {"status": "error", "data": {"clicks": [{"recipient": e, "classification": "phish", "time": "2026-10-31T09:30:00Z"} for e in clicks]}}}}]
    return rep("r1", "proofpoint", {"tap": True, "no_mail": list(no_mail), "results": rows, "people": {
        "vap": [{"emails": [e], "name": e.split("@")[0], "attack_index": 900} for e in vap],
        "top_clickers": [{"emails": [e], "name": e.split("@")[0], "clicks": 2} for e in clickers]}})


def ias(*users):
    return rep("r2", "ias", {"results": [{"domain": e, "email": e, "display_name": e, "checks": {
        "signin": {"status": "error" if pw else "valid", "data": {"password_status": "enabled" if pw else "disabled", "privileged": priv}},
        "mfa": {"status": "valid" if mfa else "error", "data": {"mfa": mfa}}}} for e, pw, mfa, priv in users]})


def pra(users=(), assets=()):
    rows = [{"kind": "user", "domain": name, "email": email, "checks": {
        "authentication": {"data": {"provider_type": ptype, "mfa": mfa}}, "privileges": {"data": {"admin": admin}}}}
        for name, email, ptype, mfa, admin in users]
    rows += [{"kind": "asset", "domain": name, "host": host, "checks": {"exposure": {"data": {"host": host}}}} for name, host in assets]
    return rep("r3", "pra", {"results": rows})


def edr(*hosts):
    return rep("r4", "edr", {"results": [{"domain": h, "profile": p} for h, p in hosts]})


def codes(reports):
    return [(x["code"], x["subject"]) for x in correlations.build(reports)["links"]]


class PeopleTest(unittest.TestCase):
    def test_clicker_with_privileged_access(self):
        got = correlations.build([pp(clicks=["alice@contoso.com"]),
                                  pra(users=[("Alice@Contoso.com", "", "local", True, True)])])  # user name is the e-mail, any case
        self.assertEqual([(x["code"], x["subject"]) for x in got["links"]], [("CLICKER_PRIVILEGED", "alice@contoso.com")])
        link = got["links"][0]
        self.assertEqual({r["area"] for r in link["refs"]}, {"proofpoint", "pra"})
        self.assertTrue(all(r["report"] and r["hash"] for r in link["refs"]))       # deep links to both reports
        self.assertEqual(got["summary"]["people_joined"], 1)

    def test_attacked_user_without_mfa(self):
        self.assertEqual(codes([pp(vap=["bob@contoso.com"]), ias(("bob@contoso.com", True, False, False))]),
                         [("ATTACKED_NO_MFA", "bob@contoso.com")])
        # corporate sign-in only (no IAS password): the IdP enforces MFA, nothing to report
        self.assertEqual(codes([pp(vap=["bob@contoso.com"]), ias(("bob@contoso.com", False, False, False))]), [])
        # SAML users of PRA get MFA from the identity provider: not "without MFA", but PRA access is privileged access
        self.assertEqual(codes([pp(vap=["bob@contoso.com"]), pra(users=[("bob", "bob@contoso.com", "saml", False, False)])]),
                         [("ATTACKED_PRIVILEGED", "bob@contoso.com")])

    def test_attacked_privileged_with_mfa_is_a_warning(self):
        got = correlations.build([pp(vap=["carol@contoso.com"]), ias(("carol@contoso.com", True, True, True))])["links"]
        self.assertEqual([(x["code"], x["severity"]) for x in got], [("ATTACKED_PRIVILEGED", "warning")])

    def test_privileged_without_mfa_elsewhere(self):
        self.assertEqual(codes([ias(("dan@contoso.com", True, True, True)), pra(users=[("dan", "dan@contoso.com", "local", False, False)])]),
                         [("PRIVILEGED_NO_MFA_ELSEWHERE", "dan@contoso.com")])

    def test_people_in_one_module_only_are_not_risks(self):
        self.assertEqual(codes([pp(vap=["eve@contoso.com"], clicks=["eve@contoso.com"]), ias(("frank@contoso.com", True, False, True))]), [])

    def test_proofpoint_without_tap_is_ignored(self):
        p = pp(clicks=["alice@contoso.com"])
        p["payload"]["tap"] = False
        self.assertEqual(codes([p, pra(users=[("alice", "alice@contoso.com", "local", True, True)])]), [])


class EndpointTest(unittest.TestCase):
    def test_pra_targets_against_edr(self):
        got = correlations.build([pra(assets=[("dc01", "dc01.contoso.local"), ("sql", "SQL-PROD"), ("web", "web01"), ("plc", "10.20.0.5")]),
                                  edr(("DC01", "threat"), ("sql-prod.contoso.local", "detect"))])
        self.assertEqual([(x["code"], x["subject"]) for x in got["links"]],
                         [("PRA_TARGET_THREAT", "dc01.contoso.local"), ("PRA_TARGET_EDR_WEAK", "sql-prod"), ("PRA_TARGET_NO_EDR", "web01")])
        s = got["summary"]
        self.assertEqual((s["pra_targets"], s["pra_targets_matched"], s["pra_targets_by_address"]), (4, 2, 1))  # IPs are not compared

    def test_no_edr_report_means_unknown_not_unprotected(self):
        self.assertEqual(codes([pra(assets=[("web", "web01")])]), [])


class MailDomainTest(unittest.TestCase):
    def dns(self, *rows):
        return rep("d1", "email", {"results": [{"domain": d, "profile": prof, "tier": "high", "dmarc": {"status": "valid", "policy": pol, "pct": 100},
                                                "issues": [], "overall_score": 70} for d, prof, pol in rows]})

    def pp_row(self, domain, profile, from_domains=()):
        return {"domain": domain, "profile": profile, "overall_score": 60, "tier": "high", "issues": [], "checks": {
            "routing": {"data": {"mx_status": "ok", "mx": [{"host": "mx." + domain}]}},
            "threats": {"data": {"malicious": len(from_domains), "messages": [{"from_domain": f, "time": "2026-11-01T08:00:00Z"} for f in from_domains]}}}}

    def signals(self, reports):
        return {a["key"]: sorted(s["code"] for s in a["signals"]) for a in inventory.build(reports)["assets"]}

    def test_unfiltered_and_spoofable_domain_is_critical(self):
        inv = inventory.build([self.dns(("contoso.com", "mail", "none")), pp(results=[self.pp_row("contoso.com", "unprotected")])])
        a = inv["assets"][0]
        sig = {s["code"]: s for s in a["signals"]}
        self.assertEqual(sig["MAIL_NOT_FILTERED"]["severity"], "critical")
        self.assertIn("impersonated", sig["MAIL_NOT_FILTERED"]["text"])
        self.assertEqual(a["mail"][0]["filtered"], False)
        self.assertEqual(inv["summary"]["mail_filtered"], 1)

    def test_threat_delivered_with_own_domain_as_sender(self):
        got = self.signals([self.dns(("contoso.com", "mail", "none")),
                            pp(results=[self.pp_row("contoso.com", "protected", ["contoso.com", "evil.example"])])])
        self.assertIn("SELF_SPOOF_DELIVERED", got["contoso.com"])
        enforced = self.signals([self.dns(("contoso.com", "mail", "reject")), pp(results=[self.pp_row("contoso.com", "protected", ["contoso.com"])])])
        self.assertNotIn("SELF_SPOOF_DELIVERED", enforced["contoso.com"])

    def test_mail_domain_missing_from_proofpoint(self):
        got = self.signals([self.dns(("contoso.com", "mail", "reject"), ("fabrikam.com", "mail", "reject"), ("parked.com", "parked", "reject")),
                            pp(results=[self.pp_row("contoso.com", "protected")], no_mail=["parked.com"])])
        self.assertEqual(got["fabrikam.com"], ["MAIL_NOT_IN_PROOFPOINT"])
        self.assertEqual(got["contoso.com"], [])
        self.assertEqual(got["parked.com"], [])          # receives no mail: not a gap
        # without a Proofpoint report nothing is a gap
        self.assertEqual(self.signals([self.dns(("fabrikam.com", "mail", "reject"))])["fabrikam.com"], [])


if __name__ == "__main__":
    unittest.main()
