"""BeyondTrust PRA module: objects and findings, read-only client, CLI, portal and orchestrator."""

import io
import json
import os
import urllib.parse
from datetime import datetime, timezone
from unittest import mock

from securityhub import cli, orchestrator as orch, portal
from securityhub.common import EXIT_OK, EXIT_USAGE
from securityhub.scanners import pra
from securityhub.scanners.pra import api as praapi

from .helpers import TempDirTest, fixture, silenced


def snapshot():
    with open(fixture("pra_snapshot.json"), encoding="utf-8") as f:
        return json.load(f)


def analyze(snap=None):
    s = snap or snapshot()
    return pra.analyze_snapshot(s, list(pra.CHECKS), self_client_id=s.get("self_client_id"))


class AnalysisTest(TempDirTest):
    def test_objects(self):
        results, account, _, extra = analyze()
        r = {(x.kind, x.domain): x for x in results}
        codes = lambda k, n: {i.code for i in r[(k, n)].issues}
        self.assertNotIn(("user", "left@contoso.example"), r)                     # disabled: not assessed
        self.assertEqual(codes("user", "breakglass"), {"ADMIN_NO_MFA", "ADMIN_LOCAL", "USER_ADMIN", "USER_VAULT_ADMIN"})
        self.assertEqual(codes("user", "anna.rossi@contoso.example"), {"USER_ADMIN"})   # SAML: MFA at the IdP
        self.assertTrue({"USER_NO_MFA", "USER_INACTIVE", "FAILED_LOGINS"} <= codes("user", "ops.local"))
        self.assertEqual(codes("user", "new.local"), {"USER_NEVER_USED"})
        self.assertTrue({"VENDOR_NO_MFA", "VENDOR_NO_EXPIRY"} <= codes("vendor_user", "acme.tech"))
        self.assertEqual(codes("vendor_user", "globex.eng"), {"VENDOR_INACTIVE"})
        self.assertTrue({"ASSET_RECORDING_OFF", "ASSET_TELNET"} <= codes("asset", "plc-gateway"))
        self.assertEqual(codes("asset", "dc01"), {"ASSET_NO_POLICY", "ASSET_RDP_UNTRUSTED"})
        self.assertEqual(codes("asset", "sql-prod"), {"ASSET_PERSONAL", "ASSET_TUNNEL"})
        self.assertEqual(codes("asset", "sap-prd-app01"), set())
        self.assertEqual(codes("gateway", "GW-PLANT"), {"GATEWAY_OFFLINE", "GATEWAY_SINGLE_NODE", "GATEWAY_PROXY_OPEN"})
        self.assertEqual(codes("api_account", "Old ITSM integration"), {"API_NO_IP_WRITE", "API_WRITE"})
        self.assertEqual(codes("api_account", "SecurityHub"), {"API_SELF_EXCESS"})      # license / syslog reports not needed
        self.assertEqual(codes("vault_account", "CONTOSO\\svc-backup"), {"VAULT_CHECKOUT", "VAULT_NO_ROTATION", "VAULT_SHARED_USE"})
        self.assertLessEqual(r[("user", "breakglass")].overall_score, 30)
        self.assertEqual(r[("user", "breakglass")].checks["access_policy"].status, "na")   # not applicable to users
        self.assertEqual({i.code for i in account}, {"POLICY_MFA_OPTIONAL", "VENDOR_GROUP_NO_EXPIRY", "VENDOR_GROUP_NO_APPROVAL",
                                                     "SESSIONS_UNRECORDED", "SESSIONS_FILE_TRANSFER"})
        self.assertEqual(extra["totals"]["sessions"]["by_vendors"], 1)

    def test_local_only_and_no_sessions(self):
        snap = snapshot()
        snap["security_providers"] = [p for p in snap["security_providers"] if p["type"] == "local"]
        snap["sessions"] = None
        _, account, _, extra = analyze(snap)
        self.assertIn("LOCAL_AUTH_ONLY", {i.code for i in account})
        self.assertIsNone(extra["totals"]["sessions"])


    def test_mfa_of_sso_users_is_left_to_the_identity_provider(self):
        """PRA on Pathfinder with SSO: the API exposes MFA only for local and LDAP users (Configuration API schema)."""
        snap = snapshot()
        snap["security_providers"] += [{"id": 3, "type": "scim", "name": "Pathfinder SSO", "enabled": True, "user_authentication": True},
                                       {"id": 4, "type": "ldap", "name": "AD", "enabled": True, "user_authentication": True},
                                       {"id": 5, "type": "radius", "name": "RADIUS", "enabled": True, "user_authentication": True}]
        base = {"enabled": True, "two_factor_type": "optional", "two_factor_enabled": False, "last_authentication": "2026-10-30T08:00:00Z",
                "created_at": "2025-01-01T00:00:00Z", "perm_admin": False}
        snap["users"] = [dict(base, id=10, username="sso.admin@contoso.example", security_provider_id=3, perm_admin=True),
                         dict(base, id=11, username="ldap.user", security_provider_id=4),
                         dict(base, id=12, username="radius.user", security_provider_id=5)]
        results, account, _, _ = analyze(snap)
        r = {x.domain: x for x in results if x.kind == "user"}
        auth = lambda n: r[n].checks["authentication"]
        self.assertFalse({"ADMIN_NO_MFA", "USER_NO_MFA"} & {i.code for i in r["sso.admin@contoso.example"].issues})
        self.assertIsNone(auth("sso.admin@contoso.example").data["mfa"])
        self.assertEqual(auth("sso.admin@contoso.example").data["mfa_by"], "identity provider (Pathfinder SSO)")
        self.assertNotIn("USER_NO_MFA", {i.code for i in r["radius.user"].issues})
        self.assertIn("USER_NO_MFA", {i.code for i in r["ldap.user"].issues})            # LDAP: MFA is set in PRA
        self.assertIn("POLICY_MFA_OPTIONAL", {i.code for i in account})                   # applies to the LDAP user
        snap["users"] = snap["users"][:1]                                                 # SSO users only
        _, account, _, _ = analyze(snap)
        self.assertNotIn("POLICY_MFA_OPTIONAL", {i.code for i in account})


class FakeResponse(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


XML = (b'<?xml version="1.0"?><session_list xmlns="http://www.beyondtrust.com/sra/namespaces/API/reporting">'
       b'<session lsid="x1"><start_time timestamp="1">2026-10-30T09:00:00Z</start_time><end_time>2026-10-30T10:00:00Z</end_time>'
       b'<duration>01:00:00</duration><jump_group type="shared" id="1">Prod</jump_group><jumpoint id="1">GW</jumpoint>'
       b'<file_transfer_count>2</file_transfer_count><primary_customer gsnumber="1">srv01</primary_customer>'
       b'<primary_rep gsnumber="2" id="5">anna</primary_rep><rep_list><representative id="5"><username>anna</username>'
       b'<public_ip>198.51.100.9</public_ip></representative></rep_list>'
       b'<session_recording_view_url>https://x/rec</session_recording_view_url></session></session_list>')


class ReadOnlyClientTest(TempDirTest):
    def test_requests_are_reads_on_a_closed_list(self):
        seen = []

        def fake(req, timeout, context):
            path = urllib.parse.urlsplit(req.full_url).path
            seen.append((req.get_method(), path, req.data))
            if path == "/oauth2/token":
                return FakeResponse(b'{"access_token": "tok", "expires_in": 3600}')
            if path == "/api/reporting":
                return FakeResponse(XML)
            if path == "/api/config/v1/user":
                page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["current_page"][0])
                return FakeResponse(json.dumps([{"id": i, "email_address": "x@y", "phone_number": "+39 000", "enabled": True}
                                                for i in range(100 if page == 1 else 3)]).encode())
            if path == "/api/config/v1/vendor":
                return FakeResponse(b'[{"id": 7, "name": "V"}]')
            if path == "/api/config/v1/group-policy":
                return FakeResponse(b'[{"id": 9, "name": "G"}]')
            return FakeResponse(b"[]")
        api = praapi.PRAClient("access.example.com", "cid", "secret", qps=0)
        with mock.patch.object(praapi.urllib.request, "urlopen", fake):
            snap = praapi.collect(api, lambda m: None, now=datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertEqual(len(snap["users"]), 103)                                   # pagination
        self.assertNotIn("phone_number", snap["users"][0])                           # minimized
        self.assertEqual(snap["users"][0]["email_address"], "x@y")                    # kept: joins the person across modules
        text = json.dumps(snap)
        self.assertNotIn("198.51.100.9", text)                                       # no user IP addresses
        self.assertEqual(snap["sessions"][0]["file_transfers"], 2)
        self.assertTrue(snap["sessions"][0]["recorded"])
        writes = [(m, p) for m, p, d in seen if m != "GET" or d is not None]
        self.assertEqual(writes, [("POST", "/oauth2/token")])                       # the only non-GET request
        for m, p, _ in seen:
            if m == "GET":
                rel = p[len("/api/config/v1"):] if p.startswith("/api/config/v1") else p
                self.assertTrue(p == "/api/reporting" or praapi._allowed(rel), p)
        self.assertIn("/api/config/v1/vendor/7/user", {p for _, p, _ in seen})
        self.assertIn("/api/config/v1/group-policy/9/vault-account", {p for _, p, _ in seen})
        for bad in ("/user/1", "/jump-item/shell-jump/5", "/vault/account/1/check-out", "/api-account/1/regenerate"):
            with self.assertRaises(ValueError):
                api.config(bad)
        with self.assertRaises(ValueError):
            api.report("AccessSessionRecording")


class CliPortalTest(TempDirTest):
    def test_cli_and_portal(self):
        with silenced():
            self.assertEqual(cli.main(["pra", "--from-json", fixture("pra_snapshot.json"), "-o", self.path("pra.html"), "--json", "--csv"]), EXIT_OK)
        with mock.patch.dict(os.environ, {}, clear=True), silenced() as (_, err):
            self.assertEqual(cli.main(["beyondtrust", "-o", self.path("x.html")]), EXIT_USAGE)
        self.assertIn("PRA_SITE_URL", err.getvalue())
        with open(self.path("pra.html"), encoding="utf-8") as f:
            page = f.read()
        r = portal.collect([self.path("pra.html")])[0][0]
        self.assertEqual((r["type"], r["label"], r["exec"]["status"]), ("pra", "BeyondTrust PRA", "bad"))
        kpis = {k["key"]: k["value"] for k in r["exec"]["kpis"]}
        self.assertEqual(kpis["pra_vendor"], 1)
        self.assertEqual(kpis["pra_recorded"], 50)                                   # 2 of 4 assets governed and recorded
        self.assertEqual(r["exec"]["actions"][0]["code"], "ADMIN_NO_MFA")
        portal.compact_report(self.path("pra.html"))
        self.assertEqual(portal.report_page(portal.collect([self.path("pra.report.json")])[0][0]), page)

    def test_orchestrator(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": {"pra": {"options": {"from_json": fixture("pra_snapshot.json")}}}}, f)
        with silenced():
            self.assertIn(orch.run(p), (EXIT_OK, 2))
            self.assertEqual(orch.run(p, only=["beyondtrust"], dry_run=True), 0)
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            self.assertEqual([a["area"] for a in json.load(f)["areas"]], ["pra"])
