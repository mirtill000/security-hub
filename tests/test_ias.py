"""SAP Cloud Identity Services module: identity checks, SCIM client, CLI, portal and orchestrator."""

import io
import json
import os
import urllib.error
import urllib.parse
from unittest import mock

from securityhub import cli, orchestrator as orch, portal
from securityhub.common import EXIT_OK, EXIT_USAGE
from securityhub.scanners import sap_ias
from securityhub.scanners.sap_ias import api as iasapi

from .helpers import TempDirTest, fixture, silenced


def snapshot():
    with open(fixture("ias_snapshot.json"), encoding="utf-8") as f:
        return json.load(f)


def analyze(snap=None, **kw):
    kw = {"privileged_groups": ["IAS Admins"], "password_types": ["partner"], **kw}
    return sap_ias.analyze_snapshot(snap or snapshot(), list(sap_ias.CHECKS), **kw)


class AnalysisTest(TempDirTest):
    def test_users(self):
        results, account, _, extra = analyze()
        r = {x.domain: x for x in results}
        codes = lambda u: {i.code for i in r[u].issues}
        self.assertNotIn("left.company@contoso.com", r)                       # deactivated: counted, not assessed
        self.assertEqual(extra["totals"]["inactive_accounts"], 1)
        self.assertEqual(codes("admin.btp@contoso.com"), {"PASSWORD_LOGIN_PRIVILEGED", "PASSWORD_NO_MFA"})
        self.assertEqual((r["admin.btp@contoso.com"].profile, r["admin.btp@contoso.com"].overall_score), ("privileged", 30))
        self.assertEqual(codes("fornitore1@supplier.example"), {"PASSWORD_NO_MFA"})   # password expected for partners
        self.assertTrue({"PASSWORD_OLD", "PASSWORD_STANDARD_POLICY"} <= codes("marco.bianchi@contoso.com"))
        self.assertIn("FAILED_LOGINS", codes("attack.target@contoso.com"))
        self.assertEqual(codes("contractor@contoso.com"), {"EXPIRED_ACTIVE"})
        self.assertEqual(codes("old.user@contoso.com"), {"INACTIVE"})
        self.assertEqual(codes("never.used@contoso.com"), {"NEVER_USED"})
        self.assertTrue({"EMAIL_SHARED", "EMAIL_UNVERIFIED", "PASSWORD_INITIAL"} <= codes("shared1@contoso.com"))
        self.assertEqual(r["anna.rossi@contoso.com"].checks["mfa"].status, "na")      # corporate IdP handles MFA
        self.assertEqual(r["anna.rossi@contoso.com"].compliance, {"federated_only": "pass", "account_hygiene": "pass"})
        self.assertEqual({i.code for i in account}, {"PASSWORD_SHARE_HIGH"})

    def test_attributes_not_exposed_are_unknown(self):
        snap = snapshot()
        for u in snap["users"]:
            u["lastLogin"], u["mfa"] = None, None
        snap["fields_seen"] = {"lastLogin": 0, "mfa": 0}
        results, account, _, _ = analyze(snap)
        r = {x.domain: x for x in results}["old.user@contoso.com"]
        self.assertEqual(r.checks["activity"].status, "unknown")
        self.assertNotIn("activity", r.score_breakdown["components"])
        self.assertTrue({"MFA_NOT_VISIBLE", "LAST_LOGIN_NOT_VISIBLE"} <= {i.code for i in account})

    def test_large_directory_lists_users_with_findings(self):
        results, _, _, extra = analyze(all_users_limit=3)
        self.assertTrue(extra["totals"]["limited"])
        self.assertTrue(all(any(i.severity in ("critical", "warning") for i in r.issues) for r in results))
        self.assertEqual(extra["totals"]["active"], 10)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ApiTest(TempDirTest):
    def test_cursor_and_index_pagination(self):
        calls = []

        def cursor(req, timeout, context):
            calls.append(req.full_url)
            body = ({"Resources": [{"id": "1", "userName": "a", "phoneNumbers": [{"value": "555"}]}], "nextId": "abc"}
                    if "startId=initial" in req.full_url else {"Resources": [{"id": "2", "userName": "b"}], "nextId": "end"})
            return FakeResponse(json.dumps(body).encode())
        api = iasapi.IASClient("mytenant.accounts.ondemand.com", "id", "secret", qps=0)
        self.assertEqual(api.base, "https://mytenant.accounts.ondemand.com")
        with mock.patch.object(iasapi.urllib.request, "urlopen", cursor):
            snap = iasapi.collect(api, lambda m: None)
        self.assertEqual([u["userName"] for u in snap["users"]], ["a", "b"])
        self.assertNotIn("555", json.dumps(snap))
        self.assertTrue(calls[0].count("Basic") == 0)                            # credentials only in headers

        def index(req, timeout, context):
            if "startId" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO(b""))
            start = int(req.full_url.split("startIndex=")[1].split("&")[0])
            return FakeResponse(json.dumps({"totalResults": 150, "Resources": [{"id": str(i)} for i in range(start, min(151, start + 100))]}).encode())
        with mock.patch.object(iasapi.urllib.request, "urlopen", index):
            self.assertEqual(len(list(api.pages("/scim/Users"))), 150)
        with self.assertRaises(ValueError):
            iasapi.IASClient("t", None, None)


class CliPortalTest(TempDirTest):
    def test_cli_and_portal(self):
        with silenced():
            self.assertEqual(cli.main(["sap-ias", "--from-json", fixture("ias_snapshot.json"), "--privileged-groups", "IAS Admins",
                                       "-o", self.path("ias.html"), "--json", "--csv"]), EXIT_OK)
        with mock.patch.dict(os.environ, {}, clear=True), silenced() as (_, err):
            self.assertEqual(cli.main(["ias", "-o", self.path("x.html")]), EXIT_USAGE)
        self.assertIn("IAS_TENANT_URL", err.getvalue())
        with open(self.path("ias.html"), encoding="utf-8") as f:
            page = f.read()
        r = portal.collect([self.path("ias.html")])[0][0]
        self.assertEqual((r["type"], r["label"], r["exec"]["status"]), ("ias", "SAP Cloud Identity", "bad"))
        kpis = {k["key"]: k["value"] for k in r["exec"]["kpis"]}
        self.assertEqual(kpis["ias_priv_pwd"], 1)
        self.assertEqual(r["exec"]["actions"][0]["code"], "PASSWORD_LOGIN_PRIVILEGED")
        portal.compact_report(self.path("ias.html"))
        self.assertEqual(portal.collect([self.path("ias.report.json")])[0][0]["html"], page)

    def test_orchestrator(self):
        p = self.path("c.json")
        with open(p, "w") as f:
            json.dump({"output_dir": "out", "modules": {"ias": {"options": {"from_json": fixture("ias_snapshot.json")}}}}, f)
        with silenced():
            self.assertIn(orch.run(p), (EXIT_OK, 2))
        with open(self.path("out", "posture.json"), encoding="utf-8") as f:
            self.assertEqual([a["area"] for a in json.load(f)["areas"]], ["ias"])
        with open(p, "w") as f:
            json.dump({"modules": {"ias": {"options": {"client_secret": "x"}}}}, f)
        with self.assertRaises(orch.ConfigError):
            orch.run(p, dry_run=True)


class ReadOnlyTest(TempDirTest):
    def test_only_get_without_body_on_read_endpoints(self):
        seen = []

        def record(req, timeout, context):
            seen.append((req.get_method(), urllib.parse.urlsplit(req.full_url).path, req.data))
            body = {"Resources": [{"id": "1", "userName": "a"}], "nextId": "end"}
            return FakeResponse(json.dumps(body).encode())
        api = iasapi.IASClient("t.accounts.ondemand.com", "id", "secret", qps=0)
        with mock.patch.object(iasapi.urllib.request, "urlopen", record):
            iasapi.collect(api, lambda m: None)
        self.assertTrue(seen)
        self.assertEqual({m for m, _, _ in seen}, {"GET"})
        self.assertEqual({p for _, p, _ in seen}, {"/scim/Users", "/scim/Groups"})
        self.assertEqual({d for _, _, d in seen}, {None})
        for path in ("/scim/Users/123", "/service/scim/Users", "/service/users/statusPassword/new", "/scim/Groups/1"):
            with self.assertRaises(ValueError):
                api.get(path)

    def test_no_write_capable_code(self):
        import inspect
        import re
        from securityhub.scanners import sap_ias as pkg
        for mod in ("api", "analysis", "cli", "report", "exports", "models", "constants"):
            src = inspect.getsource(__import__(f"{pkg.__name__}.{mod}", fromlist=[mod]))
            self.assertIsNone(re.search(r"method\s*=\s*['\"](?!GET)", src), mod)
            self.assertIsNone(re.search(r"\b(POST|PUT|PATCH|DELETE)\b", src), mod)
            self.assertNotIn("data=", src.replace("payload", ""), mod)
        self.assertEqual(inspect.getsource(iasapi).count("urlopen("), 1)
