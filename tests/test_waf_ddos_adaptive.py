"""WAF DDoS: with an adaptive threshold the fixed-threshold tuning is not evaluated."""

import unittest

from securityhub.scanners.waf.checks import check_ddos, ddos_adaptive


ADAPTIVE = {"activation_mode": "api.threats.ddos.activation_mode.adaptive"}


def site(**rule):
    return {"site_id": 1, "domain": "www.example", "security": {"waf": {"rules": [
        {"id": "api.threats.ddos", "activation_mode": "api.threats.ddos.activation_mode.auto", **rule}]}}}


def traffic(peak_rps):
    # hourly buckets: hits per hour -> rps = hits / 3600
    pts = [[1_700_000_000_000 + i * 3_600_000, int(peak_rps * 3600 if i == 5 else 10 * 3600)] for i in range(48)]
    return {"days": 2, "granularity": 3600000, "hits_timeseries": [{"id": "api.stats.visits_timeseries.human", "data": pts}],
            "threats": [{"id": "api.threats.ddos", "incidents": 2}]}


class AdaptiveTest(unittest.TestCase):
    def test_detection(self):
        self.assertTrue(ddos_adaptive(site(**ADAPTIVE)))
        self.assertTrue(ddos_adaptive(site(activation_mode="", activation_mode_text="Adaptive")))
        # without an activation mode: fall back to other 'adaptive' parameters / DDoS settings
        self.assertTrue(ddos_adaptive(site(activation_mode="", adaptive_threshold=True)))
        self.assertTrue(ddos_adaptive(site(activation_mode="", ddos_traffic_threshold="adaptive")))
        self.assertTrue(ddos_adaptive({**site(activation_mode="", ddos_traffic_threshold="1000"), "ddos_settings": {"adaptiveProtection": "enabled"}}))
        self.assertFalse(ddos_adaptive(site(ddos_traffic_threshold="1000")))
        self.assertFalse(ddos_adaptive(site(ddos_traffic_threshold="1000", adaptive_threshold=True)))  # mode auto wins
        self.assertIsNone(ddos_adaptive({"site_id": 1}))

    def test_fixed_threshold_still_tuned(self):
        c = check_ddos(site(ddos_traffic_threshold="200"), traffic(190))
        self.assertIn("DDOS_THRESHOLD_LOW", {i.code for i in c.issues})

    def test_adaptive_skips_threshold_checks(self):
        c = check_ddos(site(ddos_traffic_threshold="200", **ADAPTIVE), traffic(190))
        codes = {i.code for i in c.issues}
        self.assertFalse(codes & {"DDOS_THRESHOLD_LOW", "DDOS_THRESHOLD_HIGH", "DDOS_DEFAULT_THRESHOLD", "DDOS_ABOVE_ORIGIN",
                                  "DDOS_HIGH_THRESHOLD", "DDOS_TRAFFIC_UNAVAILABLE"})
        self.assertIn("DDOS_ACTIVATIONS", codes)                 # mitigation events are still reported
        self.assertEqual((c.got, c.max, c.data["adaptive"], c.data.get("recommended")), (10, 10, True, None))
        self.assertEqual(check_ddos(site(**ADAPTIVE)).status, "valid")   # no traffic needed
        off = check_ddos(site(activation_mode="api.threats.ddos.activation_mode.off"))
        self.assertIn("DDOS_OFF", {i.code for i in off.issues})


class CollectTest(unittest.TestCase):
    def test_adaptive_sites_need_no_traffic_statistics(self):
        from securityhub.scanners.waf import api as wafapi
        calls = []

        class Fake(wafapi.ImpervaAPI):
            def v1(self, path, **params):
                calls.append((path, params.get("site_id")))
                if path.endswith("/account"):
                    return {"account": {"account_id": 1}}
                if path.endswith("/sites/list"):
                    return {"sites": [{"site_id": 10}, {"site_id": 11}]}
                if path.endswith("/stats/v1"):
                    return {"hits_timeseries": [], "threats": []}
                return site(**(ADAPTIVE if params.get("site_id") == 10 else {})) | {"site_id": params.get("site_id")}

            def get(self, path, **params):
                return {"value": []}
        snap = wafapi.collect(Fake("1", "k", qps=0), 1, False, set(), 2, lambda m: None, 90)
        self.assertEqual([sid for p, sid in calls if p == "/api/stats/v1"], [11])
        self.assertNotIn("10", snap["accounts"][0]["traffic"])


class ImpervaDocumentedShapeTest(unittest.TestCase):
    """Shapes from the Imperva API reference (Site Management 'site status' example, Policies ExceptionsDataDto)."""
    DOC = {"activation_mode_text": "Automatic", "ddos_traffic_threshold": "api.threats.ddos.ddos_trassic_threshold",
           "ddos_traffic_threshold_text": "750", "ddos_adaptive_threshold": "500",
           "ddos_adaptive_threshold_last_update_time": "1610396346000"}

    def test_threshold_read_from_text_field(self):
        c = check_ddos(site(**self.DOC), traffic(700))
        self.assertEqual(c.data["threshold"], 750)
        self.assertIn("DDOS_THRESHOLD_LOW", {i.code for i in c.issues})

    def test_computed_adaptive_value_is_not_the_mode(self):
        self.assertFalse(ddos_adaptive(site(**self.DOC)))                             # mode auto
        self.assertFalse(ddos_adaptive(site(**{**self.DOC, "ddos_adaptive_threshold": "1"})))
        ad = site(**{**self.DOC, "activation_mode": "api.threats.ddos.activation_mode.adaptive", "activation_mode_text": "Adaptive"})
        self.assertTrue(ddos_adaptive(ad))
        c = check_ddos(ad, traffic(700))
        self.assertEqual((c.data["adaptive"], c.data["adaptive_threshold"], c.data["threshold"]), (True, 500, None))

    def test_exception_types(self):
        from securityhub.scanners.waf.checks import assess_exception
        exc = lambda *d: {"comment": "x", "data": [{"exceptionType": t, "values": v} for t, v in d]}
        self.assertIsNone(assess_exception(exc(("SITE_ID", ["11"]), ("URL", ["/a"])), 10))
        self.assertFalse(assess_exception(exc(("SITE_ID", ["10"]), ("URL_PREFIX", ["/api/upload"])), 10)["broad"])
        neg = assess_exception(exc(("URL_NOT_EQUALS", ["/login"])), 10)
        self.assertTrue(neg["broad"])
        self.assertIn("URL is not", neg["values"][0])
        self.assertFalse(assess_exception(exc(("HTTP_PARAM", ["q"])), 10)["broad"])
        self.assertTrue(assess_exception(exc(("GEO", ["IT"])), 10)["broad"])
