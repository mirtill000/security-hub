"""WAF DDoS: with an adaptive threshold the fixed-threshold tuning is not evaluated."""

import unittest

from securityhub.scanners.waf.checks import check_ddos, ddos_adaptive


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
        self.assertTrue(ddos_adaptive(site(adaptive_threshold=True)))
        self.assertTrue(ddos_adaptive(site(ddos_traffic_threshold="adaptive")))
        self.assertTrue(ddos_adaptive(site(activation_mode="api.threats.ddos.activation_mode.adaptive")))
        self.assertTrue(ddos_adaptive({**site(ddos_traffic_threshold="1000"), "ddos_settings": {"adaptiveProtection": "enabled"}}))
        self.assertFalse(ddos_adaptive(site(ddos_traffic_threshold="1000")))
        self.assertFalse(ddos_adaptive(site(ddos_traffic_threshold="1000", adaptive_threshold="false")))
        self.assertIsNone(ddos_adaptive({"site_id": 1}))

    def test_fixed_threshold_still_tuned(self):
        c = check_ddos(site(ddos_traffic_threshold="200"), traffic(190))
        self.assertIn("DDOS_THRESHOLD_LOW", {i.code for i in c.issues})

    def test_adaptive_skips_threshold_checks(self):
        c = check_ddos(site(ddos_traffic_threshold="200", adaptive_threshold=True), traffic(190))
        codes = {i.code for i in c.issues}
        self.assertFalse(codes & {"DDOS_THRESHOLD_LOW", "DDOS_THRESHOLD_HIGH", "DDOS_DEFAULT_THRESHOLD", "DDOS_ABOVE_ORIGIN",
                                  "DDOS_HIGH_THRESHOLD", "DDOS_TRAFFIC_UNAVAILABLE"})
        self.assertIn("DDOS_ACTIVATIONS", codes)                 # mitigation events are still reported
        self.assertEqual((c.got, c.max, c.data["adaptive"], c.data.get("recommended")), (10, 10, True, None))
        self.assertEqual(check_ddos(site(adaptive_threshold=True)).status, "valid")   # no traffic needed
        off = check_ddos(site(adaptive_threshold=True, activation_mode="api.threats.ddos.activation_mode.off"))
        self.assertIn("DDOS_OFF", {i.code for i in off.issues})  # adaptive does not help if protection is off


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
                return site(adaptive_threshold=params.get("site_id") == 10) | {"site_id": params.get("site_id")}

            def get(self, path, **params):
                return {"value": []}
        snap = wafapi.collect(Fake("1", "k", qps=0), 1, False, set(), 2, lambda m: None, 90)
        self.assertEqual([sid for p, sid in calls if p == "/api/stats/v1"], [11])
        self.assertNotIn("10", snap["accounts"][0]["traffic"])
