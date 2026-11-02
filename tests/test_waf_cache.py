"""WAF: frequent runs reuse traffic statistics and heavy probes instead of repeating them."""

import json
import os
from datetime import datetime, timedelta, timezone
from unittest import mock

from securityhub import cli
from securityhub.scanners.waf import cache as wafcache
from securityhub.scanners.waf import probe as wafprobe

from .helpers import TempDirTest, fixture, silenced


def snapshot():
    with open(fixture("waf_snapshot.json"), encoding="utf-8") as f:
        snap = json.load(f)
    for acc in snap["accounts"]:
        acc["traffic"] = {str(s["site_id"]): {"days": 90, "hits_timeseries": [], "threats": []} for s in acc["sites"]}
    return snap


class ProbeTest(TempDirTest):
    def test_light_probe_skips_tls_and_origins(self):
        with mock.patch.object(wafprobe, "_resolve", return_value=([], ["203.0.113.1"])), \
                mock.patch.object(wafprobe, "_http_head", return_value={"ok": True, "status": 200, "headers": {}}) as head, \
                mock.patch.object(wafprobe, "_accepts_tls", return_value=False) as tls:
            light = wafprobe.probe_site({"domain": "www.contoso.example", "ips": ["198.51.100.7"]}, heavy=False)
            self.assertEqual((tls.call_count, head.call_count), (0, 2))     # HTTPS + HTTP only
            self.assertNotIn("origins", light)
            full = wafprobe.probe_site({"domain": "www.contoso.example", "ips": ["198.51.100.7"]})
        self.assertEqual(tls.call_count, 2)
        self.assertEqual(len(full["origins"]), 1)

    def test_freshness_and_key(self):
        now = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
        e = {"at": (now - timedelta(hours=5)).isoformat(), "key": "k"}
        self.assertTrue(wafcache.fresh(e, 24, now, "k"))
        self.assertFalse(wafcache.fresh(e, 4, now, "k"))
        self.assertFalse(wafcache.fresh(e, 24, now, "other"))      # origins changed: probe again
        self.assertFalse(wafcache.fresh(e, 0, now, "k"))           # 0 = never reuse
        site = {"domain": "A.example", "ips": ["2.2.2.2", "1.1.1.1"]}
        self.assertEqual(wafcache.probe_key(site), wafcache.probe_key({"domain": "a.example", "ips": ["1.1.1.1", "2.2.2.2"]}))
        self.assertNotEqual(wafcache.probe_key(site), wafcache.probe_key({**site, "ips": ["1.1.1.1"]}))


class CliCacheTest(TempDirTest):
    def run_waf(self, seen, probes, *extra):
        def fake_collect(api, account_id, subs, site_filter, workers, log, traffic_days=90, traffic_cache=None):
            seen.append(dict(traffic_cache or {}))
            snap = snapshot()
            for acc in snap["accounts"]:
                for sid in list(acc["traffic"]):
                    if sid in (traffic_cache or {}):
                        acc["traffic"][sid] = traffic_cache[sid]
            snap["traffic_reused"] = len(traffic_cache or {})
            return snap

        def fake_probe(site, timeout=6.0, heavy=True):
            probes.append(heavy)
            out = {"host": site.get("domain"), "addresses": ["203.0.113.1"], "cnames": [], "routed": True}
            if heavy:
                out.update({"tls10": False, "tls11": False, "origins": []})
            return out
        env = {"IMPERVA_API_ID": "1", "IMPERVA_API_KEY": "k"}
        with mock.patch.dict(os.environ, env), mock.patch("securityhub.scanners.waf.cli.collect", fake_collect), \
                mock.patch("securityhub.scanners.waf.cli.probe_site", fake_probe), silenced():
            return cli.main(["waf", "--account-id", "1", "--probe", "--cache-file", self.path("cache.json"),
                             "-o", self.path("w.html")] + list(extra))

    def test_second_run_reuses(self):
        seen, probes = [], []
        self.run_waf(seen, probes)
        n = len(probes)
        self.assertEqual(seen[0], {})
        self.assertTrue(all(probes))                                  # first run: full probes
        self.run_waf(seen, probes)
        self.assertEqual(len(seen[1]), n)                             # traffic of every site reused
        self.assertFalse(any(probes[n:]))                            # light probes only
        with open(self.path("w.html"), encoding="utf-8") as f:
            self.assertIn("come from a run of the last 24 hours", f.read())
        self.run_waf(seen, probes, "--traffic-max-age", "0", "--probe-max-age", "0")
        self.assertEqual(seen[2], {})
        self.assertTrue(all(probes[2 * n:]))
        with open(self.path("cache.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["probes"]), n)
        self.assertEqual(oct(os.stat(self.path("cache.json")).st_mode & 0o777), "0o600")

    def test_no_cache(self):
        seen, probes = [], []
        self.run_waf(seen, probes, "--no-cache")
        self.run_waf(seen, probes, "--no-cache")
        self.assertEqual(seen, [{}, {}])
        self.assertTrue(all(probes))
        self.assertFalse(os.path.exists(self.path("cache.json")))


class CollectTest(TempDirTest):
    def test_cached_traffic_is_not_downloaded(self):
        from securityhub.scanners.waf import api as wafapi
        calls = []

        class Fake(wafapi.ImpervaAPI):
            def v1(self, path, **params):
                calls.append(path)
                if path.endswith("/account"):
                    return {"account": {"account_id": 1}}
                if path.endswith("/sites/list"):
                    return {"sites": [{"site_id": 10, "domain": "a.example"}, {"site_id": 11, "domain": "b.example"}]}
                if path.endswith("/stats/v1"):
                    return {"hits_timeseries": [], "threats": []}
                return {"site_id": params.get("site_id")}

            def get(self, path, **params):
                return {"value": []}
        snap = wafapi.collect(Fake("1", "k", qps=0), 1, False, set(), 2, lambda m: None, 90,
                              {"10": {"days": 90, "hits_timeseries": [[1, 5]], "threats": []}})
        self.assertEqual(calls.count("/api/stats/v1"), 1)            # only the site not in the cache
        self.assertEqual(snap["accounts"][0]["traffic"]["10"]["hits_timeseries"], [[1, 5]])
        self.assertEqual(snap["traffic_reused"], 1)
