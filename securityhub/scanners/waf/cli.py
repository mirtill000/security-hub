"""Command line: securityhub waf."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from ...common import EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, Parser
from .analysis import analyze_snapshot, compute_diff, load_metadata
from .api import ImpervaAPI, collect
from .constants import CHECKS, DDOS_FACTOR, DDOS_FLOOR, __version__, parse_checks
from .exports import write_csv, write_json
from . import cache as wafcache
from .probe import probe_site
from .report import generate_html_report

_Parser = Parser


def build_parser() -> _Parser:
    p = _Parser(description="Imperva Cloud WAF security posture and configuration assessment (read-only)",
                formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Credentials: set IMPERVA_API_ID and IMPERVA_API_KEY (preferred), or use --api-key-file.
An API key with read access to sites and policies is enough; the tool never changes anything.

Examples:
    securityhub waf --account-id 1234567
    securityhub waf --account-id 1234567 --include-subaccounts --probe --json --csv
    securityhub waf --account-id 1234567 --sites www.example.com,12345678
    securityhub waf --account-id 1234567 --save-raw snapshot.json
    securityhub waf --from-json snapshot.json --metadata sites.csv --baseline previous.json

Checks: onboarding, waf, allowlist, bots, ddos, tls, origin (default: all; origin needs --probe)
Metadata CSV: site_id or domain, tier (critical/high/medium/low), owner, bu, tags (separated by |),
              max_rps (requests/s the origin can serve, from load tests: upper bound for the DDoS threshold)
DDoS tuning: peak legitimate requests/s over --traffic-days (hourly buckets when available);
             recommended threshold = --ddos-factor x peak (min --ddos-floor), rounded up to a value Imperva accepts.
Exit codes: 0 ok, 1 usage/API error, 2 a website scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--account-id", type=int, help="Imperva account ID (parent account)")
    p.add_argument("--include-subaccounts", action="store_true", help="Also assess every sub-account")
    p.add_argument("--sites", default="", help="Only these websites: comma-separated site IDs or domains")
    p.add_argument("--api-id", default=os.environ.get("IMPERVA_API_ID"), help="API ID (default: $IMPERVA_API_ID)")
    p.add_argument("--api-key-file", help="File containing the API key (instead of $IMPERVA_API_KEY)")
    p.add_argument("--api-key", help=argparse.SUPPRESS)
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API")
    p.add_argument("--save-raw", help="Save the raw configuration snapshot (no credentials) to this JSON file")
    p.add_argument("-o", "--output", default="wafguard_report.html", help="Output HTML file")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV summary")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--probe", action="store_true",
                   help="Also test from the Internet: DNS routing, HSTS, redirect, TLS versions, direct origin access")
    p.add_argument("--metadata", help="CSV with tier/owner/bu/tags (and origin max_rps) per website")
    p.add_argument("--no-traffic", action="store_true", help="Do not read traffic statistics (DDoS threshold not validated)")
    p.add_argument("--traffic-days", type=int, default=90, help="Traffic window for DDoS tuning, in days (default: 90)")
    p.add_argument("--ddos-factor", type=float, default=DDOS_FACTOR, help=f"Recommended threshold = factor x peak rps (default: {DDOS_FACTOR})")
    p.add_argument("--ddos-floor", type=int, default=DDOS_FLOOR, help=f"Minimum recommended threshold (default: {DDOS_FLOOR})")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--workers", type=int, default=4, help="Parallel API calls (default: 4)")
    p.add_argument("--qps", type=float, default=5.0, help="Max API requests per second (default: 5)")
    p.add_argument("--probe-workers", type=int, default=4, help="Websites probed from the Internet at the same time (default: 4)")
    p.add_argument("--traffic-max-age", type=float, default=24.0,
                   help="Reuse traffic statistics younger than N hours (default: 24; 0 = always download)")
    p.add_argument("--probe-max-age", type=float, default=24.0,
                   help="Reuse legacy-TLS and origin probes younger than N hours (default: 24; 0 = always probe)")
    p.add_argument("--cache-file", help="Cache of traffic statistics and probes (default: ~/.cache/securityhub/waf-<account>.json)")
    p.add_argument("--no-cache", action="store_true", help="Do not read or write the cache")
    p.add_argument("--timeout", type=float, default=30.0, help="API timeout in seconds (default: 30)")
    p.add_argument("--v1-base", default="https://my.imperva.com", help=argparse.SUPPRESS)
    p.add_argument("--api-base", default="https://api.imperva.com", help=argparse.SUPPRESS)
    p.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any website scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"WAFGuard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        checks = parse_checks(args.checks, args.skip)
    except ValueError as e:
        parser.error(str(e))
    log = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    site_filter = {s.strip().lower() for s in args.sites.split(",") if s.strip()}

    metadata: Dict[str, dict] = {}
    if args.metadata:
        try:
            metadata = load_metadata(args.metadata)
        except OSError as e:
            print(f"Error: cannot read metadata file: {e}", file=sys.stderr)
            return EXIT_USAGE

    t0 = time.monotonic()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    cache, cache_file = {"traffic": {}, "probes": {}}, None
    if args.from_json:
        try:
            with open(args.from_json, encoding="utf-8") as f:
                snap = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read snapshot: {e}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Snapshot {os.path.basename(args.from_json)} collected {snap.get('collected', '?')}"
        if site_filter:
            for acc in snap.get("accounts", []):
                acc["sites"] = [s for s in acc.get("sites", []) if str(s.get("site_id")) in site_filter
                                or str(s.get("domain", "")).lower() in site_filter]
    else:
        if args.api_key:
            print("Warning: --api-key is visible in the process list and shell history; prefer IMPERVA_API_KEY.", file=sys.stderr)
        api_key = args.api_key or os.environ.get("IMPERVA_API_KEY")
        if args.api_key_file:
            try:
                with open(args.api_key_file, encoding="utf-8") as f:
                    api_key = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read API key file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if not args.api_id or not api_key:
            parser.error("API credentials missing: set IMPERVA_API_ID and IMPERVA_API_KEY (or use --from-json)")
        if not args.account_id:
            parser.error("--account-id is required when reading from the API")
        api = ImpervaAPI(args.api_id, api_key, args.v1_base, args.api_base, args.timeout, args.qps,
                         verify_tls=not args.insecure)
        log(f"Reading Imperva configuration (account {args.account_id}{', with sub-accounts' if args.include_subaccounts else ''})...")
        if not args.no_cache:
            cache_file = args.cache_file or wafcache.cache_path(args.account_id)
            cache = wafcache.load(cache_file)
        traffic_days = 0 if args.no_traffic else max(1, args.traffic_days)
        reuse = {sid: e["data"] for sid, e in cache["traffic"].items()
                 if e.get("days") == traffic_days and wafcache.fresh(e, args.traffic_max_age, now)}
        try:
            snap = collect(api, args.account_id, args.include_subaccounts, site_filter, args.workers, log,
                           traffic_days, reuse)
        except KeyboardInterrupt:
            print("\nInterrupted.", file=sys.stderr)
            return EXIT_INTERRUPTED
        auth_errors = [e for e in snap["errors"] if "authentication" in e["error"] or "permission" in e["error"]]
        if auth_errors and not any(a.get("sites") for a in snap["accounts"]):
            print(f"Error: {auth_errors[0]['error']}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Imperva API, account {args.account_id}, {api.stats['requests']} requests"
        for acc in snap["accounts"]:
            for sid, t in (acc.get("traffic") or {}).items():
                if sid not in reuse and t and "error" not in t:
                    cache["traffic"][sid] = {"at": now_iso, "days": traffic_days, "data": t}
        if snap.get("traffic_reused"):
            log(f"  traffic statistics of {snap['traffic_reused']} website(s) reused (younger than {args.traffic_max_age:g}h)")

    sites = [(acc, s) for acc in snap.get("accounts", []) for s in acc.get("sites", [])]
    if not sites:
        print("No websites found (check the account ID, the --sites filter or the API key scope).", file=sys.stderr)
        return EXIT_USAGE

    probes: Dict[str, dict] = dict(snap.get("probes") or {})
    probes_reused = 0
    if args.probe:
        log(f"Testing {len(sites)} website(s) from the Internet...")
        cached_heavy: Dict[str, dict] = {}
        for _, s in sites:
            sid = str(s.get("site_id"))
            e = cache["probes"].get(sid)
            if wafcache.fresh(e, args.probe_max_age, now, wafcache.probe_key(s)):
                cached_heavy[sid] = e

        def run_probe(site: dict) -> dict:
            sid = str(site.get("site_id"))
            if sid in cached_heavy:  # light probe now, heavy part from a recent run
                res = probe_site(site, heavy=False)
                res.update(cached_heavy[sid]["heavy"])
                res["heavy_at"] = cached_heavy[sid]["at"]
                return res
            return probe_site(site)

        with ThreadPoolExecutor(max_workers=max(1, args.probe_workers)) as ex:
            futs = {ex.submit(run_probe, s): (str(s.get("site_id")), s) for _, s in sites}
            for k, fut in enumerate(as_completed(futs), 1):
                sid, site = futs[fut]
                try:
                    probes[sid] = fut.result()
                    if sid not in cached_heavy and probes[sid].get("addresses"):
                        cache["probes"][sid] = {"at": now_iso, "key": wafcache.probe_key(site),
                                                "heavy": {k2: probes[sid].get(k2) for k2 in wafcache.HEAVY_PROBE_KEYS}}
                except Exception as e:
                    probes[sid] = {"error": str(e), "addresses": [], "origins": []}
                if k % 10 == 0 or k == len(futs):
                    log(f"  probed {k}/{len(futs)}")
        probes_reused = len(cached_heavy)
        if probes_reused:
            log(f"  legacy TLS and origin tests of {probes_reused} website(s) reused (younger than {args.probe_max_age:g}h)")
        snap["probes"] = probes
    if cache_file:
        problem = wafcache.save(cache_file, cache)
        if problem:
            print(f"Warning: cache not saved ({problem})", file=sys.stderr)

    if args.save_raw:
        try:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Raw snapshot saved: {args.save_raw}")
        except OSError as e:
            print(f"Warning: cannot save snapshot: {e}", file=sys.stderr)

    results, account_issues, policy_rows = analyze_snapshot(snap, checks, probes, metadata, args.ddos_factor, args.ddos_floor)
    results.sort(key=lambda r: (-r.priority, r.domain))
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    notes = []
    if not args.probe and not snap.get("probes"):
        notes.append("Internet tests were not run (--probe): origin exposure and DNS routing are not evaluated.")
    if snap.get("errors"):
        notes.append(f"{len(snap['errors'])} API call(s) failed: see the account findings.")
    if snap.get("traffic_reused"):
        notes.append(f"Traffic statistics of {snap['traffic_reused']} website(s) come from a run of the last "
                     f"{args.traffic_max_age:g} hours (they only tune the DDoS threshold and change slowly).")
    if probes_reused:
        notes.append(f"Legacy TLS and origin exposure tests of {probes_reused} website(s) come from a run of the last "
                     f"{args.probe_max_age:g} hours; DNS routing and HTTPS were tested now.")
    try:
        generate_html_report(results, account_issues, policy_rows, args.output,
                             {"checks": checks, "source": source, "diff": diff, "notes": notes,
                              "ddos_factor": args.ddos_factor, "ddos_floor": args.ddos_floor})
        log(f"Report generated: {args.output}")
        base = args.output.rsplit(".", 1)[0]
        if args.json:
            write_json(results, account_issues, base + ".json")
            log(f"JSON output: {base}.json")
        if args.csv:
            write_csv(results, checks, base + ".csv")
            log(f"CSV output: {base}.csv")
    except OSError as e:
        print(f"Error: cannot write output: {e}", file=sys.stderr)
        return EXIT_USAGE

    sev = Counter(i.severity for r in results for i in r.issues)
    print(f"\n{'=' * 60}\nSUMMARY\n{'=' * 60}")
    print(f"Websites assessed:        {len(results)}")
    print(f"Well protected (>=80):    {sum(r.overall_score >= 80 for r in results)}")
    print(f"Need attention (50-79):   {sum(50 <= r.overall_score < 80 for r in results)}")
    print(f"Critical risk (<50):      {sum(r.overall_score < 50 for r in results)}")
    print(f"In bypass mode:           {sum(r.profile == 'bypass' for r in results)}")
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    if account_issues:
        print(f"Account findings:         {len(account_issues)}")
    for r in [r for r in results if r.priority > 0][:5]:
        first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
        print(f"  {r.domain:<38} score {r.overall_score:>3}  {first.message[:70] if first else ''}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK
