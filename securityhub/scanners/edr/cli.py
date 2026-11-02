"""Command line: securityhub edr (SentinelOne)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import List, Optional

from ...common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE, Parser
from .analysis import analyze_snapshot, compute_diff, load_inventory, load_metadata
from .api import APIError, SentinelOneAPI, collect
from .constants import CHECK_ALIASES, CHECKS, STALE_DAYS, THREAT_SLA_DAYS, __version__
from .exports import write_csv, write_json
from .report import generate_html_report


def parse_checks(spec: str = "all", skip: str = "") -> List[str]:
    def names(text):
        out = []
        for raw in [t.strip().lower() for t in (text or "").replace(" ", ",").split(",") if t.strip()]:
            n = CHECK_ALIASES.get(raw, raw)
            if n != "all" and n not in CHECKS:
                raise ValueError(f"unknown check '{raw}' (valid: {', '.join(CHECKS)}, all)")
            out.append(n)
        return out
    sel = set()
    for n in names(spec) or ["all"]:
        sel |= set(CHECKS) if n == "all" else {n}
    sel -= set(names(skip))
    if not sel:
        raise ValueError("no checks left to run")
    return [c for c in CHECKS if c in sel]


def build_parser() -> Parser:
    p = Parser(description="SentinelOne EDR security posture (read-only, Management API v2.1)",
               formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Credentials: set S1_CONSOLE_URL and S1_API_TOKEN (preferred), or use --console / --api-token-file.
A read-only token (Viewer role, service user) is enough: the tool only lists agents, sites, groups,
policies, open threats, exclusions and agent packages.

Examples:
    securityhub edr --console https://euce1-acme.sentinelone.net
    securityhub edr --sites "EMEA,US" --inventory hosts.csv --json --csv
    securityhub edr --save-raw snapshot.json          # keep the console data for offline analysis
    securityhub edr --from-json snapshot.json --baseline previous.json

Checks: health, protection, policy, version, threats, vulnerabilities, scan (default: all)
Inventory CSV: expected hosts (CMDB, AD export): a hostname column or one host per line -> coverage gaps.
Metadata CSV: hostname, group or site -> tier (critical/high/medium/low), owner, bu, tags (separated by |).
Exit codes: 0 ok, 1 usage/API error, 2 an endpoint scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--console", default=os.environ.get("S1_CONSOLE_URL"), help="Console URL (default: $S1_CONSOLE_URL)")
    p.add_argument("--api-token-file", help="File containing the API token (instead of $S1_API_TOKEN)")
    p.add_argument("--sites", default="", help="Only these sites: comma-separated names or IDs")
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API")
    p.add_argument("--save-raw", help="Save the console snapshot (no credentials) to this JSON file")
    p.add_argument("--inventory", help="Expected hosts (CSV or list): hosts without an agent are coverage gaps")
    p.add_argument("--metadata", help="CSV with tier/owner/bu/tags per hostname, group or site")
    p.add_argument("--stale-days", type=int, default=STALE_DAYS, help=f"Agent not seen for more than N days = stale (default: {STALE_DAYS})")
    p.add_argument("--threat-sla-days", type=int, default=THREAT_SLA_DAYS, help=f"Open threats older than N days breach the SLA (default: {THREAT_SLA_DAYS})")
    p.add_argument("-o", "--output", default="edr_report.html", help="Output HTML file (default: edr_report.html)")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV summary")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--qps", type=float, default=5.0, help="Max API requests per second (default: 5)")
    p.add_argument("--timeout", type=float, default=30.0, help="API timeout in seconds (default: 30)")
    p.add_argument("--no-cache", action="store_true", help="Always read the GA agent versions (cached for 24 hours)")
    p.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any endpoint scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"EDRGuard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        checks = parse_checks(args.checks, args.skip)
    except ValueError as e:
        parser.error(str(e))
    log = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    t0 = time.monotonic()
    if args.from_json:
        try:
            with open(args.from_json, encoding="utf-8") as f:
                snap = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read {args.from_json}: {e}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Snapshot {os.path.basename(args.from_json)} ({snap.get('collected', '')})"
    else:
        token = os.environ.get("S1_API_TOKEN")
        if args.api_token_file:
            try:
                with open(args.api_token_file, encoding="utf-8") as f:
                    token = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read the token file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if not args.console or not token:
            print("Error: set S1_CONSOLE_URL and S1_API_TOKEN (or --console / --api-token-file), or use --from-json",
                  file=sys.stderr)
            return EXIT_USAGE
        try:
            api = SentinelOneAPI(args.console, token, args.timeout, args.qps, verify=not args.insecure)
            log(f"Reading SentinelOne console {api.base} (read-only)")
            from ...cache import Store
            store = Store("sentinelone", enabled=not args.no_cache)
            snap = collect(api, [s.strip() for s in args.sites.split(",") if s.strip()], log, store=store)
            store.save()
        except (APIError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_USAGE
        if not snap["agents"] and snap["errors"]:
            print(f"Error: no agent could be read ({snap['errors'][0]['error']})", file=sys.stderr)
            return EXIT_USAGE
        source = f"Console {api.base}"
        if args.save_raw:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Snapshot saved: {args.save_raw}")
    try:
        metadata = load_metadata(args.metadata) if args.metadata else {}
        inventory = load_inventory(args.inventory) if args.inventory else None
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    results, account, policies, extra = analyze_snapshot(snap, checks, metadata, inventory, args.stale_days, args.threat_sla_days)
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    meta = {"checks": checks, "source": source, "diff": diff, "stale_days": args.stale_days, "sla_days": args.threat_sla_days}
    try:
        generate_html_report(results, account, policies, extra, args.output, meta)
        print(f"Report generated: {args.output}", file=sys.stderr)
        base = args.output.rsplit(".", 1)[0]
        if args.json:
            write_json(results, account, extra, base + ".json")
            print(f"JSON output: {base}.json", file=sys.stderr)
        if args.csv:
            write_csv(results, checks, base + ".csv")
            print(f"CSV output: {base}.csv", file=sys.stderr)
    except OSError as e:
        print(f"Error: cannot write output: {e}", file=sys.stderr)
        return EXIT_USAGE
    prof = Counter(r.profile for r in results)
    sev = Counter(i.severity for r in results for i in r.issues)
    cov = extra.get("coverage")
    print(f"\n{'=' * 60}\nSUMMARY\n{'=' * 60}")
    print(f"Endpoints assessed:       {len(results)}")
    print(f"Well protected (>=80):    {sum(r.overall_score >= 80 for r in results)}")
    print(f"Detect mode only:         {prof['detect']}")
    print(f"Stale or disabled:        {prof['stale'] + prof['disabled']}")
    print(f"Active threats:           {sum(1 for r in results if any(i.code == 'THREAT_ACTIVE' for i in r.issues))}")
    if cov:
        print(f"Inventory coverage:       {cov['covered']}/{cov['inventory']}")
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    print(f"Console findings:         {len(account)}")
    for r in [r for r in results if r.priority > 0][:5]:
        first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
        print(f"  {r.domain:<36} score {r.overall_score:>3}  {first.message[:66] if first else ''}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK
