"""Command line: securityhub pra (BeyondTrust Privileged Remote Access)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import List, Optional

from ...common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE, Parser
from .analysis import analyze_snapshot, compute_diff
from .api import APIError, PRAClient, collect
from .constants import ALL_OBJECTS_LIMIT, CHECK_ALIASES, CHECKS, INACTIVE_DAYS, SESSION_DAYS, __version__
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
    p = Parser(description="BeyondTrust Privileged Remote Access posture (read-only Configuration and Reporting API)",
               formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Credentials: PRA_SITE_URL, PRA_CLIENT_ID and PRA_CLIENT_SECRET (preferred), or --secret-file.
API account (Management > API Configuration): Command API Deny; Configuration API Allow Access without
Manage Vault Accounts; Reporting API: Session Reports and Vault Account Activity; a network allow list.
The tool only sends GET requests (plus the OAuth token request), to a closed list of endpoints.

Examples:
    securityhub pra --site https://access.example.com
    securityhub pra --session-days 30 --json --csv
    securityhub pra --save-raw pra.json                  # keep the data for offline analysis
    securityhub pra --from-json pra.json --baseline previous.json

Checks: authentication, privileges, lifecycle, access_policy, exposure (default: all)
Exit codes: 0 ok, 1 usage/API error, 2 an object scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--site", default=os.environ.get("PRA_SITE_URL"), help="PRA site URL (default: $PRA_SITE_URL)")
    p.add_argument("--client-id", default=os.environ.get("PRA_CLIENT_ID"), help="OAuth client id (default: $PRA_CLIENT_ID)")
    p.add_argument("--secret-file", help="File with the OAuth client secret (instead of $PRA_CLIENT_SECRET)")
    p.add_argument("--session-days", type=int, default=SESSION_DAYS, help=f"Session report window in days (default: {SESSION_DAYS})")
    p.add_argument("--inactive-days", type=int, default=INACTIVE_DAYS, help=f"No sign-in for N days = inactive (default: {INACTIVE_DAYS})")
    p.add_argument("--objects-limit", type=int, default=ALL_OBJECTS_LIMIT,
                   help=f"Above this many objects, list only those that need action (default: {ALL_OBJECTS_LIMIT})")
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API")
    p.add_argument("--save-raw", help="Save the snapshot (no credentials) to this JSON file")
    p.add_argument("-o", "--output", default="pra_report.html", help="Output HTML file (default: pra_report.html)")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV of the objects")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--qps", type=float, default=5.0, help="Max API requests per second (default: 5)")
    p.add_argument("--timeout", type=float, default=60.0, help="API timeout in seconds (default: 60)")
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any object scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"PRAGuard {__version__}")
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
        self_id = snap.get("self_client_id")
    else:
        secret = os.environ.get("PRA_CLIENT_SECRET")
        if args.secret_file:
            try:
                with open(args.secret_file, encoding="utf-8") as f:
                    secret = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read the secret file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if not args.site or not args.client_id or not secret:
            print("Error: set PRA_SITE_URL, PRA_CLIENT_ID and PRA_CLIENT_SECRET (or --secret-file), or use --from-json",
                  file=sys.stderr)
            return EXIT_USAGE
        try:
            api = PRAClient(args.site, args.client_id, secret, args.timeout, args.qps)
            log(f"Reading BeyondTrust PRA {api.base} (read-only)")
            api.token()
            snap = collect(api, log, args.session_days)
        except (APIError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_USAGE
        self_id = args.client_id   # public by design (the docs say it can be shared): used to spot this tool's account
        snap["self_client_id"] = self_id
        if not snap.get("users") and snap["errors"]:
            print(f"Error: nothing could be read ({snap['errors'][0]['error']})", file=sys.stderr)
            return EXIT_USAGE
        source = f"Site {api.base}"
        if args.save_raw:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Snapshot saved: {args.save_raw}")
    results, account, _, extra = analyze_snapshot(snap, checks, args.inactive_days, self_id, args.objects_limit)
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    meta = {"checks": checks, "source": source, "diff": diff, "site": snap.get("site", ""), "inactive_days": args.inactive_days}
    try:
        generate_html_report(results, account, extra, args.output, meta)
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
    tot = extra["totals"]
    sev = Counter(i.severity for r in results for i in r.issues)
    print(f"\n{'=' * 60}\nSUMMARY\n{'=' * 60}")
    print("Objects:                  " + ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(tot["objects"].items())))
    s = tot.get("sessions")
    if s:
        print(f"Sessions ({s['days']} days):      {s['total']} ({s['unrecorded']} not recorded, {s['by_vendors']} by vendors, "
              f"{s['file_transfers']} with file transfers)")
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    for i in account:
        print(f"  [{i.severity}] {i.message}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK
