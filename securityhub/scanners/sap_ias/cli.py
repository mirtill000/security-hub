"""Command line: securityhub sap-ias (SAP Cloud Identity Services, identity posture)."""

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
from .api import APIError, IASClient, collect
from .constants import ALL_USERS_LIMIT, CHECK_ALIASES, CHECKS, INACTIVE_DAYS, PASSWORD_MAX_DAYS, __version__
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


def _list(v: str) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def build_parser() -> Parser:
    p = Parser(description="SAP Cloud Identity Services (IAS) identity posture (read-only SCIM 2.0)",
               formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Credentials: IAS_TENANT_URL, IAS_CLIENT_ID and IAS_CLIENT_SECRET (preferred), or --secret-file,
or a client certificate (IAS_CLIENT_CERT / IAS_CLIENT_KEY or --client-cert / --client-key).
Use a dedicated technical user with read-only authorizations (read users, read groups).

Examples:
    securityhub sap-ias --tenant https://mytenant.accounts.ondemand.com
    securityhub sap-ias --privileged-groups "IAS Admins,BTP Admins" --password-types partner,customer --csv
    securityhub sap-ias --save-raw ias.json                 # keep the directory data for offline analysis
    securityhub sap-ias --from-json ias.json --baseline previous.json

Checks: signin, mfa, password, activity, lifecycle, email (default: all)
Exit codes: 0 ok, 1 usage/API error, 2 a user scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--tenant", default=os.environ.get("IAS_TENANT_URL"), help="Tenant URL (default: $IAS_TENANT_URL)")
    p.add_argument("--client-id", default=os.environ.get("IAS_CLIENT_ID"), help="Technical user (default: $IAS_CLIENT_ID)")
    p.add_argument("--secret-file", help="File with the technical user's secret (instead of $IAS_CLIENT_SECRET)")
    p.add_argument("--client-cert", default=os.environ.get("IAS_CLIENT_CERT"), help="Client certificate (PEM) instead of a secret")
    p.add_argument("--client-key", default=os.environ.get("IAS_CLIENT_KEY"), help="Private key of the client certificate (PEM)")
    p.add_argument("--privileged-groups", default="", help="Groups whose members must never have a local IAS password")
    p.add_argument("--password-types", default="", help="User types expected to use IAS passwords (e.g. partner,customer)")
    p.add_argument("--inactive-days", type=int, default=INACTIVE_DAYS, help=f"No sign-in for N days = inactive (default: {INACTIVE_DAYS})")
    p.add_argument("--password-max-days", type=int, default=PASSWORD_MAX_DAYS,
                   help=f"Local password older than N days = old (default: {PASSWORD_MAX_DAYS})")
    p.add_argument("--all-users-limit", type=int, default=ALL_USERS_LIMIT,
                   help=f"Above this many active users, list only those that need action (default: {ALL_USERS_LIMIT})")
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API")
    p.add_argument("--save-raw", help="Save the directory snapshot (no credentials) to this JSON file")
    p.add_argument("-o", "--output", default="ias_report.html", help="Output HTML file (default: ias_report.html)")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV of the users")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--qps", type=float, default=5.0, help="Max API requests per second (default: 5)")
    p.add_argument("--timeout", type=float, default=30.0, help="API timeout in seconds (default: 30)")
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any user scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"IASGuard {__version__}")
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
        secret = os.environ.get("IAS_CLIENT_SECRET")
        if args.secret_file:
            try:
                with open(args.secret_file, encoding="utf-8") as f:
                    secret = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read the secret file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if not args.tenant or not (args.client_cert or (args.client_id and secret)):
            print("Error: set IAS_TENANT_URL and IAS_CLIENT_ID + IAS_CLIENT_SECRET (or a client certificate), "
                  "or use --from-json", file=sys.stderr)
            return EXIT_USAGE
        try:
            api = IASClient(args.tenant, args.client_id, secret, args.client_cert, args.client_key, args.timeout, args.qps)
            log(f"Reading SAP Cloud Identity Services {api.base} (read-only SCIM)")
            snap = collect(api, log)
        except (APIError, ValueError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_USAGE
        if not snap["users"] and snap["errors"]:
            print(f"Error: no user could be read ({snap['errors'][0]['error']})", file=sys.stderr)
            return EXIT_USAGE
        source = f"Tenant {api.base}"
        if args.save_raw:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Snapshot saved: {args.save_raw}")
    results, account, _, extra = analyze_snapshot(snap, checks, _list(args.privileged_groups), _list(args.password_types),
                                                  args.inactive_days, args.password_max_days, args.all_users_limit)
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    meta = {"checks": checks, "source": source, "diff": diff, "tenant": snap.get("tenant", ""),
            "inactive_days": args.inactive_days, "password_max_days": args.password_max_days}
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
    print(f"Users:                    {tot['active']} active, {tot['inactive_accounts']} deactivated, {tot['groups']} groups")
    print(f"Corporate sign-in only:   {tot['federated']}")
    print(f"Local IAS password:       {tot['password_enabled']} ({tot['password_unexpected']} not expected)")
    print(f"Privileged users:         {tot['privileged']}")
    print(f"Users needing action:     {tot['with_findings']}" + (f" (listed: {tot['listed']})" if tot.get("limited") else ""))
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    for i in account:
        print(f"  [{i.severity}] {i.message}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK
