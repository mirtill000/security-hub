"""Command line: securityhub proofpoint (Proofpoint TAP + mail routing)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

from ...common import EXIT_FAIL_UNDER, EXIT_OK, EXIT_USAGE, Parser
from .analysis import analyze_snapshot, compute_diff
from .api import TAP_BASE, APIError, TapAPI, collect
from .constants import (CHECK_ALIASES, CHECKS, DNS_CHECKS, PEOPLE_WINDOW_DAYS, PROOFPOINT_HOSTS, TAP_CHECKS, WINDOW_HOURS,
                        __version__)
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
    p = Parser(description="Proofpoint email protection posture (read-only: TAP API and public DNS)",
               formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
TAP credentials: set PROOFPOINT_PRINCIPAL and PROOFPOINT_SECRET (preferred), or --principal / --secret-file.
Create a dedicated service principal in TAP (Settings > Connected Applications): the tool only reads the
SIEM API (delivered threats, permitted clicks) and the People API (Very Attacked People, top clickers).
Without credentials only the DNS checks run.

Examples:
    securityhub proofpoint --domains domains.csv
    securityhub proofpoint --domains domains.csv --hours 72 --json --csv
    securityhub proofpoint --domains domains.csv --no-tap               # DNS routing only
    securityhub proofpoint --save-raw pp.json                            # keep the data for offline analysis
    securityhub proofpoint --from-json pp.json --baseline previous.json

Checks: routing, direct, spf (DNS); threats, clicks, rewrite, people (TAP). Default: all.
Domain list: the same file as the email module (plain list, or CSV with domain, tier, owner, bu, tags).
Exit codes: 0 ok, 1 usage/API error, 2 a domain scored below --fail-under, 130 interrupted.
""")
    p.add_argument("--domains", help="Mail domains to assess (plain list or CSV with tier/owner/bu/tags)")
    p.add_argument("--principal", default=os.environ.get("PROOFPOINT_PRINCIPAL"),
                   help="TAP service principal (default: $PROOFPOINT_PRINCIPAL)")
    p.add_argument("--secret-file", help="File containing the TAP secret (instead of $PROOFPOINT_SECRET)")
    p.add_argument("--hours", type=int, default=WINDOW_HOURS, help=f"TAP window in hours, 1-168 (default: {WINDOW_HOURS})")
    p.add_argument("--people-days", type=int, default=PEOPLE_WINDOW_DAYS, choices=(14, 30, 90),
                   help=f"Window of the People API (default: {PEOPLE_WINDOW_DAYS})")
    p.add_argument("--no-tap", action="store_true", help="Skip TAP: DNS routing checks only")
    p.add_argument("--siem-reuse-hours", type=float, default=12.0,
                   help="Reuse settled hours of SIEM data read in the last N hours (default: 12; 0 = always read)")
    p.add_argument("--people-max-age", type=float, default=24.0,
                   help="Reuse People API data (VAP, top clickers) younger than N hours (default: 24; 0 = always read)")
    p.add_argument("--no-cache", action="store_true", help="Do not read or write the cache")
    p.add_argument("--no-dns", action="store_true", help="Skip the DNS routing checks: TAP only")
    p.add_argument("--gateway-hosts", default="", help="Extra MX host suffixes to treat as Proofpoint (e.g. on-premises PPS)")
    p.add_argument("--nameservers", default="1.1.1.1,8.8.8.8,9.9.9.9", help="DNS resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)")
    p.add_argument("--system-resolver", action="store_true", help="Use the resolvers of the operating system")
    p.add_argument("--dns-qps", type=float, default=20.0, help="Max DNS queries per second (default: 20)")
    p.add_argument("--dns-workers", type=int, default=8, help="Domains resolved in parallel (default: 8)")
    p.add_argument("--from-json", help="Analyze a snapshot saved with --save-raw instead of calling the API and DNS")
    p.add_argument("--save-raw", help="Save the snapshot (no credentials, no message content) to this JSON file")
    p.add_argument("-o", "--output", default="proofpoint_report.html", help="Output HTML file (default: proofpoint_report.html)")
    p.add_argument("-j", "--json", action="store_true", help="Also write JSON results (usable as --baseline)")
    p.add_argument("--csv", action="store_true", help="Also write a CSV summary")
    p.add_argument("-c", "--checks", default="all", help="Checks: " + ",".join(CHECKS) + " (default: all)")
    p.add_argument("--skip", default="", help="Checks to exclude")
    p.add_argument("--baseline", help="Previous JSON export to compare with")
    p.add_argument("--qps", type=float, default=1.0, help="Max TAP API requests per second (default: 1)")
    p.add_argument("--timeout", type=float, default=60.0, help="API timeout in seconds (default: 60)")
    p.add_argument("--tap-url", default=TAP_BASE, help=argparse.SUPPRESS)
    p.add_argument("--fail-under", type=int, help="Exit with code 2 if any domain scores below this value")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    p.add_argument("--version", action="version", version=f"PPGuard {__version__}")
    return p


def _load_domains(path: str):
    from ..dns_email.inputs import load_domains
    items, invalid = load_domains(path)
    meta = {i.domain: {"tier": i.tier, "owner": i.owner, "bu": i.bu, "tags": i.tags} for i in items}
    return [i.domain for i in items], meta, invalid


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        checks = parse_checks(args.checks, args.skip)
    except ValueError as e:
        parser.error(str(e))
    if not 1 <= args.hours <= 168:
        parser.error("--hours must be between 1 and 168 (TAP keeps 7 days)")
    log = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    t0 = time.monotonic()
    notes: List[str] = []
    if args.from_json:
        try:
            with open(args.from_json, encoding="utf-8") as f:
                snap = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read {args.from_json}: {e}", file=sys.stderr)
            return EXIT_USAGE
        source = f"Snapshot {os.path.basename(args.from_json)} ({snap.get('collected', '')})"
    else:
        domains, dmeta = [], {}
        if args.domains:
            try:
                domains, dmeta, invalid = _load_domains(args.domains)
            except OSError as e:
                print(f"Error: {e}", file=sys.stderr)
                return EXIT_USAGE
            if invalid:
                print(f"Warning: {len(invalid)} invalid entries ignored: {', '.join(invalid[:5])}", file=sys.stderr)
        want_tap = not args.no_tap and any(c in TAP_CHECKS for c in checks)
        want_dns = not args.no_dns and any(c in DNS_CHECKS for c in checks) and bool(domains)
        secret = os.environ.get("PROOFPOINT_SECRET")
        if args.secret_file:
            try:
                with open(args.secret_file, encoding="utf-8") as f:
                    secret = f.read().strip()
            except OSError as e:
                print(f"Error: cannot read the secret file: {e}", file=sys.stderr)
                return EXIT_USAGE
        if want_tap and not (args.principal and secret):
            if not domains:
                print("Error: set PROOFPOINT_PRINCIPAL and PROOFPOINT_SECRET (or --principal / --secret-file), "
                      "or give --domains for the DNS checks", file=sys.stderr)
                return EXIT_USAGE
            print("Warning: TAP credentials not set (PROOFPOINT_PRINCIPAL / PROOFPOINT_SECRET): DNS checks only", file=sys.stderr)
            notes.append("TAP credentials were not configured: delivered threats, clicks and people were not assessed.")
            want_tap = False
        if not want_tap and not want_dns:
            print("Error: nothing to assess (give --domains for the DNS checks and/or TAP credentials)", file=sys.stderr)
            return EXIT_USAGE
        snap = {"tool": f"PPGuard {__version__}", "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "domains": domains, "domain_meta": dmeta}
        sources = []
        if want_dns:
            from ..dns_email.dnsclient import DNSClient, preflight
            from .routing import collect_dns
            ns = None if args.system_resolver else [n.strip() for n in args.nameservers.split(",") if n.strip()]
            client = DNSClient(ns, 5.0, args.system_resolver, args.dns_qps, 8)
            ok, msg = preflight(client)  # a broken resolver must not make every domain look like "no mail"
            if not ok:
                print(f"Error: DNS not usable: {msg}", file=sys.stderr)
                return EXIT_USAGE
            gateways = PROOFPOINT_HOSTS + tuple(g.strip().lower().lstrip(".") for g in args.gateway_hosts.split(",") if g.strip())
            log(f"Resolving the mail routing of {len(domains)} domain(s)")
            snap["dns"] = collect_dns(domains, client, gateways, args.dns_workers, log)
            snap["gateways"] = list(gateways)
            sources.append("public DNS")
        if want_tap:
            try:
                api = TapAPI(args.principal, secret, args.timeout, args.qps, args.tap_url)
                log(f"Reading Proofpoint TAP ({api.base}, read-only), last {args.hours} hours")
                from ...cache import Store
                store = Store("proofpoint", enabled=not args.no_cache)
                snap.update(collect(api, log, args.hours, args.people_days, store=store,
                                    siem_reuse_hours=args.siem_reuse_hours, people_max_age=args.people_max_age))
                problem = store.save()
                if problem:
                    print(f"Warning: cache not saved ({problem})", file=sys.stderr)
                if snap.get("siem_hours_reused") or snap.get("people_reused"):
                    notes.append("Reused from earlier runs: " + ", ".join(
                        ([f"{snap['siem_hours_reused']} settled hours of SIEM data (read again after "
                          f"{args.siem_reuse_hours:g} hours)"] if snap.get("siem_hours_reused") else [])
                        + ([f"People API data (refreshed every {args.people_max_age:g} hours)"] if snap.get("people_reused") else [])) + ".")
                snap["domains"], snap["domain_meta"] = domains, dmeta
            except (APIError, ValueError) as e:
                print(f"Error: {e}", file=sys.stderr)
                return EXIT_USAGE
            if snap.get("siem_failed") and not want_dns:
                print(f"Error: TAP could not be read ({(snap.get('errors') or [{}])[0].get('error')})", file=sys.stderr)
                return EXIT_USAGE
            sources.append("TAP " + api.base)
        source = " and ".join(sources)
        if args.save_raw:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=1, ensure_ascii=False)
            log(f"Snapshot saved: {args.save_raw}")
    results, account, _, extra = analyze_snapshot(snap, checks, snap.get("domain_meta") or {})
    if not results:
        print("Error: no mail domain to assess (no MX found and no TAP event)", file=sys.stderr)
        return EXIT_USAGE
    diff = None
    if args.baseline:
        try:
            diff = compute_diff(results, args.baseline)
        except (OSError, ValueError) as e:
            print(f"Warning: baseline not used ({e})", file=sys.stderr)
    meta = {"checks": checks, "source": source, "diff": diff, "notes": notes}
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
    prof = Counter(r.profile for r in results)
    sev = Counter(i.severity for r in results for i in r.issues)
    tot = extra.get("totals") or {}
    print(f"\n{'=' * 60}\nSUMMARY\n{'=' * 60}")
    print(f"Mail domains assessed:    {len(results)}" + (f" ({len(extra['no_mail'])} without MX skipped)" if extra.get("no_mail") else ""))
    print(f"Well protected (>=80):    {sum(r.overall_score >= 80 for r in results)}")
    print(f"Not routed via Proofpoint:{prof['unprotected']:>4}   bypass MX: {prof['bypass']}")
    print(f"Direct delivery to verify:{sum(1 for r in results if any(i.code == 'DIRECT_DELIVERY' for i in r.issues)):>4}")
    if extra.get("tap"):
        print(f"TAP ({(extra.get('window') or {}).get('hours')}h):  {tot.get('malicious', 0)} malicious delivered, "
              f"{tot.get('clicks_permitted', 0)} clicks permitted, {tot.get('blocked_messages', 0)} blocked")
    print(f"Findings:                 {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info")
    for r in [r for r in results if r.priority > 0][:5]:
        first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
        print(f"  {r.domain:<36} score {r.overall_score:>3}  {first.message[:66] if first else ''}")
    print(f"Completed in {time.monotonic() - t0:.1f}s")
    if args.fail_under is not None and any(r.overall_score < args.fail_under for r in results):
        return EXIT_FAIL_UNDER
    return EXIT_OK
