"""Command line: securityhub dns."""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from ...common import EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, Parser
from .analyzer import EmailSecurityAnalyzer
from .baseline import compute_diff
from .constants import (CHECK_ALIASES, CHECKS, CHECK_LABELS, DEFAULT_CHECKS, DEFAULT_DKIM_SELECTORS, TIER_ALIASES, __version__,
                        parse_checks)
from .dmarc_reports import load_dmarc_reports
from .dnsclient import DNSClient, preflight
from .domains import PublicSuffixList, set_psl
from .exports import write_csv, write_json
from .inputs import find_dkim_file, load_config, load_dkim_file, load_domains
from .models import DomainResult
from .rdap import RDAPClient
from .report import generate_html_report
from .views import VIEWS, email_output, view_checks, view_results, views_for

_Parser = Parser


class Progress:
    """Single-line progress bar with ETA on a terminal, one line per domain otherwise."""

    def __init__(self, total: int, quiet: bool = False):
        self.total, self.quiet = total, quiet
        self.done = 0
        self.counts = Counter()
        self.start = time.monotonic()
        self.tty = sys.stderr.isatty()
        self._last = 0.0
        self.width = len(str(total))

    def update(self, r: DomainResult) -> None:
        self.done += 1
        key = "err" if r.error or r.profile == "unreachable" else "ok" if r.overall_score >= 80 else \
            "warn" if r.overall_score >= 50 else "crit"
        self.counts[key] += 1
        if self.quiet:
            return
        if not self.tty:
            tag = {"ok": " OK", "warn": "  !", "crit": "  X", "err": "ERR"}[key]
            print(f"  [{self.done:>{self.width}}/{self.total}] {tag} {r.domain} (score: {r.overall_score})", file=sys.stderr)
            return
        now = time.monotonic()
        if now - self._last < 0.15 and self.done < self.total:
            return
        self._last = now
        elapsed = now - self.start
        eta = elapsed / self.done * (self.total - self.done) if self.done else 0
        filled = int(28 * self.done / self.total)
        bar = "#" * filled + "." * (28 - filled)
        line = (f"\r  [{bar}] {self.done}/{self.total} {100 * self.done // self.total:3d}%  "
                f"ETA {int(eta // 60)}m{int(eta % 60):02d}s  ok {self.counts['ok']}  ! {self.counts['warn']}  "
                f"X {self.counts['crit']}  err {self.counts['err']}   ")
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self) -> None:
        if self.tty and not self.quiet:
            sys.stderr.write("\n")


def print_timing_summary(results: List[DomainResult], top: int = 5) -> None:
    """Where does the time go? Average/max per check and the slowest domains."""
    per_check: Dict[str, List[int]] = {}
    for r in results:
        for name, ms in r.timings.items():
            per_check.setdefault(name, []).append(ms)
    if not per_check:
        return
    print("\nTiming per check (avg / max ms):")
    for name, values in sorted(per_check.items(), key=lambda kv: -sum(kv[1]) / len(kv[1])):
        print(f"  {name:<12} {sum(values) / len(values):8.0f} / {max(values):6d}")
    print("Slowest domains:")
    for r in sorted(results, key=lambda r: -r.duration_ms)[:top]:
        worst = max(r.timings.items(), key=lambda kv: kv[1], default=("-", 0))
        print(f"  {r.domain:<40} {r.duration_ms:7d} ms  (slowest: {worst[0]} {worst[1]} ms)")
    unreachable = sum(1 for r in results if r.profile == "unreachable")
    if unreachable:
        print(f"Unreachable name servers: {unreachable} domain(s) - checks skipped after retries")


COMMANDS = {
    "email": {
        "description": "E-mail security of a domain portfolio via live DNS (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, "
                       "DMARC aggregate reports)",
        "output": "email_report.html",
        "checks": "mx, spf, dkim, dmarc, mta-sts, tls-rpt (= 'all', the default); bimi only on request (all,bimi)",
    },
    "dns": {
        "description": "DNS security of a domain portfolio via live DNS (DNSSEC, CAA, dependency takeover and "
                       "registrations, zone transfer, resolver consistency, lookalike domains)",
        "output": "dns_report.html",
        "checks": "dnssec, caa, takeover (= 'all', the default), plus the opt-in axfr (active zone transfer test), "
                  "consistency and lookalikes ('full' = everything)",
    },
}


def build_parser(command: str = "dns") -> _Parser:
    c = COMMANDS[command]
    parser = _Parser(
        description=c["description"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
    securityhub {command} domains.txt
    securityhub {command} portfolio.csv -o report.html --json --csv
    securityhub {command} domains.txt --baseline previous.json
    securityhub {command} domains.txt --config mailguard.yaml --profile weekly
""" + ("""    securityhub email domains.txt --checks spf,dmarc --dmarc-reports ./rua/
""" if command == "email" else """    securityhub dns domains.txt --checks all,axfr,lookalikes --lookalike-tiers critical,high
""") + f"""
Checks: {c["checks"]}. Combine: --checks all,<check>
Input: a plain list (one domain per line; URLs/e-mails accepted; '#' comments) or CSV with optional
       tier (critical/high/medium/low), owner, bu, tags (separated by |).
Config: JSON or YAML with option names as keys (e.g. checks, workers, nameservers) and optional
        'profiles: {{name: {{...}}}}' selected with --profile. Command-line options override it.
Exit codes: 0 ok, 1 usage/input/resolver error, 2 a domain scored below --fail-under, 130 interrupted.
        """,
    )
    parser.add_argument("input_file", help="Text or CSV file with domains ('-' for stdin)")
    parser.add_argument("-o", "--output", default=c["output"], help=f"Output HTML report (default: {c['output']})")
    if command == "dns":
        # used by 'securityhub run' to assess e-mail and DNS with one scan: also write the e-mail report there
        parser.add_argument("--email-output", help=argparse.SUPPRESS)
        parser.add_argument("--combined", action="store_true",
                            help="One report with every e-mail and DNS check (as before version 4)")
    parser.add_argument("-c", "--checks", default="all",
                        help="Checks to run, comma-separated: " + ",".join(CHECKS) + ", all, full (default: all)")
    parser.add_argument("--skip", default="", help="Checks to exclude, e.g. --skip dkim,tls-rpt")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Per-query DNS/HTTP timeout in seconds (default: 5)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Domains analyzed in parallel (default: 10)")
    parser.add_argument("-j", "--json", action="store_true", help="Also write JSON results")
    parser.add_argument("--csv", action="store_true", help="Also write a CSV summary (';' separated, Excel friendly)")
    parser.add_argument("--nameservers", default="1.1.1.1,8.8.8.8,9.9.9.9",
                        help="Comma-separated resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)")
    parser.add_argument("--system-resolver", action="store_true", help="Use the OS resolver configuration")
    parser.add_argument("--qps", type=float, default=0, help="Max DNS queries per second (0 = unlimited)")
    parser.add_argument("--max-inflight", type=int, default=32,
                        help="Max DNS queries in flight at the same time (default: 32; 0 = no cap)")
    parser.add_argument("--skip-preflight", action="store_true", help="Do not test the resolver before scanning")
    parser.add_argument("--selectors", default="", help="Extra DKIM selectors, comma-separated")
    parser.add_argument("--selectors-file", help="File with extra DKIM selectors (one per line)")
    parser.add_argument("--only-selectors", action="store_true", help="Probe only the selectors you provide")
    parser.add_argument("--dkim-file", metavar="CSV",
                        help="DKIM selectors per domain (domain;selector), probed first and expected to exist. "
                             "Default: dkim.csv next to the domain list or in the current folder ('none' to ignore it)")
    parser.add_argument("--full-dkim", action="store_true",
                        help="Probe every DKIM selector even after a valid key is found (complete audit, ~5x slower)")
    parser.add_argument("--fast-dkim", action="store_true",
                        help="Skip selector probing when _domainkey is NXDOMAIN (RFC 8020; faster on large portfolios)")
    parser.add_argument("--no-http", action="store_true", help="Do not fetch MTA-STS policies over HTTPS")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow MTA-STS fetches to private/loopback addresses (internal assessments only)")
    parser.add_argument("--cache-max-age", type=float, default=24.0,
                        help="Reuse discovery results younger than N hours: full DKIM selector search, RDAP, lookalikes, "
                             "consistency, zone transfer, MTA-STS policy (default: 24; 0 = always redo)")
    parser.add_argument("--no-cache", action="store_true", help="Do not read or write the discovery cache")
    parser.add_argument("--no-rdap", action="store_true", help="Skip RDAP registration lookups (takeover/lookalikes)")
    parser.add_argument("--offline", action="store_true",
                        help="No downloads at all (PSL, RDAP): use cached data or fallbacks")
    parser.add_argument("--psl-file", help="Local copy of public_suffix_list.dat")
    parser.add_argument("--dmarc-reports", action="append", default=[], metavar="PATH",
                        help="DMARC aggregate reports (.xml/.gz/.zip/.eml) - file or folder, repeatable")
    parser.add_argument("--baseline", help="Previous JSON export to compare with")
    parser.add_argument("--lookalike-limit", type=int, default=150, help="Lookalike candidates per domain (default: 150)")
    parser.add_argument("--lookalike-tiers", default="", help="Only check lookalikes for these tiers, e.g. critical,high")
    parser.add_argument("--fail-under", type=int, help="Exit with code 2 if any domain scores below this value")
    parser.add_argument("--config", help="JSON/YAML configuration file")
    parser.add_argument("--profile", help="Profile name inside the configuration file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    parser.add_argument("--version", action="version", version=f"MailGuard DNS {__version__}")
    return parser


def parse_arguments(argv: Optional[List[str]] = None, command: str = "dns") -> argparse.Namespace:
    parser = build_parser(command)
    args = parser.parse_args(argv)
    if args.config:
        try:
            cfg = load_config(args.config, args.profile)
        except (OSError, ValueError) as e:
            parser.error(f"config: {e}")
        known = {a.dest for a in parser._actions}
        unknown = sorted(k for k in cfg if k not in known)
        if unknown:
            print(f"Config: ignoring unknown option(s) {', '.join(unknown)}", file=sys.stderr)
        parser.set_defaults(**{k: v for k, v in cfg.items() if k in known and k not in ("config", "profile")})
        args = parser.parse_args(argv)  # command line wins over the config file
    elif args.profile:
        parser.error("--profile needs --config")
    return args


def main_email(argv: Optional[List[str]] = None) -> int:
    """securityhub email: e-mail checks only, one report."""
    return main(argv, "email")


def main(argv: Optional[List[str]] = None, command: str = "dns") -> int:
    """securityhub dns: DNS checks only, one report (with --email-output: e-mail too, from the same scan)."""
    args = parse_arguments(argv, command)
    parser = build_parser(command)
    email_output_path = getattr(args, "email_output", None)
    combined = getattr(args, "combined", False)
    try:
        checks = parse_checks(args.checks, args.skip)
        if command == "email" or not (email_output_path or combined):
            scope = VIEWS[command]["checks"]
            other = "dns" if command == "email" else "email"
            named = [CHECK_ALIASES.get(t, t) for t in re.split(r"[,\s]+", args.checks.strip().lower()) if t]
            wrong = [t for t in named if t in VIEWS[other]["checks"]]
            if wrong:
                raise ValueError(f"{', '.join(wrong)}: {'e-mail' if other == 'email' else 'DNS'} check(s), "
                                 f"use 'securityhub {other}'")
            checks = [c for c in checks if c in scope]
            if not checks:
                raise ValueError("no checks left to run")
    except ValueError as e:
        parser.error(str(e))

    # Public Suffix List first: everything that computes organizational domains depends on it
    try:
        psl, psl_note = PublicSuffixList.load(args.psl_file, allow_download=not args.offline)
    except (OSError, ValueError) as e:
        parser.error(f"--psl-file: {e}")
    set_psl(psl)
    if psl_note.startswith("WARNING"):
        print(psl_note, file=sys.stderr)

    try:
        inputs, invalid = load_domains(args.input_file)
    except (OSError, ValueError) as e:
        print(f"Error: cannot read '{args.input_file}': {e}", file=sys.stderr)
        return EXIT_USAGE
    if invalid:
        print(f"Skipped {len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: "
              f"{', '.join(invalid[:5])}{' ...' if len(invalid) > 5 else ''}", file=sys.stderr)
    if not inputs:
        print("Error: no valid domains found in input", file=sys.stderr)
        return EXIT_USAGE

    extra = [s.strip() for s in args.selectors.split(",") if s.strip()]
    if args.selectors_file:
        try:
            with open(args.selectors_file, encoding="utf-8") as f:
                extra += [l.split("#", 1)[0].strip() for l in f if l.split("#", 1)[0].strip()]
        except OSError as e:
            print(f"Error: cannot read selectors file '{args.selectors_file}': {e.strerror or e}", file=sys.stderr)
            return EXIT_USAGE
    dkim_file = None if (args.dkim_file or "").lower() == "none" else (args.dkim_file or find_dkim_file(args.input_file))
    domain_selectors: Dict[str, List[str]] = {}
    if dkim_file:
        try:
            domain_selectors, bad = load_dkim_file(dkim_file)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read DKIM selectors file '{dkim_file}': {getattr(e, 'strerror', None) or e}", file=sys.stderr)
            return EXIT_USAGE
        if bad:
            print(f"{dkim_file}: skipped {len(bad)} invalid entr{'y' if len(bad) == 1 else 'ies'}: "
                  f"{', '.join(bad[:5])}{' ...' if len(bad) > 5 else ''}", file=sys.stderr)
        listed = {i.domain for i in inputs}
        unknown = sorted(set(domain_selectors) - listed)
        if unknown:
            print(f"{dkim_file}: {len(unknown)} domain(s) not in the domain list, ignored: "
                  f"{', '.join(unknown[:5])}{' ...' if len(unknown) > 5 else ''}", file=sys.stderr)
        domain_selectors = {d: s for d, s in domain_selectors.items() if d in listed}
    if args.only_selectors and not extra and not domain_selectors:
        parser.error("--only-selectors needs --selectors, --selectors-file or a dkim.csv file")
    selectors = extra if args.only_selectors else DEFAULT_DKIM_SELECTORS + extra
    nameservers = [n.strip() for n in args.nameservers.split(",") if n.strip()]
    workers = max(1, args.workers)

    client = DNSClient(nameservers, args.timeout, args.system_resolver, args.qps, args.max_inflight)
    notes: List[str] = [psl_note]
    if not args.skip_preflight:
        ok, message = preflight(client)
        if not ok:
            print(f"Error: {message}", file=sys.stderr)
            return EXIT_USAGE
        if message.startswith("WARNING"):
            print(message, file=sys.stderr)
            notes.append(message)

    report_data: Dict[str, dict] = {}
    unscanned: List[str] = []
    if args.dmarc_reports:
        try:
            report_data, report_errors, n_reports = load_dmarc_reports(args.dmarc_reports)
        except FileNotFoundError as e:
            print(f"Error: DMARC reports path not found: {e}", file=sys.stderr)
            return EXIT_USAGE
        print(f"DMARC reports: {n_reports} report(s), {len(report_data)} domain(s)"
              + (f", {len(report_errors)} file(s) skipped" if report_errors else ""), file=sys.stderr)
        for err in report_errors[:5]:
            print(f"  skipped {err}", file=sys.stderr)
        scanned = {i.domain for i in inputs}
        unscanned = sorted(d for d in report_data if d not in scanned)
        notes.append(f"DMARC reports: {n_reports} aggregate reports loaded.")

    from ...cache import Store
    store = Store("dns-email", enabled=not args.no_cache and args.cache_max_age > 0)
    rdap = None
    if ("takeover" in checks or "lookalikes" in checks) and not args.no_rdap and not args.offline:
        rdap = RDAPClient(timeout=max(args.timeout, 8.0), store=store if store.enabled else None,
                          max_age_hours=args.cache_max_age)
    lookalike_tiers = {TIER_ALIASES.get(t.strip().lower(), t.strip().lower())
                       for t in args.lookalike_tiers.split(",") if t.strip()} or None

    checks_label = "default set" if checks == DEFAULT_CHECKS else ", ".join(CHECK_LABELS[c] for c in checks)
    dkim_info = (f"; {len(selectors)} DKIM selectors" + (f", own selectors for {len(domain_selectors)} domain(s) from {os.path.basename(dkim_file)}"
                                                          if domain_selectors else "")) if "dkim" in checks else ""
    print(f"Analyzing {len(inputs)} domain(s) via live DNS "
          f"({'system resolver' if args.system_resolver else ', '.join(nameservers)}; "
          f"{workers} workers{dkim_info})\nChecks: {checks_label}", file=sys.stderr)

    t0 = time.monotonic()
    results: List[DomainResult] = []
    interrupted = False
    analyzer = EmailSecurityAnalyzer(timeout=args.timeout, selectors=selectors, fast_dkim=args.fast_dkim, full_dkim=args.full_dkim,
                                     http_checks=not args.no_http, dkim_threads=min(64, workers * 4),
                                     checks=checks, dns_client=client, rdap=rdap, allow_private=args.allow_private,
                                     report_data=report_data, known_domains=[i.domain for i in inputs],
                                     lookalike_limit=args.lookalike_limit, lookalike_tiers=lookalike_tiers,
                                     cache=store if store.enabled else None, discovery_max_age=args.cache_max_age)
    analyzer.extra_selectors = extra
    analyzer.domain_selectors = domain_selectors
    progress = Progress(len(inputs), args.quiet)
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="domain")
    try:
        futures = [executor.submit(analyzer.analyze_domain, item) for item in inputs]
        for fut in as_completed(futures):
            r = fut.result()  # analyze_domain never raises
            results.append(r)
            progress.update(r)
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted - writing a partial report...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        progress.finish()
        executor.shutdown(wait=not interrupted)
        analyzer.close()

    elapsed = time.monotonic() - t0
    st = client.stats
    stats_line = (f"{len(results)} domains in {elapsed:.1f}s, {st['queries']} DNS queries, {st['cache_hits']} cache hits, "
                  f"{st['coalesced']} coalesced, {st['retries']} retries, {st['errors']} DNS errors")
    results.sort(key=lambda x: (-x.priority, x.domain))
    if rdap and rdap.note:
        notes.append(rdap.note)
    if store.enabled and not interrupted:
        problem = store.save()
        if problem:
            print(f"Warning: discovery cache not saved ({problem})", file=sys.stderr)
    reused = {k: v for k, v in store.hits.items() if v}
    if reused:
        names = {"dkim": "DKIM selector search", "rdap": "RDAP registration data", "lookalikes": "lookalike search",
                 "consistency": "name server consistency", "axfr": "zone transfer test", "mta-sts": "MTA-STS policy"}
        notes.append(f"Reused from runs of the last {args.cache_max_age:g} hours (they change slowly; core records "
                     "were queried now): " + ", ".join(f"{names.get(k, k)} {v}" for k, v in sorted(reused.items())) + ".")
        stats_line += ", reused: " + ", ".join(f"{k} {v}" for k, v in sorted(reused.items()))
    base_meta = {"resolver": "System resolver" if args.system_resolver else f"Resolvers: {', '.join(nameservers)}",
                 "stats": stats_line, "notes": notes, "unscanned_report_domains": unscanned}

    # One scan, two reports (e-mail, DNS) unless --combined; a view without selected checks is not written.
    if combined:
        plan = [(None, results, checks, args.output)]
    else:
        names = views_for(checks) if email_output_path else [command]
        plan = [(v, view_results(results, v, checks), view_checks(v, checks),
                 email_output_path if (v == "email" and command == "dns") else args.output)
                for v in names]
    written = []
    try:
        for view, vres, vchecks, path in plan:
            diff = None
            baseline = args.baseline
            if baseline and view == "email" and command == "dns" and os.path.isfile(email_output(baseline)):
                baseline = email_output(baseline)  # e-mail export of the previous run; else the given (older) one
            if baseline:
                try:
                    diff = compute_diff(vres, baseline, view)
                except (OSError, ValueError) as e:
                    print(f"Warning: baseline not used for the {view or 'combined'} report ({e})", file=sys.stderr)
            generate_html_report(vres, path, {**base_meta, "view": view, "checks": vchecks, "diff": diff})
            print(f"Report generated: {path}", file=sys.stderr)
            base = path.rsplit(".", 1)[0]
            if args.json:
                write_json(vres, base + ".json", view)
                print(f"JSON output: {base}.json", file=sys.stderr)
            if args.csv:
                write_csv(vres, base + ".csv", view)
                print(f"CSV output: {base}.csv", file=sys.stderr)
            written.append((view, vres, diff))
    except OSError as e:
        print(f"Error: cannot write output: {e}", file=sys.stderr)
        return EXIT_USAGE

    print(f"\n{'=' * 56}\nSUMMARY{' (partial)' if interrupted else ''}\n{'=' * 56}")
    print(f"Checks:                   {checks_label}")
    print(f"Total domains analyzed:   {len(results)}")
    print(f"Non-mail domains:         {sum(1 for r in results if r.profile == 'non-mail')}")
    for view, vres, diff in written:
        name = {"email": "E-MAIL", "dns": "DNS", None: "E-MAIL AND DNS"}[view]
        print(f"\n{name}")
        print(f"  Fully protected (>=80):   {sum(1 for r in vres if r.overall_score >= 80)}")
        print(f"  Needs attention (50-79):  {sum(1 for r in vres if 50 <= r.overall_score < 80)}")
        print(f"  Critical risk (<50):      {sum(1 for r in vres if r.overall_score < 50)}")
        if diff:
            print(f"  Since baseline:           {diff['improved']} improved, {diff['worsened']} worsened, "
                  f"{diff['new_critical']} new critical findings")
        top = [r for r in vres if r.priority > 0][:5]
        if top:
            print("  Fix first:")
            for r in top:
                first = next((i for i in r.issues if i.severity == "critical"), r.issues[0] if r.issues else None)
                print(f"    {r.domain:<36} score {r.overall_score:>3}  {first.message[:66] if first else ''}")
    print(f"\nStats: {stats_line}")
    print_timing_summary(results)

    if interrupted:
        return EXIT_INTERRUPTED
    if args.fail_under is not None and any(r.overall_score < args.fail_under for _, vres, _ in written for r in vres):
        return EXIT_FAIL_UNDER
    return EXIT_OK
