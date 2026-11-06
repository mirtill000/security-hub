"""`securityhub` command line: one entry point for every module.

    securityhub run      [-c securityhub.yaml]    run every enabled module, update portal + posture.json
    securityhub status   <output_dir|reports...>  print the current posture (or --json)
    securityhub doctor   [-c securityhub.yaml]    check credentials, APIs and inputs of every module (read-only)
    securityhub init     [securityhub.yaml]       write an example configuration
    securityhub email    <domains> [options]      e-mail security: MX, SPF, DKIM, DMARC... (MailGuard)
    securityhub dns      <domains> [options]      DNS security: DNSSEC, CAA, takeover, AXFR... (MailGuard)
    securityhub waf      --account-id N [options] Imperva Cloud WAF posture (WAFGuard)
    securityhub edr      [options]                SentinelOne EDR posture (EDRGuard)
    securityhub proofpoint --domains F [options]  Proofpoint email protection: routing, TAP threats, clicks (PPGuard)
    securityhub sap-ias  [options]                SAP Cloud Identity Services identities (IASGuard)
    securityhub pra      [options]                BeyondTrust Privileged Remote Access posture (PRAGuard)
    securityhub zta      <report folder> [opts]   Microsoft Zero Trust Assessment (ZTAGuard)
    securityhub portal   <reports...> [options]   combine reports into one portal (GuardHub)

`securityhub <module> --help` shows the options of each module.
Exit codes (every command): 0 ok, 1 usage / input / API error, 2 score below --fail-under, 130 interrupted;
'status --fail-stale': 3 when the data of an area is older than its limit.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import List, Optional

from . import __version__
from .common import EXIT_OK, EXIT_USAGE, Parser

# command -> (module, entry point, description)
TOOLS = {
    "email": ("securityhub.scanners.dns_email", "main_email", "E-mail security of a domain portfolio: MX, SPF, DKIM, DMARC... (MailGuard)"),
    "dns": ("securityhub.scanners.dns_email", "main", "DNS security of a domain portfolio: DNSSEC, CAA, takeover, AXFR... (MailGuard)"),
    "waf": ("securityhub.scanners.waf", "main", "Imperva Cloud WAF configuration assessment (WAFGuard)"),
    "edr": ("securityhub.scanners.edr", "main", "SentinelOne EDR posture: agents, policies, threats, exclusions (EDRGuard)"),
    "proofpoint": ("securityhub.scanners.proofpoint", "main", "Proofpoint email protection: MX routing, TAP threats, clicks, people (PPGuard)"),
    "pra": ("securityhub.scanners.pra", "main", "BeyondTrust PRA: MFA, vendors, asset policies and recording, API accounts, vault (PRAGuard)"),
    "sap-ias": ("securityhub.scanners.sap_ias", "main", "SAP Cloud Identity Services: sign-in method, MFA, passwords, inactive accounts (IASGuard)"),
    "zta": ("securityhub.scanners.zero_trust", "main", "Microsoft Zero Trust Assessment report (ZTAGuard)"),
    "portal": ("securityhub.portal", "main", "Combine reports into one navigable portal (GuardHub)"),
}
ALIASES = {"mail": "email", "e-mail": "email", "zt": "zta", "zerotrust": "zta", "hub": "portal",
           "sentinelone": "edr", "s1": "edr", "pp": "proofpoint", "tap": "proofpoint", "ias": "sap-ias", "beyondtrust": "pra", "bt-pra": "pra"}
DEFAULT_CONFIG = "securityhub.yaml"


def _usage() -> str:
    lines = [f"Security Hub {__version__} - security posture monitoring for e-mail, DNS, WAF, EDR, Proofpoint, SAP identity, privileged access and Zero Trust", "",
             "usage: securityhub <command> [options]", "", "Commands:",
             "  run        Run the enabled modules from a configuration file, update the portal and posture.json",
             "  status     Print the current posture from an output folder or from reports",
             "  doctor     Check credentials, API access and inputs of every configured module (read-only)",
             "  init       Write an example configuration file"]
    lines += [f"  {k:<10} {v[2]}" for k, v in TOOLS.items()]
    lines += ["", "Run 'securityhub <command> --help' for the options of a command."]
    return "\n".join(lines)


def _run_cmd(argv: List[str]) -> int:
    from . import orchestrator
    p = Parser(prog="securityhub run", description="Run every enabled module (in parallel, each in its own process with a log), "
                                                   "then rebuild the portal and posture.json")
    p.add_argument("modules", nargs="*", metavar="MODULE",
                   help="Only these modules (e.g. 'securityhub run pra'): the portal is rebuilt with their new reports "
                        "and the latest reports of every other area")
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help=f"Configuration file (default: {DEFAULT_CONFIG})")
    p.add_argument("--only", default="", help="Only these modules, comma-separated (e.g. dns,waf,ias)")
    p.add_argument("-o", "--output-dir", help="Override output_dir of the configuration")
    p.add_argument("--dry-run", action="store_true", help="Show the commands that would run, without running them")
    p.add_argument("-q", "--quiet", action="store_true", help="No progress, only the posture (and why a module failed)")
    p.add_argument("-v", "--verbose", action="store_true", help="Also stream the output of every module, prefixed by its name")
    p.add_argument("-p", "--max-parallel", type=int, metavar="N", help="Modules run at the same time (default: all; 1 = one after the other)")
    p.add_argument("--timeout", type=float, metavar="SECONDS", help="Stop a module that runs longer than this (default: module_timeout)")
    a = p.parse_args(argv)
    if not os.path.isfile(a.config):
        print(f"Error: configuration not found: {a.config} (create one with 'securityhub init')", file=sys.stderr)
        return EXIT_USAGE
    only = [m.strip() for m in a.only.split(",") + [x for v in a.modules for x in v.split(",")] if m.strip()] or None
    try:
        return orchestrator.run(a.config, only=[ALIASES.get(m, m) for m in only] if only else None,
                                dry_run=a.dry_run, quiet=a.quiet, output_dir=a.output_dir, verbose=a.verbose and not a.quiet,
                                max_parallel=a.max_parallel, timeout=a.timeout)
    except (orchestrator.ConfigError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE


def _status_cmd(argv: List[str]) -> int:
    from . import orchestrator
    p = Parser(prog="securityhub status", description="Print the security posture from an output folder or reports")
    p.add_argument("inputs", nargs="*", default=["reports"], help="Output folder of 'run', report folders or HTML reports")
    p.add_argument("--json", action="store_true", help="Print the posture as JSON")
    p.add_argument("--json-out", metavar="FILE", help="Also write the posture JSON to this file")
    p.add_argument("--max-age", default="", metavar="AREA=DAYS,...", help="Stale data limits (default: dns=2,waf=2,zta=35)")
    p.add_argument("--fail-stale", action="store_true", help="Exit with code 3 if the data of an area is stale (for monitoring)")
    a = p.parse_args(argv)
    try:
        return orchestrator.status(a.inputs, a.json_out, a.json, a.max_age, a.fail_stale)
    except FileNotFoundError as e:
        print(f"Error: not found: {e}", file=sys.stderr)
        return EXIT_USAGE


def _init_cmd(argv: List[str]) -> int:
    from . import orchestrator
    p = Parser(prog="securityhub init", description="Write an example configuration file")
    p.add_argument("path", nargs="?", default=DEFAULT_CONFIG)
    p.add_argument("--force", action="store_true", help="Overwrite an existing file")
    a = p.parse_args(argv)
    if os.path.exists(a.path) and not a.force:
        print(f"Error: {a.path} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_USAGE
    with open(a.path, "w", encoding="utf-8") as f:
        f.write(orchestrator.EXAMPLE_CONFIG)
    print(f"Configuration written: {a.path}\nEdit it, then run: securityhub run -c {a.path}")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage())
        return EXIT_OK if argv else EXIT_USAGE
    if argv[0] == "--version":
        print(f"Security Hub {__version__}")
        return EXIT_OK
    cmd, rest = ALIASES.get(argv[0], argv[0]), argv[1:]
    if cmd == "run":
        return _run_cmd(rest)
    if cmd == "status":
        return _status_cmd(rest)
    if cmd == "init":
        return _init_cmd(rest)
    if cmd == "doctor":
        from . import doctor
        return doctor.main(rest)
    if cmd not in TOOLS:
        print(f"securityhub: unknown command '{argv[0]}'\n\n{_usage()}", file=sys.stderr)
        return EXIT_USAGE
    try:
        mod = importlib.import_module(TOOLS[cmd][0])
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    _set_prog(mod, f"securityhub {cmd}")
    try:
        return getattr(mod, TOOLS[cmd][1])(rest)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else EXIT_USAGE


def _set_prog(mod, prog: str) -> None:
    """Show 'securityhub <cmd>' instead of the module file name in usage messages."""
    targets = [mod] + [m for m in (getattr(mod, "cli", None),) if m is not None]
    for target in targets:
        build = getattr(target, "build_parser", None)
        if build is None:
            continue
        original = getattr(build, "_hub_original", build)

        def wrapped(*a, _orig=original, **k):
            parser = _orig(*a, **k)
            parser.prog = prog
            return parser
        wrapped._hub_original = original
        target.build_parser = wrapped


if __name__ == "__main__":
    sys.exit(main())
