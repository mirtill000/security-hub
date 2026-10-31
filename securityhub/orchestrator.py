"""Orchestrator: one command that assesses WAF, DNS/e-mail and Zero Trust and updates the hub.

`securityhub run` reads a configuration file, runs every enabled module into a dated run
folder, feeds each module the previous run as baseline (so reports show what changed),
rebuilds the portal from every run kept (latest run embedded, older runs become KPI trends)
and writes a machine-readable posture summary for monitoring.

Layout of the output directory:

    <output_dir>/
      runs/2026-10-31T0800Z/dns.html  dns.json  dns.csv
                            waf.html  waf.json  waf.csv
                            zta.html  zta.json  zta.csv
      security_hub.html     <- portal (open this)
      posture.json          <- summary for SIEM / dashboards / CI gates
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import os
import shutil
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .common import EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE

# name -> (module, positional argument fed from `input`, human label)
MODULES: Dict[str, Tuple[str, Optional[str], str]] = {
    "dns": ("securityhub.scanners.dns_email", "input_file", "DNS / e-mail security (MailGuard DNS)"),
    "waf": ("securityhub.scanners.waf", None, "Imperva Cloud WAF (WAFGuard)"),
    "zta": ("securityhub.scanners.zero_trust", "input", "Microsoft Zero Trust (ZTAGuard)"),
}
ORDER = list(MODULES)
RUNS_DIR = "runs"
RUN_FORMAT = "%Y-%m-%dT%H%M%SZ"

# Options the orchestrator manages itself: setting them in the configuration is an error.
RESERVED = {"output", "version", "help"}
# Secrets never belong in a configuration file: use the environment or a key file.
FORBIDDEN = {"api_key": "use the IMPERVA_API_KEY environment variable or api_key_file"}
# Option values that are paths: resolved relative to the configuration file.
PATH_OPTIONS = {"input", "input_file", "metadata", "from_json", "save_raw", "api_key_file", "selectors_file",
                "psl_file", "dmarc_reports", "baseline", "config"}

EXAMPLE_CONFIG = """\
# Security Hub - configuration for `securityhub run`
# Relative paths are resolved from the folder of this file.

title: "Contoso - Security posture"      # shown in the portal
output_dir: reports                      # runs, portal and posture summary go here
keep_runs: 12                            # older run folders are deleted (0 = keep all)
# fail_under: 70                         # exit code 2 if an area / asset scores below this
# auto_baseline: true                    # compare every module with its previous run

modules:
  # E-mail and DNS security of a domain portfolio (needs: pip install dnspython)
  dns:
    enabled: true
    input: domains.csv                   # text (one domain per line) or CSV with tier/owner/bu/tags
    options:
      checks: all,takeover               # add lookalikes,consistency for deeper (slower) scans
      csv: true
      # dmarc_reports: [./rua]           # DMARC aggregate reports (.xml/.gz/.zip/.eml)
      # nameservers: [1.1.1.1, 8.8.8.8]
      # qps: 50

  # Imperva Cloud WAF configuration (read-only API calls)
  # Credentials: export IMPERVA_API_ID=... IMPERVA_API_KEY=...  (never in this file)
  waf:
    enabled: false
    options:
      account_id: 1234567
      include_subaccounts: true
      probe: true                        # DNS routing, TLS and origin exposure checks
      csv: true
      # metadata: sites.csv              # tier/owner/bu/tags/max_rps per website
      # from_json: snapshot.json         # offline: analyze a saved snapshot instead of the API

  # Microsoft Zero Trust Assessment (run Invoke-ZtAssessment first, then point to its folder)
  zta:
    enabled: false
    input: ./ZeroTrustReport             # report folder, ZeroTrustAssessmentReport.json or HTML
    options:
      csv: true
"""


class ConfigError(ValueError):
    pass


@dataclass
class ModuleResult:
    name: str
    code: int
    seconds: float
    report: Optional[str] = None
    error: str = ""
    argv: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ConfigError("YAML configuration needs PyYAML (pip install pyyaml) - or use a .json file")
        cfg = yaml.safe_load(text) or {}
    else:
        try:
            cfg = json.loads(text)
        except ValueError as e:
            raise ConfigError(f"invalid JSON: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError("the configuration must be a mapping")
    mods = cfg.get("modules") or {}
    if not isinstance(mods, dict):
        raise ConfigError("'modules' must be a mapping of dns / waf / zta")
    unknown = set(mods) - set(MODULES)
    if unknown:
        raise ConfigError(f"unknown module(s): {', '.join(sorted(unknown))} (available: {', '.join(ORDER)})")
    return cfg


def _resolve(base_dir: str, value: Any) -> Any:
    if isinstance(value, list):
        return [_resolve(base_dir, v) for v in value]
    if isinstance(value, str) and value and value != "-":
        return os.path.normpath(os.path.join(base_dir, os.path.expanduser(value)))
    return value


def options_to_argv(parser: argparse.ArgumentParser, options: Dict[str, Any]) -> List[str]:
    """Translate {option: value} into command-line arguments, using the module's own parser.

    true/false toggles flags, lists become repeated options (for options that can be given
    several times) or comma-separated values, everything else is passed as text.
    """
    actions = {a.dest: a for a in parser._actions if a.option_strings}
    argv: List[str] = []
    for key, value in options.items():
        dest = str(key).replace("-", "_")
        if dest in FORBIDDEN:
            raise ConfigError(f"option '{key}' is not allowed in the configuration: {FORBIDDEN[dest]}")
        if dest in RESERVED:
            raise ConfigError(f"option '{key}' is managed by the hub")
        action = actions.get(dest)
        if action is None:
            known = ", ".join(sorted(d for d, a in actions.items() if a.help != argparse.SUPPRESS and d not in RESERVED))
            raise ConfigError(f"unknown option '{key}' (known: {known})")
        flag = max(action.option_strings, key=len)
        if value is None or value is False:
            continue
        if isinstance(action, (argparse._StoreTrueAction, argparse._StoreConstAction)):
            if value is not True:
                raise ConfigError(f"option '{key}' is a switch: use true or false")
            argv.append(flag)
        elif isinstance(action, argparse._AppendAction):
            for v in value if isinstance(value, list) else [value]:
                argv += [flag, str(v)]
        else:
            argv += [flag, ",".join(str(v) for v in value) if isinstance(value, list) else str(value)]
    return argv


def module_argv(name: str, spec: dict, base_dir: str, out_html: str, baseline: Optional[str],
                fail_under: Optional[int]) -> List[str]:
    mod = importlib.import_module(MODULES[name][0])
    parser = mod.build_parser()
    options = dict(spec.get("options") or {})
    if not isinstance(options, dict):
        raise ConfigError(f"{name}: 'options' must be a mapping")
    options = {k: (_resolve(base_dir, v) if str(k).replace("-", "_") in PATH_OPTIONS else v) for k, v in options.items()}
    options.setdefault("json", True)  # the JSON export is the baseline of the next run
    if baseline and not options.get("baseline"):
        options["baseline"] = baseline
    if fail_under is not None and options.get("fail_under") is None:
        options["fail_under"] = fail_under
    argv: List[str] = []
    positional = MODULES[name][1]
    if positional:
        if not spec.get("input"):
            raise ConfigError(f"{name}: 'input' is required")
        argv.append(_resolve(base_dir, spec["input"]))
    elif spec.get("input"):
        raise ConfigError(f"{name}: this module takes no 'input' (use options)")
    return argv + ["-o", out_html] + options_to_argv(parser, options)


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

def list_runs(output_dir: str) -> List[str]:
    root = os.path.join(output_dir, RUNS_DIR)
    if not os.path.isdir(root):
        return []
    out = []
    for n in sorted(os.listdir(root)):
        try:
            datetime.strptime(n, RUN_FORMAT)
        except ValueError:
            continue
        if os.path.isdir(os.path.join(root, n)):
            out.append(os.path.join(root, n))
    return out


def previous_export(runs: List[str], name: str) -> Optional[str]:
    for run in reversed(runs):
        p = os.path.join(run, f"{name}.json")
        if os.path.isfile(p):
            return p
    return None


def prune_runs(output_dir: str, keep: int) -> List[str]:
    if keep <= 0:
        return []
    runs = list_runs(output_dir)
    removed = runs[:-keep] if len(runs) > keep else []
    for r in removed:
        shutil.rmtree(r, ignore_errors=True)
    return removed


def run_module(name: str, argv: List[str], out_html: str, quiet: bool) -> ModuleResult:
    t0 = time.monotonic()
    captured = io.StringIO()
    error = ""
    with contextlib.ExitStack() as stack:
        if quiet:  # keep the module output, show it only if the module fails
            stack.enter_context(contextlib.redirect_stdout(captured))
            stack.enter_context(contextlib.redirect_stderr(captured))
        try:
            mod = importlib.import_module(MODULES[name][0])
            code = mod.main(argv)
        except KeyboardInterrupt:
            raise
        except SystemExit as e:  # argparse errors / --version
            code = e.code if isinstance(e.code, int) else EXIT_USAGE
        except ImportError as e:
            code, error = EXIT_USAGE, str(e)
        except Exception as e:  # one module must never stop the others
            traceback.print_exc()
            code, error = EXIT_USAGE, f"{type(e).__name__}: {e}"
    code = code if isinstance(code, int) else EXIT_OK
    report = out_html if os.path.isfile(out_html) and not error else None
    if not report and not error:
        error = "no report produced"
    if quiet and (error or code not in (EXIT_OK, EXIT_FAIL_UNDER)):
        tail = captured.getvalue().strip().splitlines()[-15:]
        if tail:
            print("\n".join(tail), file=sys.stderr)
    return ModuleResult(name, code, time.monotonic() - t0, report, error, argv)


def run(config_path: str, only: Optional[List[str]] = None, dry_run: bool = False, quiet: bool = False,
        output_dir: Optional[str] = None, now: Optional[datetime] = None,
        log: Callable[[str], None] = lambda m: print(m, file=sys.stderr)) -> int:
    cfg = load_config(config_path)
    base_dir = os.path.dirname(os.path.abspath(config_path))
    out_dir = _resolve(base_dir, output_dir or cfg.get("output_dir") or "reports")
    fail_under = cfg.get("fail_under")
    auto_baseline = cfg.get("auto_baseline", True)
    mods = cfg.get("modules") or {}
    selected = [m for m in ORDER if m in mods and (mods[m] or {}).get("enabled", True)]
    if only:
        bad = set(only) - set(ORDER)
        if bad:
            raise ConfigError(f"unknown module(s) in --only: {', '.join(sorted(bad))}")
        selected = [m for m in ORDER if m in only and m in mods]
        missing = set(only) - set(selected)
        if missing:
            raise ConfigError(f"not configured: {', '.join(sorted(missing))}")
    if not selected:
        raise ConfigError("no module enabled in the configuration")

    previous = list_runs(out_dir)
    when = now or datetime.now(timezone.utc)
    stamp = when.strftime(RUN_FORMAT)
    while os.path.exists(os.path.join(out_dir, RUNS_DIR, stamp)):  # two runs in the same second
        when += timedelta(seconds=1)
        stamp = when.strftime(RUN_FORMAT)
    run_dir = os.path.join(out_dir, RUNS_DIR, stamp)
    plans = []
    for name in selected:
        out_html = os.path.join(run_dir, f"{name}.html")
        baseline = previous_export(previous, name) if auto_baseline else None
        plans.append((name, out_html, module_argv(name, mods[name] or {}, base_dir, out_html, baseline, fail_under)))

    if dry_run:
        for name, _, argv in plans:
            print(f"securityhub {name} {' '.join(argv)}")  # no secrets: they are rejected from the config
        return EXIT_OK

    os.makedirs(run_dir, exist_ok=True)
    results: List[ModuleResult] = []
    for name, out_html, argv in plans:
        log(f"\n=== {MODULES[name][2]} ===")
        try:
            results.append(run_module(name, argv, out_html, quiet))
        except KeyboardInterrupt:
            log("Interrupted.")
            return EXIT_INTERRUPTED
        r = results[-1]
        log(f"--- {name}: exit {r.code} in {r.seconds:.0f}s" + (f" ({r.error})" if r.error else ""))

    if not any(r.report for r in results):
        shutil.rmtree(run_dir, ignore_errors=True)
        log("Error: no module produced a report; the portal was not updated.")
        return EXIT_USAGE

    removed = prune_runs(out_dir, int(cfg.get("keep_runs", 12) or 0))
    if removed:
        log(f"Removed {len(removed)} old run(s) (keep_runs={cfg.get('keep_runs')})")
    from . import portal
    reports, history = portal.collect(list_runs(out_dir))
    hub = os.path.join(out_dir, "security_hub.html")
    portal.build_hub(reports, hub, str(cfg.get("title") or ""), history)
    summary = portal.posture(reports, history)
    summary["run"] = {"id": stamp, "folder": run_dir,
                      "modules": [{"module": r.name, "exit_code": r.code, "seconds": round(r.seconds, 1),
                                   "report": r.report, "error": r.error} for r in results]}
    with open(os.path.join(out_dir, "posture.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print_posture(summary)
    print(f"\nPortal:  {hub}\nSummary: {os.path.join(out_dir, 'posture.json')}")

    if any(r.code == EXIT_INTERRUPTED for r in results):
        return EXIT_INTERRUPTED
    if any(r.code not in (EXIT_OK, EXIT_FAIL_UNDER) or r.error for r in results):
        return EXIT_USAGE
    if any(r.code == EXIT_FAIL_UNDER for r in results):
        return EXIT_FAIL_UNDER
    if fail_under is not None and summary.get("overall_score") is not None and summary["overall_score"] < fail_under:
        return EXIT_FAIL_UNDER
    return EXIT_OK


# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

STATUS_TEXT = {"good": "OK", "warn": "ATTENTION", "bad": "AT RISK", "unknown": "n/a", None: "n/a"}


def print_posture(summary: dict, file=None) -> None:
    out = file or sys.stdout
    overall = summary.get("overall_score")
    print(f"\n{'=' * 64}\nSECURITY POSTURE  {summary.get('overall_grade', '-')}"
          f"{f'  ({overall}/100)' if overall is not None else ''}\n{'=' * 64}", file=out)
    print(summary.get("summary", ""), file=out)
    for a in summary.get("areas", []):
        score = "" if a.get("score") is None else f"{a['score']:>3}"
        print(f"  {a['label']:<24} {a.get('grade') or '-':>2} {score:>4}  {STATUS_TEXT.get(a.get('status'), a.get('status')):<10} "
              f"{a.get('date', '')[:10]}  {a.get('headline') or ''}", file=out)
        for k in a.get("kpis", []):
            if k.get("value") is not None:
                print(f"      - {k['label']}: {k['value']}{'%' if k.get('unit') == '%' else k.get('unit') or ''}", file=out)
    acts = summary.get("actions", [])
    if acts:
        print("Top actions:", file=out)
        for a in acts[:5]:
            print(f"  [{a.get('severity', ''):<8}] {a.get('label', ''):<24} {a.get('title', '')}", file=out)


def status(inputs: List[str], json_out: Optional[str] = None, as_json: bool = False) -> int:
    from . import portal
    expanded = []
    for p in inputs:
        runs = list_runs(p) if os.path.isdir(p) else []
        expanded += runs or [p]  # an output_dir: read its runs (the portal file itself is skipped)
    reports, history = portal.collect(expanded)
    if not reports:
        print("Error: no reports found", file=sys.stderr)
        return EXIT_USAGE
    summary = portal.posture(reports, history)
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    if as_json:
        json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print_posture(summary)
    return EXIT_OK
