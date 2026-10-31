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
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .common import EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE
from .console import Progress, Style, fmt_secs, print_posture

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
# max_parallel: 3                        # modules run at the same time (1 = one after the other)
# module_timeout: 3600                   # stop a module after this many seconds (per module: timeout)

modules:
  # E-mail and DNS security of a domain portfolio (needs: pip install dnspython)
  dns:
    enabled: true
    # timeout: 7200                      # large portfolios with lookalikes can take long
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
    log: str = ""
    timed_out: bool = False


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


PKG_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_echo_lock = threading.Lock()


def run_module(name: str, argv: List[str], out_html: str, log_path: str, timeout: Optional[float] = None,
               echo: Optional[Callable[[str], None]] = None, procs: Optional[Dict[str, subprocess.Popen]] = None,
               cmd: Optional[List[str]] = None) -> ModuleResult:
    """Run one module in its own Python process; its output goes to `log_path` (and to `echo`, if given).

    A separate process isolates the modules (state, crashes, memory), lets them run in parallel
    and can be stopped when it exceeds `timeout` seconds.
    """
    t0 = time.monotonic()
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    env["PYTHONPATH"] = PKG_PARENT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = cmd or [sys.executable, "-m", "securityhub", name] + argv
    timed_out = False
    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"$ securityhub {name} {' '.join(argv)}\n")
        log.flush()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1)
        except OSError as e:
            return ModuleResult(name, EXIT_USAGE, time.monotonic() - t0, error=f"cannot start: {e}", argv=argv, log=log_path)
        if procs is not None:
            procs[name] = proc

        def pump():
            for line in proc.stdout:
                log.write(line)
                if echo:
                    echo(f"[{name}] {line.rstrip()}")
        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        try:
            code = proc.wait(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            code = EXIT_USAGE
        reader.join(timeout=5)
        if procs is not None:
            procs.pop(name, None)
    seconds = time.monotonic() - t0
    if timed_out:
        return ModuleResult(name, code, seconds, None, f"timed out after {fmt_secs(timeout)}", argv, log_path, True)
    if code < 0 or code == EXIT_INTERRUPTED:  # killed by a signal / interrupted
        code = EXIT_INTERRUPTED
    report = out_html if os.path.isfile(out_html) else None
    error = "" if report else "no report produced"
    return ModuleResult(name, code, seconds, report, error, argv, log_path)


def _tail(path: str, n: int = 12) -> List[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [line.rstrip() for line in f.readlines()[-n:]]
    except OSError:
        return []


def run(config_path: str, only: Optional[List[str]] = None, dry_run: bool = False, quiet: bool = False,
        output_dir: Optional[str] = None, now: Optional[datetime] = None, verbose: bool = False,
        max_parallel: Optional[int] = None, timeout: Optional[float] = None,
        log: Optional[Callable[[str], None]] = None) -> int:
    err = Style(sys.stderr)
    say = log or (lambda m: print(m, file=sys.stderr))
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
    try:
        raw = max_parallel if max_parallel is not None else cfg.get("max_parallel")
        parallel = len(selected) if raw is None else int(raw)
    except (TypeError, ValueError):
        raise ConfigError("max_parallel must be a number")
    if parallel < 1:
        raise ConfigError("max_parallel must be 1 or more")
    default_timeout = timeout if timeout is not None else cfg.get("module_timeout")

    previous = list_runs(out_dir)
    when = now or datetime.now(timezone.utc)
    stamp = when.strftime(RUN_FORMAT)
    while os.path.exists(os.path.join(out_dir, RUNS_DIR, stamp)):  # two runs in the same second
        when += timedelta(seconds=1)
        stamp = when.strftime(RUN_FORMAT)
    run_dir = os.path.join(out_dir, RUNS_DIR, stamp)
    plans = []
    for name in selected:
        spec = mods[name] or {}
        out_html = os.path.join(run_dir, f"{name}.html")
        baseline = previous_export(previous, name) if auto_baseline else None
        t = spec.get("timeout", default_timeout)
        try:
            t = float(t) if t not in (None, "", 0) else None
        except (TypeError, ValueError):
            raise ConfigError(f"{name}: timeout must be a number of seconds")
        plans.append((name, out_html, module_argv(name, spec, base_dir, out_html, baseline, fail_under), t))

    if dry_run:
        for name, _, argv, t in plans:  # no secrets: they are rejected from the configuration
            print(f"securityhub {name} {' '.join(argv)}" + (f"    # timeout {fmt_secs(t)}" if t else ""))
        return EXIT_OK

    os.makedirs(run_dir, exist_ok=True)
    if not quiet:
        say(err("Security Hub", "bold") + f" run {stamp}  {err.dot}  {len(plans)} module{'s' if len(plans) != 1 else ''}"
            + (f", up to {min(parallel, len(plans))} in parallel" if parallel > 1 and len(plans) > 1 else "")
            + f"  {err.dot}  {err(run_dir, 'dim')}")
    labels = {n: MODULES[n][2] for n, *_ in plans}
    progress = Progress([n for n, *_ in plans], labels, sys.stderr, enabled=not quiet, live=False if verbose else None)

    def echo(line: str) -> None:
        with _echo_lock:
            print(err(line, "dim"), file=sys.stderr, flush=True)

    procs: Dict[str, subprocess.Popen] = {}
    results: Dict[str, ModuleResult] = {}

    def job(name, out_html, argv, t):
        progress.start(name)
        r = run_module(name, argv, out_html, os.path.join(run_dir, f"{name}.log"), t, echo if verbose else None, procs)
        status = ("timeout" if r.timed_out else "interrupted" if r.code == EXIT_INTERRUPTED else
                  "failed" if r.error or r.code not in (EXIT_OK, EXIT_FAIL_UNDER) else "below" if r.code == EXIT_FAIL_UNDER else "ok")
        progress.finish(name, status, r.error)
        return r

    pool = ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="module")
    try:
        with progress:
            futures = {pool.submit(job, *plan): plan[0] for plan in plans}
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()
    except KeyboardInterrupt:
        for p in list(procs.values()):
            with contextlib.suppress(OSError):
                p.terminate()
        pool.shutdown(wait=False, cancel_futures=True)
        say(err("Interrupted.", "red"))
        return EXIT_INTERRUPTED
    finally:
        pool.shutdown(wait=True)
    ordered = [results[n] for n, *_ in plans if n in results]

    for r in ordered:  # show why a module failed, from its log
        if r.error or r.code not in (EXIT_OK, EXIT_FAIL_UNDER):
            say("\n" + err(f"{labels[r.name]}: {r.error or f'exit code {r.code}'}", "red", "bold") + err(f"  (log: {r.log})", "dim"))
            for line in _tail(r.log):
                say("  " + err(line, "dim"))

    if not any(r.report for r in ordered):
        shutil.rmtree(run_dir, ignore_errors=True)
        say(err("Error: no module produced a report; the portal was not updated.", "red"))
        return EXIT_USAGE

    removed = prune_runs(out_dir, int(cfg.get("keep_runs", 12) or 0))
    if removed and not quiet:
        say(err(f"Removed {len(removed)} old run{'s' if len(removed) != 1 else ''} (keep_runs={cfg.get('keep_runs')})", "dim"))
    from . import portal
    reports, history = portal.collect(list_runs(out_dir))
    hub = os.path.join(out_dir, "security_hub.html")
    portal.build_hub(reports, hub, str(cfg.get("title") or ""), history)
    summary = portal.posture(reports, history)
    summary["run"] = {"id": stamp, "folder": run_dir, "max_parallel": parallel,
                      "modules": [{"module": r.name, "exit_code": r.code, "seconds": round(r.seconds, 1), "report": r.report,
                                   "log": r.log, "timed_out": r.timed_out, "error": r.error} for r in ordered]}
    posture_file = os.path.join(out_dir, "posture.json")
    with open(posture_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print_posture(summary)
    out = Style(sys.stdout)
    print(f"\n{out('Portal ', 'bold')}  {out.link(hub)}\n{out('Summary', 'bold')}  {out.link(posture_file)}\n"
          f"{out('Logs   ', 'bold')}  {out.link(run_dir)}")

    if any(r.code == EXIT_INTERRUPTED for r in ordered):
        return EXIT_INTERRUPTED
    if any(r.code not in (EXIT_OK, EXIT_FAIL_UNDER) or r.error for r in ordered):
        return EXIT_USAGE
    if any(r.code == EXIT_FAIL_UNDER for r in ordered):
        return EXIT_FAIL_UNDER
    if fail_under is not None and summary.get("overall_score") is not None and summary["overall_score"] < fail_under:
        return EXIT_FAIL_UNDER
    return EXIT_OK


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
