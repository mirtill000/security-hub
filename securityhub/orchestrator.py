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

from .common import EXIT_FAIL_UNDER, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, LockBusy, RunLock, atomic_write
from .console import Progress, Style, fmt_secs, print_posture

# name -> (module, positional argument fed from `input`, human label)
MODULES: Dict[str, Tuple[str, Optional[str], str]] = {
    "email": ("securityhub.scanners.dns_email", "input_file", "E-mail security (MailGuard)"),
    "dns": ("securityhub.scanners.dns_email", "input_file", "DNS security (MailGuard)"),
    "proofpoint": ("securityhub.scanners.proofpoint", None, "Proofpoint email protection (PPGuard)"),
    "waf": ("securityhub.scanners.waf", None, "Imperva Cloud WAF (WAFGuard)"),
    "edr": ("securityhub.scanners.edr", None, "SentinelOne EDR (EDRGuard)"),
    "zta": ("securityhub.scanners.zero_trust", "input", "Microsoft Zero Trust (ZTAGuard)"),
}
ORDER = list(MODULES)
MAILGUARD = ("email", "dns")
# Modules that generate a lot of network traffic (DNS queries, Internet probes): at most max_parallel_network
# of them run at the same time (default 1), so their peaks never add up. The others (API reads of a few
# hundred requests) keep running in parallel with them.
NETWORK_HEAVY = {"email", "dns", "proofpoint", "waf"}  # same scanner: one scan can produce both reports
RUNS_DIR = "runs"
RUN_FORMAT = "%Y-%m-%dT%H%M%SZ"

# Options the orchestrator manages itself: setting them in the configuration is an error.
RESERVED = {"output", "version", "help"}
# Secrets never belong in a configuration file: use the environment or a key file.
FORBIDDEN = {"api_key": "use the IMPERVA_API_KEY environment variable or api_key_file",
             "api_token": "use the S1_API_TOKEN environment variable or api_token_file",
             "secret": "use the PROOFPOINT_SECRET environment variable or secret_file"}
# Option values that are paths: resolved relative to the configuration file.
PATH_OPTIONS = {"input", "input_file", "metadata", "from_json", "save_raw", "api_key_file", "api_token_file", "inventory",
                "domains", "secret_file", "cache_file",
                "selectors_file",
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
# max_parallel_network: 1                # of which DNS / Internet-probing ones (email+dns, proofpoint, waf): default 1
# max_age_days: {email: 2, dns: 2, proofpoint: 2, waf: 2, edr: 2, zta: 35}  # data older than this is flagged as stale in portal and summary
# publish: /var/www/html/securityhub     # after each run copy the portal there as index.html (web server)
#   or: publish: {dir: /var/www/html/securityhub, posture: true, mode: "0640"}
# module_timeout: 3600                   # stop a module after this many seconds (per module: timeout)

modules:
  # E-mail and DNS security of a domain portfolio (needs: pip install dnspython).
  # On the same input, email and dns are assessed with ONE scan (two reports): options they share must match.
  email:
    enabled: true
    input: domains.csv                   # a plain list of domains is enough; tier/owner/bu/tags columns are optional
    options:
      checks: all                        # mx, spf, dkim, dmarc, mta-sts, tls-rpt (bimi only on request: all,bimi)
      csv: true
      # dmarc_reports: [./rua]           # DMARC aggregate reports (.xml/.gz/.zip/.eml)
      # full_dkim: true                  # probe every DKIM selector (complete audit, slower; e.g. once a month)

  dns:
    enabled: true
    # timeout: 7200                      # large portfolios with lookalikes can take long
    input: domains.csv
    options:
      checks: all                        # dnssec, caa, takeover; add axfr (active test), lookalikes, consistency
      csv: true
      # nameservers: [1.1.1.1, 8.8.8.8]  # shared with email: set the same value in both, or the scans are separate
      # qps: 50                          # max DNS queries per second (default: unlimited)
      # max_inflight: 32                 # max DNS queries on the wire at once (default 32: router friendly)
      # cache_max_age: 24                # hours: full DKIM search, RDAP, lookalikes... redone once a day (0 = every run)

  # Proofpoint email protection: mail routing from public DNS + TAP (SIEM and People APIs, read-only)
  # Credentials: export PROOFPOINT_PRINCIPAL=... PROOFPOINT_SECRET=...  (TAP service principal; never in this file)
  # Without credentials only the DNS routing checks run.
  proofpoint:
    enabled: false
    options:
      domains: domains.csv               # same list as the email module
      csv: true
      # hours: 24                        # TAP window (1-168); keep it equal to the run interval
      # secret_file: /etc/securityhub/proofpoint.secret  # instead of PROOFPOINT_SECRET
      # gateway_hosts: [pps.contoso.com] # extra MX hosts that are Proofpoint (e.g. on-premises PPS)
      # dns_qps: 20                      # max DNS queries per second

  # Imperva Cloud WAF configuration (read-only API calls)
  # Credentials: export IMPERVA_API_ID=... IMPERVA_API_KEY=...  (never in this file)
  waf:
    enabled: false
    options:
      account_id: 1234567
      include_subaccounts: true
      probe: true                        # DNS routing, TLS and origin exposure checks
      # traffic_max_age: 24              # hours: traffic statistics (DDoS tuning) are downloaded once a day
      # probe_max_age: 24                # hours: legacy TLS and origin tests once a day (DNS and HTTPS every run)
      # qps: 5                           # max API requests per second
      # probe_workers: 4                 # websites probed at the same time
      csv: true
      # metadata: sites.csv              # tier/owner/bu/tags/max_rps per website
      # from_json: snapshot.json         # offline: analyze a saved snapshot instead of the API

  # SentinelOne EDR posture (read-only API calls; a token with the Viewer role is enough)
  # Credentials: export S1_CONSOLE_URL=https://<tenant>.sentinelone.net S1_API_TOKEN=...  (never in this file)
  edr:
    enabled: false
    options:
      csv: true
      # console: https://contoso.sentinelone.net   # instead of S1_CONSOLE_URL
      # api_token_file: /etc/securityhub/s1.token  # instead of S1_API_TOKEN (file readable only by the service user)
      # sites: [EMEA, US]                # only these sites (default: every site the token can see)
      # inventory: hosts.csv             # expected hosts: those without an agent are reported as coverage gaps
      # metadata: endpoints.csv          # tier/owner/bu/tags per hostname, group or site
      # stale_days: 14                   # agent not seen for more than N days = stale
      # threat_sla_days: 7               # open threats older than N days breach the SLA
      # from_json: s1_snapshot.json      # offline: analyze a saved snapshot instead of the API

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
        raise ConfigError("'modules' must be a mapping of email / dns / proofpoint / waf / edr / zta")
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
    parser = mod.build_parser(name) if name in MAILGUARD else mod.build_parser()
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
    if not os.path.isfile(out_html) and name == "dns":  # MailGuard writes dns.html and email.html: either one counts
        from .scanners.dns_email.views import email_output
        out_html = email_output(out_html)
    report = out_html if os.path.isfile(out_html) else None
    error = "" if report else "no report produced"
    return ModuleResult(name, code, seconds, report, error, argv, log_path)


def parse_publish(value: Any, base_dir: str) -> Optional[dict]:
    """'publish: /var/www/html/securityhub' or {dir: ..., posture: false, mode: "0644"}.

    Only the portal (as index.html) and, if asked, posture.json are copied: never the run folders, JSON/CSV
    exports or logs, which hold far more detail than a web page needs.
    """
    if value in (None, "", False):
        return None
    spec = {"dir": value} if isinstance(value, str) else value
    if not isinstance(spec, dict) or not spec.get("dir"):
        raise ConfigError("publish must be a folder, or a mapping with 'dir' (and optionally 'posture', 'mode')")
    unknown = set(spec) - {"dir", "posture", "mode"}
    if unknown:
        raise ConfigError(f"publish: unknown option(s) {', '.join(sorted(unknown))} (known: dir, posture, mode)")
    folder = _resolve(base_dir, str(spec["dir"]))
    try:
        mode = int(str(spec.get("mode", "0644")), 8)
    except ValueError:
        raise ConfigError("publish.mode must be octal, e.g. \"0644\" or \"0640\"")
    if mode & 0o7133:
        raise ConfigError("publish.mode must not make the files executable or writable by others (e.g. 0644 or 0640)")
    if not os.path.isdir(folder):
        raise ConfigError(f"publish folder does not exist: {folder} (create it and give the run user write access)")
    return {"dir": folder, "posture": bool(spec.get("posture", False)), "mode": mode}


def publish_outputs(publish: dict, hub: str, posture_file: str) -> List[str]:
    """Copy the portal (index.html) and optionally posture.json to the web folder, atomically."""
    pairs = [(hub, os.path.join(publish["dir"], "index.html"))]
    if publish["posture"]:
        pairs.append((posture_file, os.path.join(publish["dir"], "posture.json")))
    done = []
    for src, dst in pairs:
        with open(src, encoding="utf-8") as f:
            atomic_write(dst, f.read(), publish["mode"])
        done.append(dst)
    return done


def mailguard_scan(mods: dict, selected: List[str]) -> Optional[dict]:
    """The 'dns' module spec of one scan producing both the e-mail and the DNS report, or None.

    - only 'dns' is configured (configurations written before the 'email' module existed): both reports,
      with the checks of 'dns' as they were;
    - 'email' and 'dns' both enabled on the same input, without conflicting options: one scan with the
      checks of each, so the DNS traffic is not doubled (the takeover check needs SPF/DKIM/DMARC data).
    """
    from .scanners.dns_email import parse_checks
    from .scanners.dns_email.views import VIEWS
    if "dns" in selected and "email" not in mods:
        spec = dict(mods["dns"] or {})
        opts = dict(spec.get("options") or {})
        opts.setdefault("checks", "all")
        spec["options"] = opts
        return spec
    if not {"email", "dns"} <= set(selected):
        return None
    e, d = mods["email"] or {}, mods["dns"] or {}
    if _resolve("/", str(e.get("input") or "")) != _resolve("/", str(d.get("input") or "")):
        return None
    eo, do = dict(e.get("options") or {}), dict(d.get("options") or {})
    norm = lambda o: {str(k).replace("-", "_"): v for k, v in o.items()}
    eo, do = norm(eo), norm(do)
    if any(eo[k] != do[k] for k in set(eo) & set(do) - {"checks", "skip"}):
        return None  # e.g. different resolvers or timeouts: keep two scans
    try:
        checks = []
        for name, o in (("email", eo), ("dns", do)):
            spec = o.get("checks", "all")
            spec = ",".join(spec) if isinstance(spec, list) else str(spec)
            skip = o.get("skip", "")
            skip = ",".join(skip) if isinstance(skip, list) else str(skip)
            checks += [c for c in parse_checks(spec, skip) if c in VIEWS[name]["checks"]]
    except ValueError as ex:
        raise ConfigError(f"checks: {ex}")
    opts = {**eo, **do, "checks": ",".join(checks)}
    opts.pop("skip", None)
    spec = {"input": d.get("input"), "options": opts}
    t = [x.get("timeout") for x in (e, d)]
    if None not in t:
        spec["timeout"] = max(float(x) for x in t)
    return spec


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
    try:
        net_parallel = int(cfg.get("max_parallel_network", 1))
    except (TypeError, ValueError):
        raise ConfigError("max_parallel_network must be a number")
    if net_parallel < 1:
        raise ConfigError("max_parallel_network must be 1 or more")

    default_timeout = timeout if timeout is not None else cfg.get("module_timeout")
    max_age = cfg.get("max_age_days") or {}
    if not isinstance(max_age, dict) or set(max_age) - set(MODULES):
        raise ConfigError(f"max_age_days must map {' / '.join(MODULES)} to a number of days")
    try:
        max_age = {k: float(v) for k, v in max_age.items()}
    except (TypeError, ValueError):
        raise ConfigError("max_age_days values must be numbers")

    publish = parse_publish(cfg.get("publish"), base_dir)

    previous = list_runs(out_dir)
    when = now or datetime.now(timezone.utc)
    stamp = when.strftime(RUN_FORMAT)
    while os.path.exists(os.path.join(out_dir, RUNS_DIR, stamp)):  # a run in the same second: next free name
        when += timedelta(seconds=1)
        stamp = when.strftime(RUN_FORMAT)
    run_dir = os.path.join(out_dir, RUNS_DIR, stamp)
    plans = []
    labels = {n: MODULES[n][2] for n in selected}
    merged = mailguard_scan(mods, selected)  # e-mail + DNS with one scan, when they can share it
    for name in selected:
        if merged and name == "email":
            continue
        spec = merged if (merged and name == "dns") else (mods[name] or {})
        out_html = os.path.join(run_dir, f"{name}.html")
        baseline = previous_export(previous, name) if auto_baseline else None
        t = spec.get("timeout", default_timeout)
        try:
            t = float(t) if t not in (None, "", 0) else None
        except (TypeError, ValueError):
            raise ConfigError(f"{name}: timeout must be a number of seconds")
        argv = module_argv(name, spec, base_dir, out_html, baseline, fail_under)
        if merged and name == "dns":
            argv += ["--email-output", os.path.join(run_dir, "email.html")]
            labels["dns"] = "E-mail and DNS security (MailGuard, one scan)"
        plans.append((name, out_html, argv, t))

    if dry_run:
        for name, _, argv, t in plans:  # no secrets: they are rejected from the configuration
            print(f"securityhub {name} {' '.join(argv)}" + (f"    # timeout {fmt_secs(t)}" if t else ""))
        if publish:
            print(f"# then publish the portal to {os.path.join(publish['dir'], 'index.html')}"
                  + (" and posture.json" if publish["posture"] else ""))
        return EXIT_OK

    try:
        lock = RunLock(out_dir).__enter__()
    except LockBusy as e:
        say(err(f"Error: {e}. Wait for it to finish: the lock is released automatically when that run ends.", "red"))
        return EXIT_USAGE
    try:
        return _execute(cfg, plans, out_dir, stamp, when, run_dir, parallel, max_age, fail_under, quiet, verbose, say, err,
                        publish, labels, net_parallel)
    finally:
        lock.__exit__(None, None, None)


def _claim_run_dir(out_dir: str, stamp: str, when: datetime) -> Tuple[str, str]:
    """Create the run folder; never reuse an existing one (another run in the same second)."""
    while True:
        run_dir = os.path.join(out_dir, RUNS_DIR, stamp)
        try:
            os.makedirs(run_dir)
            return run_dir, stamp
        except FileExistsError:
            when += timedelta(seconds=1)
            stamp = when.strftime(RUN_FORMAT)


def _execute(cfg, plans, out_dir, stamp, when, run_dir, parallel, max_age, fail_under, quiet, verbose, say, err,
             publish=None, labels=None, net_parallel: int = 1) -> int:
    net_slots = threading.BoundedSemaphore(net_parallel)
    os.makedirs(os.path.join(out_dir, RUNS_DIR), exist_ok=True)
    claimed, stamp = _claim_run_dir(out_dir, stamp, when)
    if claimed != run_dir:  # the planned folder was taken meanwhile: move the outputs of every module
        plans = [(n, os.path.join(claimed, os.path.basename(o)), [claimed + a[len(run_dir):] if a.startswith(run_dir) else a for a in argv], t)
                 for n, o, argv, t in plans]
        run_dir = claimed
    if not quiet:
        say(err("Security Hub", "bold") + f" run {stamp}  {err.dot}  {len(plans)} module{'s' if len(plans) != 1 else ''}"
            + (f", up to {min(parallel, len(plans))} in parallel" if parallel > 1 and len(plans) > 1 else "")
            + f"  {err.dot}  {err(run_dir, 'dim')}")
    labels = {n: (labels or {}).get(n) or MODULES[n][2] for n, *_ in plans}
    progress = Progress([n for n, *_ in plans], labels, sys.stderr, enabled=not quiet, live=False if verbose else None)

    def echo(line: str) -> None:
        with _echo_lock:
            print(err(line, "dim"), file=sys.stderr, flush=True)

    procs: Dict[str, subprocess.Popen] = {}
    results: Dict[str, ModuleResult] = {}

    def job(name, out_html, argv, t):
        heavy = name in NETWORK_HEAVY
        if heavy:
            net_slots.acquire()  # shown as queued until a network slot is free
        try:
            progress.start(name)
            r = run_module(name, argv, out_html, os.path.join(run_dir, f"{name}.log"), t, echo if verbose else None, procs)
        finally:
            if heavy:
                net_slots.release()
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

    # One HTML in the end: the portal. Module pages become report data (<module>.report.json), in this run
    # and in older runs still holding pages; the portal rebuilds the pages with the current UI.
    from . import portal
    for folder in list_runs(out_dir):
        for n in sorted(os.listdir(folder)):
            if n.lower().endswith(".html"):
                try:
                    data = portal.compact_report(os.path.join(folder, n))
                except (OSError, ValueError) as e:
                    say(err(f"Warning: {os.path.join(folder, n)} kept as a page ({e})", "yellow"))
                    continue
                for r in ordered:
                    if r.report and os.path.realpath(r.report) == os.path.realpath(os.path.join(folder, n)) and data:
                        r.report = data
    removed = prune_runs(out_dir, int(cfg.get("keep_runs", 12) or 0))
    if removed and not quiet:
        say(err(f"Removed {len(removed)} old run{'s' if len(removed) != 1 else ''} (keep_runs={cfg.get('keep_runs')})", "dim"))
    # Areas whose module failed now: the portal still shows their previous data, and must say so.
    failed: Dict[str, dict] = {}
    for r in ordered:
        if r.error or r.code not in (EXIT_OK, EXIT_FAIL_UNDER):
            why = next((l.strip() for l in reversed(_tail(r.log)) if l.strip().lower().startswith(("error", "securityhub"))), "")
            info = {"at": stamp, "error": ("timed out" if r.timed_out else r.error or f"exit code {r.code}")
                    + (f": {why}" if why else ""), "log": r.log}
            for area in [r.name] + (["email"] if r.name == "dns" and "--email-output" in r.argv else []):
                failed[area] = info
    reports, history = portal.collect(list_runs(out_dir))
    hub = os.path.join(out_dir, "security_hub.html")
    portal.build_hub(reports, hub, str(cfg.get("title") or ""), history, max_age, failed)
    summary = portal.posture(reports, history, max_age, failed=failed)
    summary["run"] = {"id": stamp, "folder": run_dir, "max_parallel": parallel,
                      "modules": [{"module": r.name, "exit_code": r.code, "seconds": round(r.seconds, 1), "report": r.report,
                                   "log": r.log, "timed_out": r.timed_out, "error": r.error} for r in ordered]}
    posture_file = os.path.join(out_dir, "posture.json")
    atomic_write(posture_file, json.dumps(summary, indent=2, ensure_ascii=False))

    print_posture(summary)
    out = Style(sys.stdout)
    print(f"\n{out('Portal ', 'bold')}  {out.link(hub)}\n{out('Summary', 'bold')}  {out.link(posture_file)}\n"
          f"{out('Logs   ', 'bold')}  {out.link(run_dir)}")
    published_ok = True
    if publish:
        try:
            for target in publish_outputs(publish, hub, posture_file):
                print(f"{out('Published', 'bold')}  {target}")
        except OSError as e:
            published_ok = False
            say(err(f"Error: cannot publish to {publish['dir']}: {e}", "red"))

    if any(r.code == EXIT_INTERRUPTED for r in ordered):
        return EXIT_INTERRUPTED
    if not published_ok or any(r.code not in (EXIT_OK, EXIT_FAIL_UNDER) or r.error for r in ordered):
        return EXIT_USAGE
    if any(r.code == EXIT_FAIL_UNDER for r in ordered):
        return EXIT_FAIL_UNDER
    if fail_under is not None and any(a.get("score") is not None and a["score"] < fail_under for a in summary["areas"]):
        return EXIT_FAIL_UNDER
    return EXIT_OK


EXIT_STALE = 3


def status(inputs: List[str], json_out: Optional[str] = None, as_json: bool = False, max_age: str = "",
           fail_stale: bool = False) -> int:
    from . import portal
    expanded = []
    for p in inputs:
        runs = list_runs(p) if os.path.isdir(p) else []
        expanded += runs or [p]  # an output_dir: read its runs (the portal file itself is skipped)
    reports, history = portal.collect(expanded)
    if not reports:
        print("Error: no reports found", file=sys.stderr)
        return EXIT_USAGE
    try:
        limits = portal.parse_max_age(max_age)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    summary = portal.posture(reports, history, limits)
    if json_out:
        atomic_write(json_out, json.dumps(summary, indent=2, ensure_ascii=False))
    if as_json:
        json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print_posture(summary)
    if fail_stale and summary["overall"]["stale"]:
        return EXIT_STALE
    return EXIT_OK
