"""`securityhub doctor`: are the credentials, APIs and inputs of every configured module working?

Each enabled module is checked the way a real run would use it: its options are read from the configuration
and the environment through the module's own command-line parser, then ONE cheap read-only call proves that
the credential is accepted and has the access the module needs. Nothing is changed anywhere.

Calls made (all reads):
  email / dns   input file, dkim.csv, DNS resolver answers (and validates DNSSEC)
  waf           Imperva account (prov/v1/account)
  edr           SentinelOne sites (1 item)
  proofpoint    TAP SIEM API (last minute) - Threat Protection token only (the reports have a daily quota) -
                PoD log: the message stream is opened for the last minute and closed
  ias           SAP Cloud Identity SCIM users (1 item)
  pra           BeyondTrust PRA OAuth token and users (1 page)
  zta           Zero Trust Assessment export present, and its age

The result is printed, written to <output_dir>/health.json and shown on the Status page of the portal.
Exit code 0 when every check passed, 1 when one failed.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .common import EXIT_OK, EXIT_USAGE, atomic_write

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"


def _check(name: str, status: str, detail: str = "", hint: str = "") -> dict:
    return {"check": name, "status": status, "detail": detail, "hint": hint}


def _secret(env: str, file_path: Optional[str]) -> Tuple[Optional[str], str]:
    """(value, where it comes from) the way the modules read it: the file wins over the environment."""
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as f:
                return f.read().strip() or None, f"file {file_path}"
        except OSError as e:
            return None, f"file {file_path} not readable ({e.strerror or e})"
    return (os.environ.get(env) or None), f"${env}"


def _present(name: str, value: Any, source: str, hint: str) -> dict:
    return _check(name, OK if value else FAIL, f"set ({source})" if value else f"missing ({source})", "" if value else hint)


def _timed(fn: Callable[[], str], name: str, hint: str = "", http: bool = True) -> dict:
    t0 = time.monotonic()
    try:
        detail = fn()
        return _check(name, OK, f"{detail} ({time.monotonic() - t0:.1f}s)")
    except Exception as e:  # every failure is a result, never a crash of the doctor
        status = getattr(e, "status", None)
        if status in (401, 403) or not http:
            why = hint
        elif status:
            why = f"The service answered HTTP {status}: retry later; if it persists check the service status"
        else:   # no HTTP answer: name resolution, proxy, firewall, TLS
            why = "No answer: check the URL, DNS resolution and outbound HTTPS (proxy / firewall) from this host"
        return _check(name, FAIL, f"{type(e).__name__}: {e}"[:400], why)


# ---------------------------------------------------------------------------
# probes (one per module)
# ---------------------------------------------------------------------------

def probe_mailguard(args) -> List[dict]:
    out = []
    from .scanners.dns_email.inputs import find_dkim_file, load_dkim_file, load_domains
    try:
        items, invalid = load_domains(args.input_file)
        out.append(_check("Domain list", OK if items else FAIL, f"{len(items)} domains in {args.input_file}"
                          + (f", {len(invalid)} invalid entries" if invalid else "")))
    except (OSError, ValueError) as e:
        out.append(_check("Domain list", FAIL, f"{args.input_file}: {e}"))
    dk = None if (getattr(args, "dkim_file", "") or "").lower() == "none" else (getattr(args, "dkim_file", None) or find_dkim_file(args.input_file))
    if dk:
        try:
            sel, bad, _ = load_dkim_file(dk)
            out.append(_check("dkim.csv", WARN if bad else OK, f"{sum(map(len, sel.values()))} records of {len(sel)} domains in {dk}"
                              + (f", {len(bad)} invalid lines" if bad else "")))
        except (OSError, ValueError) as e:
            out.append(_check("dkim.csv", FAIL, f"{dk}: {e}"))
    else:
        out.append(_check("dkim.csv", WARN, "not found next to the domain list: DKIM selectors are searched among the common ones (e-mail report)",
                          "Put the DKIM records of each domain in dkim.csv next to the domain list"))
    from .scanners.dns_email.dnsclient import DNSClient, preflight
    ns = None if args.system_resolver else [n.strip() for n in args.nameservers.split(",") if n.strip()]

    def dns_ok() -> str:
        ok, msg = preflight(DNSClient(ns, 5.0, args.system_resolver))
        if not ok:
            raise RuntimeError(msg)
        return msg or "resolver answers"
    out.append(_timed(dns_ok, "DNS resolver", "Check the nameservers option and outbound DNS (UDP/TCP 53)", http=False))
    return out


def probe_waf(args) -> List[dict]:
    key, src = _secret("IMPERVA_API_KEY", getattr(args, "api_key_file", None))
    out = [_present("API ID", args.api_id, "$IMPERVA_API_ID or api_id", "Set IMPERVA_API_ID"),
           _present("API key", key, src, "Set IMPERVA_API_KEY (or api_key_file)")]
    if not args.account_id:
        out.append(_check("Account ID", FAIL, "account_id option missing", "Set account_id in the waf options"))
    if any(c["status"] == FAIL for c in out):
        return out
    from .scanners.waf.api import ImpervaAPI
    api = ImpervaAPI(args.api_id, key, args.v1_base, args.api_base, timeout=15, retries=1)

    def call() -> str:
        info = api.v1("/api/prov/v1/account", account_id=args.account_id).get("account", {}) or {}
        return f"account {info.get('account_name') or info.get('account_id') or args.account_id} readable"
    out.append(_timed(call, "Imperva API", "The API key needs read access to the account (Account > API Keys)"))
    return out


def probe_edr(args) -> List[dict]:
    token, src = _secret("S1_API_TOKEN", getattr(args, "api_token_file", None))
    out = [_present("Console URL", args.console, "$S1_CONSOLE_URL or console", "Set S1_CONSOLE_URL"),
           _present("API token", token, src, "Set S1_API_TOKEN (service user, Viewer role)")]
    if any(c["status"] == FAIL for c in out):
        return out
    from .scanners.edr.api import SentinelOneAPI
    api = SentinelOneAPI(args.console, token, timeout=15)

    def call() -> str:
        body = api.get("/sites", limit=1, state="active")
        total = ((body.get("pagination") or {}).get("totalItems"))
        return f"sites readable{f' ({total} active)' if total is not None else ''}"
    out.append(_timed(call, "SentinelOne API", "Token expired or without the Viewer role: renew it (service users expire)"))
    return out


def probe_proofpoint(args) -> List[dict]:
    out = []
    if args.domains:
        out += [c for c in probe_mailguard_list(args.domains)]
    tap_secret, src = _secret("PROOFPOINT_SECRET", getattr(args, "secret_file", None))
    if args.principal or tap_secret:
        out += [_present("TAP principal", args.principal, "$PROOFPOINT_PRINCIPAL", "Set PROOFPOINT_PRINCIPAL"),
                _present("TAP secret", tap_secret, src, "Set PROOFPOINT_SECRET")]
        if args.principal and tap_secret:
            from .scanners.proofpoint.api import TapAPI
            api = TapAPI(args.principal, tap_secret, timeout=20, qps=0)
            out.append(_timed(lambda: f"SIEM API answers ({len((api.get('/v2/siem/all', format='json', sinceSeconds=60) or {}).get('messagesDelivered') or [])} delivered threats in the last minute)",
                              "TAP API", "Use a TAP service credential: TAP Dashboard > Settings > Connected Applications"))
    else:
        out.append(_check("TAP", SKIP, "not configured (PROOFPOINT_PRINCIPAL / PROOFPOINT_SECRET)"))
    key, secret = os.environ.get("PROOFPOINT_TP_KEY"), os.environ.get("PROOFPOINT_TP_SECRET")
    if key or secret:
        from .scanners.proofpoint.tpapi import ThreatProtectionAPI
        if key and secret:
            api = ThreatProtectionAPI(key, secret, timeout=20)
            out.append(_timed(lambda: (api.token() and "token issued (reports not called: daily quota)"), "Threat Protection API",
                              "Create the key in Cloud Admin UI > Settings > API Key Management > Threat Protection"))
        else:
            out.append(_check("Threat Protection API", FAIL, "PROOFPOINT_TP_KEY and PROOFPOINT_TP_SECRET must both be set"))
    else:
        out.append(_check("Threat Protection API", SKIP, "not configured (PROOFPOINT_TP_KEY / PROOFPOINT_TP_SECRET)"))
    cluster, token = os.environ.get("PROOFPOINT_POD_CLUSTER"), os.environ.get("PROOFPOINT_POD_TOKEN")
    if cluster or token:
        if cluster and token:
            from .scanners.proofpoint import podlog

            def pod() -> str:
                now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
                ws = podlog.open_stream(cluster, token, "message", now - timedelta(minutes=1), now, timeout=10)
                n, _ = podlog.read_stream(ws, podlog.MessageStats([]), max_events=50)
                return f"message stream opened, {n} event(s) in the last minute"
            out.append(_timed(pod, "PoD Log API", "Check the cluster ID and the PoD Logging key (one session per key: use a dedicated one)"))
        else:
            out.append(_check("PoD Log API", FAIL, "PROOFPOINT_POD_CLUSTER and PROOFPOINT_POD_TOKEN must both be set"))
    else:
        out.append(_check("PoD Log API", SKIP, "not configured (PROOFPOINT_POD_CLUSTER / PROOFPOINT_POD_TOKEN)"))
    return out


def probe_mailguard_list(path: str) -> List[dict]:
    from .scanners.dns_email.inputs import load_domains
    try:
        items, invalid = load_domains(path)
        return [_check("Domain list", OK if items else FAIL, f"{len(items)} domains in {path}"
                       + (f", {len(invalid)} invalid entries (e.g. {invalid[0]})" if invalid else ""),
                       "Remove the invalid lines (a DKIM record name belongs in dkim.csv)" if invalid else "")]
    except (OSError, ValueError) as e:
        return [_check("Domain list", FAIL, f"{path}: {e}")]


def probe_ias(args) -> List[dict]:
    secret, src = _secret("IAS_CLIENT_SECRET", getattr(args, "secret_file", None))
    cert = bool(args.client_cert)
    out = [_present("Tenant URL", args.tenant, "$IAS_TENANT_URL or tenant", "Set IAS_TENANT_URL")]
    out.append(_check("Credentials", OK, "client certificate") if cert else
               _present("Credentials", args.client_id and secret, f"$IAS_CLIENT_ID + {src}", "Set IAS_CLIENT_ID and IAS_CLIENT_SECRET"))
    if any(c["status"] == FAIL for c in out):
        return out
    from .scanners.sap_ias.api import IASClient
    api = IASClient(args.tenant, args.client_id, secret, args.client_cert, args.client_key, timeout=15)

    def call() -> str:
        body = api.get("/scim/Users", count=1)
        return f"SCIM users readable ({body.get('totalResults', '?')} users)"
    out.append(_timed(call, "SAP Cloud Identity API", "The technical user needs the 'Read Users' and 'Read Groups' authorizations"))
    return out


def probe_pra(args) -> List[dict]:
    secret, src = _secret("PRA_CLIENT_SECRET", getattr(args, "secret_file", None))
    out = [_present("Site URL", args.site, "$PRA_SITE_URL or site", "Set PRA_SITE_URL"),
           _present("Client ID", args.client_id, "$PRA_CLIENT_ID", "Set PRA_CLIENT_ID"),
           _present("Client secret", secret, src, "Set PRA_CLIENT_SECRET")]
    if any(c["status"] == FAIL for c in out):
        return out
    from .scanners.pra.api import PRAClient
    api = PRAClient(args.site, args.client_id, secret, timeout=15)
    tok = _timed(lambda: api.token() and "OAuth token issued", "PRA OAuth token",
                 "Check the API account client ID and secret (/login > Management > API Configuration)")
    out.append(tok)
    if tok["status"] == OK:
        out.append(_timed(lambda: f"users readable ({len(api.config('/user', per_page=1) or [])} on the first page)", "PRA Configuration API",
                          "The API account needs 'Allow Access' to the Configuration API"))
    return out


def probe_zta(args) -> List[dict]:
    p = args.input
    if not p or not os.path.exists(p):
        return [_check("Zero Trust export", FAIL, f"not found: {p}", "Copy the ZeroTrustAssessment report folder to this path")]
    age = (time.time() - os.path.getmtime(p)) / 86400
    return [_check("Zero Trust export", WARN if age > 35 else OK, f"{p}, {age:.0f} days old",
                   "Run the Zero Trust Assessment again and copy the new export" if age > 35 else "")]


PROBES = {"email": probe_mailguard, "dns": probe_mailguard, "waf": probe_waf, "edr": probe_edr, "proofpoint": probe_proofpoint,
          "ias": probe_ias, "pra": probe_pra, "zta": probe_zta}


def module_args(name: str, spec: dict, base_dir: str):
    """The module's options parsed exactly as `securityhub run` passes them (configuration + environment)."""
    from . import orchestrator as orch
    mod = importlib.import_module(orch.MODULES[name][0])
    target = mod if hasattr(mod, "build_parser") else importlib.import_module(orch.MODULES[name][0] + ".cli")
    parser = target.build_parser(name) if name in orch.MAILGUARD else target.build_parser()
    argv = orch.module_argv(name, spec, base_dir, os.devnull, None, None)
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# last run: freshness, failures, API errors and data coverage of the latest reports
# ---------------------------------------------------------------------------

def run_state(out_dir: str) -> Dict[str, dict]:
    from . import orchestrator as orch, portal
    if not os.path.isdir(out_dir):
        return {}
    try:
        reports, _ = portal.collect(orch.list_runs(out_dir))
    except Exception:
        return {}
    posture = {}
    try:
        with open(os.path.join(out_dir, "posture.json"), encoding="utf-8") as f:
            posture = {a["area"]: a for a in json.load(f).get("areas") or []}
    except (OSError, ValueError):
        pass
    out = {}
    for r in reports:
        if r["type"] == "other":
            continue
        fresh = portal.freshness(r)
        out[r["type"]] = {"date": r["date"], **fresh, **portal.coverage(r["type"], r.get("payload") or {}),
                          "last_run_failed": (posture.get(r["type"]) or {}).get("last_run_failed")}
    return out


# ---------------------------------------------------------------------------

def diagnose(config_path: str, only: Optional[List[str]] = None, output_dir: Optional[str] = None,
             log: Callable[[str], None] = lambda m: None) -> dict:
    from . import orchestrator as orch
    cfg = orch.load_config(config_path)
    base_dir = os.path.dirname(os.path.abspath(config_path))
    out_dir = orch._resolve(base_dir, output_dir or cfg.get("output_dir") or "reports")
    mods = cfg.get("modules") or {}
    selected = [m for m in orch.ORDER if m in mods and (mods[m] or {}).get("enabled", True)]
    if only:
        wanted = {orch.MODULE_ALIASES.get(m, m) for m in only}
        selected = [m for m in selected if m in wanted]
    modules: Dict[str, dict] = {}
    done_mailguard = None
    for name in selected:
        log(f"Checking {name}...")
        if name in orch.MAILGUARD and done_mailguard is not None and (mods[name] or {}).get("input") == done_mailguard[0]:
            modules[done_mailguard[2]]["label"] = "E-mail and DNS security (MailGuard, one scan)"
            modules[name] = {"label": orch.MODULES[name][2], "checks": done_mailguard[1], "same_as": done_mailguard[2]}
            continue
        try:
            args = module_args(name, mods[name] or {}, base_dir)
            checks = PROBES[name](args)
        except SystemExit:
            checks = [_check("Configuration", FAIL, "the module options are not valid", f"Run: securityhub run --dry-run --only {name}")]
        except Exception as e:
            checks = [_check("Configuration", FAIL, f"{type(e).__name__}: {e}"[:300])]
        if name in orch.MAILGUARD:
            done_mailguard = ((mods[name] or {}).get("input"), checks, name)
        modules[name] = {"label": orch.MODULES[name][2], "checks": checks}
    for m in modules.values():
        st = {c["status"] for c in m["checks"]}
        m["status"] = FAIL if FAIL in st else WARN if WARN in st else OK
    worst = {m["status"] for m in modules.values()}
    return {"schema": 1, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": FAIL if FAIL in worst else WARN if WARN in worst else OK, "modules": modules,
            "runs": run_state(out_dir), "output_dir": out_dir}


def main(argv: Optional[List[str]] = None) -> int:
    from .common import Parser
    from .console import Style
    p = Parser(prog="securityhub doctor", description="Check credentials, API access and inputs of every configured module "
                                                      "(one read-only call each), then show the state of the last run")
    p.add_argument("modules", nargs="*", metavar="MODULE", help="Only these modules (default: every enabled module)")
    p.add_argument("-c", "--config", default="securityhub.yaml", help="Configuration file (default: securityhub.yaml)")
    p.add_argument("-o", "--output-dir", help="Override output_dir of the configuration")
    p.add_argument("--json", action="store_true", help="Print the result as JSON")
    p.add_argument("--no-write", action="store_true", help="Do not write health.json nor refresh the portal")
    a = p.parse_args(argv)
    if not os.path.isfile(a.config):
        print(f"Error: configuration not found: {a.config}", file=sys.stderr)
        return EXIT_USAGE
    from . import orchestrator as orch
    try:
        res = diagnose(a.config, [x for v in a.modules for x in v.split(",") if x], a.output_dir,
                       (lambda m: None) if a.json else (lambda m: print(m, file=sys.stderr)))
    except orch.ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    if not a.no_write:
        os.makedirs(res["output_dir"], exist_ok=True)
        atomic_write(os.path.join(res["output_dir"], "health.json"), json.dumps(res, indent=2, ensure_ascii=False))
        try:
            orch.refresh_portal(a.config, res["output_dir"])
        except Exception as e:
            print(f"Warning: portal not refreshed ({type(e).__name__}: {e})", file=sys.stderr)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        out = Style(sys.stdout)
        sym = {OK: out("OK  ", "green"), WARN: out("WARN", "yellow"), FAIL: out("FAIL", "red"), SKIP: out("--  ", "dim")}
        for name, m in res["modules"].items():
            if m.get("same_as"):
                continue
            print(f"\n{out(m['label'], 'bold')}")
            for c in m["checks"]:
                print(f"  {sym[c['status']]}  {c['check']:<26} {c['detail']}")
                if c.get("hint") and c["status"] in (FAIL, WARN):
                    print(f"        {out('-> ' + c['hint'], 'dim')}")
        if res["runs"]:
            print(f"\n{out('Last run', 'bold')}")
            for area, r in res["runs"].items():
                flags = (["STALE"] if r.get("stale") else []) + (["LAST RUN FAILED"] if r.get("last_run_failed") else []) \
                    + ([f"{len(r['api_errors'])} API error(s)"] if r.get("api_errors") else [])
                print(f"  {area:<11} {str(r.get('age_days')):>5} days old   scored {r.get('scored')}/{r.get('items')}   "
                      f"read errors: {r.get('read_errors', r.get('not_evaluable', 0))}   not verifiable: {r.get('not_available', 0)}   {', '.join(flags)}")
        print(f"\nOverall: {sym[res['status']].strip()}" + (" - health.json and the Status page of the portal updated" if not a.no_write else ""))
    return EXIT_OK if res["status"] != FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
