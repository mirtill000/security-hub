"""Remediation steps (console and Terraform)."""

from __future__ import annotations

import re
from typing import List

from .constants import DDOS_DEFAULT_THRESHOLD
from .models import SiteResult


def tf_name(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", text).strip("_").lower()[:40] or "site"


def suggest_remediation(r: SiteResult) -> List[dict]:
    out: List[dict] = []
    sid = str(r.site_id)
    key = tf_name(r.domain)
    codes = {i.code for i in r.issues}

    def rec(title, kind, value, note=""):
        out.append({"title": title, "name": kind, "type": "Terraform" if value and value.lstrip().startswith(("resource", "#")) else "Action",
                    "value": value, "note": note})

    waf = r.checks.get("waf")
    if waf and codes & {"WAF_NO_POLICY", "WAF_RULE_MISSING", "WAF_RULE_IGNORED", "WAF_RULE_ALERT", "WAF_POLICY_DISABLED", "WAF_LEGACY_RULES"}:
        existing = (waf.data.get("policy") or {}).get("name")
        rec("Enforce the core WAF rules in blocking mode", "incapsula_policy / incapsula_policy_asset_association",
            'resource "incapsula_policy" "waf_block" {\n'
            '  name        = "WAF rules - block"\n'
            '  enabled     = true\n'
            '  policy_type = "WAF_RULES"\n'
            '  policy_settings = jsonencode([\n'
            '    { policySettingType = "SQL_INJECTION",           settingsAction = "BLOCK" },\n'
            '    { policySettingType = "CROSS_SITE_SCRIPTING",    settingsAction = "BLOCK" },\n'
            '    { policySettingType = "ILLEGAL_RESOURCE_ACCESS", settingsAction = "BLOCK" },\n'
            '    { policySettingType = "REMOTE_FILE_INCLUSION",   settingsAction = "BLOCK" },\n'
            '  ])\n}\n\n'
            f'resource "incapsula_policy_asset_association" "waf_{key}" {{\n'
            '  policy_id  = incapsula_policy.waf_block.id\n'
            f'  asset_id   = "{sid}"\n'
            '  asset_type = "WEBSITE"\n}',
            (f"Or change policy '{existing}' in place. " if existing else "") +
            "Move from Alert to Block after reviewing Security Events for false positives.")
    ddos = r.checks.get("ddos")
    if ddos and codes & {"DDOS_OFF", "DDOS_THRESHOLD_LOW", "DDOS_THRESHOLD_HIGH", "DDOS_ABOVE_ORIGIN", "DDOS_DEFAULT_THRESHOLD"}:
        recommended = ddos.data.get("recommended")
        value = recommended or ddos.data.get("threshold") or DDOS_DEFAULT_THRESHOLD
        title = "Turn DDoS protection on" if "DDOS_OFF" in codes else f"Set the DDoS threshold to {value} requests/s"
        note = (f"Recommended {recommended}: {ddos.data.get('recommended_why')}. " if recommended else
                "No traffic data: pick a threshold just above normal peak traffic. ") + \
               "Re-check after seasonal peaks (sales, campaigns) and keep it below what the origin can serve." + \
               ("" if "DDOS_OFF" in codes else " Alternative: enable the adaptive DDoS threshold, if your plan includes it - "
                "Imperva then derives it from the site's traffic and no fixed value needs tuning.")
        rec(title, "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "ddos_{key}" {{\n  site_id                = "{sid}"\n'
            '  rule_id                = "api.threats.ddos"\n'
            '  activation_mode        = "api.threats.ddos.activation_mode.auto"\n'
            f'  ddos_traffic_threshold = "{value}"\n}}', note)
    if codes & {"BOT_BAD_NOT_BLOCKED", "BOT_SUSPECTED_NOT_CHALLENGED", "BOT_RULE_MISSING"}:
        rec("Block bad bots and challenge suspected ones", "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "bots_{key}" {{\n  site_id                   = "{sid}"\n'
            '  rule_id                   = "api.threats.bot_access_control"\n'
            '  block_bad_bots            = "true"\n'
            '  challenge_suspicious_bots = "true"\n}')
    if "WAF_BACKDOOR_WEAK" in codes:
        rec("Quarantine backdoor uploads", "incapsula_waf_security_rule",
            f'resource "incapsula_waf_security_rule" "backdoor_{key}" {{\n  site_id              = "{sid}"\n'
            '  rule_id              = "api.threats.backdoor"\n'
            '  security_rule_action = "api.threats.action.quarantine_url"\n}')
    if "SITE_BYPASS" in codes:
        rec("Take the website out of bypass", "incapsula_site",
            f'# in the incapsula_site resource of {r.domain}\nactive = "active"',
            "Bypass is often left on after an incident or a migration: confirm with the site owner first.")
    if "TLS_NO_HSTS" in codes:
        rec("Enable HSTS", "incapsula_site_ssl_settings",
            f'resource "incapsula_site_ssl_settings" "ssl_{key}" {{\n  site_id = "{sid}"\n  hsts {{\n'
            '    is_enabled           = true\n    max_age              = 31536000\n'
            '    sub_domains_included = true\n    pre_loaded           = false\n  }\n}',
            "Enable includeSubDomains only if every subdomain is served over HTTPS.")
    if "TLS_LEGACY" in codes:
        rec("Disable TLS 1.0 and 1.1", "incapsula_site_ssl_settings", "",
            "Set the inbound TLS configuration of the website to TLS 1.2 and 1.3 only (inbound_tls_settings).")
    if "ORIGIN_EXPOSED" in codes or "ORIGIN_REACHABLE" in codes:
        rec("Lock the origin to Imperva", "Origin firewall", "",
            "Allow inbound 80/443 on the origin only from the Imperva IP ranges (published by Imperva and retrievable "
            "via its IP ranges integration API), then re-run with --probe.")
    if "ALLOW_BROAD_IP" in codes or "ALLOW_BROAD_URL" in codes:
        rec("Shrink the allow-lists", "WHITELIST policy", "",
            "Every allow-listed IP or URL skips WAF inspection: replace wide ranges with the specific hosts that need it.")
    if "WAF_BROAD_EXCEPTION" in codes:
        rec("Narrow the broad WAF exceptions", "WAF Rules policy exceptions", "",
            "Scope exceptions to the exact URL and parameter, add a comment with owner and expiry date.")
    if "CERT_EXPIRED" in codes or "CERT_EXPIRING" in codes:
        rec("Renew the certificate", "incapsula_custom_certificate", "",
            "Upload the renewed certificate, or move the website to an Imperva-generated certificate with automatic renewal.")
    return out
