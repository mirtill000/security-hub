"""Security Hub - security posture monitoring for WAF, DNS / e-mail and Zero Trust.

Modules
  securityhub.scanners.dns_email   MailGuard DNS: e-mail and DNS security of a domain portfolio
  securityhub.scanners.waf         WAFGuard: Imperva Cloud WAF configuration assessment
  securityhub.scanners.zero_trust  ZTAGuard: Microsoft Zero Trust Assessment viewer
  securityhub.portal               GuardHub: one portal over every report, with KPI history
  securityhub.orchestrator         `securityhub run`: scheduled assessments from a config file
"""

__version__ = "2.0.0"
