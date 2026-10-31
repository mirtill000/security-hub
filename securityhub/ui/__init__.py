"""Shared design system of the reports and the portal.

The HTML outputs stay single, self-contained files: the CSS, JavaScript and HTML in this
folder are assembled into each page when it is generated. A line `/* @include name */`
is replaced by the content of that file, so a change in a shared file (tokens, components,
helpers) reaches every report and the portal at once.

  base.css          design tokens, layout and components shared by all pages
  print-head.css    print header shared by all pages (kept last in the cascade)
  dns|waf|zta|portal.css   page-specific styles
  core.js           helpers shared by all pages
  report-core.js    helpers shared by the three reports
  asset-report.js   table/filter/drawer application shared by the DNS and WAF reports
  dns|waf|zta|portal.js    page applications
  report.html, portal.html page skeletons
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

INCLUDE = re.compile(r"^/\* @include ([\w.-]+) \*/\n", re.M)


@lru_cache(maxsize=None)
def asset(name: str, _depth: int = 0) -> str:
    """Content of a UI file with its includes resolved."""
    if _depth > 8:
        raise ValueError(f"include loop at {name}")
    text = resources.files(__name__).joinpath(name).read_text(encoding="utf-8")
    return INCLUDE.sub(lambda m: asset(m.group(1), _depth + 1), text)
