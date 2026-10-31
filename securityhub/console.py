"""Terminal output of `securityhub run` and `securityhub status`.

Colors and live redraw are used only on an interactive terminal; in logs, cron mails and CI
the output is plain text, one line per event. NO_COLOR disables colors, FORCE_COLOR forces them.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, TextIO

STATUS_TEXT = {"good": "On track", "warn": "Attention", "bad": "At risk", "unknown": "Not verified", None: "Not verified"}


def age_txt(a: dict, st: "Style") -> str:
    """'2026-10-01, 30 days old' - yellow and marked when beyond the area's limit."""
    age = a.get("age_days")
    text = a.get("date", "")[:10] + ("" if age is None else f", {age:.0f} day{'' if round(age) == 1 else 's'} old" if age >= 1 else ", today")
    if a.get("stale"):
        return st(f"{text} {st.warn} stale (limit {a.get('max_age_days'):g} days)", "yellow")
    return st(text, "dim")
STATUS_TONE = {"good": "green", "warn": "yellow", "bad": "red"}
GRADE_TONE = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
SEV_TONE = {"critical": "red", "warning": "yellow", "info": "dim"}
CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36"}


class Style:
    """ANSI styling and symbols for one output stream."""

    def __init__(self, stream: TextIO, color: Optional[bool] = None):
        self.stream = stream
        tty = hasattr(stream, "isatty") and stream.isatty()
        if color is None:
            color = bool(os.environ.get("FORCE_COLOR")) or (tty and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb")
        self.color = color
        self.live = tty and os.environ.get("TERM") != "dumb"
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        uni = enc in ("utf8", "utf8sig")
        self.ok, self.fail, self.warn, self.dot = ("✔", "✖", "▲", "·") if uni else ("OK", "X", "!", "-")
        self.spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if uni else "|/-\\"
        self.rule = "─" if uni else "-"

    def __call__(self, text: str, *tones: str) -> str:
        if not self.color or not tones:
            return text
        return "\033[" + ";".join(CODES[t] for t in tones if t in CODES) + "m" + text + "\033[0m"

    def link(self, path: str) -> str:
        """Clickable file link where the terminal supports it (OSC 8), plain path otherwise."""
        uri = Path(path).resolve().as_uri()
        return f"\033]8;;{uri}\033\\{path}\033]8;;\033\\" if self.color and self.live else path


def fmt_secs(s: float) -> str:
    return f"{s:.0f}s" if s < 60 else f"{int(s // 60)}m{int(s % 60):02d}s"


class Progress:
    """Status of the modules of a run: redrawn in place on a terminal, one line per change otherwise."""

    def __init__(self, names: List[str], labels: Dict[str, str], stream: TextIO = None, enabled: bool = True,
                 live: Optional[bool] = None):
        self.st = Style(stream or sys.stderr)
        if live is not None:
            self.st.live = live and self.st.live
        self.names, self.labels, self.enabled = names, labels, enabled
        self.state = {n: {"status": "queued", "t0": None, "t1": None, "note": ""} for n in names}
        self.lock = threading.Lock()
        self.drawn = 0
        self.tick = 0
        self._stop = threading.Event()
        self._thread = None

    # -- events
    def start(self, name: str) -> None:
        self._update(name, status="running", t0=time.monotonic())

    def finish(self, name: str, status: str, note: str = "") -> None:
        self._update(name, status=status, t1=time.monotonic(), note=note)

    def _update(self, name: str, **kw) -> None:
        with self.lock:
            self.state[name].update(kw)
            if not self.enabled:
                return
            if self.st.live:
                self._draw()
            else:
                self.st.stream.write(self._line(name) + "\n")
                self.st.stream.flush()

    # -- live redraw
    def __enter__(self):
        if self.enabled and self.st.live:
            with self.lock:
                self._draw()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()
            with self.lock:
                self._draw()
        return False

    def _loop(self) -> None:
        while not self._stop.wait(0.12):
            with self.lock:
                self.tick += 1
                self._draw()

    def _draw(self) -> None:
        out = self.st.stream
        if self.drawn:
            out.write(f"\033[{self.drawn}F")
        for n in self.names:
            out.write("\033[2K" + self._line(n) + "\n")
        self.drawn = len(self.names)
        out.flush()

    def _line(self, name: str) -> str:
        s, st = self.state[name], self.st
        now = time.monotonic()
        took = fmt_secs((s["t1"] or now) - s["t0"]) if s["t0"] else ""
        icon, tone, word = {
            "queued": (st.dot, "dim", "queued"),
            "running": (st.spin[self.tick % len(st.spin)] if st.live else ">", "cyan", "running"),
            "ok": (st.ok, "green", "done"),
            "below": (st.warn, "yellow", "below threshold"),
            "failed": (st.fail, "red", "failed"),
            "timeout": (st.fail, "red", "timed out"),
            "interrupted": (st.fail, "red", "interrupted"),
        }.get(s["status"], ("?", "", s["status"]))
        note = f"  {st(s['note'], 'dim')}" if s["note"] else ""
        return f"  {st(icon, tone)} {self.labels.get(name, name):<40} {st(f'{word:<16}', tone)} {took:>6}{note}"


def print_posture(summary: dict, file: TextIO = None) -> None:
    out = file or sys.stdout
    st = Style(out)
    ov = summary.get("overall") or {}
    s0 = ov.get("status", "unknown")
    counts = ov.get("areas") or {}
    parts = [f"{counts[k]} {w}" for k, w in (("bad", "at risk"), ("warn", "need attention"), ("good", "on track"),
                                              ("unknown", "not verified")) if counts.get(k)]
    print("", file=out)
    print(st("SECURITY POSTURE", "bold") + "  " + st(f" {STATUS_TEXT.get(s0, s0).upper()} ", "bold", STATUS_TONE.get(s0, "dim"))
          + (st("  " + " \u00b7 ".join(parts) if st.dot != "-" else "  " + ", ".join(parts), "dim") if parts else ""), file=out)
    if ov and not ov.get("complete", True):
        gaps = ([f"stale: {', '.join(ov['stale'])}"] if ov.get("stale") else []) + \
               ([f"not verified: {', '.join(ov['not_verified'])}"] if ov.get("not_verified") else [])
        print(st(f"{st.warn} Incomplete picture - {'; '.join(gaps)}", "yellow"), file=out)
    print(st(st.rule * 72, "dim"), file=out)
    if summary.get("summary"):
        print(summary["summary"], file=out)
    print("", file=out)
    for a in summary.get("areas", []):
        s = a.get("status")
        score = "  -" if a.get("score") is None else f"{a['score']:>3}"
        gr = a.get("grade") or "-"
        print(f"  {a['label']:<26} {st(f'{gr:>2}', 'bold', GRADE_TONE.get(gr, ''))} {score}  "
              f"{st(f'{STATUS_TEXT.get(s, s):<12}', STATUS_TONE.get(s, 'dim'))} {age_txt(a, st)}", file=out)
        if a.get("headline"):
            print(f"  {'':<26} {st(a['headline'], 'dim')}", file=out)
        for k in a.get("kpis", []):
            if k.get("value") is not None:
                unit = k.get("unit") or ""
                print(f"  {'':<26} {st(st.dot, 'dim')} {k['label']}: {st(str(k['value']) + unit, 'bold')}", file=out)
    inv = (summary.get("assets") or {})
    sm = inv.get("summary") or {}
    if sm.get("total"):
        parts = [f"{sm['total']} assets"]
        if sm.get("at_risk"):
            parts.append(st(f"{sm['at_risk']} at risk", "red"))
        if sm.get("attention"):
            parts.append(st(f"{sm['attention']} need attention", "yellow"))
        if sm.get("coverage_gaps"):
            parts.append(st(f"{sm['coverage_gaps']} coverage gap{'s' if sm['coverage_gaps'] != 1 else ''}", "yellow"))
        if sm.get("expiring"):
            parts.append(st(f"{sm['expiring']} expiring", "yellow"))
        print("\n" + st("Assets", "bold") + "  " + f" {st.dot} ".join(parts), file=out)
        for a in [x for x in inv.get("items", []) if x["status"] in ("bad", "warn")][:5]:
            sig = (a.get("signals") or [{}])[0].get("text") or (f"lowest score {a['score']}" if a.get("score") is not None else "")
            print(f"  {st(st.fail if a['status'] == 'bad' else st.warn, STATUS_TONE[a['status']])} {a['asset']:<28} "
                  f"{st(sig, 'dim')}", file=out)
    acts = summary.get("actions", [])
    if acts:
        print("\n" + st("Top actions", "bold"), file=out)
        for a in acts[:5]:
            sev = a.get("severity", "")
            label = f"{a.get('label', ''):<24}"
            print(f"  {st(f'{sev:<8}', SEV_TONE.get(sev, ''))} {st(label, 'dim')} {a.get('title', '')}", file=out)
