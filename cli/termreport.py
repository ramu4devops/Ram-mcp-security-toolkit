#!/usr/bin/env python3
"""
termreport.py -- pretty, readable terminal rendering of review results.

The CLI prints a one-line-per-module summary by default (great for CI). With
--details, this module prints the FULL findings for every module right in the
terminal -- verdict, rationale, and each finding with where / evidence / why /
fix -- so an engineer never has to open the HTML report just to read results.

Same finding schema every module already emits:
  {severity, layer, subject, title, evidence, impact, remediation}
so one renderer covers all ten modules.
"""
import os
import sys
import shutil
import textwrap


# ---- ANSI ----------------------------------------------------------------
class Palette:
    def __init__(self, on):
        def c(code):
            return code if on else ""
        self.reset = c("\033[0m")
        self.b = c("\033[1m")
        self.dim = c("\033[2m")
        self.ital = c("\033[3m")
        self.red = c("\033[91m")
        self.green = c("\033[92m")
        self.yellow = c("\033[93m")
        self.blue = c("\033[94m")
        self.mag = c("\033[95m")
        self.cyan = c("\033[96m")
        self.gray = c("\033[90m")
        self.white = c("\033[97m")
        # severity chips (padded, background where it earns attention)
        self.sev = {
            "critical": c("\033[97;41m") + " CRITICAL " + c("\033[0m"),
            "high":     c("\033[91m") + "▲ HIGH" + c("\033[0m"),
            "medium":   c("\033[93m") + "▲ MEDIUM" + c("\033[0m"),
            "low":      c("\033[90m") + "• low" + c("\033[0m"),
            "info":     c("\033[90m") + "• info" + c("\033[0m"),
        }
        self.on = on


GATE_BLOCK = {"FAIL", "HIGH_SUSPICION", "HIGH SUSPICION", "ERROR"}
GATE_REVIEW = {"REVIEW", "CHANGED", "NEEDS_DYNAMIC", "NEEDS DYNAMIC",
               "NO_BASELINE", "EXTRACTED"}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _status_color(p, status):
    s = (status or "").upper().replace("-", "_")
    if s in {x.replace(" ", "_") for x in GATE_BLOCK}:
        return p.red
    if s in {x.replace(" ", "_") for x in GATE_REVIEW}:
        return p.yellow
    return p.green


def _width():
    try:
        w = shutil.get_terminal_size((100, 24)).columns
    except Exception:
        w = 100
    return max(60, min(w, 100))


def _field(p, label, text, width, lcolor):
    """A labelled, wrapped field: '   label  wrapped text…' with the
    continuation lines aligned under the text, not the label."""
    if not text:
        return []
    lw = 7
    head = f"     {lcolor}{label:<{lw}}{p.reset}"
    avail = width - (5 + lw + 1)
    wrapped = textwrap.wrap(str(text), width=max(20, avail)) or [""]
    pad = " " * (5 + lw + 1)
    out = [head + " " + wrapped[0]]
    out += [pad + line for line in wrapped[1:]]
    return out


def render(results, recommendation, color=None, out=sys.stdout, show_clean=True):
    """Print the detailed terminal report. `results` is the list of run_box
    dicts; `recommendation` is (word, cls, why)."""
    if color is None:
        color = out.isatty() and not os.environ.get("NO_COLOR")
    p = Palette(color)
    W = _width()

    def line(s=""):
        out.write(s + "\n")

    line()
    title = " DETAILED FINDINGS "
    bar = "━" * ((W - len(title)) // 2)
    line(f"{p.cyan}{p.b}{bar}{title}{bar}{p.reset}")

    for br in results:
        res = br.get("result") or {}
        v = res.get("verdict", {})
        status = br.get("status", "ERROR")
        sc = _status_color(p, status)
        counts = br.get("counts", {}) or v.get("counts", {})
        findings = sorted(res.get("findings", []),
                          key=lambda x: -SEV_RANK.get(x.get("severity", "info"), 0))

        # ---- module header bar ----
        line()
        name = br.get("name", "")
        head = f"{p.b}{p.cyan}{name}{p.reset}"
        owasp = br.get("owasp", "")
        badge = f"{sc}{p.b}[{status}]{p.reset}"
        # plain-length accounting for the fill
        fill = max(1, W - len(name) - len(f"[{status}]") - len(owasp) - 4)
        line(f"{head} {p.gray}{'─'*fill} {owasp}{p.reset} {badge}")

        if br.get("error"):
            for ln in _field(p, "error", br["error"], W, p.red):
                line(ln)
            continue

        # ---- verdict rationale + next step ----
        if v.get("rationale"):
            for ln in textwrap.wrap(v["rationale"], width=W - 2):
                line(f"  {p.dim}{ln}{p.reset}")
        if v.get("note"):
            for ln in textwrap.wrap(v["note"], width=W - 2):
                line(f"  {p.dim}{ln}{p.reset}")

        # ---- stat line ----
        tot = counts.get("total", 0)
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        med = counts.get("medium", 0)
        cc = p.red if crit else p.dim
        hc = p.red if high else p.dim
        line(f"  {p.gray}findings{p.reset} {p.b}{tot}{p.reset}   "
             f"{cc}critical {crit}{p.reset}   {hc}high {high}{p.reset}   "
             f"{p.dim}medium {med}{p.reset}")

        # ---- findings ----
        if not findings:
            if show_clean:
                line(f"  {p.green}✓ no findings for this module{p.reset}")
            continue

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            chip = p.sev.get(sev, sev)
            layer = f.get("layer", "")
            title = f.get("title", "")
            line()
            lay = f"{p.gray}{layer}{p.reset} " if layer else ""
            line(f"  {p.b}{i:>2}.{p.reset} {chip}  {lay}{p.b}{title}{p.reset}")
            for ln in _field(p, "where", f.get("subject"), W, p.blue):
                line(ln)
            for ln in _field(p, "evidence", f.get("evidence"), W, p.mag):
                line(ln)
            for ln in _field(p, "why", f.get("impact"), W, p.yellow):
                line(ln)
            for ln in _field(p, "fix", f.get("remediation"), W, p.green):
                line(ln)

    # ---- closing recommendation ----
    word, cls, why = recommendation
    wc = p.red if cls == "block" else p.yellow if cls == "review" else p.green
    line()
    line(f"{p.cyan}{p.b}{'━'*W}{p.reset}")
    line(f"  {p.b}Recommendation:{p.reset} {wc}{p.b}{word}{p.reset}")
    for ln in textwrap.wrap(why, width=W - 4):
        line(f"  {p.dim}{ln}{p.reset}")
    line()
