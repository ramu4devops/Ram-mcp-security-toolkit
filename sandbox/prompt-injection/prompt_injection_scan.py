#!/usr/bin/env python3
"""
prompt_injection_scan.py -- Box-04: Prompt & Template Injection.

Static assessment of an MCP server's PROMPT surface -- the layer where an
MCP prompt template, or a server-rendered instruction string, interpolates
untrusted input (a prompt argument, a tool argument, or the contents of a
fetched resource) directly into text the model reads as instructions. Where
Box-01 asks "does the tool *description* try to manipulate the model" and
Box-08 asks "does a tool argument reach a native RCE sink", Box-04 asks:
"can a caller (or a resource) rewrite the model's own instruction flow by
being placed, unescaped, inside a prompt or template?"

Reads files only; nothing from the target repo is ever executed.

Five layers:

  P1  Untrusted input in a prompt template -- an @mcp.prompt()/registerPrompt
      handler that builds the prompt it returns by f-string / concatenation /
      .format() from its own arguments, so a caller-supplied value lands
      inside the instruction text verbatim.
  P2  Server-side template injection (SSTI) into a prompt -- a caller value
      reaches a template engine (render_template_string, Jinja2 Template(),
      Environment.from_string, Handlebars/Mustache.compile, ejs.render) as
      the template SOURCE, letting template syntax in the value execute.
  P3  Resource content flows into instructions -- the bytes from a file /
      URL read are concatenated into a prompt / system / instruction string
      with no sanitisation, so a poisoned resource carries an injection
      payload straight into context.
  P4  Unescaped interpolation into role-framed messages -- a caller value is
      concatenated into a string that also contains role/turn framing
      ("system:", "assistant:", "<|...|>", "### Instruction"), letting the
      caller forge a new turn or system instruction.
  P5  Unconstrained prompt arguments -- a prompt argument declared as free
      text with no enum / Literal / length constraint, i.e. nothing stops it
      carrying an instruction payload in the first place.

Usage:
    python3 prompt_injection_scan.py /path/to/repo [--json] [--all]

Exit codes: 0 = PASS, 1 = REVIEW, 2 = FAIL.
"""
import os, re, sys, json, argparse
from promptlib import (walk_repo, read_lines, snippet, classify_path, CODE_EXTS,
                       TAINT_NAME, declares_prompt_surface, declares_mcp_surface,
                       MCP_PROMPT_DECOR)

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_CHAIN = ["info", "low", "medium", "high", "critical"]
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"


def F(layer, severity, title, path, line_no, evidence, remediation):
    return {"layer": layer, "severity": severity, "title": title,
            "file": path, "line": line_no, "evidence": evidence,
            "remediation": remediation}


def downgrade(sev, steps=1):
    return SEV_CHAIN[max(0, SEV_CHAIN.index(sev) - steps)]


def _iter_code_lines(root):
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        if lines:
            yield path, rel, lines


# ----------------------------------------------------------------------
# helpers for locating prompt-handler bodies (Python & JS, brace/indent-lite)
# ----------------------------------------------------------------------
FSTRING_PY = re.compile(r"""\bf["']""")
FORMAT_CALL = re.compile(r"""\.format\s*\(""")
CONCAT_PLUS = re.compile(r"""["'`][^"'`]*["'`]\s*\+\s*\w""")
JS_TEMPLATE_INTERP = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")
RETURN_LINE = re.compile(r"\breturn\b|\byield\b|\bmessages\b|\bprompt\b|\bcontent\b|\btext\b")


def _prompt_handler_line_ranges(lines):
    """Best-effort: yield (start_idx, end_idx) for lines belonging to a
    function/handler decorated as an MCP prompt. Indent-based for Python,
    naive brace/next-30-lines for JS."""
    ranges = []
    n = len(lines)
    for i, line in enumerate(lines):
        if MCP_PROMPT_DECOR.search(line) or re.search(r"registerPrompt\s*\(|server\.prompt\s*\(", line):
            # scan forward to the function body; capture up to ~40 lines / dedent
            j = i + 1
            # find the def/function line
            while j < n and not re.search(r"\bdef\b|\bfunction\b|=>|\basync\b", lines[j]):
                j += 1
                if j - i > 6:
                    break
            start = j
            end = min(n, start + 40)
            ranges.append((max(i, start), end))
    return ranges


# ----------------------------------------------------------------------
# P1 -- untrusted input in a prompt template
# ----------------------------------------------------------------------
def layer_p1(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not declares_prompt_surface(lines):
            continue
        ctx = classify_path(rel)
        for (s, e) in _prompt_handler_line_ranges(lines):
            # if the handler's arguments are themselves constrained (enum/Literal/
            # length/pattern), an interpolated value can't carry an arbitrary
            # payload -- Box-04 P5 already notes unconstrained args, so don't
            # double-flag a bounded one here.
            sig = "\n".join(lines[max(0, s - 1):min(len(lines), s + 3)])
            if CONSTRAINED.search(sig):
                continue
            for i in range(s, min(e, len(lines))):
                line = lines[i]
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*")):
                    continue
                if STRUCT_MSG.search(line):   # a structured {role, content} message is the safe form
                    continue
                builds = (FSTRING_PY.search(line) or FORMAT_CALL.search(line)
                          or CONCAT_PLUS.search(line) or JS_TEMPLATE_INTERP.search(line))
                if builds and TAINT_NAME.search(line):
                    # medium on its own: interpolating caller text into a prompt is a
                    # real smell but not, by itself, confirmed injection (P2/P3/P4 are
                    # the high/critical drivers).
                    sev = "medium" if ctx == "runtime" else downgrade("medium")
                    findings.append(F("P1", sev,
                        "Prompt handler builds its returned instruction text by interpolating a "
                        "caller-supplied argument (f-string / concat / template literal)",
                        rel, i + 1, snippet(line),
                        "Keep the prompt template fixed and pass caller values only as clearly "
                        "delimited data (e.g. inside quotes or a dedicated <user_input> block that "
                        "the surrounding template tells the model to treat as untrusted). Never "
                        "let a caller value land in the instruction portion of the prompt."))
                    break
    return findings


# ----------------------------------------------------------------------
# P2 -- SSTI into a prompt / message
# ----------------------------------------------------------------------
SSTI_SINKS = [
    (re.compile(r"\brender_template_string\s*\("), "Flask render_template_string()"),
    (re.compile(r"\bTemplate\s*\([^)]*\)\s*\.\s*render\s*\("), "Jinja2 Template().render()"),
    (re.compile(r"\.from_string\s*\("), "Jinja2 Environment.from_string()"),
    (re.compile(r"\b(?:Handlebars|Mustache)\.compile\s*\("), "Handlebars/Mustache.compile()"),
    (re.compile(r"\bejs\.render\s*\("), "ejs.render()"),
]


def layer_p2(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label in SSTI_SINKS:
                if rx.search(line) and TAINT_NAME.search(line):
                    sev = "critical" if ctx == "runtime" else downgrade("critical")
                    findings.append(F("P2", sev,
                        f"Caller-controlled value reaches {label} as the template SOURCE — "
                        "template syntax in the value is executed, not rendered as data",
                        rel, i, snippet(line),
                        "Never build the template string from caller input. Keep a fixed template "
                        "and pass caller values only as render context variables (which are "
                        "auto-escaped as data)."))
                    break
    return findings


# ----------------------------------------------------------------------
# P3 -- resource content flows into instructions
# ----------------------------------------------------------------------
READ_CALL = re.compile(r"\.read\s*\(|\bopen\s*\(|\brequests\.get\s*\(|\bfetch\s*\(|\baxios\.\w+\s*\(|\burlopen\s*\(")
INSTRUCTION_NAME = re.compile(r"(?i)\b(prompt|system|instruction|messages?|context|preamble|persona)\b")


def layer_p3(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        # track variables assigned from a read/fetch, then see if they feed an
        # instruction-shaped concatenation within a small window.
        read_vars = {}
        for i, line in enumerate(lines):
            m = re.match(r"\s*(\w+)\s*=\s*.*", line)
            if m and READ_CALL.search(line):
                read_vars[m.group(1)] = i
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if not INSTRUCTION_NAME.search(line):
                continue
            # instruction var built by concatenation referencing a read var
            if not (CONCAT_PLUS.search(line) or FSTRING_PY.search(line)
                    or JS_TEMPLATE_INTERP.search(line) or "+=" in line):
                continue
            for var, vi in read_vars.items():
                if 0 <= (i - 1) - vi <= 30 and re.search(r"\b" + re.escape(var) + r"\b", line):
                    sev = "high" if ctx == "runtime" else downgrade("high")
                    findings.append(F("P3", sev,
                        "Content read from a file/URL is concatenated into a prompt / system / "
                        "instruction string — a poisoned resource carries an injection payload "
                        "straight into the model's context",
                        rel, i, snippet(line),
                        "Treat fetched resource content as untrusted data: wrap it in a clearly "
                        "delimited, explicitly-untrusted block, and never place it in the "
                        "instruction/system portion of a prompt."))
                    break
    return findings


# ----------------------------------------------------------------------
# P4 -- unescaped interpolation into role-framed messages
# ----------------------------------------------------------------------
# Inline role/turn framing embedded IN a string -- forged-turn territory. The
# generic dict-key form ("role": "user") is the SAFE structured pattern and is
# handled by STRUCT_MSG below, not matched here.
ROLE_FRAME = re.compile(r"(?i)(system\s*:|assistant\s*:|###\s*instruction|<\|\w+\|>)")
STRUCT_MSG = re.compile(r"""["']role["']\s*:""")


def layer_p4(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if STRUCT_MSG.search(line):   # {"role": "...", "content": ...} is the safe structured form
                continue
            if not ROLE_FRAME.search(line):
                continue
            interpolates = (FSTRING_PY.search(line) or JS_TEMPLATE_INTERP.search(line)
                            or CONCAT_PLUS.search(line) or FORMAT_CALL.search(line))
            if interpolates and TAINT_NAME.search(line):
                sev = "high" if ctx == "runtime" else downgrade("high")
                findings.append(F("P4", sev,
                    "A caller-supplied value is interpolated into a string that also contains "
                    "role/turn framing (system:/assistant:/<|...|>) — the caller can forge a new "
                    "turn or a system instruction",
                    rel, i, snippet(line),
                    "Build messages structurally (a list of typed role/content objects), never by "
                    "concatenating caller text next to role markers in a single string; strip or "
                    "escape any role-delimiter tokens from caller input."))
    return findings


# ----------------------------------------------------------------------
# P5 -- unconstrained prompt arguments
# ----------------------------------------------------------------------
CONSTRAINED = re.compile(r"(?i)Literal\[|Enum\b|enum\b|maxLength|max_length|pattern\s*[:=]|regex|"
                         r"\bchoices\b|oneOf|\bconst\b")


def layer_p5(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not declares_prompt_surface(lines):
            continue
        ctx = classify_path(rel)
        for (s, e) in _prompt_handler_line_ranges(lines):
            # look at the signature line(s) for str-typed args with no constraint nearby
            head = "\n".join(lines[max(0, s - 2):min(len(lines), s + 3)])
            if re.search(r"[:(]\s*str\b|:\s*string\b|\btype\s*[:=]\s*[\"']string[\"']", head) \
               and not CONSTRAINED.search("\n".join(lines[max(0, s - 3):min(len(lines), e)])):
                # only report once per handler
                sev = "low" if ctx == "runtime" else "info"
                first = s if s < len(lines) else 0
                findings.append(F("P5", sev,
                    "Prompt argument is free-form text with no enum / length / pattern constraint — "
                    "nothing bounds what instruction payload it can carry",
                    rel, first + 1, snippet(lines[first] if first < len(lines) else ""),
                    "Constrain prompt arguments wherever the domain allows (an enum/Literal of "
                    "allowed values, a max length, a validating pattern) so a free-text injection "
                    "payload can't be supplied in the first place."))
    return findings


def verdict_for_findings(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    blocking = [f for f in findings if f["severity"] in ("critical", "high")]
    review = [f for f in findings if f["severity"] in ("medium", "low")]
    if blocking:
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- prompt / template injection indicators found",
                "next_step": "Fix every critical/high finding: a caller value or a fetched resource "
                             "can reach the model's instruction flow (via a prompt template, an "
                             "SSTI sink, or forged role framing). Keep templates fixed and pass "
                             "untrusted input only as clearly-delimited data.",
                "counts": counts}
    if review:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- prompt-handling weaknesses, none high-confidence",
                "next_step": "No high-confidence injection path was found, but the prompt handling "
                             "above lacks the constraints/escaping that keep it safe. A reviewer "
                             "should confirm each is intentional.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no prompt/template-injection findings",
            "next_step": "None of the five prompt-injection layers fired. Static scan of prompt "
                         "handlers and template sinks -- re-run on every change to prompts.",
            "counts": counts}


NAMES = {"P1": "Untrusted input in prompt template", "P2": "Server-side template injection",
         "P3": "Resource content into instructions", "P4": "Forged role-framed messages",
         "P5": "Unconstrained prompt arguments"}


def print_report(root, findings, v, show_all):
    print(f"\nBox-04 Prompt & Template Injection -- {root}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    by = {}
    for f in findings:
        by.setdefault(f["layer"], []).append(f)
    for layer in ("P1", "P2", "P3", "P4", "P5"):
        fs = by.get(layer, [])
        if not fs:
            continue
        fs.sort(key=lambda f: -SEV_ORDER[f["severity"]])
        print(f"\n--- {layer}: {NAMES[layer]} ({len(fs)}) ---")
        for f in (fs if show_all else fs[:6]):
            c = COLOR.get(f["severity"], "")
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"{c}[{f['severity'].upper():8}]{RESET} {f['title']}")
            print(f"           {loc}")
            if f["evidence"]:
                print(f"           {f['evidence']}")
    print("\n" + "=" * 72)
    color = {"PASS": "\033[92m", "REVIEW": "\033[93m", "FAIL": "\033[91m"}[v["status"]]
    print(f"VERDICT: {color}{v['headline']}{RESET}\n  {v['next_step']}  (exit {v['exit_code']})\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = os.path.abspath(args.repo)
    findings = []
    findings += layer_p1(root)
    findings += layer_p2(root)
    findings += layer_p3(root)
    findings += layer_p4(root)
    findings += layer_p5(root)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))
    v = verdict_for_findings(findings)
    if args.json:
        print(json.dumps({"repo": root, "findings": findings, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, args.all)
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
