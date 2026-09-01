#!/usr/bin/env python3
"""
sast_scan.py -- Box-8: Static Code Security (SAST).

Static assessment of a cloned MCP server repo. Reads files only; nothing
from the target repo is ever executed. Looks for the code-level patterns
that let a caller-controlled MCP tool argument reach a dangerous native
sink -- the layer above "is this dependency vulnerable" (Box-7) and below
"does this tool description lie" (Box-1): what the handler's own code does
with the arguments once the model hands them over.

Five layers:

  C1  OS command injection -- a caller-controlled value reaches a shell
      (subprocess with shell=True, os.system/os.popen, child_process.exec)
      instead of an argv-array call that never invokes a shell.
  C2  Code injection / dynamic evaluation -- a caller-controlled value
      reaches eval/exec/compile (Python) or eval/new Function/vm.runIn*
      (Node), letting a tool argument execute as code.
  C3  Insecure deserialization -- pickle.load(s)/marshal.load(s) on
      caller-reachable input, or yaml.load() without a safe loader, any of
      which can execute code embedded in the serialized payload.
  C4  SQL / NoSQL injection -- a query string built by f-string/%/+
      concatenation instead of a parameterized placeholder, or a NoSQL
      operator (`$where`) built from caller input.
  C5  Server-side template injection (SSTI) -- a caller-controlled string
      reaches a template renderer (render_template_string, Jinja2
      Template(), a JS template-engine .compile/.render) as the template
      source itself, not just as data passed into a fixed template.

Usage:
    python3 sast_scan.py /path/to/repo
    python3 sast_scan.py /path/to/repo --json

Exit codes:
    0 = PASS      no findings
    1 = REVIEW    medium/low findings only -- human review required
    2 = FAIL      critical/high findings -- gate the submission
"""
import os, re, sys, json, argparse
from sastlib import walk_repo, read_lines, snippet, classify_path, CODE_EXTS

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_CHAIN = ["info", "low", "medium", "high", "critical"]
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"


def F(layer, severity, title, path, line_no, evidence, remediation, extra=None):
    f = {"layer": layer, "severity": severity, "title": title,
         "file": path, "line": line_no, "evidence": evidence,
         "remediation": remediation}
    if extra:
        f.update(extra)
    return f


def downgrade(sev, steps=1):
    i = SEV_CHAIN.index(sev)
    return SEV_CHAIN[max(0, i - steps)]


# ----------------------------------------------------------------------
# Shared taint-ish vocabulary -- same idea as Box-5's reslib TAINT_NAME:
# variable/parameter names that plausibly carry CALLER-controlled data (an
# MCP tool argument, a resource URI segment, a request field). Not proof of
# taint -- the signal a static, non-executing scanner can reasonably use.
# ----------------------------------------------------------------------
TAINT_NAME = re.compile(
    r"(?i)\b(?:arg|args|argument|arguments|param|params|kwargs|input|query|"
    r"cmd|command|script|code|expr|expression|template|payload|body|user|"
    r"name|value|text|content|data|target|url|uri|path|req(?:uest)?\.(?:params|query|body))\b")

MCP_TOOL_DECORATOR = re.compile(r"@(?:\w+\.)?tool\s*\(")
MCP_RESOURCE_DECORATOR = re.compile(r"@(?:\w+\.)?resource\s*\(")


def file_declares_mcp_surface(lines):
    text = "\n".join(lines)
    return bool(MCP_TOOL_DECORATOR.search(text) or MCP_RESOURCE_DECORATOR.search(text)
                or "tools/call" in text or "server.tool(" in text or "registerTool(" in text)


def _iter_code_lines(root):
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        if not lines:
            continue
        yield path, rel, lines


# ----------------------------------------------------------------------
# C1 -- OS command injection
# ----------------------------------------------------------------------
SHELL_TRUE = re.compile(r"shell\s*=\s*True")
CMD_SINKS_PY = [
    (re.compile(r"\bos\.system\s*\("), "os.system()"),
    (re.compile(r"\bos\.popen\s*\("), "os.popen()"),
    (re.compile(r"\bsubprocess\.(?:call|run|check_call|check_output|Popen)\s*\("), "subprocess.*()"),
]
CMD_SINKS_JS = [
    (re.compile(r"\bchild_process\.exec\s*\("), "child_process.exec()"),
    (re.compile(r"\bchild_process\.execSync\s*\("), "child_process.execSync()"),
    (re.compile(r"(?<!\.)\bexec\s*\(\s*[`\"']?[^)]*\$\{"), "exec() with a template literal"),
]


def layer_c1(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not file_declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label in CMD_SINKS_PY:
                if rx.search(line) and TAINT_NAME.search(line):
                    shell_flag = SHELL_TRUE.search(line) or (
                        i < len(lines) and SHELL_TRUE.search("\n".join(lines[i:min(len(lines), i + 2)])))
                    if label == "subprocess.*()" and not shell_flag:
                        # argv-array form (no shell=True) never invokes a shell --
                        # still worth a lower-severity note if it's built from taint.
                        sev = "low" if ctx == "runtime" else "info"
                        findings.append(F("C1", sev,
                            "subprocess call built from a tool argument, but no shell=True found "
                            "(argv-array form does not invoke a shell -- confirm the argument list "
                            "itself isn't concatenated into a single string)",
                            rel, i, snippet(line),
                            "Keep using the argv-array form (no shell=True) and pass each argument "
                            "as its own list element -- never join them into one string."))
                        continue
                    sev = "critical" if ctx == "runtime" else downgrade("critical")
                    findings.append(F("C1", sev,
                        f"Caller-controlled value reaches a shell via {label}"
                        + (" with shell=True" if shell_flag else ""),
                        rel, i, snippet(line),
                        "Never build a shell command string from caller input. Use the argv-array "
                        "form (subprocess.run([...], shell=False)) so the value is passed as a "
                        "single argument, not interpreted by a shell -- and validate/allowlist the "
                        "value regardless."))
                    break
            for rx, label in CMD_SINKS_JS:
                if rx.search(line) and (TAINT_NAME.search(line) or "${" in line):
                    sev = "critical" if ctx == "runtime" else downgrade("critical")
                    findings.append(F("C1", sev,
                        f"Caller-controlled value reaches a shell via {label}",
                        rel, i, snippet(line),
                        "Use child_process.execFile()/spawn() with an argument array instead of "
                        "exec()/execSync() with an interpolated string -- execFile/spawn never "
                        "invoke a shell, so shell metacharacters in the argument can't matter."))
                    break
    return findings


# ----------------------------------------------------------------------
# C2 -- code injection / dynamic evaluation
# ----------------------------------------------------------------------
EVAL_SINKS_PY = [
    (re.compile(r"(?<!\.)\beval\s*\("), "eval()"),
    (re.compile(r"(?<!\.)\bexec\s*\("), "exec()"),
    (re.compile(r"\bcompile\s*\([^)]*[\"']exec[\"']"), "compile(..., 'exec')"),
]
EVAL_SINKS_JS = [
    (re.compile(r"(?<!\.)\beval\s*\("), "eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()"),
    (re.compile(r"\bvm\.runInNewContext\s*\(|\bvm\.runInThisContext\s*\(|\bvm\.runInContext\s*\("), "vm.runIn*()"),
]


def layer_c2(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not file_declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        sinks = EVAL_SINKS_PY if rel.endswith(".py") else EVAL_SINKS_JS
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label in sinks:
                if rx.search(line):
                    tainted = bool(TAINT_NAME.search(line))
                    sev = ("critical" if tainted else "high")
                    if ctx != "runtime":
                        sev = downgrade(sev)
                    findings.append(F("C2", sev,
                        f"Dynamic code evaluation via {label}"
                        + (" on what looks like a tool argument" if tainted else ""),
                        rel, i, snippet(line),
                        "Remove the eval/exec/Function-constructor path entirely if possible. If "
                        "a tool genuinely needs to evaluate an expression, use a restricted "
                        "expression parser (e.g. a whitelisted AST evaluator) instead of the "
                        "language's own interpreter -- eval() on caller input is equivalent to "
                        "full remote code execution."))
                    break
    return findings


# ----------------------------------------------------------------------
# C3 -- insecure deserialization
# ----------------------------------------------------------------------
DESER_SINKS = [
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle.load(s)()", "critical"),
    (re.compile(r"\bmarshal\.loads?\s*\("), "marshal.load(s)()", "critical"),
    (re.compile(r"\byaml\.load\s*\("), "yaml.load()", "high"),
    (re.compile(r"\.unserialize\s*\("), "node-serialize .unserialize()", "critical"),
]
YAML_SAFE_HINT = re.compile(r"(?i)SafeLoader|yaml\.safe_load")


def layer_c3(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label, base_sev in DESER_SINKS:
                if not rx.search(line):
                    continue
                if label == "yaml.load()":
                    lo, hi = max(0, i - 2), min(len(lines), i + 1)
                    if YAML_SAFE_HINT.search("\n".join(lines[lo:hi])):
                        continue
                sev = base_sev if ctx == "runtime" else downgrade(base_sev)
                findings.append(F("C3", sev,
                    f"Insecure deserialization via {label} -- a crafted payload can execute "
                    "arbitrary code during deserialization, not just supply data",
                    rel, i, snippet(line),
                    "Never unpickle/unmarshal data that reaches this server from outside your "
                    "own process. Use a data-only format (JSON) or, for YAML, always call "
                    "yaml.safe_load() / yaml.load(..., Loader=yaml.SafeLoader)."))
                break
    return findings


# ----------------------------------------------------------------------
# C4 -- SQL / NoSQL injection
# ----------------------------------------------------------------------
EXECUTE_CALL = re.compile(r"\.execute\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+)|[\"'][^\"']*\{)")
EXECUTE_FSTRING = re.compile(r"\.execute\s*\(\s*f[\"']")
EXECUTE_CONCAT = re.compile(r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*(?:%|\+)\s*\w")
JS_SQL_TEMPLATE = re.compile(r"\b(?:query|execute)\s*\(\s*`[^`]*\$\{")
MONGO_WHERE = re.compile(r"[\"']\$where[\"']\s*:")
PLACEHOLDER_HINT = re.compile(r"%s|\?\s*,|\bparamstyle\b")


def layer_c4(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if EXECUTE_FSTRING.search(line) or EXECUTE_CONCAT.search(line):
                sev = "critical" if ctx == "runtime" else downgrade("critical")
                findings.append(F("C4", sev,
                    "SQL query built by string formatting/concatenation instead of a "
                    "parameterized placeholder",
                    rel, i, snippet(line),
                    "Pass values as query parameters (cursor.execute(\"... WHERE id = %s\", "
                    "(value,))) instead of interpolating them into the query string -- the "
                    "driver then escapes the value instead of it becoming part of the SQL."))
                continue
            if JS_SQL_TEMPLATE.search(line):
                sev = "critical" if ctx == "runtime" else downgrade("critical")
                findings.append(F("C4", sev,
                    "SQL/NoSQL query built from a template literal with an interpolated value",
                    rel, i, snippet(line),
                    "Use the driver's parameterized query form (placeholders + a values array) "
                    "instead of interpolating a value directly into the query template literal."))
                continue
            if MONGO_WHERE.search(line) and TAINT_NAME.search(line):
                sev = "high" if ctx == "runtime" else downgrade("high")
                findings.append(F("C4", sev,
                    "MongoDB $where operator built from what looks like caller input -- $where "
                    "runs as JavaScript server-side",
                    rel, i, snippet(line),
                    "Avoid $where entirely for caller-influenced queries; express the condition "
                    "with standard query operators instead, which cannot execute code."))
    return findings


# ----------------------------------------------------------------------
# C5 -- server-side template injection (SSTI)
# ----------------------------------------------------------------------
SSTI_SINKS = [
    (re.compile(r"\brender_template_string\s*\("), "Flask render_template_string()"),
    (re.compile(r"\bTemplate\s*\(\s*[^)]*\)\s*\.\s*render\s*\("), "Jinja2 Template().render()"),
    (re.compile(r"\b(?:Handlebars|Mustache)\.compile\s*\("), "template-engine .compile()"),
    (re.compile(r"\bejs\.render\s*\("), "ejs.render()"),
]


def layer_c5(root):
    findings = []
    for path, rel, lines in _iter_code_lines(root):
        if not file_declares_mcp_surface(lines):
            continue
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label in SSTI_SINKS:
                if rx.search(line) and TAINT_NAME.search(line):
                    sev = "critical" if ctx == "runtime" else downgrade("critical")
                    findings.append(F("C5", sev,
                        f"Caller-controlled value reaches {label} as the TEMPLATE SOURCE itself, "
                        "not as data rendered into a fixed template",
                        rel, i, snippet(line),
                        "Never build the template string from caller input. Keep a fixed template "
                        "on disk / in source, and pass caller-supplied values only as render "
                        "context variables -- template syntax in a context variable is auto-"
                        "escaped as data, but template syntax in the template source itself is "
                        "executed."))
                    break
    return findings


# ----------------------------------------------------------------------
# Verdict
# ----------------------------------------------------------------------
def verdict_for_findings(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    blocking = [f for f in findings if f["severity"] in ("critical", "high")]
    review = [f for f in findings if f["severity"] in ("medium", "low")]
    if blocking:
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- static code security indicators found",
                "next_step": "Fix every critical/high finding (command injection, code "
                             "injection/eval, insecure deserialization, SQL/NoSQL injection, or "
                             "SSTI) before this server is approved -- each is a path from a tool "
                             "argument to arbitrary code execution or data-store compromise.",
                "counts": counts}
    if review:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- code-security weaknesses, none high-confidence",
                "next_step": "No high-confidence RCE-shaped pattern was found, but the sinks "
                             "above lack the guard/allowlist that keeps them safe. A reviewer "
                             "should confirm each is intentional.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no static-code-security findings",
            "next_step": "None of the five SAST layers fired. This is a static scan of source "
                         "call sites -- re-run on every change to tool/resource handlers.",
            "counts": counts}


def print_report(root, findings, v, show_all):
    print(f"\nBox-8 Static Code Security (SAST) -- {root}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    by_layer = {}
    for f in findings:
        by_layer.setdefault(f["layer"], []).append(f)
    NAMES = {"C1": "OS command injection", "C2": "Code injection / dynamic eval",
             "C3": "Insecure deserialization", "C4": "SQL/NoSQL injection",
             "C5": "Server-side template injection"}
    for layer in ("C1", "C2", "C3", "C4", "C5"):
        fs = by_layer.get(layer, [])
        if not fs:
            continue
        fs.sort(key=lambda f: -SEV_ORDER[f["severity"]])
        print(f"\n--- {layer}: {NAMES[layer]} ({len(fs)} finding(s)) ---")
        shown = fs if show_all else fs[:6]
        for f in shown:
            c = COLOR.get(f["severity"], "")
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"{c}[{f['severity'].upper():8}]{RESET} {f['title']}")
            print(f"           {loc}")
            if f["evidence"]:
                print(f"           {f['evidence']}")
        if len(fs) > len(shown):
            print(f"           ... and {len(fs) - len(shown)} more (use --all to list)")
    print("\n" + "=" * 72)
    c = v["counts"]
    summary = ", ".join(f"{n} {s}" for s, n in sorted(c.items(), key=lambda kv: -SEV_ORDER[kv[0]])) or "none"
    print(f"Summary: {len(findings)} finding(s) -- {summary}")
    color = {"PASS": "\033[92m", "REVIEW": "\033[93m", "FAIL": "\033[91m"}[v["status"]]
    print(f"\nVERDICT: {color}{v['headline']}{RESET}")
    print(f"  {v['next_step']}")
    print(f"  (exit code {v['exit_code']})\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.repo)
    findings = []
    findings += layer_c1(root)
    findings += layer_c2(root)
    findings += layer_c3(root)
    findings += layer_c4(root)
    findings += layer_c5(root)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))

    v = verdict_for_findings(findings)

    if args.json:
        print(json.dumps({"repo": root, "findings": findings, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, args.all)
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
