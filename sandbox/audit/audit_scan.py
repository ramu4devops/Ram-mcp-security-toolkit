#!/usr/bin/env python3
"""
audit_scan.py -- Box-13: Audit, Telemetry & Logging.

Static assessment of whether an MCP server produces enough of an audit trail
for a security team to investigate an incident after the fact -- and whether
its logging is itself a liability (secrets/PII written to logs, or noisy
stdout logging that corrupts the stdio JSON-RPC channel).

This is an ASSURANCE module: most findings are gaps (medium/low) rather than
active exploits, so the module leans toward REVIEW rather than FAIL. The one
genuinely high-severity case is sensitive data written into logs (T3).

Five layers:

  T1  No logging framework configured -- the server exposes MCP tools but no
      logging library is imported/configured anywhere. Nothing is recorded.
  T2  Tool invocations not audited -- individual tool handlers run without
      emitting any log/audit line, so there's no record of what was called.
  T3  Sensitive data written to logs -- a log/print call whose arguments
      look like a secret or PII (token, password, key, env dump, email, SSN).
      This is both a leak and, on a stdio server, protocol corruption.
  T4  Privileged operation without an audit record -- a delete/admin/grant/
      revoke-shaped handler with no log call anywhere in its body.
  T5  Debug / verbose logging left enabled -- DEBUG-level logging, setLevel
      (DEBUG), console.debug, or print()-as-logging in runtime code, which
      both over-shares and (on stdio servers) pollutes the transport.

Usage:
    python3 audit_scan.py /path/to/repo [--json] [--all]

Exit codes: 0 = PASS, 1 = REVIEW, 2 = FAIL.
"""
import os, re, sys, json, argparse
from auditlib import (walk_repo, read_lines, snippet, classify_path, CODE_EXTS,
                      LOG_FRAMEWORK, LOG_CALL, TOOL_DECOR, PRIV_NAME, declares_tool_surface)

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"


def F(layer, severity, title, path, line_no, evidence, remediation):
    return {"layer": layer, "severity": severity, "title": title,
            "file": path, "line": line_no, "evidence": evidence,
            "remediation": remediation}


def _iter(root):
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        if lines:
            yield path, rel, lines


SECRET_IN_LOG = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|bearer|authorization|session[_-]?id|"
    r"os\.environ|process\.env|\.env\b|ssn|social.?security)\b")
PII_IN_LOG = re.compile(r"(?i)\b(email|e-mail|phone|address|dob|birth|credit.?card|card.?number)\b")


def _handler_ranges(lines):
    """Yield (name, start, end) for each tool-decorated function body, bounding
    the body by dedent / next decorator / next def so it never overruns into
    module-level code (which would falsely satisfy the 'has a log call' check)."""
    ranges = []
    n = len(lines)
    for i, line in enumerate(lines):
        if TOOL_DECOR.search(line) or re.search(r"registerTool\s*\(|server\.tool\s*\(", line):
            j = i + 1
            name = "?"
            while j < n and j - i < 6:
                m = re.search(r"\b(?:def|function)\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s*)?\(", lines[j])
                if m:
                    name = m.group(1) or m.group(2) or "?"
                    break
                j += 1
            start = min(j, n - 1) if n else 0
            def_indent = len(lines[start]) - len(lines[start].lstrip()) if start < n else 0
            end = start + 1
            while end < n:
                l = lines[end]
                if l.strip() == "":
                    end += 1
                    continue
                indent = len(l) - len(l.lstrip())
                # the body is always more indented than the def line; the first
                # non-blank line at or below the def's indent ends it.
                if indent <= def_indent:
                    break
                if end - start > 60:
                    break
                end += 1
            ranges.append((name, start, end))
    return ranges


# ----------------------------------------------------------------------
# T1 -- no logging framework configured at all
# ----------------------------------------------------------------------
def layer_t1(root):
    any_surface = False
    has_framework = False
    surface_file = None
    for path, rel, lines in _iter(root):
        if declares_tool_surface(lines):
            any_surface = True
            surface_file = surface_file or rel
        if any(LOG_FRAMEWORK.search(l) for l in lines):
            has_framework = True
    if any_surface and not has_framework:
        return [F("T1", "medium",
                  "The server exposes MCP tools but no logging framework is imported or configured "
                  "anywhere in the repository — tool activity leaves no audit trail",
                  surface_file or "(repo)", 0, "no logging/structlog/winston/pino import found",
                  "Add a structured logging framework and initialise it at startup; log every tool "
                  "invocation (who / which tool / arguments summary / outcome) to a persistent, "
                  "SOC-ingestible sink — not stdout on a stdio server.")]
    return []


# ----------------------------------------------------------------------
# T2 -- tool handlers with no audit line
# ----------------------------------------------------------------------
def layer_t2(root):
    findings = []
    for path, rel, lines in _iter(root):
        if not declares_tool_surface(lines):
            continue
        ctx = classify_path(rel)
        if ctx != "runtime":
            continue
        for name, s, e in _handler_ranges(lines):
            body = lines[s:min(e, len(lines))]
            if not any(LOG_CALL.search(b) for b in body):
                findings.append(F("T2", "low",
                    f"Tool handler '{name}' emits no log/audit line — its invocations are not "
                    "recorded, so there is no trail of what was called or with what arguments",
                    rel, s + 1, snippet(lines[s] if s < len(lines) else ""),
                    "Log an audit record at the start (and ideally the outcome) of every tool "
                    "handler: the tool name, a summary of the arguments, the calling context, and "
                    "success/failure."))
    return findings


# ----------------------------------------------------------------------
# T3 -- sensitive data written to logs
# ----------------------------------------------------------------------
def layer_t3(root):
    findings = []
    for path, rel, lines in _iter(root):
        ctx = classify_path(rel)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if not LOG_CALL.search(line):
                continue
            if SECRET_IN_LOG.search(line):
                sev = "high" if ctx == "runtime" else "low"
                findings.append(F("T3", sev,
                    "A log / print call includes what looks like a secret or credential — this both "
                    "leaks the secret into log storage and, on a stdio MCP server, corrupts the "
                    "JSON-RPC transport",
                    rel, i, snippet(line),
                    "Never log secrets, tokens, environment dumps, or authorization headers. Redact "
                    "or omit them; log an opaque reference (e.g. a key id or a hash) if a record is "
                    "needed."))
            elif PII_IN_LOG.search(line):
                sev = "medium" if ctx == "runtime" else "info"
                findings.append(F("T3", sev,
                    "A log / print call includes what looks like PII (email / phone / address / "
                    "card) — logging PII creates a privacy and retention liability",
                    rel, i, snippet(line),
                    "Avoid logging PII; mask or tokenise it if a record is genuinely required, and "
                    "document the retention/redaction policy."))
    return findings


# ----------------------------------------------------------------------
# T4 -- privileged operation with no audit record
# ----------------------------------------------------------------------
def layer_t4(root):
    findings = []
    for path, rel, lines in _iter(root):
        if not declares_tool_surface(lines):
            continue
        ctx = classify_path(rel)
        if ctx != "runtime":
            continue
        for name, s, e in _handler_ranges(lines):
            if not PRIV_NAME.search(name):
                # also allow: the body performs a privileged-looking op
                body_head = " ".join(lines[s:min(s + 4, len(lines))])
                if not PRIV_NAME.search(body_head):
                    continue
            body = lines[s:min(e, len(lines))]
            if not any(LOG_CALL.search(b) for b in body):
                findings.append(F("T4", "medium",
                    f"Privileged-looking handler '{name}' (delete / admin / grant / revoke shape) "
                    "performs its action with no audit log — a destructive or privilege-changing "
                    "action would leave no forensic record",
                    rel, s + 1, snippet(lines[s] if s < len(lines) else ""),
                    "Emit a tamper-evident audit record for every privileged operation: the actor, "
                    "the target, the action, the timestamp, and the result — before and after the "
                    "action."))
    return findings


# ----------------------------------------------------------------------
# T5 -- debug / verbose logging left on
# ----------------------------------------------------------------------
DEBUG_LOG = re.compile(
    r"(?i)(logging\.DEBUG|setLevel\s*\(\s*(?:logging\.)?DEBUG|level\s*=\s*[\"']?debug|"
    r"console\.debug\s*\(|\.debug\s*\(\s*True|DEBUG\s*=\s*True|basicConfig\([^)]*DEBUG)")


def layer_t5(root):
    findings = []
    for path, rel, lines in _iter(root):
        ctx = classify_path(rel)
        if ctx != "runtime":
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if DEBUG_LOG.search(line):
                findings.append(F("T5", "low",
                    "Debug / verbose logging appears to be enabled in runtime code — debug logs "
                    "over-share internal detail and, on a stdio server, add noise to the transport",
                    rel, i, snippet(line),
                    "Default to INFO/WARN in production; gate DEBUG behind an explicit, off-by-"
                    "default environment flag, and never write debug output to the stdio channel."))
    return findings


def verdict_for_findings(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    # T3 secrets-in-logs (high) is the only blocking condition; everything else
    # is an assurance gap that needs review, not an outright gate.
    if any(f["severity"] in ("critical", "high") for f in findings):
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- sensitive data written to logs",
                "next_step": "Remove every secret/credential from log and print calls before this "
                             "server is approved — logged secrets are both a leak and, on a stdio "
                             "server, protocol corruption. Then address the audit-coverage gaps.",
                "counts": counts}
    if findings:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- audit / telemetry gaps",
                "next_step": "No secret was found in a log call, but the server's audit trail has "
                             "gaps (missing logging framework, un-logged tool or privileged "
                             "handlers, or debug logging left on). A reviewer should decide whether "
                             "the telemetry is sufficient for incident investigation.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no audit / telemetry findings",
            "next_step": "A logging framework is present, tool and privileged handlers emit audit "
                         "lines, no secrets/PII were seen in log calls, and debug logging is not "
                         "left on. Static assurance check -- re-run on change.",
            "counts": counts}


NAMES = {"T1": "No logging framework", "T2": "Tool invocations not audited",
         "T3": "Sensitive data in logs", "T4": "Privileged op without audit",
         "T5": "Debug logging left on"}


def print_report(root, findings, v, show_all):
    print(f"\nBox-13 Audit, Telemetry & Logging -- {root}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    by = {}
    for f in findings:
        by.setdefault(f["layer"], []).append(f)
    for layer in ("T1", "T2", "T3", "T4", "T5"):
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
    findings += layer_t1(root)
    findings += layer_t2(root)
    findings += layer_t3(root)
    findings += layer_t4(root)
    findings += layer_t5(root)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))
    v = verdict_for_findings(findings)
    if args.json:
        print(json.dumps({"repo": root, "findings": findings, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, args.all)
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
