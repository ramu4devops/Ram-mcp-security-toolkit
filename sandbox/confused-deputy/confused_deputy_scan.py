#!/usr/bin/env python3
"""
confused_deputy_scan.py -- Box-9: Confused Deputy & Authorization.

Static assessment of a cloned MCP server repo. Reads files only; nothing
from the target repo is ever executed.

An MCP server is a classic confused-deputy setup: it often holds its own
privileged credential (an API key, a service-account token, an OAuth
client secret) and acts on a caller's behalf every time a tool runs. If
the server doesn't check *who* is asking and *what they're allowed to do*
before using that credential, any caller who can reach the server inherits
all of its privilege -- the deputy is confused about whose authority it is
exercising.

Five layers:

  A1  Shared/static privileged credential used inside a tool handler with
      no visible per-caller identity or scope check in that handler.
  A2  Privileged/write-shaped operation (delete/admin/write/grant) with no
      authorization check found nearby.
  A3  Bearer/access token accepted as a parameter and forwarded to another
      call with no audience/scope/expiry validation (OAuth token
      pass-through -- the MCP-specific confused-deputy pattern).
  A4  Caller-supplied identity parameter (user_id/tenant_id/account_id)
      used to scope a privileged action without checking it matches the
      authenticated session/context -- an impersonation vector.
  A5  No authorization framework detected anywhere in a repo that exposes
      MCP tools/resources at all (informational -- confirms whether any
      per-call authz exists in the codebase).

Usage:
    python3 confused_deputy_scan.py /path/to/repo
    python3 confused_deputy_scan.py /path/to/repo --json

Exit codes:
    0 = PASS      no findings
    1 = REVIEW    medium/low findings only -- human review required
    2 = FAIL      critical/high findings -- gate the submission
"""
import os, re, sys, json, argparse
from authlib import walk_repo, read_lines, snippet, classify_path, CODE_EXTS

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


MCP_RESOURCE_DECORATOR = re.compile(r"@(?:\w+\.)?resource\s*\(")
MCP_TOOL_DECORATOR = re.compile(r"@(?:\w+\.)?tool\s*\(")
MCP_HANDLER_JS = re.compile(r"(?:server\.)?(?:tool|setRequestHandler)\s*\(")


def file_declares_mcp_surface(text):
    return bool(MCP_RESOURCE_DECORATOR.search(text) or MCP_TOOL_DECORATOR.search(text)
                or MCP_HANDLER_JS.search(text) or "tools/call" in text)


AUTHZ_HINT = re.compile(
    r"(?i)\b(?:require[_-]?(?:auth|permission|role|scope)|check[_-]?(?:auth|permission|"
    r"role|scope|access)|is[_-]?authorized|has[_-]?permission|has[_-]?role|"
    r"@(?:login_required|requires_auth|permission_required)|authorize\s*\(|"
    r"can\s*\(\s*['\"]|ability\.can|casl|policy\.enforce|enforcer\.enforce|rbac|abac)\b")

AUTHN_CONTEXT_HINT = re.compile(
    r"(?i)\b(?:current_user|req\.user|request\.user|ctx\.user|session\[['\"]?user|"
    r"get_current_user|authenticated_user|caller_id|principal)\b")


# ----------------------------------------------------------------------
# A1 -- shared/static privileged credential used inside a handler with no
#        visible caller-identity check in that same handler
# ----------------------------------------------------------------------
PRIV_CRED_USE = re.compile(
    r"(?i)\b(?:os\.getenv\s*\(\s*['\"](?:[A-Z0-9_]*(?:API|SERVICE|CLIENT)[A-Z0-9_]*"
    r"(?:KEY|SECRET|TOKEN)[A-Z0-9_]*)['\"]|process\.env\.[A-Z0-9_]*(?:API|SERVICE|CLIENT)"
    r"[A-Z0-9_]*(?:KEY|SECRET|TOKEN)[A-Z0-9_]*)\b")
DECORATOR_LINE = re.compile(r"^\s*@")
DEF_LINE = re.compile(r"^\s*(?:async\s+)?(?:def|function)\s+(\w+)")


def _handler_windows(lines):
    """Yield (start, end, header) index ranges for python 'def'/js
    'function'/arrow-exported handlers, using indentation/blank-line
    heuristics -- not a real parser, good enough to scope a line window."""
    out = []
    n = len(lines)
    i = 0
    while i < n:
        m = DEF_LINE.match(lines[i])
        if m:
            start = i
            base_indent = len(lines[i]) - len(lines[i].lstrip())
            j = i + 1
            while j < n:
                l = lines[j]
                if l.strip() == "":
                    j += 1
                    continue
                indent = len(l) - len(l.lstrip())
                if indent <= base_indent and not l.strip().startswith(("#", "//")):
                    break
                j += 1
            out.append((start, min(j, n), m.group(1)))
            i = j
        else:
            i += 1
    return out


MODULE_CRED_ASSIGN = re.compile(
    r"(?i)^\s*([A-Z][A-Z0-9_]{2,})\s*[:=].*(?:os\.getenv\s*\(|os\.environ|"
    r"process\.env\.)")


def _module_credential_names(lines):
    """Module-level constants assigned from an env-var read whose NAME looks
    privileged (API/SERVICE/CLIENT ... KEY/SECRET/TOKEN) -- the common real
    pattern of 'load the credential once, use the variable everywhere'."""
    names = set()
    for line in lines:
        m = MODULE_CRED_ASSIGN.match(line)
        if m and re.search(r"(?:API|SERVICE|CLIENT).*(?:KEY|SECRET|TOKEN)|(?:KEY|SECRET|TOKEN).*(?:API|SERVICE|CLIENT)", m.group(1)):
            names.add(m.group(1))
    return names


def layer_a1(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        text = "\n".join(lines)
        if not file_declares_mcp_surface(text):
            continue
        ctx = classify_path(rel)
        cred_names = _module_credential_names(lines)
        for start, end, name in _handler_windows(lines):
            window = lines[start:end]
            wtext = "\n".join(window)
            m = PRIV_CRED_USE.search(wtext)
            cred_ref_line = None
            if not m and cred_names:
                for cname in cred_names:
                    ref = re.search(r"\b" + re.escape(cname) + r"\b", wtext)
                    if ref:
                        cred_ref_line = ref.start()
                        break
            if not m and cred_ref_line is None:
                continue
            has_authz = bool(AUTHZ_HINT.search(wtext) or AUTHN_CONTEXT_HINT.search(wtext))
            if has_authz:
                continue
            offset = m.start() if m else cred_ref_line
            line_no = start + wtext[:offset].count("\n") + 1
            sev = "high" if ctx == "runtime" else downgrade("high")
            findings.append(F(
                "A1", sev,
                f"Handler '{name}' uses a shared/service-level credential with no visible per-caller authorization check",
                rel, line_no, snippet(window[min(len(window) - 1, line_no - start)] if window else ""),
                "Before using the server's own privileged credential on a caller's behalf, "
                "check that the calling identity/session is authorized for this specific "
                "action and resource. Otherwise every caller who can reach this tool "
                "inherits the full privilege of the server's own credential -- the textbook "
                "confused-deputy pattern."))
    return findings


# ----------------------------------------------------------------------
# A2 -- privileged/write-shaped operation with no authorization check
# ----------------------------------------------------------------------
PRIV_OP_NAME = re.compile(
    r"(?i)\b(?:def|function)\s+(\w*(?:delete|remove|admin|grant|revoke|approve|ban|"
    r"disable|enable|promote|demote|reset[_-]?password|change[_-]?role|impersonat|"
    r"set[_-]?permission|update[_-]?role)\w*)\s*\(")


def layer_a2(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        text = "\n".join(lines)
        if not file_declares_mcp_surface(text):
            continue
        ctx = classify_path(rel)
        for start, end, name in _handler_windows(lines):
            header = lines[start]
            if not PRIV_OP_NAME.search(header):
                continue
            window = "\n".join(lines[start:end])
            if AUTHZ_HINT.search(window):
                continue
            sev = "critical" if ctx == "runtime" else downgrade("critical", 2)
            findings.append(F(
                "A2", sev,
                f"Privileged-shaped operation '{name}' has no authorization check in its body",
                rel, start + 1, snippet(header),
                "Add an explicit authorization check (role/permission/scope) as the first "
                "thing this handler does, before performing the privileged action. A tool "
                "name alone ('delete_user', 'grant_access') is not a security control -- "
                "the model will call whatever tool the conversation leads it to."))
    return findings


# ----------------------------------------------------------------------
# A3 -- token pass-through with no audience/scope/expiry validation
# ----------------------------------------------------------------------
TOKEN_PARAM_FORWARD = re.compile(r"(?i)\bBearer[\"']?\s*(?:\+\s*)?\{?\s*([A-Za-z_][A-Za-z0-9_.]*)")
TOKEN_VALIDATION_HINT = re.compile(
    r"(?i)\b(?:verify(?:_jwt|_token)?|jwt\.decode|introspect|validate[_-]?token|"
    r"aud(?:ience)?\s*==|check[_-]?audience|token_info|tokeninfo|verify_signature)\b")


def _looks_like_forwarded_caller_token(varname):
    """True if the interpolated identifier looks like a caller-supplied
    parameter (lower/camel/snake case, e.g. access_token, callerToken) rather
    than the server's own SCREAMING_SNAKE_CASE credential constant."""
    leaf = varname.split(".")[-1]
    if leaf.upper() == leaf and len(leaf) > 2:
        return False  # ALL_CAPS constant -- the server's own credential
    return True


def layer_a3(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        text = "\n".join(lines)
        if not file_declares_mcp_surface(text):
            continue
        ctx = classify_path(rel)
        file_validates = bool(TOKEN_VALIDATION_HINT.search(text))
        if file_validates:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            bm = TOKEN_PARAM_FORWARD.search(line)
            if bm and _looks_like_forwarded_caller_token(bm.group(1)):
                sev = "high" if ctx == "runtime" else downgrade("high")
                findings.append(F(
                    "A3", sev,
                    "A bearer/access token is forwarded to another call with no audience/scope/expiry validation found in this file",
                    rel, i, snippet(line),
                    "Validate the token before using it: check its signature, that its "
                    "audience is this server (not just any resource that will accept it), "
                    "its scopes cover the requested action, and it hasn't expired. Passing a "
                    "token through unchecked lets a token minted for one purpose be replayed "
                    "against a different, more privileged downstream service through this "
                    "server."))
    return findings


# ----------------------------------------------------------------------
# A4 -- caller-supplied identity parameter trusted without cross-check
# ----------------------------------------------------------------------
IDENTITY_PARAM = re.compile(r"(?i)\b(?:user_id|tenant_id|account_id|org_id|owner_id|customer_id)\b")
IDENTITY_USE_SINK = re.compile(
    r"(?i)\b(?:where|filter|query|select|WHERE)\b.*(?:user_id|tenant_id|account_id|org_id|owner_id|customer_id)"
    r"|\.(?:find|get|delete|update)\w*\s*\([^)]*(?:user_id|tenant_id|account_id|org_id|owner_id|customer_id)")
SESSION_CROSS_CHECK = re.compile(
    r"(?i)\b(?:current_user\.id|req\.user\.id|session\[.user.\]\.id|ctx\.user\.id)\s*"
    r"(?:==|!=|is)\s*|assert\s+.*(?:user_id|tenant_id|account_id)")


def layer_a4(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        text = "\n".join(lines)
        if not file_declares_mcp_surface(text):
            continue
        ctx = classify_path(rel)
        for start, end, name in _handler_windows(lines):
            header = lines[start]
            if not IDENTITY_PARAM.search(header):
                continue
            window = "\n".join(lines[start:end])
            if not IDENTITY_USE_SINK.search(window):
                continue
            if SESSION_CROSS_CHECK.search(window) or AUTHN_CONTEXT_HINT.search(window):
                continue
            sev = "high" if ctx == "runtime" else downgrade("high")
            findings.append(F(
                "A4", sev,
                f"Handler '{name}' takes an identity parameter from the caller and uses it to scope data access with no cross-check against the authenticated session",
                rel, start + 1, snippet(header),
                "Never trust an identity value the caller supplies as an argument. Derive the "
                "acting identity from the authenticated session/context, and if a "
                "caller-supplied id is also present, verify it matches (or that the session "
                "is explicitly permitted to act on that id) before using it in any query or "
                "mutation -- otherwise any caller can read or modify another tenant's data "
                "just by passing a different id."))
    return findings


# ----------------------------------------------------------------------
# A5 -- no authorization framework anywhere in an MCP-surfaced repo
# ----------------------------------------------------------------------
def layer_a5(root):
    any_mcp_surface = False
    any_authz = False
    example_file = None
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        text = "\n".join(lines)
        if file_declares_mcp_surface(text):
            any_mcp_surface = True
            if example_file is None:
                example_file = rel
        if AUTHZ_HINT.search(text) or AUTHN_CONTEXT_HINT.search(text):
            any_authz = True
    if any_mcp_surface and not any_authz:
        return [F(
            "A5", "medium",
            "No authorization/authentication-context pattern found anywhere in this repo",
            example_file or ".", 0,
            "no require_auth / current_user / role / permission / scope pattern matched in any scanned file",
            "This server exposes MCP tools/resources but nothing in the codebase checks who "
            "is calling or what they're allowed to do. If every tool is genuinely meant to be "
            "unauthenticated and equally available to any caller, document that explicitly; "
            "otherwise add an authorization layer before this server is approved for use with "
            "any privileged backend.")]
    return []


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
                "headline": "FAIL -- confused-deputy / authorization indicators found",
                "next_step": "Fix every critical/high finding -- a privileged operation or a "
                             "shared credential with no per-caller authorization check means "
                             "any caller who can reach this server inherits its full "
                             "privilege. Gate the submission until each is resolved.",
                "counts": counts}
    if review:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- authorization weaknesses, none high-confidence",
                "next_step": "No high-confidence confused-deputy pattern was found, but the "
                             "gaps above (missing authz framework, unvalidated identity "
                             "params) need a human decision before approval.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no confused-deputy / authorization findings",
            "next_step": "None of the five confused-deputy/authorization layers fired. This "
                         "is a static scan of handler bodies -- re-run on every change to "
                         "tool/resource handlers or the auth layer.",
            "counts": counts}


def print_report(root, findings, v, show_all):
    print(f"\nBox-9 Confused Deputy & Authorization -- {root}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    by_layer = {}
    for f in findings:
        by_layer.setdefault(f["layer"], []).append(f)
    NAMES = {"A1": "Shared credential, no caller-authz check",
             "A2": "Privileged operation, no authorization check",
             "A3": "Token pass-through, no audience/scope validation",
             "A4": "Untrusted caller-supplied identity parameter",
             "A5": "No authorization framework detected"}
    for layer in ("A1", "A2", "A3", "A4", "A5"):
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
    findings += layer_a1(root)
    findings += layer_a2(root)
    findings += layer_a3(root)
    findings += layer_a4(root)
    findings += layer_a5(root)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))

    v = verdict_for_findings(findings)

    if args.json:
        print(json.dumps({"repo": root, "findings": findings, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, args.all)
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
