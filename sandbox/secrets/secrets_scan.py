#!/usr/bin/env python3
"""
secrets_scan.py -- Box-6: Secrets Management & Token Handling.

Static assessment of a cloned MCP server repo. Reads files only; never
executes anything from the target repo, so it is safe to point at an
unreviewed clone with no sandbox of its own.

Six layers, in order of MCP-specificity:

  S1  Hardcoded credentials in the working tree
  S2  Credentials in GIT HISTORY (deleted from HEAD != gone)      [--history]
  S3  Secrets leaking into the MCP CHANNEL  <-- MCP-SPECIFIC
        stdout on a stdio server IS the JSON-RPC transport; anything a tool
        returns lands in the model's context and reaches the LLM provider.
  S4  Over-broad credential surface (whole-environ reads, ~/.aws, .env, keychains)
  S5  Token lifecycle (plaintext persistence, tokens in URLs/query strings)
  S6  Repo hygiene (.env committed, .gitignore gaps, real values in .env.example)

Usage:
    python3 secrets_scan.py /path/to/repo
    python3 secrets_scan.py /path/to/repo --history          # also scan git log -p
    python3 secrets_scan.py /path/to/repo --history --max-commits 500
    python3 secrets_scan.py /path/to/repo --json

Exit codes:
    0 = PASS            no findings
    1 = REVIEW          medium findings only -- human review required
    2 = FAIL            critical/high findings -- gate the submission
"""
import os, re, sys, json, argparse, subprocess
from secrets_lib import (scan_line_for_secrets, redact, redact_line, walk_repo,
                         read_lines, is_placeholder, looks_random)

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"

CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".rb", ".java"}


def F(layer, severity, title, path, line_no, evidence, remediation, extra=None):
    f = {"layer": layer, "severity": severity, "title": title,
         "file": path, "line": line_no, "evidence": evidence,
         "remediation": remediation}
    if extra:
        f.update(extra)
    return f


# ----------------------------------------------------------------------
# File context classification
# ----------------------------------------------------------------------
# Not every file in a repo is the MCP server. A console.log in a build
# script is not a protocol-channel leak, and a self-signed cert under
# tests/ is not a production credential. Rather than hardcode filenames,
# devscripts are discovered from what package.json's own "scripts" block
# invokes -- evidence from the repo itself.
SEV_CHAIN = ["info", "low", "medium", "high", "critical"]
TEST_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs", "e2e",
                 "fixtures", "fixture", "testdata", "test_data", "mocks", "__mocks__"}
EXAMPLE_SEGMENTS = {"example", "examples", "sample", "samples", "demo", "demos", "docs", "doc"}
COMMON_DEVSCRIPTS = {"setup.py", "conftest.py", "noxfile.py", "tasks.py",
                     "gulpfile.js", "rollup.config.js", "webpack.config.js",
                     "esbuild.config.js", "makefile", "dangerfile.js"}


def discover_devscripts(root):
    """Files invoked by package.json 'scripts' are build/dev tooling, not
    the server runtime. Read them out of the repo instead of guessing."""
    found = set()
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        try:
            data = json.loads("\n".join(read_lines(pkg)))
            for cmd in (data.get("scripts") or {}).values():
                for m in re.finditer(r"[\w./\\-]+\.(?:js|mjs|cjs|ts)\b", str(cmd)):
                    found.add(m.group(0).lstrip("./").replace("\\", "/"))
        except Exception:
            pass
    return found


def classify_path(rel, devscripts):
    p = rel.replace("\\", "/")
    low = p.lower()
    segs = set(low.split("/"))
    base = os.path.basename(low)
    if p in devscripts or base in devscripts or base in COMMON_DEVSCRIPTS:
        return "devscript"
    if segs & TEST_SEGMENTS or re.search(r"(?:^|/)(?:test_|conftest)|\.(?:spec|test)\.[a-z]+$|_test\.[a-z]+$", low):
        return "test"
    if segs & EXAMPLE_SEGMENTS:
        return "example"
    if re.match(r"^(?:scripts?|build|ci|\.github)/", low):
        return "devscript"
    return "runtime"


def downgrade(sev, steps=1):
    i = SEV_CHAIN.index(sev)
    return SEV_CHAIN[max(0, i - steps)]


def adjust_for_context(findings, root, devscripts):
    """Re-rank findings by where they live. Non-runtime code is still
    reported -- a live credential committed anywhere is still leaked -- but
    it must not outrank the same issue in the actual server."""
    out = []
    for f in findings:
        ctx = "repo" if f["layer"] == "S6" else classify_path(f["file"], devscripts)
        f["context"] = ctx
        if ctx in ("runtime", "repo"):
            out.append(f)
            continue
        # A self-signed cert under tests/ is standard practice, not a leak.
        if f.get("kind") == "private_key_block" and ctx in ("test", "example"):
            f["severity"] = "low"
            f["title"] += f"  [{ctx} fixture -- likely a self-signed test cert]"
            f["remediation"] = ("Confirm this is a throwaway self-signed key used only by the "
                                "test suite. If it is ever used against a real service, rotate it.")
        else:
            f["severity"] = downgrade(f["severity"])
            f["title"] += f"  [in {ctx} path]"
        out.append(f)
    return out


# ----------------------------------------------------------------------
# S1 -- hardcoded credentials in the working tree
# ----------------------------------------------------------------------
def layer_s1(root):
    findings = []
    for path in walk_repo(root):
        rel = os.path.relpath(path, root)
        # A lockfile full of base64 integrity hashes is not a credential store.
        if os.path.basename(path) in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock"):
            continue
        for i, line in enumerate(read_lines(path), 1):
            for hit in scan_line_for_secrets(line):
                findings.append(F(
                    "S1", hit["severity"],
                    f"Hardcoded credential: {hit['name']}",
                    rel, i, redact_line(line, hit["value"]),
                    "Remove from source, rotate the credential, and load it from the "
                    "environment or a secrets manager at runtime.",
                    {"kind": hit["kind"], "confidence": hit["confidence"],
                     "redacted_value": redact(hit["value"])}))
    return findings


# ----------------------------------------------------------------------
# S2 -- credentials in git history
# ----------------------------------------------------------------------
def layer_s2(root, max_commits):
    """A secret deleted in HEAD is still readable in history by anyone who
    clones the repo. This is the single most under-checked item in a
    'here is our GitHub repo' review."""
    findings = []
    if not os.path.isdir(os.path.join(root, ".git")):
        return [F("S2", "info", "Git history not scanned (no .git directory present)",
                  ".", 0, "repo appears to be an extracted archive, not a clone",
                  "Request the actual git repository so history can be reviewed.")]
    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--no-color", f"-n{max_commits}",
             "--", ".", ":(exclude)*lock.json", ":(exclude)*.lock"],
            cwd=root, capture_output=True, text=True, timeout=300)
    except Exception as e:
        return [F("S2", "info", f"Git history scan failed: {e}", ".", 0, "", "Run manually with git log -p.")]
    if proc.returncode != 0:
        return [F("S2", "info", "git log failed", ".", 0, proc.stderr[-200:], "")]

    commit, path = None, None
    seen = set()
    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for hit in scan_line_for_secrets(line[1:]):
                key = (hit["kind"], hit["value"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(F(
                    "S2", hit["severity"],
                    f"Credential found in GIT HISTORY: {hit['name']}",
                    path or "?", 0, redact_line(line[1:], hit["value"]),
                    "Rotate this credential NOW -- it is readable by anyone who clones "
                    "the repo, even if later deleted. Removing the file does not remove "
                    "it from history; rewrite history (git filter-repo / BFG) after rotating.",
                    {"kind": hit["kind"], "commit": commit,
                     "redacted_value": redact(hit["value"])}))
    return findings


# ----------------------------------------------------------------------
# S3 -- MCP CHANNEL leakage  (the MCP-specific layer)
# ----------------------------------------------------------------------
STDOUT_WRITERS = [
    (re.compile(r"\bconsole\.log\s*\("), "console.log"),
    (re.compile(r"\bprocess\.stdout\.write\s*\("), "process.stdout.write"),
    (re.compile(r"(?<![\w.])print\s*\("), "print()"),
    (re.compile(r"\bsys\.stdout\.write\s*\("), "sys.stdout.write"),
    (re.compile(r"\bfmt\.Print(?:ln|f)?\s*\("), "fmt.Print*"),
]
LOGGERS = [
    (re.compile(r"\bconsole\.(?:error|warn|info|debug)\s*\("), "console.*"),
    (re.compile(r"\blogg(?:er|ing)\.(?:debug|info|warning|error|exception)\s*\("), "logger.*"),
    (re.compile(r"\bsys\.stderr\.write\s*\("), "sys.stderr.write"),
]
# NOTE on the lookarounds: do NOT use \b here. '_' is a word character, so
# \btoken\b never matches inside `github_token` -- and snake_case is the
# dominant naming convention for exactly these variables. An earlier build
# used \b and silently missed `return f"github_token={GITHUB_TOKEN}"`, the
# single most important case this layer exists to catch. Treating '_' and
# '-' as separators is what makes S3 work on real code.
SECRETISH = re.compile(
    r"(?i)(?<![A-Za-z])(?:api[_\-]?keys?|apikeys?|secrets?|passwords?|passwd|"
    r"passphrases?|tokens?|credentials?|authorization|auth[_\-]?header|bearer|"
    r"private[_\-]?keys?|env)(?![A-Za-z])")
# A string literal that is an ALL_CAPS identifier is the NAME of something
# (an env var, a config key), not a secret VALUE. Code like
#     return 'PLAYWRIGHT_MCP_SECRETS_FILE';
# is naming an environment variable, not leaking one. Without this, every
# config-name helper in a repo reads as a credential leak.
IDENTIFIER_LITERAL = re.compile(r"""['"`]([A-Z][A-Z0-9_]{2,})['"`]""")


def secret_bearing(line):
    """True only if a secret-ish word survives after removing ALL_CAPS
    identifier string literals -- i.e. the line references a secret VALUE
    rather than merely naming one."""
    return bool(SECRETISH.search(IDENTIFIER_LITERAL.sub("''", line)))


ENV_WHOLE = [
    (re.compile(r"\bprocess\.env\b(?!\s*\.\s*[A-Za-z_])"), "process.env (whole object)"),
    (re.compile(r"\bos\.environ\b(?!\s*[\[.]\s*['\"A-Za-z_])"), "os.environ (whole mapping)"),
    (re.compile(r"\bdict\s*\(\s*os\.environ\s*\)"), "dict(os.environ)"),
    (re.compile(r"\bjson\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ"), "json.dumps(os.environ)"),
    (re.compile(r"JSON\.stringify\s*\(\s*process\.env"), "JSON.stringify(process.env)"),
]


def layer_s3(root, devscripts):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        ctx = classify_path(rel, devscripts)
        for i, line in enumerate(read_lines(path), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            # S3a -- writing to stdout at all, on a stdio MCP server
            for rx, label in STDOUT_WRITERS:
                if rx.search(line):
                    secretish = secret_bearing(line)
                    envwhole = any(r.search(line) for r, _ in ENV_WHOLE)
                    if secretish or envwhole:
                        findings.append(F(
                            "S3", "critical",
                            f"Secret-bearing value written to STDOUT via {label}",
                            rel, i, redact_line(line, None),
                            "On a stdio MCP server stdout IS the JSON-RPC channel. This both "
                            "corrupts the protocol and can hand the value to the client. Route "
                            "diagnostics to stderr and redact secrets first."))
                    elif ctx == "runtime":
                        # Only the server's own runtime code shares stdout with
                        # the JSON-RPC transport. A console.log in a build
                        # script or test harness is not a protocol concern --
                        # reporting it buries the findings that matter.
                        findings.append(F(
                            "S3", "medium",
                            f"Write to STDOUT via {label} on a stdio MCP server",
                            rel, i, redact_line(line, None),
                            "stdout is the MCP transport; any stray write corrupts framing. "
                            "Use stderr (or a file) for logging."))
                    break

            # S3b -- secret-bearing value sent to a logger
            for rx, label in LOGGERS:
                if rx.search(line) and secret_bearing(line):
                    findings.append(F(
                        "S3", "high",
                        f"Secret-bearing value passed to logger ({label})",
                        rel, i, redact_line(line, None),
                        "Logs are frequently shipped to a SIEM or captured by the MCP client. "
                        "Redact before logging; never log whole config/env objects."))
                    break

            # S3c -- secret-bearing value returned to the MODEL
            if re.search(r"\breturn\b", line) and secret_bearing(line):
                if not re.search(r"(?i)\b(?:redact|mask|sanitiz|scrub|\*{3,})", line):
                    findings.append(F(
                        "S3", "high",
                        "Secret-bearing value appears in a return path (reaches model context)",
                        rel, i, redact_line(line, None),
                        "Tool results are injected into the agent's context and sent to the LLM "
                        "provider. Never return raw credentials; return a status or a redacted "
                        "reference instead."))
    return findings


# ----------------------------------------------------------------------
# S4 -- over-broad credential surface
# ----------------------------------------------------------------------
CRED_PATHS = [
    (re.compile(r"~/\.aws|\.aws/credentials"), "AWS credentials file", "critical"),
    (re.compile(r"~/\.ssh|id_rsa|id_ed25519"), "SSH private key material", "critical"),
    (re.compile(r"~/\.kube/config|kubeconfig"), "Kubernetes config", "high"),
    (re.compile(r"~/\.docker/config\.json"), "Docker registry credentials", "high"),
    (re.compile(r"\.netrc"), ".netrc credentials", "high"),
    (re.compile(r"(?i)\bkeychain\b|security\s+find-generic-password"), "OS keychain access", "high"),
    (re.compile(r"(?i)\bmcp\.json\b|claude_desktop_config\.json"), "MCP client config (contains other servers' secrets)", "high"),
    # The lookbehind must exclude '?' and '.' as well as word chars. Without
    # them this matched JavaScript property access and spread syntax --
    # `options?.env` and `...env` are an object property named "env", not a
    # .env FILE. '/' is deliberately still allowed so "/srv/app/.env" matches.
    (re.compile(r"(?<![\w?.])\.env(?:\.[a-z]+)?\b"), ".env file access", "medium"),
]


def layer_s4(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        for i, line in enumerate(read_lines(path), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for rx, label, sev in CRED_PATHS:
                if rx.search(line):
                    findings.append(F(
                        "S4", sev, f"Code references {label}",
                        rel, i, redact_line(line, None),
                        "A local MCP server inherits the developer's ambient credentials. "
                        "Confirm this access is essential and documented; prefer a narrowly "
                        "scoped credential passed in explicitly."))
                    break
            for rx, label in ENV_WHOLE:
                if rx.search(line):
                    findings.append(F(
                        "S4", "high",
                        f"Whole-environment access: {label}",
                        rel, i, redact_line(line, None),
                        "Reading the entire environment pulls in every unrelated secret on the "
                        "host. Read only the specific variables this server needs, by name."))
                    break
    return findings


# ----------------------------------------------------------------------
# S5 -- token lifecycle
# ----------------------------------------------------------------------
TOKEN_IN_URL = re.compile(
    r"""(?ix) [?&] \s* (?:access_token|api[_\-]?key|apikey|token|auth|key|secret|password)
        \s* = \s* (?![\s"'&]) """)
PERSIST_WRITE = re.compile(
    r"(?i)\b(?:writeFileSync|writeFile|open\s*\([^)]*['\"][wa]|json\.dump|"
    r"pickle\.dump|fs\.writeFile|localStorage\.setItem)\b")
NO_EXPIRY = re.compile(r"(?i)\b(?:expires_?in|expiry|expires_?at|ttl|max_?age|refresh_?token)\b")
# Narrow trigger for the expiry check. An earlier build flagged EVERY file
# that merely mentioned a token-ish word and lacked a TTL reference -- that
# fired on type-declaration files (config.d.ts) and produced pure noise.
# The question is only meaningful where the code actually ACQUIRES a token.
TOKEN_ACQUISITION = re.compile(
    r"(?i)\b(?:grant_type|client_credentials|oauth2?|/token\b|authorize\b|"
    r"refresh_?token|access_?token\s*=|getAccessToken|fetchToken|acquireToken)\b")


def layer_s5(root):
    findings = []
    for path in walk_repo(root, CODE_EXTS):
        rel = os.path.relpath(path, root)
        lines = read_lines(path)
        file_acquires_token = any(TOKEN_ACQUISITION.search(l) for l in lines)
        file_has_expiry = any(NO_EXPIRY.search(l) for l in lines)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if TOKEN_IN_URL.search(line):
                findings.append(F(
                    "S5", "high", "Credential passed in a URL query string",
                    rel, i, redact_line(line, None),
                    "Query strings are logged by proxies, servers, and browser history. "
                    "Send credentials in an Authorization header instead."))
            if PERSIST_WRITE.search(line) and SECRETISH.search(line):
                findings.append(F(
                    "S5", "high", "Token/secret appears to be persisted to disk",
                    rel, i, redact_line(line, None),
                    "Avoid caching credentials in plaintext. If persistence is required, use "
                    "the OS keychain or an encrypted store, and set restrictive file modes."))
        if file_acquires_token and not file_has_expiry:
            findings.append(F(
                "S5", "medium",
                "Token acquisition with no expiry/refresh handling",
                rel, 0, "token-acquisition code present, but no expires_in / ttl / refresh_token reference",
                "Confirm the acquired token is short-lived and refreshed. A long-lived static "
                "token widens the blast radius of any leak."))
    return findings


# ----------------------------------------------------------------------
# S6 -- repo hygiene
# ----------------------------------------------------------------------
def layer_s6(root):
    findings = []
    gitignore_path = os.path.join(root, ".gitignore")
    gitignore = "\n".join(read_lines(gitignore_path)) if os.path.isfile(gitignore_path) else ""

    for path in walk_repo(root):
        rel = os.path.relpath(path, root)
        base = os.path.basename(path)
        # A real .env committed into the repo
        if base == ".env" or re.match(r"^\.env\.(local|prod|production|staging)$", base):
            findings.append(F(
                "S6", "critical", f"Environment file '{base}' is present in the repository",
                rel, 0, "file exists in the working tree",
                "Remove from version control, rotate anything it contained, and add it to "
                ".gitignore. Ship a .env.example with placeholder values instead."))
        # .env.example / sample with REAL-looking values
        if re.match(r"^\.env\.(example|sample|template)$|^env\.example$", base):
            for i, line in enumerate(read_lines(path), 1):
                if "=" not in line or line.strip().startswith("#"):
                    continue
                _, _, val = line.partition("=")
                val = val.strip().strip("\"'")
                if val and not is_placeholder(val) and looks_random(val):
                    findings.append(F(
                        "S6", "high", f"Real-looking value in example file '{base}'",
                        rel, i, redact_line(line, val),
                        "Example files are meant to hold placeholders. Replace with "
                        "<YOUR_VALUE> and rotate the exposed credential.",
                        {"redacted_value": redact(val)}))

    if gitignore and not re.search(r"(?m)^\s*\.env", gitignore):
        findings.append(F(
            "S6", "medium", ".gitignore does not exclude .env files",
            ".gitignore", 0, "no '.env' rule found",
            "Add '.env' and '.env.*' (with a '!.env.example' exception) to .gitignore."))
    elif not gitignore:
        findings.append(F(
            "S6", "medium", "No .gitignore present",
            ".", 0, "repository has no .gitignore",
            "Add a .gitignore that excludes .env, credential files, and local config."))
    return findings


# ----------------------------------------------------------------------
# Verdict
# ----------------------------------------------------------------------
def fingerprint(f):
    """Stable ID for a finding so an accepted one can be allowlisted without
    suppressing a whole file or rule. Deliberately built from the REDACTED
    value -- an allowlist file must never contain a live credential."""
    import hashlib
    basis = "|".join([f["layer"], f.get("kind", ""), f["file"],
                      f.get("redacted_value", ""), f["title"].split("  [")[0]])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def apply_allowlist(findings, allowlist_path):
    """Suppress previously-accepted findings. Returns (kept, suppressed)."""
    if not allowlist_path or not os.path.isfile(allowlist_path):
        return findings, []
    try:
        data = json.loads("\n".join(read_lines(allowlist_path)))
    except Exception:
        return findings, []
    accepted = {e["fingerprint"]: e.get("reason", "") for e in data.get("accepted", [])}
    kept, suppressed = [], []
    for f in findings:
        fp = fingerprint(f)
        if fp in accepted:
            f["suppressed_reason"] = accepted[fp]
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed


def write_allowlist(findings, path):
    entries = [{"fingerprint": fingerprint(f), "file": f["file"],
                "title": f["title"], "severity": f["severity"],
                "reason": "ACCEPTED -- replace this text with the review justification"}
               for f in findings]
    json.dump({"accepted": entries}, open(path, "w"), indent=2)
    return len(entries)


def verdict_for_findings(findings):
    """Same three-tier language as Box-1/Box-3."""
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    blocking = [f for f in findings if f["severity"] in ("critical", "high")]
    review = [f for f in findings if f["severity"] in ("medium", "low")]

    if blocking:
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- credential exposure found",
                "next_step": "Rotate every credential listed as critical/high BEFORE anything "
                             "else; removing it from source does not un-leak it. Then gate the "
                             "submission until the code no longer embeds or emits secrets.",
                "counts": counts}
    if review:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- secret-handling weaknesses, no live credential found",
                "next_step": "No usable credential was recovered, but the handling patterns above "
                             "widen exposure. Confirm each with the app team before approval.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no secret-management findings",
            "next_step": "Nothing found by these six layers. Note this is a static scan: "
                         "pair it with runtime egress monitoring for full coverage.",
            "counts": counts}


def print_report(root, findings, v, show_all):
    print(f"\nBox-6 Secrets & Token Handling -- {root}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    by_layer = {}
    for f in findings:
        by_layer.setdefault(f["layer"], []).append(f)
    LAYER_NAMES = {
        "S1": "Hardcoded credentials (working tree)",
        "S2": "Credentials in git history",
        "S3": "MCP channel leakage (stdout / logs / model context)",
        "S4": "Over-broad credential surface",
        "S5": "Token lifecycle",
        "S6": "Repo hygiene",
    }
    for layer in ("S1", "S2", "S3", "S4", "S5", "S6"):
        fs = by_layer.get(layer, [])
        if not fs:
            continue
        fs.sort(key=lambda f: -SEV_ORDER[f["severity"]])
        print(f"\n--- {layer}: {LAYER_NAMES[layer]}  ({len(fs)} finding(s)) ---")
        shown = fs if show_all else fs[:6]
        for f in shown:
            c = COLOR.get(f["severity"], "")
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"{c}[{f['severity'].upper():8}]{RESET} {f['title']}")
            print(f"           {loc}")
            if f.get("commit"):
                print(f"           commit: {f['commit']}")
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
    ap.add_argument("--history", action="store_true", help="also scan git history (S2)")
    ap.add_argument("--max-commits", type=int, default=200)
    ap.add_argument("--all", action="store_true", help="list every finding, not just the first few per layer")
    ap.add_argument("--allowlist", help="JSON file of previously-accepted findings to suppress")
    ap.add_argument("--write-allowlist", metavar="PATH",
                    help="write current findings out as an allowlist template, then exit")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.repo)
    devscripts = discover_devscripts(root)
    findings = []
    findings += layer_s1(root)
    if args.history:
        findings += layer_s2(root, args.max_commits)
    findings += layer_s3(root, devscripts)
    findings += layer_s4(root)
    findings += layer_s5(root)
    findings += layer_s6(root)

    findings = adjust_for_context(findings, root, devscripts)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))
    for f in findings:
        f["fingerprint"] = fingerprint(f)

    if args.write_allowlist:
        n = write_allowlist(findings, args.write_allowlist)
        print(f"Wrote {n} finding(s) to {args.write_allowlist}. "
              f"Edit each 'reason' to record why it is accepted, then re-run with "
              f"--allowlist {args.write_allowlist}.")
        sys.exit(0)

    findings, suppressed = apply_allowlist(findings, args.allowlist)
    v = verdict_for_findings(findings)

    if args.json:
        print(json.dumps({"repo": root, "findings": findings,
                          "suppressed": suppressed, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, args.all)
        if suppressed:
            print(f"({len(suppressed)} finding(s) suppressed by allowlist)\n")
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
