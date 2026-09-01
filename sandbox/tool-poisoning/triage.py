#!/usr/bin/env python3
"""
triage.py -- decide Method A (sandboxed bring-up) vs Method B (static
extraction) for a cloned MCP server repo, automatically.

Run it FROM INSIDE the cloned repo:

    cd playwright-mcp
    python3 /path/to/triage.py

...or point it at a path:

    python3 triage.py /path/to/playwright-mcp

SAFE BY DEFAULT: this script only reads files and runs text/regex checks.
It never installs dependencies and never executes anything from the target
repo. That's deliberate -- a triage tool that must run against an unknown,
possibly-malicious repo should not itself need a sandbox to be safe to run.

Exit codes (for scripting/CI):
    0 = STATIC extraction recommended
    1 = SANDBOXED bring-up recommended
    2 = inconclusive / doesn't look like an MCP server repo -- review manually

Usage:
    python3 triage.py [path]              human-readable report
    python3 triage.py [path] --json       machine-readable report
"""
import os, re, sys, json, argparse

# ----------------------------------------------------------------------
# What counts as "this repo declares itself an MCP server"
# ----------------------------------------------------------------------
MCP_MANIFEST_SIGNALS = [
    (r'"mcpName"\s*:', "package.json"),
    (r'@modelcontextprotocol/sdk', "package.json"),
    (r'\bmodelcontextprotocol\b', "pyproject.toml/requirements*.txt"),
    (r'\bfastmcp\b', "pyproject.toml/requirements*.txt"),
    (r'\bmcp\[cli\]|\bmcp\s*[><=]', "pyproject.toml/requirements*.txt"),
    (r'mark3labs/mcp-go|modelcontextprotocol/go-sdk', "go.mod"),
]
MANIFEST_FILES = ["package.json", "pyproject.toml", "requirements.txt",
                  "setup.py", "setup.cfg", "go.mod", "Cargo.toml"]

# ----------------------------------------------------------------------
# In-repo tool-registration patterns -- if these hit, source is HERE.
# STRONG = this line IS a tool being defined/registered. WEAK = merely
# suggestive (e.g. some object happens to have an .inputSchema property);
# weak hits are shown for context but never score on their own -- an
# early version of this script used a weak-only pattern and it produced
# a false STATIC verdict on a helper script that just referenced
# `tool.inputSchema` while formatting docs. Lesson kept as a code comment
# on purpose: don't let secondary signals outvote the primary ones.
# ----------------------------------------------------------------------
REGISTRATION_PATTERNS_STRONG = [
    r'@mcp\.tool\s*\(',                 # Python official SDK / FastMCP
    r'@server\.tool\s*\(',
    r'FastMCP\s*\(',
    r'\.registerTool\s*\(',             # TS/JS official SDK
    r'\bserver\.tool\s*\(\s*[\'"]',      # server.tool("name", ...) call site
    r'setRequestHandler\s*\(\s*ListToolsRequestSchema',
]
REGISTRATION_PATTERNS_WEAK = [
    r'inputSchema\s*[:=]',
]
SOURCE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__",
            ".venv", "venv", ".mypy_cache", "vendor", "target"}

# ----------------------------------------------------------------------
# "The source actually lives elsewhere" pointer phrases
# ----------------------------------------------------------------------
POINTER_PATTERNS = [
    r"source code is located",
    r"has (?:been )?moved to",
    r"see the .* monorepo",
    r"packages?/[\w-]+/src",
    r"this (?:repo|package) (?:is|acts as) (?:a |an )?(?:thin )?(?:cli )?wrapper",
]

MAX_FILE_BYTES = 2_000_000   # skip absurdly large files (bundles handled separately)


def walk_files(root, exts=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            if exts and os.path.splitext(f)[1] not in exts:
                continue
            path = os.path.join(dirpath, f)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def check_manifest_declares_mcp(root):
    hits = []
    for fname in MANIFEST_FILES:
        path = os.path.join(root, fname)
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        for pat, _label in MCP_MANIFEST_SIGNALS:
            if re.search(pat, text, re.IGNORECASE):
                hits.append(f"{fname}: matched /{pat}/")
    return hits


def check_registration_patterns(root):
    strong_hits = []   # list of (pattern, file, line, snippet)
    weak_hits = []
    strong_files = set()
    for path in walk_files(root, SOURCE_EXTS):
        text = read_text(path)
        if not text:
            continue
        rel = os.path.relpath(path, root)
        for i, line in enumerate(text.splitlines(), 1):
            for pat in REGISTRATION_PATTERNS_STRONG:
                if re.search(pat, line):
                    strong_hits.append((pat, rel, i, line.strip()[:100]))
                    strong_files.add(rel)
            for pat in REGISTRATION_PATTERNS_WEAK:
                if re.search(pat, line):
                    weak_hits.append((pat, rel, i, line.strip()[:100]))
    return strong_hits, weak_hits, strong_files


def check_pointer_phrases(root):
    hits = []
    candidates = ["README.md", "CONTRIBUTING.md"]
    for path in walk_files(root):
        rel = os.path.relpath(path, root)
        base = os.path.basename(path)
        if base not in candidates and not rel.startswith("src"):
            continue
        text = read_text(path)
        for pat in POINTER_PATTERNS:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                hits.append(f"{rel}: \"{m.group(0)}\"")
    return hits


def check_build_step_needed(root):
    pkg = os.path.join(root, "package.json")
    if not os.path.isfile(pkg):
        return None    # not a Node project, N/A
    text = read_text(pkg)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    build_script = (data.get("scripts") or {}).get("build", "")
    trivial = build_script.strip() in ("", "echo OK") or "echo" in build_script.lower() and len(build_script) < 20
    has_tsconfig = os.path.isfile(os.path.join(root, "tsconfig.json"))
    has_dist = os.path.isdir(os.path.join(root, "dist")) or os.path.isdir(os.path.join(root, "lib"))
    if has_tsconfig and not has_dist and not trivial:
        return f"tsconfig.json present, no dist/lib output, build script: '{build_script}'"
    return None


def check_source_tree_thin(root):
    """A repo that clearly wants to be an MCP server but has almost no
    source files is a vendoring red flag on its own."""
    n = sum(1 for _ in walk_files(root, SOURCE_EXTS))
    return n


def triage(root):
    root = os.path.abspath(root)
    manifest_hits = check_manifest_declares_mcp(root)
    strong_hits, weak_hits, strong_files = check_registration_patterns(root)
    pointer_hits = check_pointer_phrases(root)
    build_flag = check_build_step_needed(root)
    n_source_files = check_source_tree_thin(root)

    declares_mcp = bool(manifest_hits)
    has_registrations = len(strong_files) > 0   # STRONG signals only decide this

    static_score = 0
    sandbox_score = 0
    reasons = []

    if declares_mcp:
        reasons.append(("info", f"Repo declares itself an MCP server ({len(manifest_hits)} manifest signal(s))"))
    else:
        reasons.append(("warn", "No manifest signal found declaring this an MCP server -- verify manually"))

    if has_registrations:
        static_score += 4
        reasons.append(("static", f"Found {len(strong_hits)} tool-registration call(s) across {len(strong_files)} file(s) -- source is HERE"))
    else:
        reasons.append(("neutral", "Zero STRONG tool-registration patterns found in source tree"))
        if weak_hits:
            reasons.append(("neutral", f"({len(weak_hits)} weak/secondary match(es) only -- e.g. a stray '.inputSchema' reference; not treated as proof of in-repo source)"))

    if declares_mcp and not has_registrations:
        sandbox_score += 5
        reasons.append(("sandbox", "Declares an MCP SDK dependency but defines NO tools in-repo -- classic vendored/monorepo split"))

    if pointer_hits:
        sandbox_score += 3
        for h in pointer_hits:
            reasons.append(("sandbox", f"Pointer phrase found -- {h}"))

    if build_flag:
        sandbox_score += 2
        reasons.append(("sandbox", f"Build step likely required before source is usable -- {build_flag}"))

    if declares_mcp and n_source_files <= 2 and not has_registrations:
        sandbox_score += 2
        reasons.append(("sandbox", f"Source tree is essentially empty ({n_source_files} source file(s)) for a repo that claims to be an MCP server"))

    if has_registrations and len(strong_files) >= 2:
        static_score += 1
        reasons.append(("static", "Registrations spread across multiple files -- looks like real, in-repo implementation, not a stray mention"))

    # ---- verdict ----
    if not declares_mcp and not has_registrations:
        verdict = "INCONCLUSIVE"
        exit_code = 2
        headline = "Doesn't look like an MCP server repo (no manifest or registration signals) -- review manually"
    elif static_score > sandbox_score:
        verdict = "STATIC"
        exit_code = 0
        headline = "Static extraction recommended -- tool source is present in this repo"
    elif sandbox_score > static_score:
        verdict = "SANDBOX"
        exit_code = 1
        headline = "Sandboxed bring-up recommended -- tool source is not (fully) present in this repo"
    else:
        verdict = "SANDBOX"   # tie-break toward the safer, always-correct default
        exit_code = 1
        headline = "Ambiguous signals -- defaulting to sandboxed bring-up (always correct, just slower)"

    return {
        "root": root,
        "verdict": verdict,
        "exit_code": exit_code,
        "headline": headline,
        "static_score": static_score,
        "sandbox_score": sandbox_score,
        "declares_mcp": declares_mcp,
        "has_registrations": has_registrations,
        "n_source_files": n_source_files,
        "reasons": reasons,
        "registration_hits_sample": [
            {"file": f, "line": ln, "text": txt} for _p, f, ln, txt in strong_hits[:8]
        ],
    }


LABEL = {"static": "[STATIC ]", "sandbox": "[SANDBOX]", "info": "[INFO   ]",
        "warn": "[WARN   ]", "neutral": "[--     ]"}
COLOR = {"static": "\033[96m", "sandbox": "\033[93m", "info": "\033[90m",
        "warn": "\033[91m", "neutral": "\033[90m"}
RESET = "\033[0m"


def print_report(r):
    print(f"\nTriage: {r['root']}")
    print("-" * 64)
    for kind, msg in r["reasons"]:
        c = COLOR.get(kind, "")
        print(f"{c}{LABEL.get(kind,'[?]'):10}{RESET} {msg}")
    print("-" * 64)
    print(f"static_score={r['static_score']}   sandbox_score={r['sandbox_score']}")
    print()
    badge = {"STATIC": "\033[96mSTATIC EXTRACTION\033[0m",
             "SANDBOX": "\033[93mSANDBOXED BRING-UP\033[0m",
             "INCONCLUSIVE": "\033[91mINCONCLUSIVE\033[0m"}[r["verdict"]]
    print(f"VERDICT: {badge}")
    print(f"  {r['headline']}")
    if r["registration_hits_sample"]:
        print("\n  sample registration matches:")
        for h in r["registration_hits_sample"]:
            print(f"    {h['file']}:{h['line']}  {h['text']}")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".", help="path to the cloned repo (default: current dir)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = triage(args.path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
