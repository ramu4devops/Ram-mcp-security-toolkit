#!/usr/bin/env python3
"""
auditlib.py -- shared stdlib-only helpers for Box-13 (Audit, Telemetry &
Logging). Static, read-only file walking / line reading. No repo code is ever
executed. Same helper shape as reslib.py / sastlib.py / promptlib.py.
"""
import os, re

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".venv",
             "venv", ".mypy_cache", "vendor", "target", ".next", "coverage"}
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
               ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
               ".so", ".dylib", ".dll", ".class", ".jar", ".wasm"}
CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".rb", ".java"}
MAX_FILE_BYTES = 2_000_000


def walk_repo(root, exts=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in BINARY_EXTS:
                continue
            if exts and ext not in exts:
                continue
            p = os.path.join(dirpath, f)
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def snippet(line, n=200):
    return line.strip()[:n]


TEST_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs", "e2e",
                 "fixtures", "fixture", "testdata", "test_data", "mocks", "__mocks__"}
EXAMPLE_SEGMENTS = {"example", "examples", "sample", "samples", "demo", "demos", "docs", "doc"}


def classify_path(rel):
    p = rel.replace("\\", "/").lower()
    segs = set(p.split("/"))
    if segs & TEST_SEGMENTS:
        return "test"
    if segs & EXAMPLE_SEGMENTS:
        return "example"
    return "runtime"


# A logging framework is imported / configured somewhere.
LOG_FRAMEWORK = re.compile(
    r"(?i)\b(?:import\s+logging|from\s+logging|getLogger\s*\(|structlog|loguru|"
    r"winston|pino\b|bunyan|log4js|createLogger|import\s+logging\.config|"
    r"\bslog\b|zerolog|zap\.New|logrus)")

# A line that emits a log / audit record.
LOG_CALL = re.compile(
    r"(?i)(?:\blogger?\.\w+\s*\(|\blogging\.\w+\s*\(|\blog\.\w+\s*\(|\baudit\w*\s*\(|"
    r"console\.(?:log|info|warn|error|debug)\s*\(|\bprint\s*\(|winston\.\w+\s*\(|"
    r"\.info\s*\(|\.warn(?:ing)?\s*\(|\.error\s*\(|\.debug\s*\(|\.log\s*\()")

# MCP tool/handler surface.
TOOL_DECOR = re.compile(r"@(?:\w+\.)?tool\s*\(")
PRIV_NAME = re.compile(r"(?i)\b(delete|remove|drop|destroy|admin|grant|revoke|"
                       r"promote|escalate|sudo|approve|disable|deactivate|wipe|purge)\w*")


def declares_tool_surface(lines):
    text = "\n".join(lines)
    return bool(TOOL_DECOR.search(text) or "tools/call" in text
                or "server.tool(" in text or "registerTool(" in text
                or "setRequestHandler" in text)
