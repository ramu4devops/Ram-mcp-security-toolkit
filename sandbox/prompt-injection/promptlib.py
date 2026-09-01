#!/usr/bin/env python3
"""
promptlib.py -- shared stdlib-only helpers for Box-04 (Prompt & Template
Injection). Static, read-only file walking / line reading. No code from the
target repo is ever executed. Same helper shape as reslib.py / sastlib.py.
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


# Caller-controlled-looking names — an MCP prompt/tool argument, a resource
# value, a request field. Not proof of taint; the signal a static scanner uses.
TAINT_NAME = re.compile(
    r"(?i)\b(?:arg|args|argument|arguments|param|params|kwargs|input|query|"
    r"user|name|value|text|content|message|msg|prompt|question|task|instruction|"
    r"topic|subject|body|data|payload|context|req(?:uest)?\.(?:params|query|body))\b")

# A file participates in the MCP prompt/tool surface.
MCP_PROMPT_DECOR = re.compile(r"@(?:\w+\.)?prompt\s*\(")
MCP_TOOL_DECOR = re.compile(r"@(?:\w+\.)?tool\s*\(")


def declares_prompt_surface(lines):
    text = "\n".join(lines)
    return bool(MCP_PROMPT_DECOR.search(text) or "prompts/list" in text
                or "prompts/get" in text or "registerPrompt(" in text
                or "server.prompt(" in text or ".setRequestHandler" in text)


def declares_mcp_surface(lines):
    text = "\n".join(lines)
    return bool(MCP_PROMPT_DECOR.search(text) or MCP_TOOL_DECOR.search(text)
                or "tools/call" in text or "server.tool(" in text
                or "registerTool(" in text or declares_prompt_surface(lines))
