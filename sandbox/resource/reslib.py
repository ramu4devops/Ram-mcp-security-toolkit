#!/usr/bin/env python3
"""
reslib.py -- shared stdlib-only helpers for Box-5 (Resource Exploitation).
Static, read-only file walking/line-reading. No code from the target repo
is ever executed.
"""
import os

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
    p = rel.replace("\\", "/")
    low = p.lower()
    segs = set(low.split("/"))
    if segs & TEST_SEGMENTS:
        return "test"
    if segs & EXAMPLE_SEGMENTS:
        return "example"
    return "runtime"
