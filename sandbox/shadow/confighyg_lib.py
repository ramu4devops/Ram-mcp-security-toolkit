#!/usr/bin/env python3
"""
confighyg_lib.py -- stdlib-only helpers for Box-14 (Shadow MCP Servers /
Configuration & Manifest Hygiene). Static, read-only. No repo code executed.

Unlike the code-scanning boxes, this one is CONFIG-focused: it locates the
server's manifest / config / entrypoint declaration files and reads their
declared surface (exposed tools, transport, credentials, launch command).
"""
import os, re, json

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".venv",
             "venv", ".mypy_cache", "vendor", "target", ".next", "coverage"}
MAX_FILE_BYTES = 1_000_000

# Files that declare an MCP server's configuration / manifest / launch spec.
MANIFEST_NAMES = {
    "mcp.json", ".mcp.json", "mcp-config.json", "mcpconfig.json",
    "claude_desktop_config.json", "claude_config.json",
    "server.json", "manifest.json", "smithery.yaml", "smithery.yml",
    "mcp.yaml", "mcp.yml", "config.json", "config.yaml", "config.yml",
    "package.json", "pyproject.toml",
}
MANIFEST_SUFFIXES = (".mcp.json",)


def find_manifests(root):
    """Return [(abs_path, rel_path, kind)] for candidate manifest/config files."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        depth = dirpath[len(root):].count(os.sep)
        if depth > 4:
            dirnames[:] = []
            continue
        for f in filenames:
            low = f.lower()
            if low in MANIFEST_NAMES or low.endswith(MANIFEST_SUFFIXES):
                p = os.path.join(dirpath, f)
                try:
                    if os.path.getsize(p) > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                out.append((p, os.path.relpath(p, root), _kind(low)))
    return out


def _kind(name):
    if name == "package.json":
        return "package.json"
    if name == "pyproject.toml":
        return "pyproject.toml"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "json"


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def load_json(path):
    txt = read_text(path)
    try:
        return json.loads(txt), txt
    except Exception:
        return None, txt


def line_of(text, needle):
    """1-based line number where `needle` first appears, else 0."""
    idx = text.find(needle)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


def iter_mcp_server_blocks(obj):
    """Yield (server_name, block_dict) for the common config shapes:
    {"mcpServers": {name: {...}}} (Claude desktop / mcp.json),
    {"servers": {...}} / {"servers": [...]}, or a bare launch block."""
    if not isinstance(obj, dict):
        return
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = obj.get(key)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, dict):
                    yield name, spec
        elif isinstance(block, list):
            for spec in block:
                if isinstance(spec, dict):
                    yield spec.get("name", "?"), spec
    # a bare server spec (command/args at top level)
    if "command" in obj and "mcpServers" not in obj:
        yield obj.get("name", "?"), obj


# Well-known / high-trust server name stems that a shadow server might squat on.
WELL_KNOWN_SERVERS = {
    "filesystem", "github", "gitlab", "google-drive", "gdrive", "slack",
    "postgres", "postgresql", "sqlite", "memory", "fetch", "puppeteer",
    "playwright", "brave-search", "everything", "git", "sentry", "notion",
    "aws", "gcp", "azure", "stripe", "jira", "confluence", "linear",
}
