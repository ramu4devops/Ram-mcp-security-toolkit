#!/usr/bin/env python3
"""
inspect_repo.py -- read-only metadata about an extracted MCP server repo.

Reads manifests and counts file types. Executes NOTHING from the repo and
opens only well-known text files -- same risk profile as unzipping. Used to
show the engineer a confirmation card right after upload ("here's what we
think this server is") before any sandboxed review runs.
"""
import os, re, json, pathlib

try:
    import tomllib  # py3.11+
except Exception:  # pragma: no cover
    tomllib = None

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__",
             ".venv", "venv", "vendor", "target", ".mypy_cache"}

LANG_BY_EXT = {
    ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby",
    ".cs": "C#", ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
    ".sh": "Shell", ".kt": "Kotlin", ".swift": "Swift",
}


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
        for f in fns:
            yield pathlib.Path(dp) / f


def _languages(root):
    counts = {}
    total = 0
    for p in _walk(root):
        lang = LANG_BY_EXT.get(p.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
            total += 1
    out = [{"language": k, "files": v, "pct": round(100 * v / total)}
           for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
    return out, total


def _readme_summary(root):
    for name in ("README.md", "readme.md", "README.rst", "README.txt", "README"):
        p = root / name
        if p.is_file():
            text = _read(p)
            para = []
            for raw in text.splitlines():
                line = raw.strip()
                if not line:
                    if para:
                        break
                    continue
                if line.startswith("#") or line.startswith("!") or line.startswith("[!"):
                    continue  # heading / badge
                if re.match(r"^[-=*_]{3,}$", line):
                    continue
                para.append(line)
                if sum(len(x) for x in para) > 260:
                    break
            if para:
                s = " ".join(para)
                return (s[:280] + "…") if len(s) > 280 else s
    return None


def _parse_pyproject(text):
    if tomllib:
        try:
            d = tomllib.loads(text)
            proj = d.get("project", {}) or {}
            return {
                "name": proj.get("name"),
                "version": proj.get("version"),
                "description": proj.get("description"),
                "deps": len(proj.get("dependencies", []) or []),
            }
        except Exception:
            pass
    # regex fallback
    def g(key):
        m = re.search(rf'^\s*{key}\s*=\s*"([^"]+)"', text, re.MULTILINE)
        return m.group(1) if m else None
    return {"name": g("name"), "version": g("version"),
            "description": g("description"), "deps": None}


def inspect(root: pathlib.Path) -> dict:
    root = pathlib.Path(root)
    info = {
        "name": None, "version": None, "about": None,
        "languages": [], "source_files": 0, "dependencies": None,
        "mcp_sdk": None, "entry_point": None, "manifest": None,
    }

    langs, nfiles = _languages(root)
    info["languages"] = langs
    info["source_files"] = nfiles

    pkg = root / "package.json"
    pyproj = root / "pyproject.toml"

    if pkg.is_file():
        info["manifest"] = "package.json"
        try:
            data = json.loads(_read(pkg))
        except Exception:
            data = {}
        info["name"] = data.get("name") or data.get("mcpName")
        info["version"] = data.get("version")
        info["about"] = data.get("description")
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        info["dependencies"] = len(deps)
        if any("@modelcontextprotocol/sdk" in k for k in deps):
            info["mcp_sdk"] = "@modelcontextprotocol/sdk (Node)"
        b = data.get("bin")
        if isinstance(b, str):
            info["entry_point"] = b
        elif isinstance(b, dict) and b:
            info["entry_point"] = sorted(b.values())[0]
        elif data.get("main"):
            info["entry_point"] = data.get("main")
    elif pyproj.is_file():
        info["manifest"] = "pyproject.toml"
        pp = _parse_pyproject(_read(pyproj))
        info["name"] = pp["name"]
        info["version"] = pp["version"]
        info["about"] = pp["description"]
        info["dependencies"] = pp["deps"]

    # MCP SDK signal for Python
    if info["mcp_sdk"] is None:
        blob = ""
        for m in ("pyproject.toml", "requirements.txt", "setup.py"):
            p = root / m
            if p.is_file():
                blob += _read(p)
        if re.search(r"\bfastmcp\b|\bmodelcontextprotocol\b|\bmcp\[cli\]|\bmcp\s*[><=~]", blob, re.I):
            info["mcp_sdk"] = "mcp / fastmcp (Python)"

    if not info["about"]:
        info["about"] = _readme_summary(root)
    if not info["name"]:
        info["name"] = root.name
    if not info["about"]:
        info["about"] = "No description found in the manifest or README."

    info["primary_language"] = info["languages"][0]["language"] if info["languages"] else None
    return info
