#!/usr/bin/env python3
"""
orchestrator.py -- headless engine for the LOCAL MCP Security Review CLI.

This is the same review engine the web console (`backend/app.py`) uses, with
the FastAPI/streaming layer stripped off. It runs each security "box" against
a local MCP server repo and returns the SAME normalized result envelope the
UI renders, so a local scan and a console scan are guaranteed to agree.

Design goals
------------
* ONE source of truth. The box detectors under ../sandbox/boxNN/ and the
  normalizers in ../backend/secrets_supply.py + ../backend/box3_review.py are
  imported / invoked verbatim -- nothing is re-implemented here.
* TWO runners, same commands:
    - "docker" (default, recommended): every box runs inside the hardened,
      disposable image built from ../sandbox/Dockerfile with the exact flags
      app.py uses (--network none, --read-only, --cap-drop ALL, non-root,
      no-new-privileges, pids/mem/cpu caps). Submitted code is NEVER executed
      on the host.
    - "local" (fallback / air-gapped triage): the stdlib-only STATIC boxes
      (04/05/06/08/09/13/14 and box-1 static extraction, box-3 pin/timeline)
      run directly with the host's python3. Boxes that must install or start
      the target's code (box-1 dynamic bring-up, box-7's npm ci / npm audit)
      are REFUSED in this runner -- they execute untrusted code and require the
      Docker sandbox. This mirrors the safety line app.py draws.

The per-box docker command builders below are copied 1:1 from
backend/app.py so the sandbox posture is identical.
"""
import os
import io
import re
import json
import time
import uuid
import shutil
import zipfile
import pathlib
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent                       # repo root (has sandbox/, backend/)
BACKEND = ROOT / "backend"
SANDBOX = ROOT / "sandbox"

import sys
sys.path.insert(0, str(BACKEND))
import inspect_repo          # noqa: E402
import box3_review           # noqa: E402
import secrets_supply        # noqa: E402

IMAGE = os.environ.get("MCP_SCANNER_IMAGE", "mcp-sec-scanner:latest")
WORKDIR = pathlib.Path(os.environ.get("MCP_SCAN_WORKDIR", ROOT / ".scan_work"))
BASELINE_DIR = pathlib.Path(os.environ.get("MCP_BASELINE_DIR", ROOT / ".baselines"))
ALLOW_DYNAMIC = os.environ.get("MCP_ALLOW_DYNAMIC", "1") != "0"
MAX_UNZIP_BYTES = int(os.environ.get("MCP_MAX_UNZIP_BYTES", 800 * 1024 * 1024))
SCAN_TIMEOUT = int(os.environ.get("MCP_SCAN_TIMEOUT", 240))
INSTALL_TIMEOUT = int(os.environ.get("MCP_INSTALL_TIMEOUT", 300))

WORKDIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)

HARDEN_COMMON = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--pids-limit", "512", "--memory", "1g", "--cpus", "2"]

# --------------------------------------------------------------------------
# Review-module registry -- keyed by the module's review-type name (the value
# a user passes to --module). Keeps "one module or all" selection ordered.
# `static` modules can run in the "local" runner; the rest require docker.
# `dir` is the module's folder under sandbox/ and /opt in the image.
# --------------------------------------------------------------------------
MODULES = {
    "tool-poisoning":  {"name": "Tool Poisoning & Description Integrity", "static": True,
                        "dir": "tool-poisoning", "owasp": "MCP03/MCP06", "network": "none"},
    "rug-pull":        {"name": "Rug Pull & Change Integrity", "static": True,
                        "dir": "rug-pull", "owasp": "MCP03", "network": "none"},
    "prompt-injection": {"name": "Prompt & Template Injection", "static": True,
                        "dir": "prompt-injection", "script": "prompt-injection/prompt_injection_scan.py",
                        "norm": "normalize_prompt_injection", "owasp": "MCP06/MCP10", "network": "none"},
    "resource":        {"name": "Resource Exploitation", "static": True,
                        "dir": "resource", "script": "resource/resource_exploitation_scan.py",
                        "norm": "normalize_resource_exploit", "owasp": "MCP10", "network": "none"},
    "secrets":         {"name": "Secrets & Token Handling", "static": True,
                        "dir": "secrets", "script": "secrets/secrets_scan.py",
                        "norm": "normalize_secrets", "owasp": "MCP01", "network": "none", "history": True},
    "supply-chain":    {"name": "Supply Chain & Dependency Security", "static": False,
                        "dir": "supply-chain", "script": "supply-chain/supplychain_scan.py",
                        "norm": "normalize_supply", "owasp": "MCP04", "network": "bridge", "install": True},
    "sast":            {"name": "Static Code Security (SAST)", "static": True,
                        "dir": "sast", "script": "sast/sast_scan.py",
                        "norm": "normalize_sast", "owasp": "MCP05", "network": "none"},
    "confused-deputy": {"name": "Confused Deputy & Authorization", "static": True,
                        "dir": "confused-deputy", "script": "confused-deputy/confused_deputy_scan.py",
                        "norm": "normalize_confused_deputy", "owasp": "MCP02/MCP07", "network": "none"},
    "audit":           {"name": "Audit, Telemetry & Logging", "static": True,
                        "dir": "audit", "script": "audit/audit_scan.py",
                        "norm": "normalize_audit", "owasp": "MCP08", "network": "none"},
    "shadow":          {"name": "Shadow MCP Servers", "static": True,
                        "dir": "shadow", "script": "shadow/config_hygiene_scan.py",
                        "norm": "normalize_config_hygiene", "owasp": "MCP09", "network": "none"},
}
# Backwards-compatible alias so any code/tests still referencing BOXES keep working.
BOXES = MODULES
# canonical run order (highest-priority reviews first)
ORDER = ["tool-poisoning", "secrets", "supply-chain", "sast", "rug-pull",
         "prompt-injection", "resource", "confused-deputy", "audit", "shadow"]
# extra synonyms a user may type -> the canonical review-type name
ALIASES = {
    "poisoning": "tool-poisoning", "tool_poisoning": "tool-poisoning",
    "rugpull": "rug-pull", "rug_pull": "rug-pull", "change-integrity": "rug-pull",
    "prompt": "prompt-injection", "prompt_injection": "prompt-injection", "template-injection": "prompt-injection",
    "resource-exploitation": "resource", "resources": "resource",
    "secret": "secrets", "token-handling": "secrets",
    "supply": "supply-chain", "dependencies": "supply-chain", "deps": "supply-chain",
    "static-code-security": "sast", "code-security": "sast",
    "confused_deputy": "confused-deputy", "authz": "confused-deputy", "authorization": "confused-deputy",
    "audit-logging": "audit", "logging": "audit", "telemetry": "audit",
    "shadow-servers": "shadow", "config": "shadow", "config-hygiene": "shadow",
}

# status -> gate level (0 clean, 1 review, 2 block, 3 error)
GATE = {
    "PASS": 0, "BASELINE_PINNED": 0,
    "REVIEW": 1, "CHANGED": 1, "NEEDS_DYNAMIC": 1, "NO_BASELINE": 1,
    "EXTRACTED": 1, "NEEDS DYNAMIC": 1,
    "FAIL": 2, "HIGH_SUSPICION": 2, "HIGH SUSPICION": 2,
    "ERROR": 3,
}


def gate_level(status):
    return GATE.get((status or "").upper().replace("-", "_"), 1)


def resolve_box(token):
    t = (token or "").strip().lower()
    if t in MODULES:
        return t
    return ALIASES.get(t)


# clearer public name; keep resolve_box as an alias for compatibility
resolve_module = resolve_box


def aliases_for(module):
    """Every accepted token for a module (its canonical name + any synonyms),
    so `--list` can show them."""
    syn = sorted([a for a, b in ALIASES.items() if b == module])
    return [module] + syn


def display_name(module):
    """The name shown in CLI output IS the review-type name the user types."""
    return module


def suggest_box(token):
    """Closest valid token(s) for a typo, e.g. 'secret' -> 'secrets'."""
    import difflib
    pool = list(BOXES) + list(ALIASES)
    return difflib.get_close_matches((token or "").strip().lower(), pool, n=3, cutoff=0.6)


# --------------------------------------------------------------------------
# docker helpers (verbatim posture from backend/app.py)
# --------------------------------------------------------------------------
def docker_available():
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def image_present():
    try:
        return subprocess.run(["docker", "image", "inspect", IMAGE],
                              capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _analyze_cmd(repo_dir, server_name, mode, extra=None):
    return ["docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
            "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
            "/work/repo", "--server-name", server_name, "--mode", mode, *(extra or [])]


def _install_cmd(repo_dir):
    inner = ("cd /work/repo && (npm ci --no-audit --no-fund --loglevel=error "
             "|| npm install --no-audit --no-fund --loglevel=error)")
    return ["docker", "run", "--rm", "--network", "bridge", *HARDEN_COMMON,
            "--entrypoint", "sh", "-v", f"{repo_dir}:/work/repo:rw", IMAGE, "-c", inner]


def _dynamic_cmd(repo_dir, server_name, extra=None):
    return ["docker", "run", "--rm", "--network", "none",
            "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
            "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
            "/work/repo", "--server-name", server_name, "--mode", "dynamic", *(extra or [])]


def _timeline_cmd(repo_dir, server_name, last=3):
    return ["docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,size=256m", "--user", "10001", *HARDEN_COMMON,
            "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
            "/opt/rug-pull/run_rug_pull_timeline.py", "/work/repo",
            "--last", str(last), "--server-name", server_name]


def _script_cmd(repo_dir, script, extra=None, network="none"):
    """Generic single-detector docker run for the stdlib-only static boxes and
    box-7. `network`='none' for the offline static boxes, 'bridge' for box-7."""
    ro = ["--read-only"] if network == "none" else ["--read-only"]
    tmp = "128m" if network == "none" else "256m"
    return ["docker", "run", "--rm", "--network", network, *ro,
            "--tmpfs", f"/tmp:rw,size={tmp}", "--user", "10001", *HARDEN_COMMON,
            "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
            f"/opt/{script}", "/work/repo", "--json", *(extra or [])]


def _pretty(cmd):
    return " ".join(("'%s'" % c if " " in c else c) for c in cmd)


def _parse_envelope(stdout):
    stdout = (stdout or "").strip()
    i = stdout.find("{")
    if i < 0:
        return None
    try:
        return json.loads(stdout[i:])
    except Exception:
        return None


# --------------------------------------------------------------------------
# input resolution: dir | .zip | git URL  ->  a repo directory on disk
# --------------------------------------------------------------------------
def safe_extract(zip_path, dest):
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError("Zip contains an unsafe path (zip-slip).")
            total += info.file_size
            if total > MAX_UNZIP_BYTES:
                raise ValueError("Archive is too large when extracted.")
        z.extractall(dest)


def find_repo_root(extracted):
    entries = [p for p in extracted.iterdir() if not p.name.startswith("__MACOSX")]
    dirs = [p for p in entries if p.is_dir()]
    files = [p for p in entries if p.is_file()]
    return dirs[0] if (len(dirs) == 1 and not files) else extracted


def is_git_url(s):
    s = s.strip()
    return (s.startswith(("http://", "https://", "git@", "ssh://"))
            or s.endswith(".git"))


def resolve_target(target, scratch):
    """Return (repo_dir, source_kind). scratch is a temp dir we own."""
    p = pathlib.Path(target).expanduser()
    if is_git_url(target):
        dest = scratch / "clone"
        # full clone so box-3 timeline (last-3-commits) has history
        r = subprocess.run(["git", "clone", "--quiet", target, str(dest)],
                           capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {(r.stderr or '').strip()[:300]}")
        return dest, "git"
    if p.is_dir():
        return p.resolve(), "dir"
    if p.is_file() and p.suffix.lower() == ".zip":
        dest = scratch / "extracted"
        dest.mkdir(parents=True, exist_ok=True)
        safe_extract(p, dest)
        return find_repo_root(dest), "zip"
    raise FileNotFoundError(f"Target not found or unsupported: {target} "
                            "(expected a repo directory, a .zip, or a git URL).")


def is_node_repo(repo):
    return (repo / "package.json").is_file()


# --------------------------------------------------------------------------
# box-1 / box-3 result adapters -> uniform result envelope
# --------------------------------------------------------------------------
def _stats_from_counts(counts):
    return [
        {"cls": "s-tools", "n": counts.get("total", 0), "l": "Findings"},
        {"cls": "s-crit", "n": counts.get("critical", 0), "l": "Critical"},
        {"cls": "s-high", "n": counts.get("high", 0), "l": "High"},
        {"cls": "", "n": counts.get("medium", 0), "l": "Medium"},
    ]


def _adapt_box1(env):
    v = env.get("verdict", {})
    if "stats_tiles" not in env:
        env["stats_tiles"] = _stats_from_counts(v.get("counts", {}))
    env.setdefault("box", "tool-poisoning")
    env.setdefault("box_name", "Tool Poisoning & Description Integrity")
    return env


def _debox(result, module):
    """Strip UI-era 'box' vocabulary from the normalized result so the CLI's
    artifacts (per-module JSON) never expose 'box'/'BOX-13' to users. The shared
    normalizers are left untouched; this is a CLI-side presentation cleanup.
    Renames the result's box fields to the review-type name and drops the
    per-finding 'box' tag (which is not displayed anywhere)."""
    if not isinstance(result, dict):
        return result
    result.pop("box", None)
    result["module"] = module
    if "box_name" in result:
        result.setdefault("module_name", result.pop("box_name"))
    for f in result.get("findings", []) or []:
        if isinstance(f, dict):
            f.pop("box", None)
    return result


# --------------------------------------------------------------------------
# core: run a single box, returning a rich result dict
# --------------------------------------------------------------------------
def _log(runlog, msg, status="run", detail=""):
    entry = {"t": round(time.time(), 3), "msg": msg, "status": status, "detail": detail}
    runlog.append(entry)
    return entry


def run_box(repo, server_name, box, runner="docker", mode=None, log_cb=None):
    """Run one box. Returns:
       {box, id, name, owasp, status, counts, result, runlog, error, cmd}
    `result` is the normalized UI envelope (identical to app.py's `result`)."""
    spec = BOXES[box]
    runlog = []

    def emit(msg, status="run", detail=""):
        e = _log(runlog, msg, status, detail)
        if log_cb:
            log_cb(box, e)
        return e

    out = {"module": box, "name": spec["name"], "owasp": spec["owasp"],
           "status": "ERROR", "counts": {}, "result": None, "runlog": runlog,
           "error": None, "cmd": None}

    try:
        if runner == "local" and not spec.get("static", False):
            raise RuntimeError(
                f"{spec['name']} installs or starts the target's own code, which must "
                "run inside the Docker sandbox. Re-run with the docker runner "
                "(remove --no-sandbox) after starting Docker Desktop.")

        # ---- box-6/5/8/9/04/13/14 : single static detector ----
        if box in ("prompt-injection", "resource", "secrets", "sast",
                   "confused-deputy", "audit", "shadow"):
            extra = []
            if spec.get("history") and (repo / ".git").is_dir():
                extra = ["--history"]
            if runner == "docker":
                cmd = _script_cmd(repo, spec["script"], extra, network="none")
            else:
                cmd = ["python3", str(SANDBOX / spec["script"]), str(repo), "--json", *extra]
            out["cmd"] = _pretty(cmd)
            emit(f"Running {spec['name']} detector", "run", out["cmd"])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                raise RuntimeError((proc.stderr or "no output from detector")[:400])
            result = getattr(secrets_supply, spec["norm"])(rep, server_name)

        # ---- box-7 : optional install phase, then network-enabled scan ----
        elif box == "supply-chain":
            if ALLOW_DYNAMIC and is_node_repo(repo):
                icmd = _install_cmd(repo)
                emit("Installing dependencies (network) for full node_modules coverage",
                     "run", _pretty(icmd))
                iproc = subprocess.run(icmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
                emit("Dependency install", "ok" if iproc.returncode == 0 else "fail",
                     "" if iproc.returncode == 0 else (iproc.stderr or "")[:200])
            cmd = _script_cmd(repo, spec["script"], network="bridge")
            out["cmd"] = _pretty(cmd)
            emit("Scanning dependencies — SBOM, CVEs, typosquat, install scripts", "run", out["cmd"])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                raise RuntimeError((proc.stderr or "no output from detector")[:400])
            result = secrets_supply.normalize_supply(rep, server_name)

        # ---- box-1 : extract (static, +dynamic bring-up on docker) + detect ----
        elif box == "tool-poisoning":
            if runner == "docker":
                cmd = _analyze_cmd(repo, server_name, "static", ["--full-tools"])
            else:
                cmd = ["python3", str(SANDBOX / "tool-poisoning/run_tool_poisoning.py"), str(repo),
                       "--server-name", server_name, "--mode", "static", "--full-tools"]
            out["cmd"] = _pretty(cmd)
            emit("Extracting tools + running Tool Poisoning detector (L1–L4)", "run", out["cmd"])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            env = _parse_envelope(proc.stdout)
            if env is None:
                raise RuntimeError((proc.stderr or "no output from scanner")[:400])
            ex = env.get("extraction", {})
            # dynamic bring-up (docker only, node repos with nothing found)
            if (not ex.get("ok")) and runner == "docker" and ALLOW_DYNAMIC and is_node_repo(repo):
                icmd = _install_cmd(repo)
                emit("Static extraction found no tools — installing deps (network phase)",
                     "run", _pretty(icmd))
                iproc = subprocess.run(icmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
                if iproc.returncode == 0:
                    dcmd = _dynamic_cmd(repo, server_name, ["--full-tools"])
                    emit("Introspecting running server (network OFF, tools/list)", "run", _pretty(dcmd))
                    dproc = subprocess.run(dcmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
                    denv = _parse_envelope(dproc.stdout)
                    if denv and denv.get("extraction", {}).get("ok"):
                        env = denv
            result = _adapt_box1(env)

        # ---- box-3 : pin baseline | timeline (last 3 commits) ----
        elif box == "rug-pull":
            m = mode or ("timeline" if (repo / ".git").is_dir() else "pin")
            if m == "timeline":
                if not (repo / ".git").is_dir():
                    raise RuntimeError("Rug-Pull timeline mode needs a full git clone "
                                       "(a GitHub 'Download ZIP' strips .git). Use a git URL "
                                       "or `git clone`, or run box3 in pin mode (--box3-mode pin).")
                if runner == "docker":
                    cmd = _timeline_cmd(repo, server_name, 3)
                else:
                    cmd = ["python3", str(SANDBOX / "rug-pull/run_rug_pull_timeline.py"), str(repo),
                           "--last", "3", "--server-name", server_name]
                out["cmd"] = _pretty(cmd)
                emit("Walking the last 3 commits (git archive per commit)", "run", out["cmd"])
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
                tenv = _parse_envelope(proc.stdout)
                if tenv is None:
                    raise RuntimeError((proc.stderr or "no output")[:400])
                result, extra_meta = box3_review.finalize_timeline(server_name, tenv, repo, BASELINE_DIR)
            else:  # pin
                if runner == "docker":
                    cmd = _analyze_cmd(repo, server_name, "static", ["--extract-only", "--full-tools"])
                else:
                    cmd = ["python3", str(SANDBOX / "tool-poisoning/run_tool_poisoning.py"), str(repo),
                           "--server-name", server_name, "--mode", "static",
                           "--extract-only", "--full-tools"]
                out["cmd"] = _pretty(cmd)
                emit("Extracting components and pinning baseline (commit / lockfile / entrypoint)",
                     "run", out["cmd"])
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
                env = _parse_envelope(proc.stdout)
                if env is None:
                    raise RuntimeError((proc.stderr or "no output")[:400])
                result, extra_meta = box3_review.review_pin(
                    server_name, env.get("extraction", {}), env.get("triage", {}), repo, BASELINE_DIR)
            out["baseline_meta"] = extra_meta
        else:
            raise RuntimeError(f"Unknown box '{box}'.")

        v = result.get("verdict", {})
        out["status"] = v.get("status", "ERROR")
        out["counts"] = v.get("counts", {})
        out["result"] = _debox(result, box)
        emit(f"Verdict: {out['status']}", "ok" if gate_level(out["status"]) == 0 else "flag")
    except subprocess.TimeoutExpired:
        out["error"] = f"{spec['name']} timed out after {SCAN_TIMEOUT}s."
        emit(out["error"], "fail")
    except Exception as e:
        out["error"] = str(e)[:500]
        emit(f"{spec['name']} failed", "fail", out["error"])
    return out


def inspect_target(repo):
    """Read-only repo metadata for the report header (no code executed)."""
    try:
        return inspect_repo.inspect(repo)
    except Exception:
        return {}


def preflight(runner):
    """Return (ok, message). For docker runner, both daemon + image required."""
    if runner == "local":
        return True, "local runner (static modules only; no container isolation)"
    if not docker_available():
        return False, ("Docker is not available. Start Docker Desktop and retry, "
                       "or use --no-sandbox for static-only boxes.")
    if not image_present():
        return False, (f"Scanner image '{IMAGE}' not built. Run scripts/build.sh first "
                       "(one-time), then retry.")
    return True, f"docker sandbox ready · image {IMAGE}"
