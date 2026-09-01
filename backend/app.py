#!/usr/bin/env python3
"""
MCP Security Review Platform -- backend.

Serves the security-engineer console and runs security "boxes" against an
uploaded MCP server repo. Ten boxes are wired live -- 01 Tool Poisoning,
03 Rug Pull & Change Integrity, 04 Prompt & Template Injection, 05 Resource
Exploitation, 06 Secrets & Token Handling, 07 Supply Chain & Dependency
Security, 08 Static Code Security (SAST), 09 Confused Deputy & Authorization,
13 Audit/Telemetry & Logging, 14 Shadow MCP Servers (config & manifest
hygiene) -- each running inside a hardened, disposable Docker sandbox; the
host never executes submitted code directly.

Endpoints:
  GET  /api/health
  POST /api/inspect                              read-only metadata for the upload card
  POST /api/scan/tool-poisoning/stream           NDJSON live progress + final result
  POST /api/scan/tool-poisoning
  POST /api/scan/rug-pull/stream
  POST /api/scan/rug-pull
  POST /api/scan/secrets/stream
  POST /api/scan/secrets
  POST /api/scan/supply-chain/stream
  POST /api/scan/supply-chain
  POST /api/scan/resource-exploitation/stream
  POST /api/scan/resource-exploitation
  POST /api/scan/sast/stream
  POST /api/scan/sast
  POST /api/scan/confused-deputy/stream
  POST /api/scan/confused-deputy

Run:  uvicorn app:app --reload --port 8000
"""
import os, io, re, json, shutil, zipfile, subprocess, time, uuid, pathlib
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse

import inspect_repo
import overview as overview_mod
import box3_review
import secrets_supply

# --------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
IMAGE = os.environ.get("MCP_SCANNER_IMAGE", "mcp-sec-scanner:latest")
WORKDIR = pathlib.Path(os.environ.get("MCP_SCAN_WORKDIR", ROOT / ".scan_work"))
BASELINE_DIR = pathlib.Path(os.environ.get("MCP_BASELINE_DIR", ROOT / ".baselines"))
ALLOW_DYNAMIC = os.environ.get("MCP_ALLOW_DYNAMIC", "1") != "0"
MAX_ZIP_BYTES = int(os.environ.get("MCP_MAX_ZIP_BYTES", 200 * 1024 * 1024))
MAX_UNZIP_BYTES = int(os.environ.get("MCP_MAX_UNZIP_BYTES", 800 * 1024 * 1024))
SCAN_TIMEOUT = int(os.environ.get("MCP_SCAN_TIMEOUT", 240))
INSTALL_TIMEOUT = int(os.environ.get("MCP_INSTALL_TIMEOUT", 300))

WORKDIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="MCP Security Review Platform")

HARDEN_COMMON = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--pids-limit", "512", "--memory", "1g", "--cpus", "2"]


# --------------------------------------------------------------------------
# docker helpers
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
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/work/repo", "--server-name", server_name, "--mode", mode, *(extra or []),
    ]


def _install_cmd(repo_dir):
    inner = ("cd /work/repo && (npm ci --no-audit --no-fund --loglevel=error "
             "|| npm install --no-audit --no-fund --loglevel=error)")
    return ["docker", "run", "--rm", "--network", "bridge", *HARDEN_COMMON,
            "--entrypoint", "sh", "-v", f"{repo_dir}:/work/repo:rw", IMAGE, "-c", inner]


def _dynamic_cmd(repo_dir, server_name, extra=None):
    return [
        "docker", "run", "--rm", "--network", "none",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/work/repo", "--server-name", server_name, "--mode", "dynamic", *(extra or []),
    ]


def _timeline_cmd(repo_dir, server_name, last=3):
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=256m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/rug-pull/run_rug_pull_timeline.py", "/work/repo",
        "--last", str(last), "--server-name", server_name,
    ]


def _secrets_cmd(repo_dir, history):
    # Box-6 is stdlib-only static reads — safe with the network OFF and a
    # read-only rootfs. --history adds the git-log scan (needs .git present).
    extra = ["--history"] if history else []
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/secrets/secrets_scan.py", "/work/repo", "--json", *extra,
    ]


def _resource_exploit_cmd(repo_dir):
    # Box-5 is stdlib-only static reads (no execution) — safe with the
    # network OFF and a read-only rootfs, same posture as Box-6.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/resource/resource_exploitation_scan.py", "/work/repo", "--json",
    ]


def _sast_cmd(repo_dir):
    # Box-8 is also stdlib-only static reads (regex/line scan, no code from
    # the repo is ever executed) -- network off, read-only rootfs.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/sast/sast_scan.py", "/work/repo", "--json",
    ]


def _confused_deputy_cmd(repo_dir):
    # Box-9 is also stdlib-only static reads — network off, read-only rootfs.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/confused-deputy/confused_deputy_scan.py", "/work/repo", "--json",
    ]


def _prompt_injection_cmd(repo_dir):
    # Box-04 is stdlib-only static reads — network off, read-only rootfs.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/prompt-injection/prompt_injection_scan.py", "/work/repo", "--json",
    ]


def _audit_cmd(repo_dir):
    # Box-13 is stdlib-only static reads — network off, read-only rootfs.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/audit/audit_scan.py", "/work/repo", "--json",
    ]


def _config_hygiene_cmd(repo_dir):
    # Box-14 is stdlib-only static config reads — network off, read-only rootfs.
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=128m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/shadow/config_hygiene_scan.py", "/work/repo", "--json",
    ]


def _supply_scan_cmd(repo_dir):
    # Box-7's CVE layer needs registry access (npm audit + PyPI JSON API), so
    # this phase runs with the network ON — still non-root, cap-drop, read-only
    # rootfs with a tmpfs for the npm cache.
    return [
        "docker", "run", "--rm", "--network", "bridge", "--read-only",
        "--tmpfs", "/tmp:rw,size=256m", "--user", "10001", *HARDEN_COMMON,
        "--entrypoint", "python3", "-v", f"{repo_dir}:/work/repo:ro", IMAGE,
        "/opt/supply-chain/supplychain_scan.py", "/work/repo", "--json",
    ]


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


def _step(key, label, status, detail=""):
    return {"type": "step", "key": key, "label": label, "status": status, "detail": detail}


# --------------------------------------------------------------------------
# Per-layer run-log narration
# --------------------------------------------------------------------------
# Each module evaluates several named layers. Rather than a single "Scanning
# (S1-S6)" line, we narrate each layer individually in the live run log --
# "Validating S1 - Hardcoded credentials -> clean" / "-> 2 finding(s)" -- so
# the reviewer can see every check the module actually performed and its
# result, not just an opaque range.
LAYER_DEFS = {
    "box1": [("L1", "Instruction & secrecy language"), ("L2", "Hidden / obfuscated content"),
             ("L3", "Cross-origin shadowing"), ("L4", "Exfiltration-shaped parameters")],
    "box5": [("R1", "Path traversal"), ("R2", "Unbounded reads"), ("R3", "SSRF-shaped fetch"),
             ("R4", "Overly broad URI templates"), ("R5", "Missing content-type/size validation")],
    "box6": [("S1", "Hardcoded credentials"), ("S2", "Git history"), ("S3", "MCP-channel leakage"),
             ("S4", "Over-broad credential surface"), ("S5", "Token lifecycle hygiene"),
             ("S6", "Repo hygiene")],
    "box7": [("L1", "SBOM — dependency inventory"), ("L2", "Known-CVE scan"),
             ("L3", "Typosquat / dependency confusion"), ("L4", "Malicious install scripts")],
    "box8": [("C1", "OS command injection"), ("C2", "Code injection / dynamic eval"),
             ("C3", "Insecure deserialization"), ("C4", "SQL / NoSQL injection"),
             ("C5", "Server-side template injection")],
    "box9": [("A1", "Shared credential, no caller check"), ("A2", "Unchecked privileged operation"),
             ("A3", "Unvalidated token pass-through"), ("A4", "Untrusted identity parameter"),
             ("A5", "No authorization framework")],
    "box04": [("P1", "Untrusted input in prompt template"), ("P2", "Server-side template injection"),
              ("P3", "Resource content into instructions"), ("P4", "Forged role-framed messages"),
              ("P5", "Unconstrained prompt arguments")],
    "box13": [("T1", "No logging framework"), ("T2", "Tool invocations not audited"),
              ("T3", "Sensitive data in logs"), ("T4", "Privileged op without audit"),
              ("T5", "Debug logging left on")],
    "box14": [("H1", "Over-broad tool / capability exposure"), ("H2", "Embedded / default credentials"),
              ("H3", "Insecure transport & debug flags"), ("H4", "Shadow-server indicators"),
              ("H5", "Manifest integrity & entrypoint")],
}


def _layer_counts_from_findings(findings):
    counts = {}
    for f in findings or []:
        lid = (f.get("layer") or "").strip()
        if lid:
            counts[lid] = counts.get(lid, 0) + 1
    return counts


def _box7_layer_counts(rep):
    """Box-7's raw report keeps each layer in its own section, not a flat
    findings list -- derive per-layer counts from those sections."""
    sbom = 0
    for f in rep.get("combined_findings", []):
        if f.get("layer") == "sbom" and not f.get("gate", True):
            sbom += 1
    return {
        "L1": sbom,
        "L2": len(rep.get("vuln_scan", {}).get("findings", [])),
        "L3": len(rep.get("typosquat_scan", {}).get("findings", [])),
        "L4": len(rep.get("installscript_scan", {}).get("findings", [])),
    }


def _emit_layer_steps(box, counts, sub_note=None):
    """Yield one live step per layer, showing clean vs. flagged. `counts` is a
    {layer_id: n_findings} map. Small sleeps give a progressive reveal."""
    for lid, name in LAYER_DEFS.get(box, []):
        n = counts.get(lid, 0)
        note = sub_note.get(lid) if sub_note else None
        if n:
            detail = f"{n} finding(s) — see results below"
            yield _step("layer_" + lid, f"Validating {lid} · {name}", "flag", detail)
        else:
            yield _step("layer_" + lid, f"Validating {lid} · {name}", "ok",
                        note or "none found — clear")
        time.sleep(0.08)


# --------------------------------------------------------------------------
# safe unzip
# --------------------------------------------------------------------------
def safe_extract(zip_bytes, dest):
    total = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise HTTPException(400, "Zip contains an unsafe path.")
            total += info.file_size
            if total > MAX_UNZIP_BYTES:
                raise HTTPException(400, "Archive is too large when extracted.")
        z.extractall(dest)


def find_repo_root(extracted):
    entries = [p for p in extracted.iterdir() if not p.name.startswith("__MACOSX")]
    dirs = [p for p in entries if p.is_dir()]
    files = [p for p in entries if p.is_file()]
    return dirs[0] if (len(dirs) == 1 and not files) else extracted


def is_node_repo(repo):
    return (repo / "package.json").is_file()


def _validate_upload(raw, filename):
    if not raw:
        raise HTTPException(400, "Empty upload.")
    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(400, "Uploaded archive exceeds the size limit.")
    if not (filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a .zip of the MCP server repo.")


# --------------------------------------------------------------------------
# shared container extraction phase (used by both boxes)
# --------------------------------------------------------------------------
def _extract_phase(repo, server_name, extra, meta, out):
    """Yield step events for the sandbox extraction (+ optional dynamic bring-up).
    Stores the final envelope in out['env']."""
    cmd = _analyze_cmd(repo, server_name, "static", extra)
    yield _step("sandbox", "Starting hardened Docker sandbox (--network none, read-only)",
                "run", _pretty(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    env = _parse_envelope(proc.stdout)
    if env is None:
        yield _step("sandbox", "Docker sandbox", "fail", (proc.stderr or "no output")[:300])
        out["env"] = None
        return
    yield _step("sandbox", "Hardened Docker sandbox", "ok", "container exited cleanly")

    ex = env.get("extraction", {})
    yield _step("extract_tools", "Extracting tool definitions (static AST — no code executed)",
                "ok", f"{ex.get('tool_count', 0)} tool(s) via {ex.get('method', '?')}")

    if not ex.get("ok") and ALLOW_DYNAMIC and is_node_repo(repo):
        meta["dynamic_attempted"] = True
        icmd = _install_cmd(repo)
        yield _step("install", "Installing dependencies (network phase)", "run", _pretty(icmd))
        iproc = subprocess.run(icmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
        if iproc.returncode == 0:
            yield _step("install", "Installing dependencies (network phase)", "ok")
            dcmd = _dynamic_cmd(repo, server_name, extra)
            yield _step("introspect", "Introspecting running server (network OFF, tools/list)",
                        "run", _pretty(dcmd))
            dproc = subprocess.run(dcmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            denv = _parse_envelope(dproc.stdout)
            if denv and denv.get("extraction", {}).get("ok"):
                env = denv
                meta["dynamic_used"] = True
                yield _step("introspect", "Introspecting running server (network OFF)", "ok",
                            f"{denv['extraction'].get('tool_count', 0)} tool(s)")
            else:
                yield _step("introspect", "Introspecting running server", "fail",
                            (dproc.stderr or "no tools introspected")[:200])
        else:
            yield _step("install", "Installing dependencies (network phase)", "fail",
                        (iproc.stderr or "")[:200])
    out["env"] = env


def _error_result(meta, headline, detail):
    return {"type": "result", "meta": meta,
            "result": {"extraction": {"ok": False}, "findings": [],
                       "verdict": {"status": "ERROR", "headline": headline,
                                   "next_step": detail, "rationale": detail,
                                   "counts": {"total": 0}}}}


def scan_stream(raw, filename, server_name, box, mode=None):
    scan_id = uuid.uuid4().hex[:12]
    scan_dir = WORKDIR / scan_id
    repo_parent = scan_dir / "extracted"
    repo_parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    meta = {"scan_id": scan_id, "server_name": server_name, "filename": filename,
            "box": box, "mode": mode, "dynamic_attempted": False, "dynamic_used": False}
    try:
        yield _step("receive", f"Received upload — {filename} ({len(raw)/1048576:.1f} MB)", "ok")

        yield _step("extract", "Extracting archive", "run")
        safe_extract(raw, repo_parent)
        repo = find_repo_root(repo_parent)
        nfiles = sum(1 for _ in repo.rglob("*") if _.is_file())
        has_git = (repo / ".git").is_dir()
        time.sleep(0.1)
        yield _step("extract", "Extracting archive", "ok",
                    f"{nfiles} files" + (" · git history present" if has_git else " · no .git"))

        yield _step("inspect", "Reading repo metadata (manifest, languages)", "run")
        info = inspect_repo.inspect(repo)
        meta["repo_info"] = info
        time.sleep(0.1)
        yield _step("inspect", "Reading repo metadata (manifest, languages)", "ok",
                    f"{info.get('name')} · {info.get('primary_language') or 'unknown'}")

        # ---- Box-3 timeline: walk the last 3 commits in the sandbox ----
        if box == "box3" and mode == "timeline":
            cmd = _timeline_cmd(repo, server_name, 3)
            yield _step("timeline", "Walking the last 3 commits in the sandbox (git archive per commit)",
                        "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            tenv = _parse_envelope(proc.stdout)
            if tenv is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Timeline walk produced no output.",
                                    (proc.stderr or "")[:300])
                return
            tl = tenv.get("timeline", {})
            yield _step("timeline", "Walking the last 3 commits", "ok",
                        f"{len(tl.get('commits', []))} commit(s), {len(tl.get('hops', []))} hop(s)")
            result, extra_meta = box3_review.finalize_timeline(server_name, tenv, repo, BASELINE_DIR)
            meta.update(extra_meta)
            yield _step("verdict", "Scoring verdict", "ok", result.get("verdict", {}).get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-6 Secrets: static, offline, read-only ----
        if box == "box6":
            cmd = _secrets_cmd(repo, has_git)
            lbl = "Scanning for secrets & token handling — 6 layers (S1–S6)"
            yield _step("secrets", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Secrets scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("secrets", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across S1–S6")
            note = None if has_git else {"S2": "skipped — no .git in the upload"}
            yield from _emit_layer_steps("box6", _layer_counts_from_findings(rep.get("findings", [])), note)
            result = secrets_supply.normalize_secrets(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-5 Resource Exploitation: static, offline, read-only ----
        if box == "box5":
            cmd = _resource_exploit_cmd(repo)
            lbl = "Scanning resource handlers for exploitation risk — 5 layers (R1–R5)"
            yield _step("resource", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Resource exploitation scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("resource", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across R1–R5")
            yield from _emit_layer_steps("box5", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_resource_exploit(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-8 Static Code Security (SAST): static, offline, read-only ----
        if box == "box8":
            cmd = _sast_cmd(repo)
            lbl = "Scanning source for static-code-security sinks — 5 layers (C1–C5)"
            yield _step("sast", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "SAST scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("sast", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across C1–C5")
            yield from _emit_layer_steps("box8", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_sast(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-9 Confused Deputy & Authorization: static, offline, read-only ----
        if box == "box9":
            cmd = _confused_deputy_cmd(repo)
            lbl = "Scanning for confused-deputy & authorization gaps — 5 layers (A1–A5)"
            yield _step("authz", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Confused-deputy scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("authz", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across A1–A5")
            yield from _emit_layer_steps("box9", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_confused_deputy(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-04 Prompt & Template Injection: static, offline, read-only ----
        if box == "box04":
            cmd = _prompt_injection_cmd(repo)
            lbl = "Scanning prompt handlers & templates for injection — 5 layers (P1–P5)"
            yield _step("prompt", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Prompt-injection scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("prompt", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across P1–P5")
            yield from _emit_layer_steps("box04", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_prompt_injection(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-13 Audit, Telemetry & Logging: static, offline, read-only ----
        if box == "box13":
            cmd = _audit_cmd(repo)
            lbl = "Assessing audit / telemetry / logging coverage — 5 layers (T1–T5)"
            yield _step("audit", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Audit/logging scan produced no output.", (proc.stderr or "")[:300])
                return
            yield _step("audit", lbl, "ok", f"{len(rep.get('findings', []))} finding(s) across T1–T5")
            yield from _emit_layer_steps("box13", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_audit(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-14 Shadow MCP Servers (config & manifest hygiene): static, offline ----
        if box == "box14":
            cmd = _config_hygiene_cmd(repo)
            lbl = "Inspecting manifests for shadow-server / hygiene indicators — 5 layers (H1–H5)"
            yield _step("config", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Config-hygiene scan produced no output.", (proc.stderr or "")[:300])
                return
            mans = rep.get("manifests", [])
            yield _step("config", lbl, "ok",
                        f"{len(rep.get('findings', []))} finding(s) · {len(mans)} manifest(s) inspected")
            yield from _emit_layer_steps("box14", _layer_counts_from_findings(rep.get("findings", [])))
            result = secrets_supply.normalize_config_hygiene(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        # ---- Box-7 Supply Chain: optional install, then network-enabled scan ----
        if box == "box7":
            if ALLOW_DYNAMIC and is_node_repo(repo):
                meta["dynamic_attempted"] = True
                icmd = _install_cmd(repo)
                yield _step("install", "Installing dependencies (network) for full node_modules coverage",
                            "run", _pretty(icmd))
                iproc = subprocess.run(icmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
                yield _step("install", "Installing dependencies (network)",
                            "ok" if iproc.returncode == 0 else "fail",
                            "" if iproc.returncode == 0 else (iproc.stderr or "")[:160])
            cmd = _supply_scan_cmd(repo)
            lbl = "Scanning dependencies — 4 layers: SBOM, CVEs, typosquat, install scripts (registry access)"
            yield _step("supply", lbl, "run", _pretty(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            rep = _parse_envelope(proc.stdout)
            if rep is None:
                meta["duration_sec"] = round(time.time() - started, 1)
                yield _error_result(meta, "Supply-chain scan produced no output.", (proc.stderr or "")[:300])
                return
            c = rep.get("verdict", {}).get("counts", {})
            yield _step("supply", lbl, "ok", f"{sum(v for v in c.values() if isinstance(v, int))} finding(s) across L1–L4")
            yield from _emit_layer_steps("box7", _box7_layer_counts(rep))
            result = secrets_supply.normalize_supply(rep, server_name)
            yield _step("verdict", "Scoring verdict", "ok", result["verdict"].get("status", "?"))
            meta["duration_sec"] = round(time.time() - started, 1)
            yield {"type": "result", "meta": meta, "result": result}
            return

        extra = (["--extract-only", "--full-tools"] if box == "box3"
                 else ["--full-tools"] if box == "box1" else [])
        out = {}
        yield from _extract_phase(repo, server_name, extra, meta, out)
        env = out.get("env")
        if env is None:
            meta["duration_sec"] = round(time.time() - started, 1)
            yield _error_result(meta, "Scanner produced no output.",
                                "The sandbox container did not return a readable result.")
            return

        if box == "box1":
            counts = env.get("verdict", {}).get("counts", {})
            b1_tc = env.get("extraction", {}).get("tool_count", 0)
            yield _step("detect", "Running Tool Poisoning detector — 4 layers (L1–L4)", "ok",
                        f"{counts.get('total', 0)} finding(s) across {b1_tc} tool(s)")
            yield from _emit_layer_steps("box1", _layer_counts_from_findings(env.get("findings", [])))
            yield _step("verdict", "Scoring verdict", "ok", env.get("verdict", {}).get("status", "?"))
            result = env
        else:  # box3 pin / validate
            ex = env.get("extraction", {})
            if mode == "validate":
                yield _step("compare", "Diffing components + provenance against the baseline", "run")
                result, extra_meta = box3_review.review_validate(
                    server_name, ex, env.get("triage", {}), repo, BASELINE_DIR)
            else:  # pin
                yield _step("compare", "Pinning baseline (components + commit / lockfile / entrypoint)", "run")
                result, extra_meta = box3_review.review_pin(
                    server_name, ex, env.get("triage", {}), repo, BASELINE_DIR)
            meta.update(extra_meta)
            dr = result.get("drift", {}).get("counts", {})
            act = extra_meta.get("baseline_action")
            cdetail = ("baseline pinned" if act == "pinned"
                       else f"+{dr.get('added',0)} / -{dr.get('removed',0)} / ~{dr.get('changed',0)}"
                       if act == "compared" else "—")
            step_lbl = ("Pinning baseline (components + commit / lockfile / entrypoint)"
                        if mode != "validate" else "Diffing components + provenance against the baseline")
            yield _step("compare", step_lbl, "ok", cdetail)
            yield _step("verdict", "Scoring verdict", "ok", result.get("verdict", {}).get("status", "?"))

        meta["duration_sec"] = round(time.time() - started, 1)
        yield {"type": "result", "meta": meta, "result": result}
    except HTTPException as he:
        yield _error_result(meta, "Upload rejected.", he.detail)
    except Exception as e:
        yield _error_result(meta, "Scan failed.", str(e)[:300])
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"docker": docker_available(), "image": IMAGE,
            "image_present": image_present(), "allow_dynamic": ALLOW_DYNAMIC}


@app.post("/api/inspect")
async def inspect_ep(file: UploadFile = File(...)):
    raw = await file.read()
    _validate_upload(raw, file.filename)
    scan_dir = WORKDIR / ("insp_" + uuid.uuid4().hex[:10])
    extracted = scan_dir / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    try:
        safe_extract(raw, extracted)
        repo = find_repo_root(extracted)
        info = inspect_repo.inspect(repo)
        info["upload_bytes"] = len(raw)
        info["filename"] = file.filename
        return JSONResponse(info)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


def _overview_sandbox_extract(repo, server_name):
    """Fallback tool extraction for servers whose tools are NOT in the repo
    source (e.g. bundled in a compiled dependency, like playwright-mcp). Reuses
    the same hardened sandbox pipeline the security modules use: static AST
    extraction first, then — for Node repos with nothing found — a dependency
    install + dynamic `tools/list` introspection (network OFF during
    introspection). Returns an `injected` dict or None. Best-effort: any failure
    just returns None and the in-process static result stands."""
    if not (docker_available() and image_present()):
        return None
    try:
        cmd = _analyze_cmd(repo, server_name, "static", ["--extract-only", "--full-tools"])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        env = _parse_envelope(proc.stdout)
        ex = (env or {}).get("extraction", {}) if env else {}
        method = "sandbox static extraction"
        # dynamic bring-up when static found nothing and it's a Node server
        if (not ex.get("tools_full")) and ALLOW_DYNAMIC and is_node_repo(repo):
            icmd = _install_cmd(repo)
            iproc = subprocess.run(icmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
            if iproc.returncode == 0:
                dcmd = _dynamic_cmd(repo, server_name, ["--full-tools"])
                dproc = subprocess.run(dcmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
                denv = _parse_envelope(dproc.stdout)
                dex = (denv or {}).get("extraction", {}) if denv else {}
                if dex.get("tools_full") or dex.get("ok"):
                    ex = dex
                    method = "dynamic introspection (tools/list)"
        if not ex.get("tools_full"):
            return None
        return {"tools": ex.get("tools_full", []),
                "resources": ex.get("resources_full", []),
                "prompts": ex.get("prompts_full", []),
                "method": method}
    except Exception:
        return None


@app.post("/api/overview")
async def overview_ep(file: UploadFile = File(...), server_name: str = Form(None)):
    """Static, read-only 'what is this MCP server' analysis powering the
    Analyse and Capability & Attack Surface tabs. Runs in-process (stdlib
    only, no code execution, no network) — same risk profile as /api/inspect,
    so it works even when Docker is not available. When in-process static
    parsing finds no tools AND Docker is available, it falls back to the
    hardened sandbox extractor / dynamic introspection so dependency-bundled
    servers (e.g. playwright-mcp) still surface their tools."""
    raw = await file.read()
    _validate_upload(raw, file.filename)
    scan_dir = WORKDIR / ("ovw_" + uuid.uuid4().hex[:10])
    extracted = scan_dir / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    try:
        safe_extract(raw, extracted)
        repo = find_repo_root(extracted)
        data = overview_mod.build_overview(repo, server_name)
        # fallback when nothing was found in source
        if not data["tools"]:
            injected = _overview_sandbox_extract(repo, server_name)
            if injected:
                data = overview_mod.build_overview(repo, server_name, injected=injected)
        data["upload"] = {"filename": file.filename, "bytes": len(raw)}
        return JSONResponse(data)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


def _preflight():
    if not docker_available():
        raise HTTPException(503, "Docker is not available. Start Docker Desktop and retry.")
    if not image_present():
        raise HTTPException(503, f"Scanner image '{IMAGE}' not built. Run scripts/build.sh first.")


def _stream_response(raw, filename, server_name, box, mode=None):
    def gen():
        for ev in scan_stream(raw, filename, server_name, box, mode):
            yield json.dumps(ev) + "\n"
    return StreamingResponse(gen(), media_type="application/x-ndjson")


def _collect_final(raw, filename, server_name, box, mode=None):
    final = None
    for ev in scan_stream(raw, filename, server_name, box, mode):
        if ev.get("type") == "result":
            final = ev
    return JSONResponse({"meta": final["meta"], "result": final["result"]})


@app.post("/api/scan/tool-poisoning/stream")
async def box1_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box1")


@app.post("/api/scan/tool-poisoning")
async def box1_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box1")


VALID_MODES = {"pin", "validate", "timeline"}


@app.post("/api/scan/rug-pull/stream")
async def box3_stream(server_name: str = Form(...), mode: str = Form("pin"),
                      file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    if mode not in VALID_MODES:
        raise HTTPException(400, f"Unknown mode '{mode}'.")
    return _stream_response(raw, file.filename, server_name, "box3", mode)


@app.post("/api/scan/rug-pull")
async def box3_final(server_name: str = Form(...), mode: str = Form("pin"),
                     file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    if mode not in VALID_MODES:
        raise HTTPException(400, f"Unknown mode '{mode}'.")
    return _collect_final(raw, file.filename, server_name, "box3", mode)


@app.post("/api/scan/secrets/stream")
async def box6_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box6")


@app.post("/api/scan/secrets")
async def box6_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box6")


@app.post("/api/scan/supply-chain/stream")
async def box7_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box7")


@app.post("/api/scan/supply-chain")
async def box7_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box7")


@app.post("/api/scan/resource-exploitation/stream")
async def box5_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box5")


@app.post("/api/scan/resource-exploitation")
async def box5_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box5")


@app.post("/api/scan/sast/stream")
async def box8_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box8")


@app.post("/api/scan/sast")
async def box8_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box8")


@app.post("/api/scan/confused-deputy/stream")
async def box9_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box9")


@app.post("/api/scan/confused-deputy")
async def box9_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box9")


@app.post("/api/scan/prompt-injection/stream")
async def box04_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box04")


@app.post("/api/scan/prompt-injection")
async def box04_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box04")


@app.post("/api/scan/audit-logging/stream")
async def box13_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box13")


@app.post("/api/scan/audit-logging")
async def box13_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box13")


@app.post("/api/scan/shadow-servers/stream")
async def box14_stream(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _stream_response(raw, file.filename, server_name, "box14")


@app.post("/api/scan/shadow-servers")
async def box14_final(server_name: str = Form(...), file: UploadFile = File(...)):
    _preflight(); raw = await file.read(); _validate_upload(raw, file.filename)
    return _collect_final(raw, file.filename, server_name, "box14")


@app.get("/api/baselines")
def baselines_list():
    """List the baselines currently persisted on disk (proof they survive
    across sessions/restarts)."""
    out = []
    for p in sorted(BASELINE_DIR.glob("*.json")):
        try:
            b = json.loads(p.read_text())
            out.append({"file": p.name, "server": b.get("label"),
                        "pinned_at": b.get("pinned_at"), "counts": b.get("counts", {})})
        except Exception:
            continue
    return {"dir": str(BASELINE_DIR), "count": len(out), "baselines": out}


@app.get("/api/baselines/{slug}")
def baseline_get(slug: str):
    p = BASELINE_DIR / (re.sub(r"[^a-zA-Z0-9._-]+", "-", slug) + ".json")
    if not p.is_file():
        raise HTTPException(404, "No baseline on record for that server.")
    return JSONResponse(json.loads(p.read_text()))


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
