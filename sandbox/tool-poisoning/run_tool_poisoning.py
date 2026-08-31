#!/usr/bin/env python3
"""
run_box1.py -- in-sandbox orchestrator for Box-1 (Tool Poisoning &
Description Integrity).

Runs ENTIRELY inside the disposable Docker container. The host backend
never executes any of the submitted repo's code -- it only spins this
script up inside the hardened sandbox and reads the JSON it prints to
stdout.

Pipeline (mirrors the architecture doc: Ingest -> Extract -> Analyze -> Score):
  1. triage.py            decide static vs dynamic extraction (no execution)
  2a. static_extract.py   pure-AST tool extraction, no code run   (default)
  2b. introspect.mjs      real MCP client `tools/list` on a running server
                          (only in --mode dynamic, deps pre-installed by the
                          host in a separate network-enabled phase)
  3. detect_poison_v2     the real Box-1 detector (L1/L2/L3/L4)
  4. verdict envelope     normalized {findings[], verdict{}} shape that the
                          MASTER_README asks every box to converge on.

Output: a single JSON object on stdout. Exit code encodes the verdict:
  0 = PASS, 1 = REVIEW, 2 = FAIL, 3 = NEEDS_DYNAMIC/MANUAL (could not extract).
"""
import os, sys, json, argparse, subprocess, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Reuse the *real* Box-1 toolkit code, unmodified.
import triage as triage_mod                      # noqa: E402
import static_extract as static_mod              # noqa: E402
from detect_poison_v2 import scan, SEV_ORDER     # noqa: E402

BOX_ID = "01"
BOX_NAME = "Tool Poisoning & Description Integrity"

# ---- per-layer plain-English impact + remediation (Box-7-style richness) ----
LAYER_INFO = {
    "L1": {
        "impact": "The tool description carries imperative / secrecy instructions or "
                  "points at sensitive paths. An LLM reads the description as trusted "
                  "context, so this text can silently steer the model into leaking "
                  "secrets or taking unintended actions.",
        "remediation": "Remove instruction-like or secrecy language from the description. "
                       "Descriptions must describe behaviour, never command the model.",
    },
    "L2": {
        "impact": "Hidden / invisible Unicode (zero-width or Unicode-tag characters) or an "
                  "abnormally long description. Invisible payloads reach the model but not "
                  "the human reviewer -- the classic tool-poisoning smuggling channel.",
        "remediation": "Strip non-printable characters from all tool metadata and keep "
                       "descriptions short and human-auditable.",
    },
    "L3": {
        "impact": "This tool's description references a tool that belongs to a DIFFERENT "
                  "server (cross-origin shadowing). A malicious server can redefine or "
                  "override a trusted server's tool this way.",
        "remediation": "Do not reference other servers' tools by name in a description. "
                       "Pin tool origins and reject cross-origin redefinitions.",
    },
    "L4": {
        "impact": "An optional free-text parameter shaped like an exfiltration sink "
                  "(notes / debug / context / feedback ...). It gives the model a channel "
                  "to smuggle data out inside an otherwise-innocent call.",
        "remediation": "Remove or constrain free-text side-channel parameters; make inputs "
                       "typed and purpose-specific.",
    },
    "L7": {
        "impact": "A tool definition changed since it was approved (rug-pull signal).",
        "remediation": "Re-review and re-pin the tool baseline before allowing use.",
    },
}


def run_triage(repo):
    return triage_mod.triage(repo)


def extract_static(repo):
    """Pure-AST extraction across all .py files. No code executed."""
    tools = []
    for dirpath, dirnames, files in os.walk(repo):
        dirnames[:] = [d for d in dirnames
                       if d not in {".git", "node_modules", "dist", "build",
                                    "__pycache__", ".venv", "venv", "vendor", "target"}]
        for f in files:
            if f.endswith(".py"):
                tools += static_mod.extract_from_file(os.path.join(dirpath, f))
    return tools


import ast as _ast
_COMPONENT_DECORATORS = {"tool": "tools", "resource": "resources", "prompt": "prompts"}
_SKIP = {".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv",
         "vendor", "target", ".mypy_cache"}


def extract_components_static(repo):
    """Static AST pass capturing @mcp.tool / @mcp.resource / @mcp.prompt
    functions. Resources/prompts share the exact same shape as tools so
    Box-3 can canonicalize/hash/diff them identically. No code executed."""
    out = {"tools": [], "resources": [], "prompts": []}
    for dp, dns, files in os.walk(repo):
        dns[:] = [d for d in dns if d not in _SKIP and not d.startswith(".")]
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(dp, f)
            try:
                tree = _ast.parse(open(path, encoding="utf-8", errors="ignore").read())
            except Exception:
                continue
            for node in _ast.walk(tree):
                if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    continue
                for dec in node.decorator_list:
                    d = dec.func if isinstance(dec, _ast.Call) else dec
                    if isinstance(d, _ast.Attribute) and d.attr in _COMPONENT_DECORATORS:
                        kind = _COMPONENT_DECORATORS[d.attr]
                        params, req = {}, []
                        for arg in node.args.args:
                            if arg.arg == "self":
                                continue
                            params[arg.arg] = {"type": "string"}
                            req.append(arg.arg)
                        out[kind].append({
                            "name": node.name,
                            "description": _ast.get_docstring(node) or "",
                            "input_schema": {"type": "object", "properties": params, "required": req},
                            "source": f"{os.path.relpath(path, repo)}:{node.lineno}",
                        })
                        break
    return out


def derive_start_cmd(repo):
    """Best-effort server launch command from package.json (dynamic mode)."""
    pkg = os.path.join(repo, "package.json")
    if not os.path.isfile(pkg):
        # python fallback: a server.py at the root
        for cand in ("server.py", "main.py", "app.py"):
            if os.path.isfile(os.path.join(repo, cand)):
                return f"python3 {cand}"
        return None
    try:
        data = json.load(open(pkg, encoding="utf-8"))
    except Exception:
        return None
    b = data.get("bin")
    if isinstance(b, str):
        return f"node {b}"
    if isinstance(b, dict) and b:
        return f"node {sorted(b.values())[0]}"
    if data.get("main"):
        return f"node {data['main']}"
    for cand in ("dist/index.js", "index.js", "cli.js", "build/index.js"):
        if os.path.isfile(os.path.join(repo, cand)):
            return f"node {cand}"
    return None


def extract_dynamic(repo, start_cmd):
    """Run the real MCP client against a running server, in-sandbox."""
    if not start_cmd:
        start_cmd = derive_start_cmd(repo)
    if not start_cmd:
        return None, "dynamic extraction: could not determine a server launch command"
    out = "/tmp/tools_dynamic.json"
    introspect = os.path.join(HERE, "introspect.mjs")
    try:
        proc = subprocess.run(
            ["node", introspect, start_cmd, out],
            cwd=repo, capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None, "dynamic extraction timed out (server did not respond to tools/list)"
    if proc.returncode != 0 or not os.path.isfile(out):
        return None, f"dynamic extraction failed: {(proc.stderr or '').strip()[:300]}"
    try:
        return json.load(open(out)), f"launched via: {start_cmd}"
    except Exception as e:
        return None, f"dynamic extraction produced unreadable output: {e}"


def normalize_findings(raw):
    """detect_poison_v2 finding -> UI schema with impact + remediation."""
    out = []
    for f in raw:
        layer = f.get("layer", "")
        info = LAYER_INFO.get(layer, {})
        out.append({
            "severity": f.get("severity", "info"),
            "box": f.get("box", "BOX-01"),
            "layer": layer,
            "subject": f.get("tool", "<unknown>"),
            "title": f.get("message", ""),
            "evidence": f.get("evidence", ""),
            "impact": info.get("impact", ""),
            "remediation": info.get("remediation", ""),
        })
    return out


LAYER_LABEL = {
    "L1": "imperative/secrecy instructions or sensitive-path references",
    "L2": "hidden or obfuscated content (invisible Unicode / oversized text)",
    "L3": "cross-origin tool shadowing",
    "L4": "exfiltration-shaped free-text parameters",
    "L7": "post-approval definition changes",
}


def _top_layers(findings):
    seen = []
    for f in findings:
        lbl = LAYER_LABEL.get(f.get("layer"), f.get("layer"))
        if lbl and lbl not in seen:
            seen.append(lbl)
    return seen


def build_verdict(findings, extraction_ok, triage_verdict, tool_count):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    counts["total"] = len(findings)

    if not extraction_ok:
        rationale = (
            "The scanner could not read this server's tool definitions without running it "
            f"(triage verdict: {triage_verdict}). Static AST extraction only sees Python "
            "@mcp.tool definitions, so a TypeScript/JS server, a build-required repo, or a "
            "vendored/monorepo split lands here. No tool-poisoning checks were run, so this "
            "is deliberately NOT reported as a pass -- it needs sandboxed dynamic bring-up "
            "or a manually supplied tool list.")
        return {
            "status": "NEEDS_DYNAMIC", "exit_code": 3,
            "headline": "Could not extract this server's tools without executing it.",
            "next_step": ("Enable dynamic bring-up (installs deps in a network phase, then "
                          "introspects with the network off), or supply tools.json and re-submit."),
            "rationale": rationale, "counts": counts,
        }, 3

    tops = _top_layers(findings)
    layer_phrase = ("; ".join(tops[:3]) + ("; and more" if len(tops) > 3 else "")) if tops else ""

    worst = max((SEV_ORDER[f["severity"]] for f in findings), default=0)
    if worst >= 3:       # high or critical
        status, code, head, nxt = ("FAIL", 2,
            "High-confidence tool-poisoning indicators found.",
            "Block this submission. A human must resolve or formally risk-accept every "
            "critical/high finding before the server is approved.")
        rationale = (
            f"Reviewed {tool_count} tool(s) and raised {counts['total']} finding(s): "
            f"{counts['critical']} critical, {counts['high']} high. "
            f"The strongest signals are {layer_phrase}. "
            "Because a tool's description reaches the model as trusted context, a poisoned "
            "description can silently steer the model into leaking secrets or taking actions "
            "the user never intended -- so this is a blocking result until each finding is "
            "resolved or formally risk-accepted.")
    elif worst >= 1:     # medium or low
        status, code, head, nxt = ("REVIEW", 1,
            "Lower-severity indicators found -- needs a human decision.",
            "A reviewer should accept, patch, or reject before the server proceeds.")
        rationale = (
            f"Reviewed {tool_count} tool(s) and raised {counts['total']} lower-severity "
            f"finding(s) ({layer_phrase or 'see findings'}). Nothing rose to high-confidence "
            "critical/high, so this is not an automatic block -- but a human should decide "
            "whether to accept, patch, or reject before the server is approved.")
    else:
        status, code, head, nxt = ("PASS", 0,
            "No tool-poisoning indicators detected in the extracted tool set.",
            "Safe to proceed. Re-scan on every update -- a clean scan is a snapshot, "
            "not a permanent guarantee.")
        rationale = (
            f"Extracted and inspected {tool_count} tool(s). None of the tool-poisoning checks fired -- "
            "no hidden/invisible Unicode, no imperative or secrecy instructions, no "
            "sensitive-path references, no cross-origin shadowing, and no exfiltration-shaped "
            "parameters. Treat this as a clean snapshot of the current version and re-scan on "
            "every update, since a later release could reintroduce any of these.")
    return {"status": status, "exit_code": code, "headline": head,
            "next_step": nxt, "rationale": rationale, "counts": counts}, code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--server-name", default="")
    ap.add_argument("--mode", choices=["auto", "static", "dynamic"], default="auto")
    ap.add_argument("--start-cmd", default="")
    ap.add_argument("--extract-only", action="store_true",
                    help="extract the tool set and stop (no poisoning detection) -- used by Box-3")
    ap.add_argument("--full-tools", action="store_true",
                    help="include full tool objects (name/description/schema) in the output")
    args = ap.parse_args()

    tr = run_triage(args.repo)
    triage_block = {
        "verdict": tr["verdict"], "headline": tr["headline"],
        "static_score": tr["static_score"], "sandbox_score": tr["sandbox_score"],
        "declares_mcp": tr["declares_mcp"], "has_registrations": tr["has_registrations"],
        "reasons": [{"kind": k, "text": t} for k, t in tr["reasons"]],
    }

    method = None
    tools = []
    note = ""

    want_dynamic = args.mode == "dynamic"
    if args.mode == "auto" and tr["verdict"] == "SANDBOX":
        # auto: static can't see this server's tools; try dynamic if we're
        # allowed to (deps installed). The host only invokes dynamic after a
        # network install phase, so honour that by attempting it.
        want_dynamic = True

    if want_dynamic:
        tools, note = extract_dynamic(args.repo, args.start_cmd or None)
        if tools is not None:
            method = "dynamic"
        else:
            # fall back to static so we still say *something* useful
            static_tools = extract_static(args.repo)
            if static_tools:
                tools, method = static_tools, "static (dynamic fallback)"
                note = (note or "") + " -- fell back to static extraction"
            else:
                tools = []
    if method is None and not want_dynamic:
        tools = extract_static(args.repo)
        method = "static"
        note = "pure-AST extraction, no repo code executed"

    tools = tools or []
    extraction_ok = len(tools) > 0

    extraction = {
        "method": method or "none",
        "tool_count": len(tools),
        "ok": extraction_ok,
        "note": note,
        "tools_preview": [t.get("name") for t in tools],
    }
    if args.full_tools:
        extraction["tools_full"] = [{
            "name": t.get("name"),
            "description": t.get("description", "") or "",
            "input_schema": t.get("input_schema", t.get("inputSchema", {})) or {},
            "source": t.get("source") or t.get("source_ref"),
        } for t in tools]

    if args.extract_only:
        # Box-3 (Rug Pull) needs the full component set; the drift comparison
        # against the pinned baseline + provenance happens on the host.
        comps = extract_components_static(args.repo)
        extraction["resources_full"] = comps["resources"]
        extraction["prompts_full"] = comps["prompts"]
        extraction["resource_count"] = len(comps["resources"])
        extraction["prompt_count"] = len(comps["prompts"])
        # if dynamic tools couldn't be had but static did, fall back for tools too
        if not extraction_ok and comps["tools"]:
            extraction["tools_full"] = comps["tools"]
            extraction["tools_preview"] = [t["name"] for t in comps["tools"]]
            extraction["tool_count"] = len(comps["tools"])
            extraction["ok"] = True
            extraction_ok = True
        envelope = {
            "box": BOX_ID, "box_name": BOX_NAME, "server_name": args.server_name,
            "triage": triage_block, "extraction": extraction, "findings": [],
            "verdict": {"status": "EXTRACTED", "exit_code": 0,
                        "headline": "Component set extracted.", "next_step": "",
                        "rationale": "", "counts": {"total": 0}},
        }
        print(json.dumps(envelope, indent=2))
        sys.exit(0 if extraction_ok else 3)

    findings_raw = scan(tools) if extraction_ok else []
    findings = normalize_findings(findings_raw)
    verdict, code = build_verdict(findings, extraction_ok, tr["verdict"], len(tools))

    envelope = {
        "box": BOX_ID, "box_name": BOX_NAME, "server_name": args.server_name,
        "triage": triage_block, "extraction": extraction,
        "findings": findings, "verdict": verdict,
    }
    print(json.dumps(envelope, indent=2))
    sys.exit(code)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        err = traceback.format_exc()
        print(json.dumps({
            "box": BOX_ID, "box_name": BOX_NAME,
            "error": "orchestrator crashed inside sandbox",
            "detail": err.splitlines()[-1] if err else "unknown",
            "verdict": {"status": "ERROR", "exit_code": 4,
                        "headline": "Scan failed inside the sandbox.",
                        "next_step": "Check the server logs / container output.",
                        "counts": {"total": 0}},
        }, indent=2))
        sys.exit(4)
