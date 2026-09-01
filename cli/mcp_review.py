#!/usr/bin/env python3
"""
mcp-review -- LOCAL MCP Security Review CLI.

Run the same sandboxed security modules the web console runs, against a local
MCP server repo (a directory, a .zip, or a git URL), from your terminal or a
CI job. Every module executes inside the hardened, disposable Docker image
built from sandbox/Dockerfile -- submitted code is never run on the host.

Examples
--------
  # scan a repo directory with every module, write reports to ./mcp-report
  mcp-review ./acme-mcp --name acme-mcp

  # a single module
  mcp-review ./acme-mcp --module secrets

  # a few modules, and a git URL (enables the rug-pull commit timeline)
  mcp-review https://github.com/acme/acme-mcp --module tool-poisoning,supply-chain,sast

  # CI gate: non-zero exit if anything blocks
  mcp-review ./acme-mcp --all --fail-on block --quiet

  # air-gapped / no Docker: static modules only, no container isolation
  mcp-review ./acme-mcp --module sast,secrets --no-sandbox

Exit codes:  0 clean · 1 needs review · 2 blocking finding · 3 module/setup error
"""
import os
import re
import sys
import time
import shutil
import argparse
import pathlib
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import orchestrator as orch
import reporting
import termreport

C = {"pass": "\033[92m", "review": "\033[93m", "fail": "\033[91m",
     "dim": "\033[90m", "b": "\033[1m", "cyan": "\033[96m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def col_for(status):
    lvl = orch.gate_level(status)
    return C["pass"] if lvl == 0 else C["review"] if lvl == 1 else C["fail"]


def parse_boxes(box_arg, all_flag):
    if all_flag or not box_arg or box_arg.strip().lower() == "all":
        return list(orch.ORDER)
    picked, unknown = [], []
    for tok in re.split(r"[,\s]+", box_arg.strip()):
        if not tok:
            continue
        b = orch.resolve_box(tok)
        (picked if b else unknown).append(b or tok)
    if unknown:
        lines = [f"Unknown module(s): {', '.join(unknown)}"]
        for u in unknown:
            hints = orch.suggest_box(u)
            if hints:
                lines.append(f"  did you mean:  {', '.join(hints)}  (for '{u}')")
        lines.append(f"Valid keys: {', '.join(orch.ORDER)}")
        lines.append("Run  mcp-review --list  to see every module and its aliases.")
        sys.exit("\n".join(lines))
    # keep canonical order, dedup
    seen = set()
    return [b for b in orch.ORDER if b in picked and not (b in seen or seen.add(b))]


def main():
    ap = argparse.ArgumentParser(
        prog="mcp-review", description="Local sandboxed MCP server security review.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("target", nargs="?", help="MCP server repo: a directory, a .zip, or a git URL")
    ap.add_argument("--name", default=None, help="server name (default: repo/dir name)")
    ap.add_argument("-m", "--module", dest="module", default=None,
                    help="comma-separated review modules (e.g. secrets,sast,supply-chain) or 'all'")
    ap.add_argument("--box", dest="module", help=argparse.SUPPRESS)  # deprecated alias for --module
    ap.add_argument("--all", action="store_true", help="run every module (default when --module omitted)")
    ap.add_argument("--out", default="mcp-report", help="report output directory (default: ./mcp-report)")
    ap.add_argument("--rug-pull-mode", dest="rugpull_mode",
                    choices=["pin", "timeline", "auto"], default="auto",
                    help="Rug Pull mode: pin a baseline, or walk last-3-commits timeline (needs .git)")
    ap.add_argument("--box3-mode", dest="rugpull_mode", choices=["pin", "timeline", "auto"],
                    help=argparse.SUPPRESS)  # deprecated alias for --rug-pull-mode
    ap.add_argument("--no-sandbox", action="store_true",
                    help="run static modules directly with host python3 (no Docker, no isolation, "
                         "static modules only)")
    ap.add_argument("--fail-on", choices=["block", "review", "never"], default="block",
                    help="CI gate: exit non-zero on 'block' (default), 'review', or 'never'")
    ap.add_argument("--list", action="store_true", help="list modules and exit")
    ap.add_argument("-d", "--details", action="store_true",
                    help="print full findings for every module in the terminal (no need to open the report)")
    ap.add_argument("--quiet", action="store_true", help="less console output")
    args = ap.parse_args()

    if args.list:
        print(f"{C['b']}Review modules{C['x']}  {C['dim']}(pass any name below to --module){C['x']}\n")
        for b in orch.ORDER:
            s = orch.MODULES[b]
            iso = "static" if s["static"] else "docker-only"
            print(f"  {C['cyan']}{C['b']}{b}{C['x']}  {C['dim']}{s['name']} · {s['owasp']} · {iso}{C['x']}")
            other = [a for a in orch.aliases_for(b) if a != b]
            if other:
                print(f"        {C['dim']}also: {', '.join(other)}{C['x']}")
        return 0

    if not args.target:
        ap.error("target is required (a repo directory, a .zip, or a git URL). Use --list to see modules.")

    runner = "local" if args.no_sandbox else "docker"
    ok, msg = orch.preflight(runner)
    if not ok:
        print(f"{C['fail']}• {msg}{C['x']}")
        sys.exit(2)
    if runner == "local":
        # keep the "no container isolation" warning — it's safety-relevant
        print(f"{C['dim']}• {msg}{C['x']}")

    boxes = parse_boxes(args.module, args.all)
    explicit = bool(args.module) and args.module.strip().lower() != "all"
    if runner == "local" and not explicit:
        skipped = [b for b in boxes if not orch.MODULES[b]["static"]]
        boxes = [b for b in boxes if orch.MODULES[b]["static"]]
        for b in skipped:
            print(f"{C['dim']}• skipping {orch.display_name(b)} "
                  f"— needs the Docker sandbox (use the default docker runner to include it){C['x']}")

    # ---- resolve the target once, share across boxes ----
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="mcp-review-"))
    started = time.time()
    try:
        try:
            repo, kind = orch.resolve_target(args.target, scratch)
        except Exception as e:
            sys.exit(f"{C['fail']}✗ {e}{C['x']}")
        server_name = args.name or pathlib.Path(args.target.rstrip("/")).name.replace(".zip", "") \
            or repo.name
        repo_info = orch.inspect_target(repo)
        nfiles = sum(1 for _ in repo.rglob("*") if _.is_file())
        has_git = (repo / ".git").is_dir()
        print(f"{C['b']}▪ MCP Security Review{C['x']}  ·  server "
              f"{C['cyan']}{server_name}{C['x']}  ·  {kind} source  ·  {nfiles} files  ·  "
              f"{'git history present' if has_git else 'no .git'}")
        if repo_info:
            bits = [repo_info.get("name") or "?"]
            if repo_info.get("version"):
                bits.append(f"v{repo_info['version']}")
            bits.append(repo_info.get("primary_language") or "unknown")
            if repo_info.get("dependency_count") is not None:
                bits.append(f"{repo_info['dependency_count']} deps")
            print(f"{C['dim']}  {' · '.join(bits)}{C['x']}")
        modlist = ", ".join(orch.display_name(b) for b in boxes)
        print(f"{C['dim']}  Running {len(boxes)} module(s): {modlist}{C['x']}\n")

        # ---- run each box ----
        results = []
        for b in boxes:
            spec = orch.MODULES[b]
            mode = None
            if b == "rug-pull":
                mode = None if args.rugpull_mode == "auto" else args.rugpull_mode
            sys.stdout.write(f"  {C['cyan']}▶ {orch.display_name(b)}{C['x']} … ")
            sys.stdout.flush()

            def log_cb(box, e):
                if not args.quiet and e["status"] in ("run",):
                    pass  # keep the single-line UX; run-log is saved to JSON

            br = orch.run_box(repo, server_name, b, runner=runner, mode=mode, log_cb=log_cb)
            status = br.get("status", "ERROR")
            c = br.get("counts", {})
            tag = f"{col_for(status)}{status}{C['x']}"
            extra = ""
            if c.get("total"):
                extra = f" {C['dim']}({c.get('total')} findings, {c.get('critical',0)}C/{c.get('high',0)}H){C['x']}"
            print(f"{tag}{extra}")
            if br.get("error") and not args.quiet:
                print(f"    {C['fail']}{br['error']}{C['x']}")
            results.append(br)

        # ---- write reports ----
        out_dir = pathlib.Path(args.out).resolve()
        written = reporting.write_all(out_dir, server_name, results, repo_info)
        word, cls, why = written["recommendation"]
        total_findings = sum(br.get("counts", {}).get("total", 0) for br in results)

        # ---- detailed terminal view (opt-in) or the one-line recommendation ----
        if args.details:
            termreport.render(results, written["recommendation"], color=bool(C["b"]))
        else:
            wc = C["fail"] if cls == "block" else C["review"] if cls == "review" else C["pass"]
            print(f"\n{C['b']}Recommendation:{C['x']} {wc}{C['b']}{word}{C['x']}  {C['dim']}{why}{C['x']}")
            if total_findings and not args.quiet:
                print(f"{C['dim']}  Tip: add {C['b']}--details{C['x']}{C['dim']} (or -d) to read all "
                      f"findings here in the terminal.{C['x']}")

        report_folder = pathlib.Path(written["html"]).parent
        print(f"  {C['b']}Report:{C['x']} {written['html']}")
        print(f"{C['dim']}  SARIF & JSON versions also saved in {report_folder}{C['x']}")

        # ---- gate ----
        worst = max((orch.gate_level(br.get("status")) for br in results), default=0)
        if args.fail_on == "never":
            return 0
        if args.fail_on == "review":
            return 0 if worst == 0 else (2 if worst >= 2 else 1)
        # default: block
        return 2 if worst >= 2 else 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
