#!/usr/bin/env python3
"""
rugpull_timeline.py -- Box-3 for a repo you have NEVER seen before, with
no prior baseline.json to compare against.

The trick: a "stale" repo's own git tag history already IS a sequence of
historical states. We walk consecutive release tags, extract each one's
tool list (reusing Box-1's dynamic introspection), and diff every
consecutive pair -- producing a genuine change-integrity timeline even on
the very first review.

SAFETY: this script installs dependencies and starts the server for EACH
tag -- i.e. it executes code from every historical version it walks. Only
run it inside the same sandboxed, network-isolated environment described
in the Box-1 lab (throwaway container for install, --network none for the
introspection step). Never run this directly against a host you care
about.

Usage:
    python3 rugpull_timeline.py /path/to/full/clone/of/repo \
        --last 3 --introspect-cmd "node cli.js" --out timeline.json

Requires: the repo to be cloned WITHOUT --depth 1 (tags must be present),
Node.js + npm on PATH (adjust --install-cmd for other ecosystems), and
introspect.mjs (from the Box-1 lab) next to this script or on PYTHONPATH
via --introspect-script.
"""
import os, sys, json, shutil, argparse, tempfile, subprocess
from rugpull_lib import diff_components, delta_risk_scan, added_text_from_diff

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def run(cmd, cwd, timeout=120):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, shell=isinstance(cmd, str))


def list_tags(repo_dir):
    out = run(["git", "tag", "--sort=v:refname"], repo_dir)
    if out.returncode != 0:
        raise RuntimeError(f"git tag failed: {out.stderr}")
    return [t for t in out.stdout.strip().splitlines() if t]


def worktree_for_tag(repo_dir, tag, dest):
    out = run(["git", "worktree", "add", "--detach", dest, tag], repo_dir, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"git worktree add failed for {tag}: {out.stderr}")


def remove_worktree(repo_dir, dest):
    run(["git", "worktree", "remove", "--force", dest], repo_dir, timeout=30)


def extract_tools(worktree_dir, install_cmd, introspect_cmd, introspect_script):
    inst = run(install_cmd, worktree_dir, timeout=180)
    if inst.returncode != 0:
        return None, f"install failed: {inst.stderr[-300:]}"
    out_path = os.path.join(worktree_dir, "_tools.json")
    script_dst = os.path.join(worktree_dir, "introspect.mjs")
    shutil.copy(introspect_script, script_dst)
    intro = run(["node", "introspect.mjs", introspect_cmd, out_path], worktree_dir, timeout=45)
    if intro.returncode != 0 or not os.path.isfile(out_path):
        return None, f"introspect failed: {intro.stderr[-300:] or intro.stdout[-300:]}"
    return json.load(open(out_path)), None


def diff_hop(prev_tag, curr_tag, prev_tools, curr_tools):
    d = diff_components(prev_tools, curr_tools)
    findings = []
    for name in d["added"]:
        item = next(t for t in curr_tools if t.get("name") == name)
        risk = delta_risk_scan(item.get("description", "") or "")
        sev = max((s for s, _ in risk), key=lambda s: SEV_ORDER[s], default="medium")
        findings.append({"severity": sev, "name": name, "change": "added",
                         "detail": "; ".join(m for _, m in risk) or "new tool, first appearance"})
    for name in d["removed"]:
        findings.append({"severity": "info", "name": name, "change": "removed", "detail": ""})
    for c in d["changed"]:
        added_text = added_text_from_diff(c["description_diff"])
        risk = delta_risk_scan(added_text)
        sev = "high" if risk else "medium"
        findings.append({"severity": sev, "name": c["name"], "change": "changed",
                         "detail": "; ".join(m for _, m in risk) or "description/schema changed",
                         "diff": c["description_diff"]})
    findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])
    return {"from": prev_tag, "to": curr_tag, "findings": findings,
            "added": len(d["added"]), "removed": len(d["removed"]),
            "changed": len(d["changed"]), "unchanged": len(d["unchanged"])}


def verdict_for_hops(hops):
    """Roll the whole timeline up into ONE final status, using the SAME
    three tiers as check_drift.py so both Box-3 tools speak one language.

    Pure function (no I/O) so every tier can be unit-tested directly.

      exit 0  PASS            nothing that needs a human -- no tools added
                              or changed anywhere in the walked history.
                              (A tool being REMOVED is informational only:
                              it reduces attack surface, matching how
                              check_drift.py treats removals.)
      exit 1  CHANGED         tools were added or changed, but no new text
                              matched the poisoning heuristics. ALWAYS a
                              human-review item -- "no heuristic hit" is
                              not the same as "safe".
      exit 2  HIGH SUSPICION  newly-added text matched Box-1's instruction
                              / secrecy / sensitive-path patterns.
    """
    counts = {
        "hops": len(hops),
        "added": sum(h["added"] for h in hops),
        "removed": sum(h["removed"] for h in hops),
        "changed": sum(h["changed"] for h in hops),
    }
    elevated = [
        {"hop": f"{h['from']} -> {h['to']}", "name": f["name"],
         "change": f["change"], "severity": f["severity"], "detail": f["detail"]}
        for h in hops for f in h["findings"]
        if f["severity"] in ("critical", "high")
    ]
    review = [
        {"hop": f"{h['from']} -> {h['to']}", "name": f["name"], "change": f["change"]}
        for h in hops for f in h["findings"]
        if f["change"] in ("added", "changed")
    ]

    if elevated:
        return {
            "status": "HIGH_SUSPICION", "exit_code": 2,
            "headline": "HIGH SUSPICION -- rug-pull-shaped content found in the history",
            "next_step": "Review the flagged hop(s) below by hand before this server is approved. "
                         "Newly-introduced text matched Box-1 poisoning heuristics.",
            "counts": counts, "elevated": elevated, "review_items": review,
        }
    if review:
        return {
            "status": "CHANGED_REVIEW", "exit_code": 1,
            "headline": "CHANGED -- manual review required",
            "next_step": "Tool definitions moved across this history. No text matched the "
                         "poisoning heuristics, but heuristics are not proof: read the diffs "
                         "above and confirm each change is a legitimate product change.",
            "counts": counts, "elevated": [], "review_items": review,
        }
    return {
        "status": "PASS", "exit_code": 0,
        "headline": "PASS -- no tools added or changed across the walked history",
        "next_step": "No change-integrity concerns in this tag range. Pin the current state "
                     "with pin_baseline.py so future versions can be diffed against it.",
        "counts": counts, "elevated": [], "review_items": [],
    }


def print_verdict(v):
    color = {"PASS": "\033[92m", "CHANGED_REVIEW": "\033[93m", "HIGH_SUSPICION": "\033[91m"}[v["status"]]
    reset = "\033[0m"
    c = v["counts"]
    print(f"\nSummary: {c['hops']} hop(s) compared -- "
          f"{c['added']} tool(s) added, {c['removed']} removed, {c['changed']} changed")
    if v["elevated"]:
        print("\nElevated findings:")
        for e in v["elevated"]:
            print(f"  [{e['severity'].upper()}] {e['hop']}  {e['change']} {e['name']}: {e['detail']}")
    print(f"\nVERDICT: {color}{v['headline']}{reset}")
    print(f"  {v['next_step']}")
    print(f"  (exit code {v['exit_code']})\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_dir", help="path to a full (non-shallow) local clone, tags present")
    ap.add_argument("--last", type=int, default=5, help="only walk the last N tags (default 5)")
    ap.add_argument("--install-cmd", default="npm ci --no-audit --no-fund",
                    help="dependency install command, run per-tag (default: npm ci)")
    ap.add_argument("--introspect-cmd", default="node cli.js",
                    help="command that starts the MCP server over stdio (default: node cli.js)")
    ap.add_argument("--introspect-script", default=os.path.join(os.path.dirname(__file__), "introspect.mjs"))
    ap.add_argument("--out", default="timeline.json")
    args = ap.parse_args()

    if not os.path.isfile(args.introspect_script):
        sys.exit(f"introspect.mjs not found at {args.introspect_script} -- copy it from the Box-1 lab first")

    repo_dir = os.path.abspath(args.repo_dir)
    tags = list_tags(repo_dir)[-args.last:]
    if len(tags) < 2:
        sys.exit(f"Only {len(tags)} tag(s) found -- need at least 2 to build a timeline")

    print(f"Walking {len(tags)} tag(s): {' -> '.join(tags)}\n")

    extracted = {}
    tmp_root = tempfile.mkdtemp(prefix="rugpull-timeline-")
    try:
        for tag in tags:
            wt = os.path.join(tmp_root, tag)
            print(f"[{tag}] creating worktree + installing + introspecting ...")
            worktree_for_tag(repo_dir, tag, wt)
            tools, err = extract_tools(wt, args.install_cmd.split(), args.introspect_cmd, args.introspect_script)
            remove_worktree(repo_dir, wt)
            if err:
                print(f"  SKIPPED: {err}")
                continue
            extracted[tag] = tools
            print(f"  ok -- {len(tools)} tool(s)")
    finally:
        run(["git", "worktree", "prune"], repo_dir)
        shutil.rmtree(tmp_root, ignore_errors=True)

    ok_tags = [t for t in tags if t in extracted]
    hops = []
    for prev, curr in zip(ok_tags, ok_tags[1:]):
        hops.append(diff_hop(prev, curr, extracted[prev], extracted[curr]))

    verdict = verdict_for_hops(hops)
    result = {"repo": repo_dir, "tags_walked": ok_tags, "hops": hops, "verdict": verdict}
    json.dump(result, open(args.out, "w"), indent=2)

    print(f"\n{'='*68}\nTIMELINE  ({args.out})\n{'='*68}")
    for hop in hops:
        worst = max((f["severity"] for f in hop["findings"]), key=lambda s: SEV_ORDER[s], default="info")
        flag = " <-- REVIEW" if worst in ("high", "critical") else ""
        print(f"{hop['from']:>10} -> {hop['to']:<10} "
              f"+{hop['added']} -{hop['removed']} ~{hop['changed']} ={hop['unchanged']}{flag}")
        for f in hop["findings"]:
            print(f"    [{f['severity'].upper():8}] {f['change']:8} {f['name']}: {f['detail']}")
    print(f"{'='*68}")
    print_verdict(verdict)
    sys.exit(verdict["exit_code"])


if __name__ == "__main__":
    main()
