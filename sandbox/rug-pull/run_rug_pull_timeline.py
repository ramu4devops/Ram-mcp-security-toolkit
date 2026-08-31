#!/usr/bin/env python3
"""
run_box3_timeline.py -- in-sandbox "first look, no baseline" timeline.

Strategy B from the Box-3 strategy doc: a repo you have never reviewed
before still contains multiple historical states in its own git history.
Walk the last N commits, extract each commit's component set, and diff
every consecutive pair -- a genuine change-integrity timeline with no
prior baseline.

Runs ENTIRELY inside the disposable, --network none container. Commits are
materialised with `git archive` (read-only .git, no worktree writes, no
checkout of the live tree) into tmpfs, and each state is extracted with the
pure-AST static extractor -- no repo code is executed.

Reuses rugpull_lib (canonical hash / diff / delta-risk) and
rugpull_timeline.verdict_for_hops so the verdict language matches the rest
of Box-3 exactly.

Output: one JSON object on stdout. Exit code = verdict exit code.
"""
import os, sys, json, argparse, tempfile, shutil, subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("/opt/tool-poisoning", "/opt/rug-pull", _HERE,
           os.path.join(_HERE, "..", "tool-poisoning")):
    if os.path.isdir(_p):
        sys.path.insert(0, os.path.abspath(_p))

from run_tool_poisoning import extract_components_static  # noqa: E402
import rugpull_lib as rl                                  # noqa: E402
from rugpull_timeline import diff_hop, verdict_for_hops   # noqa: E402


def git(args, cwd, timeout=60):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def last_commits(repo, n):
    out = git(["rev-list", "--max-count", str(n), "HEAD"], repo)
    if out.returncode != 0:
        return None, out.stderr.strip()
    shas = [s for s in out.stdout.split() if s]
    return list(reversed(shas)), None   # oldest -> newest


def commit_meta(repo, sha):
    out = git(["show", "-s", "--format=%h|%ci|%s", sha], repo)
    if out.returncode == 0 and out.stdout.strip():
        short, date, subj = (out.stdout.strip().split("|", 2) + ["", ""])[:3]
        return {"sha": sha, "short": short, "date": date, "subject": subj[:100]}
    return {"sha": sha, "short": sha[:10], "date": "", "subject": ""}


def tools_at_commit(repo, sha):
    d = tempfile.mkdtemp(dir="/tmp")
    try:
        p = subprocess.run(f"git -C '{repo}' archive {sha} | tar -x -C '{d}'",
                           shell=True, capture_output=True, text=True, timeout=90)
        if p.returncode != 0:
            return None
        return extract_components_static(d)["tools"]
    except Exception:
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--last", type=int, default=3)
    ap.add_argument("--server-name", default="")
    args = ap.parse_args()

    if not os.path.isdir(os.path.join(args.repo, ".git")):
        print(json.dumps({
            "box": "03", "mode": "timeline", "server_name": args.server_name,
            "extraction": {"ok": False, "tool_count": 0, "tools_preview": []},
            "timeline": {"commits": [], "hops": []}, "findings": [],
            "verdict": {"status": "NO_GIT", "exit_code": 3,
                        "headline": "No git history in the upload.",
                        "next_step": "Upload a full git clone (a .zip that INCLUDES the .git "
                                     "folder), not GitHub's flattened 'Download ZIP'.",
                        "rationale": "The last-3-commits timeline reconstructs before/after "
                                     "evidence from the repo's own git history. This upload has "
                                     "no .git directory, so there is no history to walk.",
                        "counts": {"total": 0}},
        }, indent=2))
        sys.exit(3)

    shas, err = last_commits(args.repo, args.last)
    if not shas:
        print(json.dumps({
            "box": "03", "mode": "timeline", "server_name": args.server_name,
            "extraction": {"ok": False, "tool_count": 0, "tools_preview": []},
            "timeline": {"commits": [], "hops": []}, "findings": [],
            "verdict": {"status": "NO_GIT", "exit_code": 3,
                        "headline": "Could not read commit history.",
                        "next_step": "Ensure the uploaded clone is not shallow (--depth 1).",
                        "rationale": f"git rev-list failed: {err or 'no commits'}.",
                        "counts": {"total": 0}},
        }, indent=2))
        sys.exit(3)

    metas = [commit_meta(args.repo, s) for s in shas]
    states = [(m, tools_at_commit(args.repo, m["sha"])) for m in metas]
    states = [(m, t) for m, t in states if t is not None]

    hops = []
    for (pm, pt), (cm, ct) in zip(states, states[1:]):
        h = diff_hop(pm["short"], cm["short"], pt, ct)
        hops.append(h)

    verdict = verdict_for_hops(hops)

    # Flatten hop findings into the shared findings[] shape so the UI's
    # severity stats/cards work like every other box.
    findings = []
    for h in hops:
        for f in h["findings"]:
            findings.append({
                "severity": f["severity"], "box": "BOX-03",
                "layer": f["change"], "subject": f["name"],
                "title": f"{f['change'].upper()} between {h['from']} → {h['to']}: {f.get('detail','')}",
                "evidence": "\n".join(l for l in f.get("diff", [])
                                      if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))[:400],
                "impact": "", "remediation": "",
            })
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    counts["total"] = len(findings)

    head_tools = states[-1][1] if states else []
    verdict_out = dict(verdict)
    verdict_out["counts"] = counts
    verdict_out.setdefault("rationale",
        f"Walked {len(states)} commit(s) of the repo's own history "
        f"({' → '.join(m['short'] for m, _ in states)}). "
        f"Across the walk: {verdict['counts']['added']} tool(s) added, "
        f"{verdict['counts']['removed']} removed, {verdict['counts']['changed']} changed. "
        + verdict["headline"])

    print(json.dumps({
        "box": "03", "box_name": "Rug Pull & Change Integrity", "mode": "timeline",
        "server_name": args.server_name,
        "extraction": {"ok": bool(head_tools), "method": "static @ each commit",
                       "tool_count": len(head_tools),
                       "tools_preview": [t["name"] for t in head_tools],
                       "tools_full": head_tools},
        "timeline": {
            "commits": [{"short": m["short"], "date": m["date"], "subject": m["subject"]}
                        for m, _ in states],
            "hops": [{"from": h["from"], "to": h["to"], "added": h["added"],
                      "removed": h["removed"], "changed": h["changed"],
                      "unchanged": h["unchanged"], "findings": h["findings"]} for h in hops],
        },
        "findings": findings,
        "verdict": verdict_out,
    }, indent=2))
    sys.exit(verdict.get("exit_code", 0))


if __name__ == "__main__":
    main()
