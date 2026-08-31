#!/usr/bin/env python3
"""
pin_baseline.py -- create the "approved state" record for Box-3.

Takes whatever tools.json you already produced with Box-1's tooling
(introspect.mjs for Method A, or static_extract.py for Method B) and turns
it into a signed-in-spirit baseline.json: canonical hashes for every tool,
plus repo/dependency provenance so a LATER re-scan can prove nothing
drifted underneath an approval.

Usage:
    python3 pin_baseline.py tools.json --repo-dir /path/to/cloned/repo \
        --commit <sha> --out baseline.json

    # resources/prompts are optional and use the exact same shape as tools:
    python3 pin_baseline.py tools.json --resources resources.json \
        --prompts prompts.json --repo-dir . --out baseline.json
"""
import os, sys, json, argparse, subprocess, datetime
from rugpull_lib import canonical_hash, file_hash

LOCKFILE_CANDIDATES = [
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt",
    "go.sum", "Cargo.lock",
]
ENTRYPOINT_CANDIDATES = ["cli.js", "index.js", "main.py", "server.py", "__main__.py"]


def git_commit_sha(repo_dir):
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir,
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def find_lockfile(repo_dir):
    for name in LOCKFILE_CANDIDATES:
        p = os.path.join(repo_dir, name)
        if os.path.isfile(p):
            return name, p
    return None, None


def find_entrypoint(repo_dir, hint=None):
    candidates = [hint] if hint else []
    candidates += ENTRYPOINT_CANDIDATES
    for name in candidates:
        if not name:
            continue
        p = os.path.join(repo_dir, name)
        if os.path.isfile(p):
            return name, p
    return None, None


def load_components(path):
    if not path:
        return []
    data = json.load(open(path))
    if isinstance(data, dict) and "tools" in data:
        data = data["tools"]
    return data


def build_baseline(tools_path, resources_path, prompts_path, repo_dir, commit, entrypoint_hint, label):
    tools = load_components(tools_path)
    resources = load_components(resources_path)
    prompts = load_components(prompts_path)

    pinned = {
        "tools": {t["name"]: canonical_hash(t) for t in tools if t.get("name")},
        "resources": {r["name"]: canonical_hash(r) for r in resources if r.get("name")},
        "prompts": {p["name"]: canonical_hash(p) for p in prompts if p.get("name")},
    }

    provenance = {"repo_dir": os.path.abspath(repo_dir) if repo_dir else None}
    if repo_dir:
        provenance["commit"] = commit or git_commit_sha(repo_dir)
        lock_name, lock_path = find_lockfile(repo_dir)
        provenance["lockfile"] = {"name": lock_name, "hash": file_hash(lock_path) if lock_path else None}
        ep_name, ep_path = find_entrypoint(repo_dir, entrypoint_hint)
        provenance["entrypoint"] = {"name": ep_name, "hash": file_hash(ep_path) if ep_path else None}

    return {
        "schema": "mcpsec.baseline/v1",
        "label": label,
        "pinned_at": None,     # filled in by caller with a real timestamp
        "counts": {"tools": len(tools), "resources": len(resources), "prompts": len(prompts)},
        "provenance": provenance,
        "components": pinned,
        # raw components kept too -- check_drift.py needs full text/schema,
        # not just hashes, to show *what* changed, not only *that* it did.
        "_raw": {"tools": tools, "resources": resources, "prompts": prompts},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tools_json")
    ap.add_argument("--resources")
    ap.add_argument("--prompts")
    ap.add_argument("--repo-dir", help="path to the cloned repo, for commit SHA + lockfile/entrypoint hashing")
    ap.add_argument("--commit", help="override commit SHA if repo-dir has no .git (e.g. extracted tarball)")
    ap.add_argument("--entrypoint", help="entrypoint filename hint if not one of the common ones")
    ap.add_argument("--label", default="", help="human label, e.g. 'playwright-mcp v0.0.72 -- approved 2026-08-22'")
    ap.add_argument("--out", default="baseline.json")
    args = ap.parse_args()

    baseline = build_baseline(args.tools_json, args.resources, args.prompts,
                              args.repo_dir, args.commit, args.entrypoint, args.label)
    # Timestamps are supplied by the environment, never computed with a
    # forbidden clock call inside library code -- keeps this reproducible
    # and testable. Here it's fine: this is the top-level script entrypoint.
    baseline["pinned_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    json.dump(baseline, open(args.out, "w"), indent=2)
    c = baseline["counts"]
    print(f"Pinned {c['tools']} tool(s), {c['resources']} resource(s), {c['prompts']} prompt(s) -> {args.out}")
    if baseline["provenance"].get("commit"):
        print(f"  commit:    {baseline['provenance']['commit']}")
    if baseline["provenance"].get("lockfile", {}).get("name"):
        lf = baseline["provenance"]["lockfile"]
        print(f"  lockfile:  {lf['name']}  ({lf['hash']})")
    if baseline["provenance"].get("entrypoint", {}).get("name"):
        ep = baseline["provenance"]["entrypoint"]
        print(f"  entrypoint:{ep['name']}  ({ep['hash']})")


if __name__ == "__main__":
    main()
