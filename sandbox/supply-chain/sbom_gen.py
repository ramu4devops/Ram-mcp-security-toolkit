#!/usr/bin/env python3
"""
sbom_gen.py -- Box-7, layer 1: generate a Software Bill of Materials for an
MCP server repo.

Why this comes first: every other layer in this box (CVE lookup, typosquat
check, install-script review) needs to know EXACTLY what is resolved to run
-- not what package.json/requirements.txt asks for, but what the lockfile
actually pinned. An SBOM is that list, made durable: it's what you diff
against next month to answer "did our dependency footprint change since the
last review" without re-running every scanner from scratch.

Usage:
    python3 sbom_gen.py /path/to/repo --out sbom.json
"""
import os
import sys
import json
import argparse
from supplychain_lib import (detect_ecosystems, parse_npm_lock, npm_direct_deps,
                              mark_direct, parse_requirements_txt)


def build_npm_sbom(npm_info):
    pkg, direct_spec = npm_direct_deps(npm_info["manifest"])
    if not npm_info["lockfile"]:
        return {
            "ecosystem": "npm", "name": pkg.get("name"), "version": pkg.get("version"),
            "lockfile_present": False,
            "warning": "No package-lock.json -- the dependency TREE cannot be resolved, only "
                       "the direct ranges declared in package.json. Every version-range "
                       "dependency here can silently resolve to a different, unreviewed "
                       "package the next time `npm install` runs.",
            "direct_dependencies": [{"name": n, **s} for n, s in direct_spec.items()],
            "components": [],
        }
    resolved = parse_npm_lock(npm_info["lockfile"])
    mark_direct(resolved, direct_spec.keys())
    no_integrity = [d["name"] for d in resolved if not d.get("integrity")]
    return {
        "ecosystem": "npm", "name": pkg.get("name"), "version": pkg.get("version"),
        "lockfile_present": True,
        "direct_dependencies": [{"name": n, **s} for n, s in direct_spec.items()],
        "component_count": len(resolved),
        "direct_count": sum(1 for d in resolved if d["direct"]),
        "transitive_count": sum(1 for d in resolved if not d["direct"]),
        "components_missing_integrity_hash": no_integrity,
        "components": resolved,
    }


def build_pip_sbom(pip_info):
    reqs = parse_requirements_txt(pip_info["manifest"]) if pip_info["manifest"].endswith("requirements.txt") else []
    unpinned = [r["name"] for r in reqs if not r["pinned"]]
    warning = None
    if not pip_info["lockfile"] and reqs:
        warning = ("No poetry.lock / uv.lock / Pipfile.lock found. requirements.txt only "
                   "pins DIRECT dependency versions (and only the ones written with '=='); "
                   "the full transitive tree is whatever pip resolves at install time.")
    return {
        "ecosystem": "pip", "manifest": os.path.basename(pip_info["manifest"]),
        "lockfile_present": bool(pip_info["lockfile"]),
        "warning": warning,
        "direct_count": len(reqs),
        "unpinned_direct_dependencies": unpinned,
        "components": reqs,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo_dir")
    ap.add_argument("--out", default="sbom.json")
    args = ap.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    eco = detect_ecosystems(repo_dir)
    if not eco["npm"] and not eco["pip"]:
        sys.exit("No package.json, requirements.txt, or pyproject.toml found -- "
                 "is this the right repo directory?")

    sbom = {"repo": repo_dir, "ecosystems": []}
    if eco["npm"]:
        sbom["ecosystems"].append(build_npm_sbom(eco["npm"]))
    if eco["pip"]:
        sbom["ecosystems"].append(build_pip_sbom(eco["pip"]))

    with open(args.out, "w") as fh:
        json.dump(sbom, fh, indent=2)

    print(f"SBOM written to {args.out}\n")
    for e in sbom["ecosystems"]:
        print(f"[{e['ecosystem']}] lockfile_present={e['lockfile_present']}", end="")
        if e["ecosystem"] == "npm" and e["lockfile_present"]:
            print(f"  components={e['component_count']}  direct={e['direct_count']}  "
                  f"transitive={e['transitive_count']}  missing_integrity={len(e['components_missing_integrity_hash'])}")
        elif e["ecosystem"] == "pip":
            print(f"  direct={e['direct_count']}  unpinned={len(e['unpinned_direct_dependencies'])}")
        else:
            print()
        if e.get("warning"):
            print(f"  WARNING: {e['warning']}")


if __name__ == "__main__":
    main()
