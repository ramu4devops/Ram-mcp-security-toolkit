#!/usr/bin/env python3
"""
typosquat_scan.py -- Box-7, layer 3: typosquatting & dependency-confusion
heuristics.

Two different attacks, one script, because they show up in the same place
(a dependency name that isn't what it looks like):

  TYPOSQUAT
    A package published under a name one keystroke away from a popular one
    ("reqeusts", "expres", "python-dateutil" vs "python-dateutils"),
    counting on a typo in package.json/requirements.txt (or on a developer
    misreading it) to get installed instead of the real thing.

  DEPENDENCY CONFUSION
    An internal/private package name (e.g. "acme-internal-auth") that was
    never published publicly. If the public registry (npmjs.org / pypi.org)
    has no reservation for that name, an attacker can publish it there
    themselves -- and depending on registry resolution order, a build that
    isn't pinned to a private registry/scope can silently pull the
    attacker's public package instead of the real internal one.

This is a HEURISTIC layer: it flags near-misses and registry anomalies for
a human to look at, it does not accuse a package of being malicious by
itself. A brand-new, low-maintainer-count package is completely normal for
a small utility library too.

Usage:
    python3 typosquat_scan.py /path/to/repo [--check-registry] [--json]

--check-registry makes live calls to registry.npmjs.org / pypi.org to
pull publish-date/maintainer-count signals for names that ARE typosquat
candidates or that don't already appear on the curated popular-package
list (cheap: only borderline names are looked up, not the whole tree).
"""
import os
import sys
import json
import argparse
from supplychain_lib import (detect_ecosystems, parse_npm_lock, npm_direct_deps, mark_direct,
                              parse_requirements_txt, typosquat_candidates,
                              registry_metadata_npm, registry_metadata_pypi,
                              TOP_NPM_PACKAGES, TOP_PYPI_PACKAGES)


def scan_names(names, popular_set, ecosystem, check_registry, lookup_fn):
    findings = []
    for name in sorted(set(names)):
        hits = typosquat_candidates(name, popular_set)
        if not hits:
            continue
        closest, dist = hits[0]
        sev = "high" if dist == 1 else "medium"
        finding = {
            "ecosystem": ecosystem, "package": name, "severity": sev,
            "title": f"'{name}' is edit-distance {dist} from popular package '{closest}'",
            "closest_match": closest, "distance": dist,
        }
        if check_registry:
            meta = lookup_fn(name)
            finding["registry"] = meta
            if meta.get("exists") and meta.get("version_count", 99) <= 2:
                finding["severity"] = "critical"
                finding["title"] += f" -- AND has only {meta['version_count']} published version(s) (consistent with a recently-squatted name)"
        findings.append(finding)
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo_dir")
    ap.add_argument("--check-registry", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    eco = detect_ecosystems(repo_dir)
    findings = []

    if eco["npm"]:
        names = set()
        if eco["npm"]["lockfile"]:
            resolved = parse_npm_lock(eco["npm"]["lockfile"])
            names.update(d["name"] for d in resolved)
        pkg, direct_spec = npm_direct_deps(eco["npm"]["manifest"])
        names.update(direct_spec.keys())
        findings += scan_names(names, TOP_NPM_PACKAGES, "npm", args.check_registry, registry_metadata_npm)

    if eco["pip"] and eco["pip"]["manifest"].endswith("requirements.txt"):
        reqs = parse_requirements_txt(eco["pip"]["manifest"])
        names = {r["name"] for r in reqs}
        findings += scan_names(names, TOP_PYPI_PACKAGES, "pip", args.check_registry, registry_metadata_pypi)

    findings.sort(key=lambda f: {"critical": 3, "high": 2, "medium": 1}.get(f["severity"], 0), reverse=True)

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
        sys.exit(2 if any(f["severity"] == "critical" for f in findings) else (1 if findings else 0))

    print(f"Typosquat / dependency-confusion scan: {repo_dir}")
    print("-" * 72)
    if not findings:
        print("No dependency names within edit-distance 2 of the curated popular-package list.")
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['title']}")
        if f.get("registry"):
            r = f["registry"]
            if r.get("exists"):
                print(f"           registry: {r.get('version_count')} version(s), "
                      f"repository_field={r.get('has_repository')}, created={r.get('created', r.get('author', '?'))}")
            else:
                print(f"           registry: NOT published (name is free -- lower risk from this specific check, "
                      f"but confirm it isn't a private/scoped package resolved elsewhere)")
    print(f"\n{len(findings)} finding(s)")
    sys.exit(2 if any(f["severity"] == "critical" for f in findings) else (1 if findings else 0))


if __name__ == "__main__":
    main()
