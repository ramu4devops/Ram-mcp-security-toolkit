#!/usr/bin/env python3
"""
vuln_scan.py -- Box-7, layer 2: known-CVE scanning of resolved dependencies,
direct AND transitive.

npm ecosystem : shells to `npm audit --json` (the real npm advisory
                 database) for severity/CWE/CVSS, then enriches each
                 finding's GHSA advisory ID against OSV.dev to resolve the
                 actual CVE number (npm audit's own JSON never includes one).
pip ecosystem : queries the public PyPI JSON API per pinned package/version
                 (pypi.org/pypi/<name>/<version>/json -> "vulnerabilities"
                 key, which already carries CVE aliases -- no extra lookup
                 needed). Same data pip-audit's default backend uses.

Every finding also gets a LOCAL, network-free plain-English "what this
means" line (from the CWE npm audit already supplies, or keyword matching
for pip) -- so a reviewer isn't stuck googling a CWE/CVE number just to
learn what class of bug it is. OSV.dev enrichment for the CVE number itself
is best-effort: use --no-enrich to skip it (faster, fully offline after the
initial registry calls), and if OSV.dev isn't reachable from your network
the scan still completes -- findings fall back to their GHSA advisory ID.

MCP angle: a vulnerable dependency doesn't need a network path to be
dangerous here. An MCP server's tool-calling code already receives
untrusted, model-influenced input (arguments the LLM decided to pass) and
often untrusted external content (webpage text, file contents, API
responses) as tool RESULTS. A deserialization or injection CVE in a
dependency sitting anywhere on that path turns "the model was tricked into
calling a tool with bad input" into full code execution -- which is a
Box-1 (tool poisoning) finding and a Box-7 finding meeting at the same
line of code.

Usage:
    python3 vuln_scan.py /path/to/repo [--json] [--no-enrich]
"""
import os
import sys
import json
import argparse
import concurrent.futures as cf
from supplychain_lib import (detect_ecosystems, parse_npm_lock, npm_direct_deps,
                              mark_direct, parse_requirements_txt, run_npm_audit,
                              pypi_lookup_vulns, enrich_findings, local_enrich_only,
                              sev_sort, SEV_ORDER, COLOR, RESET)


def scan_npm(npm_info):
    findings, err = run_npm_audit(os.path.dirname(npm_info["manifest"]))
    if err:
        return [], [f"npm audit could not run: {err}"]
    return findings, []


def scan_pip(pip_info, max_workers=8):
    reqs = []
    if pip_info["manifest"].endswith("requirements.txt"):
        reqs = parse_requirements_txt(pip_info["manifest"])
    findings, notes = [], []
    unpinned = [r["name"] for r in reqs if not r["pinned"]]
    if unpinned:
        notes.append(f"{len(unpinned)} dependency(ies) have no pinned version and were "
                     f"SKIPPED for CVE lookup (can't check a version that isn't fixed yet): "
                     + ", ".join(unpinned[:10]) + (" ..." if len(unpinned) > 10 else ""))

    pinned = [r for r in reqs if r["pinned"]]

    def lookup(r):
        f, err = pypi_lookup_vulns(r["name"], r["version"])
        return r, f, err

    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r, f, err in ex.map(lookup, pinned):
            if err and "not found on PyPI" not in err:
                notes.append(f"{r['name']}=={r['version']}: {err}")
            findings.extend(f)
    return findings, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo_dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-enrich", action="store_true",
                    help="skip the OSV.dev CVE-number lookup for npm findings (still shows "
                         "GHSA id, CWE, CVSS score, and the local plain-English impact line)")
    args = ap.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    eco = detect_ecosystems(repo_dir)
    if not eco["npm"] and not eco["pip"]:
        sys.exit("No package.json, requirements.txt, or pyproject.toml found.")

    all_findings, all_notes = [], []
    if eco["npm"]:
        if not eco["npm"]["lockfile"]:
            all_notes.append("npm: no package-lock.json present -- `npm audit` needs a lockfile "
                             "to know exact resolved versions. Run `npm install` first, or treat "
                             "this repo as REVIEW-required until one exists.")
        else:
            f, n = scan_npm(eco["npm"])
            all_findings += f
            all_notes += n
    if eco["pip"]:
        f, n = scan_pip(eco["pip"])
        all_findings += f
        all_notes += n

    if not args.no_enrich:
        all_findings, enrich_note = enrich_findings(all_findings)
        if enrich_note:
            all_notes.append(enrich_note)
    else:
        all_findings = local_enrich_only(all_findings)

    all_findings = sev_sort(all_findings)
    crit_high = sum(1 for f in all_findings if f["severity"] in ("critical", "high"))
    exit_code = 2 if crit_high else (1 if all_findings else 0)

    if args.json:
        print(json.dumps({"findings": all_findings, "notes": all_notes,
                          "exit_code": exit_code}, indent=2))
        sys.exit(exit_code)

    print(f"Supply-chain CVE scan: {repo_dir}")
    print("-" * 72)
    if not all_findings:
        print("No known vulnerabilities found in resolved dependency versions.")
    for f in all_findings:
        c = COLOR.get(f["severity"], "")
        direct = "direct" if f.get("direct") else ("transitive" if f.get("direct") is False else "?")
        ver = f" {f['version']}" if f.get("version") else ""
        cvss = f"  CVSS {f['cvss_score']}" if f.get("cvss_score") else ""
        print(f"{c}[{f['severity'].upper():8}]{RESET} ({direct:10}) {f['ecosystem']}:{f['package']}{ver}{cvss}")
        ids = ", ".join(f.get("cve") or [])
        if not ids:
            ids = f.get("osv_id") or "no CVE/advisory id"
        print(f"           [{ids}]  {f['title']}")
        print(f"           → {f.get('plain_english', '')}")
        if f.get("fix_versions"):
            print(f"           fix: upgrade to {', '.join(f['fix_versions'])}")
        elif f.get("fix_available"):
            print(f"           fix available (npm audit fix)")
        elif f.get("fix_available") is False:
            print(f"           NO FIX AVAILABLE YET")
        if f.get("url"):
            print(f"           {f['url']}")
    if all_notes:
        print("\nNotes:")
        for n in all_notes:
            print(f"  - {n}")

    print(f"\n{len(all_findings)} finding(s) -- {crit_high} at critical/high severity")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
