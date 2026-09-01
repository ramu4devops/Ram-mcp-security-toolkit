#!/usr/bin/env python3
"""
supplychain_scan.py -- Box-7 orchestrator: runs all four supply-chain
layers against an MCP server repo and produces ONE verdict.

  L1  SBOM            what is actually resolved to run (sbom_gen.py)
  L2  Known CVEs       npm audit / PyPI JSON API lookup (vuln_scan.py)
  L3  Typosquat /       edit-distance + registry heuristics
      dep-confusion     (typosquat_scan.py)
  L4  Install scripts  preinstall/install/postinstall + setup.py content,
                        including one layer of base64-obfuscation unwrap
                        (installscript_scan.py)

Prerequisite: the repo's dependencies must already be installed on disk
(`npm ci` / `npm install` run, so node_modules and package-lock.json
exist; or `pip install -r requirements.txt` if you want the pip layer's
CVE check to see anything beyond a plain requirements.txt). If nothing is
installed yet, L1/L2/L3 still work from the manifest/lockfile alone; L4's
node_modules walk will just have nothing to check beyond the root
package.json.

Usage:
    python3 supplychain_scan.py /path/to/repo [--check-registry] [--json] [--out report.json]
"""
import os
import sys
import json
import argparse

from supplychain_lib import (detect_ecosystems, verdict_for_findings, sev_sort,
                              enrich_findings, local_enrich_only, COLOR, RESET, SEV_ORDER)
import sbom_gen
import vuln_scan
import typosquat_scan
import installscript_scan


def run_all(repo_dir, check_registry=False, enrich=True):
    eco = detect_ecosystems(repo_dir)
    report = {"repo": repo_dir, "ecosystems_detected": {k: bool(v) for k, v in eco.items()}}

    # L1 -- SBOM
    sbom = {"ecosystems": []}
    if eco["npm"]:
        sbom["ecosystems"].append(sbom_gen.build_npm_sbom(eco["npm"]))
    if eco["pip"]:
        sbom["ecosystems"].append(sbom_gen.build_pip_sbom(eco["pip"]))
    report["sbom"] = sbom

    # L2 -- known CVEs
    vuln_findings, vuln_notes = [], []
    if eco["npm"] and eco["npm"]["lockfile"]:
        f, n = vuln_scan.scan_npm(eco["npm"])
        vuln_findings += f
        vuln_notes += n
    elif eco["npm"]:
        vuln_notes.append("npm: no package-lock.json -- CVE scan skipped, run `npm install` first")
    if eco["pip"]:
        f, n = vuln_scan.scan_pip(eco["pip"])
        vuln_findings += f
        vuln_notes += n
    if enrich:
        vuln_findings, enrich_note = enrich_findings(vuln_findings)
        if enrich_note:
            vuln_notes.append(enrich_note)
    else:
        vuln_findings = local_enrich_only(vuln_findings)
    vuln_findings = sev_sort(vuln_findings)
    report["vuln_scan"] = {"findings": vuln_findings, "notes": vuln_notes}

    # L3 -- typosquat / dependency confusion
    typo_findings = []
    if eco["npm"]:
        names = set()
        if eco["npm"]["lockfile"]:
            from supplychain_lib import parse_npm_lock
            names.update(d["name"] for d in parse_npm_lock(eco["npm"]["lockfile"]))
        _, direct_spec = sbom_gen.npm_direct_deps(eco["npm"]["manifest"])
        names.update(direct_spec.keys())
        typo_findings += typosquat_scan.scan_names(
            names, typosquat_scan.TOP_NPM_PACKAGES, "npm", check_registry, typosquat_scan.registry_metadata_npm)
    if eco["pip"] and eco["pip"]["manifest"].endswith("requirements.txt"):
        from supplychain_lib import parse_requirements_txt
        reqs = parse_requirements_txt(eco["pip"]["manifest"])
        typo_findings += typosquat_scan.scan_names(
            {r["name"] for r in reqs}, typosquat_scan.TOP_PYPI_PACKAGES, "pip", check_registry,
            typosquat_scan.registry_metadata_pypi)
    typo_findings.sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
    report["typosquat_scan"] = {"findings": typo_findings}

    # L4 -- install-time scripts
    install_findings, checked = installscript_scan.scan_npm_install_hooks(repo_dir)
    install_findings += installscript_scan.scan_pip_install_scripts(repo_dir)
    install_findings = sev_sort(install_findings)
    report["installscript_scan"] = {"findings": install_findings, "packages_checked": checked}

    # ---- combine into ONE finding stream for the verdict ----
    combined = []
    for f in vuln_findings:
        combined.append({"layer": "vuln", "severity": f["severity"],
                         "summary": f"{f['ecosystem']}:{f['package']} -- {f['title']}", "gate": True})
    for f in typo_findings:
        combined.append({"layer": "typosquat", "severity": f["severity"],
                         "summary": f"{f['ecosystem']}:{f['package']} -- {f['title']}", "gate": True})
    for f in install_findings:
        combined.append({"layer": "installscript", "severity": f["severity"],
                         "summary": f"{f['source']} -- {f['label']}", "gate": True})

    # Missing lockfile / unpinned dependencies are real findings but at
    # REVIEW tier, never FAIL on their own -- a repo with no lockfile yet
    # isn't malicious, it's just not reproducible. gate=False keeps it out
    # of the "elevated" bucket in verdict_for_findings regardless of the
    # severity label used for display.
    for e in sbom["ecosystems"]:
        if e["ecosystem"] == "npm" and not e["lockfile_present"]:
            combined.append({"layer": "sbom", "severity": "medium",
                             "summary": "npm: no package-lock.json present -- dependency tree is not reproducible/auditable",
                             "gate": False})
        if e["ecosystem"] == "npm" and e.get("components_missing_integrity_hash"):
            combined.append({"layer": "sbom", "severity": "low",
                             "summary": f"{len(e['components_missing_integrity_hash'])} package(s) in the lockfile have no integrity hash",
                             "gate": False})
        if e["ecosystem"] == "pip" and e.get("unpinned_direct_dependencies"):
            combined.append({"layer": "sbom", "severity": "medium",
                             "summary": f"{len(e['unpinned_direct_dependencies'])} direct pip dependency(ies) unpinned: "
                                        + ", ".join(e["unpinned_direct_dependencies"][:8]),
                             "gate": False})
        if e["ecosystem"] == "pip" and not e["lockfile_present"] and e.get("components"):
            combined.append({"layer": "sbom", "severity": "low",
                             "summary": "pip: no lockfile (poetry.lock/uv.lock/Pipfile.lock) -- transitive tree isn't pinned",
                             "gate": False})

    verdict = verdict_for_findings(combined)
    report["combined_findings"] = combined
    report["verdict"] = verdict
    return report


def print_report(report):
    repo = report["repo"]
    print(f"\n{'='*72}\nBOX-7 SUPPLY CHAIN & DEPENDENCY SECURITY -- {repo}\n{'='*72}")

    eco = report["ecosystems_detected"]
    print(f"Ecosystems detected: " + ", ".join(k for k, v in eco.items() if v) or "none")

    for e in report["sbom"]["ecosystems"]:
        if e["ecosystem"] == "npm" and e["lockfile_present"]:
            print(f"\n[SBOM/npm] {e['component_count']} resolved package(s) "
                  f"({e['direct_count']} direct, {e['transitive_count']} transitive)")
        elif e["ecosystem"] == "npm":
            print(f"\n[SBOM/npm] no lockfile -- {len(e['direct_dependencies'])} direct range(s) declared, tree not resolved")
        elif e["ecosystem"] == "pip":
            print(f"\n[SBOM/pip] {e['direct_count']} direct requirement(s), "
                  f"{len(e['unpinned_direct_dependencies'])} unpinned, lockfile_present={e['lockfile_present']}")

    v = report["vuln_scan"]
    ch = sum(1 for f in v["findings"] if f["severity"] in ("critical", "high"))
    print(f"\n[L2 CVE SCAN] {len(v['findings'])} known vulnerabilit(y/ies) -- {ch} critical/high")
    for f in v["findings"][:8]:
        c = COLOR.get(f["severity"], "")
        ids = ", ".join(f.get("cve") or []) or f.get("osv_id") or "no id"
        print(f"   {c}[{f['severity'].upper():8}]{RESET} {f['ecosystem']}:{f['package']} [{ids}] -- {f['title'][:70]}")
        print(f"              → {f.get('plain_english', '')}")
    if len(v["findings"]) > 8:
        print(f"   ... and {len(v['findings']) - 8} more (see --json / report file for the full list)")
    if v.get("notes"):
        for n in v["notes"]:
            print(f"   note: {n}")

    t = report["typosquat_scan"]
    print(f"\n[L3 TYPOSQUAT/CONFUSION] {len(t['findings'])} finding(s)")
    for f in t["findings"]:
        print(f"   [{f['severity'].upper()}] {f['title']}")

    i = report["installscript_scan"]
    print(f"\n[L4 INSTALL SCRIPTS] {i['packages_checked']} manifest(s) checked, {len(i['findings'])} finding(s)")
    for f in i["findings"][:8]:
        c = COLOR.get(f["severity"], "")
        print(f"   {c}[{f['severity'].upper():8}]{RESET} {f['label']}  ({f['source']})")
    if len(i["findings"]) > 8:
        print(f"   ... and {len(i['findings']) - 8} more")

    verdict = report["verdict"]
    color = {"PASS": "\033[92m", "REVIEW": "\033[93m", "FAIL": "\033[91m"}[verdict["status"]]
    print(f"\n{'-'*72}")
    print(f"VERDICT: {color}{verdict['headline']}{RESET}")
    print(f"  {verdict['next_step']}")
    print(f"  totals: {verdict['counts']}")
    print(f"  (exit code {verdict['exit_code']})\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo_dir")
    ap.add_argument("--check-registry", action="store_true",
                    help="make live registry.npmjs.org/pypi.org lookups for typosquat candidates")
    ap.add_argument("--no-enrich", action="store_true",
                    help="skip the OSV.dev CVE-number lookup for npm findings (faster; findings still show "
                         "GHSA id, CWE, CVSS score, and the local plain-English impact line)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="also write the full JSON report to this path")
    args = ap.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    if not os.path.isdir(repo_dir):
        sys.exit(f"{repo_dir} is not a directory")

    report = run_all(repo_dir, check_registry=args.check_registry, enrich=not args.no_enrich)

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    sys.exit(report["verdict"]["exit_code"])


if __name__ == "__main__":
    main()
