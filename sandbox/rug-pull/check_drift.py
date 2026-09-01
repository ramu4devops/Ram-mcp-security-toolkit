#!/usr/bin/env python3
"""
check_drift.py -- Box-3 gate: compare a NEW extraction against a pinned
baseline.json and report rug-pull / change-integrity findings.

Usage:
    python3 check_drift.py baseline.json tools_now.json \
        [--resources resources_now.json] [--prompts prompts_now.json] \
        [--repo-dir /path/to/new/clone] [--json]

Exit codes:
    0 = clean (no changes at all)
    1 = changes found requiring manual review (WARN)
    2 = changes found with elevated automated suspicion (HIGH/CRITICAL)
"""
import os, sys, json, argparse
from rugpull_lib import diff_components, delta_risk_scan, added_text_from_diff, file_hash
from pin_baseline import git_commit_sha, find_lockfile, find_entrypoint, load_components

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
        "low": "\033[92m", "info": "\033[90m", "warn": "\033[93m"}
RESET = "\033[0m"


def evaluate_kind(kind, baseline_items, current_items):
    """kind: 'tools' | 'resources' | 'prompts' -- all same shape, same rules."""
    d = diff_components(baseline_items, current_items)
    findings = []

    for name in d["removed"]:
        findings.append({"severity": "info", "kind": kind, "name": name,
                         "message": f"{kind[:-1]} REMOVED since baseline (no longer exposed)",
                         "requires_review": False})

    for name in d["added"]:
        # Never in the baseline -- treat like brand-new Box-1 material.
        item = next(t for t in current_items if t.get("name") == name)
        risk = delta_risk_scan(item.get("description", "") or "")
        sev = max((s for s, _ in risk), key=lambda s: SEV_ORDER[s], default="medium")
        msgs = "; ".join(m for _, m in risk) or "new, previously-unreviewed definition -- needs a first-time Box-1 scan"
        findings.append({"severity": sev, "kind": kind, "name": name,
                         "message": f"{kind[:-1]} ADDED since baseline -- {msgs}",
                         "requires_review": True})

    for c in d["changed"]:
        added_text = added_text_from_diff(c["description_diff"])
        risk = delta_risk_scan(added_text)
        base_sev = "high" if risk else "medium"
        # A schema change with no description change is still real: an
        # attacker doesn't need to touch prose to widen what a tool accepts.
        parts = []
        if c["description_changed"]:
            parts.append("description changed")
        if c["schema_changed"]:
            parts.append("input schema changed")
        msg = f"{kind[:-1]} CHANGED since baseline ({', '.join(parts)}) -- hash {c['baseline_hash'][:14]}... -> {c['current_hash'][:14]}..."
        if risk:
            msg += " | NEW CONTENT MATCHES POISONING HEURISTICS: " + "; ".join(m for _, m in risk)
        findings.append({"severity": base_sev, "kind": kind, "name": c["name"],
                         "message": msg, "requires_review": True,
                         "description_diff": c["description_diff"]})

    return findings, d


def check_provenance_drift(baseline, repo_dir):
    findings = []
    prov = baseline.get("provenance", {}) or {}
    if not repo_dir:
        return findings
    new_commit = git_commit_sha(repo_dir)
    old_commit = prov.get("commit")
    if old_commit and new_commit and old_commit != new_commit:
        findings.append({"severity": "info", "kind": "provenance", "name": "commit",
                         "message": f"Commit changed: {old_commit[:10]} -> {new_commit[:10]} (expected for a version bump)",
                         "requires_review": False})

    old_lock = (prov.get("lockfile") or {})
    if old_lock.get("name"):
        _, new_lock_path = find_lockfile(repo_dir)
        new_hash = file_hash(new_lock_path) if new_lock_path else None
        if new_hash and new_hash != old_lock.get("hash"):
            findings.append({"severity": "medium", "kind": "provenance", "name": "lockfile",
                             "message": f"Dependency lockfile ({old_lock['name']}) hash changed -- re-run Box-4 (supply chain)",
                             "requires_review": True})

    old_ep = (prov.get("entrypoint") or {})
    if old_ep.get("name"):
        _, new_ep_path = find_entrypoint(repo_dir, old_ep["name"])
        new_hash = file_hash(new_ep_path) if new_ep_path else None
        if new_hash and new_hash != old_ep.get("hash"):
            findings.append({"severity": "medium", "kind": "provenance", "name": "entrypoint",
                             "message": f"Entrypoint file ({old_ep['name']}) hash changed independent of tool text -- review the diff directly",
                             "requires_review": True})
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline_json")
    ap.add_argument("tools_json")
    ap.add_argument("--resources")
    ap.add_argument("--prompts")
    ap.add_argument("--repo-dir")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    baseline = json.load(open(args.baseline_json))
    raw = baseline.get("_raw", {})

    current_tools = load_components(args.tools_json)
    current_resources = load_components(args.resources)
    current_prompts = load_components(args.prompts)

    all_findings = []
    diffs = {}
    for kind, base_items, curr_items in [
        ("tools", raw.get("tools", []), current_tools),
        ("resources", raw.get("resources", []), current_resources),
        ("prompts", raw.get("prompts", []), current_prompts),
    ]:
        if not base_items and not curr_items:
            continue
        findings, d = evaluate_kind(kind, base_items, curr_items)
        all_findings += findings
        diffs[kind] = d

    all_findings += check_provenance_drift(baseline, args.repo_dir)
    all_findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])

    if args.json:
        print(json.dumps({"findings": all_findings, "diffs": diffs}, indent=2))
    else:
        print(f"\nBaseline: {baseline.get('label') or args.baseline_json}  "
              f"(pinned {baseline.get('pinned_at', '?')})")
        print("-" * 68)
        if not all_findings:
            print("No changes detected in any pinned component. VERDICT: PASS\n")
            sys.exit(0)
        for f in all_findings:
            c = COLOR.get(f["severity"], "")
            tag = "REVIEW" if f["requires_review"] else "info"
            print(f"{c}[{f['severity'].upper():8}]{RESET} ({tag:6}) {f['kind']}/{f['name']}")
            print(f"           {f['message']}")
            if f.get("description_diff"):
                for line in f["description_diff"]:
                    if line.startswith("+") and not line.startswith("+++"):
                        print(f"           \033[92m{line}\033[0m")
                    elif line.startswith("-") and not line.startswith("---"):
                        print(f"           \033[91m{line}\033[0m")
        print("-" * 68)

    needs_review = any(f["requires_review"] for f in all_findings)
    elevated = any(f["severity"] in ("critical", "high") for f in all_findings)
    if elevated:
        verdict, code = "HIGH SUSPICION -- MANUAL REVIEW REQUIRED", 2
    elif needs_review:
        verdict, code = "CHANGED -- MANUAL REVIEW REQUIRED", 1
    else:
        verdict, code = "CHANGED (informational only)", 0
    if not args.json:
        print(f"\nVERDICT: {verdict}\n")
    sys.exit(code)


if __name__ == "__main__":
    main()
