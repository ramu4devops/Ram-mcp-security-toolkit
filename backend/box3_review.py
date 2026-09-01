#!/usr/bin/env python3
"""
box3_review.py -- host-side Rug Pull & Change Integrity review.

Three sub-modes, mirroring the Box-3 strategy doc:

  pin       Strategy A step 1 -- record today's components (tools + resources
            + prompts) and provenance (commit SHA, lockfile hash, entrypoint
            hash) as the approved baseline, and show them all back.
  validate  Strategy A step 2 -- diff the current extraction against the
            pinned baseline (components + provenance) and report drift.
  timeline  Strategy B -- handled by the in-sandbox run_box3_timeline.py; this
            module just wraps its output and pins the HEAD state as a baseline.

The container extracts the components (code execution, if any, stays in the
sandbox). Everything here is hashing + regex + git-metadata over already-
extracted text -- no repo code is executed.
"""
import os, re, json, time, pathlib
import rugpull_lib as rl
import pin_baseline as pb
import check_drift as cd

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BOX_ID, BOX_NAME = "03", "Rug Pull & Change Integrity"


def _slug(name):
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", (name or "server").strip().lower())
    return s.strip("-") or "server"


def _now():
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


def compute_provenance(repo):
    if not repo:
        return {"commit": None, "lockfile": {"name": None, "hash": None},
                "entrypoint": {"name": None, "hash": None}}
    repo = str(repo)
    commit = pb.git_commit_sha(repo)
    lock_name, lock_path = pb.find_lockfile(repo)
    ep_name, ep_path = pb.find_entrypoint(repo, None)
    return {
        "commit": commit,
        "lockfile": {"name": lock_name, "hash": rl.file_hash(lock_path) if lock_path else None},
        "entrypoint": {"name": ep_name, "hash": rl.file_hash(ep_path) if ep_path else None},
    }


def _base_extraction(extraction):
    return {"method": extraction.get("method"),
            "tool_count": extraction.get("tool_count", 0),
            "resource_count": extraction.get("resource_count", 0),
            "prompt_count": extraction.get("prompt_count", 0),
            "ok": extraction.get("ok", False),
            "note": extraction.get("note", ""),
            "tools_preview": extraction.get("tools_preview", [])}


def _components_from_extraction(extraction):
    return {
        "tools": extraction.get("tools_full", []) or [],
        "resources": extraction.get("resources_full", []) or [],
        "prompts": extraction.get("prompts_full", []) or [],
    }


def _baseline_path(server_name, baseline_dir):
    return pathlib.Path(baseline_dir) / (_slug(server_name) + ".json")


def _write_baseline(server_name, comps, provenance, baseline_dir):
    baseline = {
        "schema": "mcpsec.baseline/v1", "label": server_name, "pinned_at": _now(),
        "counts": {k: len(v) for k, v in comps.items()},
        "provenance": {"repo_dir": None, **provenance},
        "components": {k: {c["name"]: rl.canonical_hash(c) for c in v if c.get("name")}
                       for k, v in comps.items()},
        "_raw": comps,
    }
    p = _baseline_path(server_name, baseline_dir)
    pathlib.Path(baseline_dir).mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(baseline, indent=2))
    return baseline


def _finding(sev, layer, name, title, evidence="", impact="", remediation=""):
    return {"severity": sev, "box": "BOX-03", "layer": layer, "subject": name,
            "title": title, "evidence": evidence, "impact": impact, "remediation": remediation}


def _counts(findings):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    c["total"] = len(findings)
    return c


def _not_extracted(server_name, triage, extraction):
    return {
        "box": BOX_ID, "box_name": BOX_NAME, "server_name": server_name, "mode": "pin",
        "triage": triage, "extraction": _base_extraction(extraction), "findings": [],
        "verdict": {"status": "NEEDS_DYNAMIC", "exit_code": 3,
                    "headline": "Could not read this server's components, so nothing can be pinned.",
                    "next_step": "Enable dynamic bring-up or supply a component list, then re-run.",
                    "rationale": ("Rug-pull detection works on the server's declared tools/resources/"
                                  "prompts. The scanner could not extract them without executing the "
                                  "server, so there is nothing to record or compare."),
                    "counts": {"total": 0}},
    }, {"baseline_action": "none"}


# --------------------------------------------------------------------------
# mode: pin
# --------------------------------------------------------------------------
def review_pin(server_name, extraction, triage, repo, baseline_dir):
    if not extraction.get("ok"):
        return _not_extracted(server_name, triage, extraction)
    comps = _components_from_extraction(extraction)
    provenance = compute_provenance(repo)
    baseline = _write_baseline(server_name, comps, provenance, baseline_dir)
    bpath = _baseline_path(server_name, baseline_dir)

    # FULL canonical hashes for every component, shown back to the user.
    hashes = {k: [{"name": c["name"], "hash": rl.canonical_hash(c)}
                  for c in v if c.get("name")] for k, v in comps.items()}
    n = baseline["counts"]
    prov_note = []
    if not provenance["commit"]:
        prov_note.append("no commit SHA (upload has no .git history)")
    if not provenance["lockfile"]["name"]:
        prov_note.append("no dependency lockfile found")

    env = {
        "box": BOX_ID, "box_name": BOX_NAME, "server_name": server_name, "mode": "pin",
        "triage": triage, "extraction": _base_extraction(extraction), "findings": [],
        "provenance": provenance,
        "hashes": hashes,
        # the complete stored record, so the UI can offer it as a download
        "baseline_record": baseline,
        "storage": {"path": str(bpath), "persists": True,
                    "note": "Stored on the backend as a JSON file. It persists across sessions, "
                            "logouts, and restarts (until this file is deleted). Point "
                            "MCP_BASELINE_DIR at a durable/shared folder to keep it elsewhere."},
        "drift": {"first_review": True, "baseline_pinned_at": baseline["pinned_at"],
                  "counts": {"added": 0, "removed": 0, "changed": 0}},
        "verdict": {
            "status": "BASELINE_PINNED", "exit_code": 0,
            "headline": f"Baseline pinned — {n['tools']} tool(s), {n['resources']} resource(s), "
                        f"{n['prompts']} prompt(s).",
            "next_step": "On the next review of this server, run “Validate drift” to compare against "
                         "this baseline.",
            "rationale": ("Recorded the approved state of this server: a canonical hash for every "
                          f"tool/resource/prompt, plus provenance — commit "
                          f"{provenance['commit'][:12] + '…' if provenance['commit'] else 'n/a'}, "
                          f"lockfile {provenance['lockfile']['name'] or 'n/a'}, and entrypoint "
                          f"{provenance['entrypoint']['name'] or 'n/a'}. Any later drift in a "
                          "definition, a dependency lockfile, or the entrypoint file is now "
                          "detectable." + (" Note: " + "; ".join(prov_note) + "." if prov_note else "")),
            "counts": {"total": 0}},
    }
    return env, {"baseline_action": "pinned", "baseline_path": str(bpath)}


# --------------------------------------------------------------------------
# mode: validate
# --------------------------------------------------------------------------
def _map_cd_finding(f):
    layer = "poison" if "POISONING HEURISTICS" in f.get("message", "") else f.get("kind", "component")
    ev = ""
    if f.get("description_diff"):
        ev = "\n".join(l for l in f["description_diff"]
                       if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))[:400]
    return _finding(f["severity"], layer, f.get("name", "?"), f.get("message", ""), ev)


def _status_rows(d):
    rows = []
    for name in d["added"]:
        rows.append({"name": name, "status": "added"})
    for c in d["changed"]:
        parts = []
        if c["description_changed"]:
            parts.append("description")
        if c["schema_changed"]:
            parts.append("schema")
        rows.append({"name": c["name"], "status": "changed", "detail": " + ".join(parts) + " changed"})
    for name in d["unchanged"]:
        rows.append({"name": name, "status": "unchanged"})
    for name in d["removed"]:
        rows.append({"name": name, "status": "removed"})
    return rows


def review_validate(server_name, extraction, triage, repo, baseline_dir):
    bpath = _baseline_path(server_name, baseline_dir)
    if not bpath.is_file():
        return {
            "box": BOX_ID, "box_name": BOX_NAME, "server_name": server_name, "mode": "validate",
            "triage": triage, "extraction": _base_extraction(extraction), "findings": [],
            "verdict": {"status": "NO_BASELINE", "exit_code": 3,
                        "headline": f"No baseline on record for “{server_name}”.",
                        "next_step": "Run “Baseline pinning” (or “First-time baseline, last 3 commits”) "
                                     "first, then come back to validate drift.",
                        "rationale": "Drift validation compares the current components against a "
                                     "previously-approved baseline. None has been pinned for this "
                                     "server name yet, so there is nothing to compare against.",
                        "counts": {"total": 0}},
        }, {"baseline_action": "none"}

    if not extraction.get("ok"):
        return _not_extracted(server_name, triage, extraction)

    baseline = json.loads(bpath.read_text())
    raw = baseline.get("_raw", {})
    cur = _components_from_extraction(extraction)

    all_findings, diffs, components = [], {}, {}
    for kind in ("tools", "resources", "prompts"):
        base_items, curr_items = raw.get(kind, []), cur.get(kind, [])
        if not base_items and not curr_items:
            components[kind] = []
            continue
        cd_findings, d = cd.evaluate_kind(kind, base_items, curr_items)
        all_findings += [_map_cd_finding(f) for f in cd_findings]
        diffs[kind] = {"added": len(d["added"]), "removed": len(d["removed"]),
                       "changed": len(d["changed"]), "unchanged": len(d["unchanged"])}
        components[kind] = _status_rows(d)

    # provenance drift (commit / lockfile / entrypoint) -- reuse check_drift
    cur_prov = compute_provenance(repo)
    prov_cd = cd.check_provenance_drift(baseline, str(repo))
    all_findings += [_map_cd_finding(f) for f in prov_cd]
    base_prov = baseline.get("provenance", {})
    provenance_rows = [
        {"item": "commit", "baseline": (base_prov.get("commit") or "n/a"),
         "current": (cur_prov["commit"] or "n/a"),
         "changed": bool(base_prov.get("commit") and cur_prov["commit"]
                         and base_prov["commit"] != cur_prov["commit"])},
        {"item": "lockfile", "baseline": (base_prov.get("lockfile", {}) or {}).get("hash") or "n/a",
         "current": cur_prov["lockfile"]["hash"] or "n/a",
         "changed": bool((base_prov.get("lockfile", {}) or {}).get("hash")
                         and cur_prov["lockfile"]["hash"]
                         and base_prov["lockfile"]["hash"] != cur_prov["lockfile"]["hash"])},
        {"item": "entrypoint", "baseline": (base_prov.get("entrypoint", {}) or {}).get("hash") or "n/a",
         "current": cur_prov["entrypoint"]["hash"] or "n/a",
         "changed": bool((base_prov.get("entrypoint", {}) or {}).get("hash")
                         and cur_prov["entrypoint"]["hash"]
                         and base_prov["entrypoint"]["hash"] != cur_prov["entrypoint"]["hash"])},
    ]

    all_findings.sort(key=lambda f: -SEV[f["severity"]])
    counts = _counts(all_findings)
    total_added = sum(d.get("added", 0) for d in diffs.values())
    total_removed = sum(d.get("removed", 0) for d in diffs.values())
    total_changed = sum(d.get("changed", 0) for d in diffs.values())
    prov_changed = any(r["changed"] for r in provenance_rows)

    elevated = any(f["severity"] in ("critical", "high") for f in all_findings)
    changed_any = total_added or total_removed or total_changed or prov_changed

    if not changed_any:
        verdict = {"status": "PASS", "exit_code": 0,
                   "headline": "No drift — components and provenance match the approved baseline.",
                   "next_step": "Safe to proceed. Re-validate on every update.",
                   "rationale": (f"Every tool/resource/prompt is byte-for-byte identical (by canonical "
                                 f"hash) to the baseline pinned {baseline.get('pinned_at')}, and the "
                                 "commit, lockfile, and entrypoint hashes are unchanged."),
                   "counts": counts}
    elif elevated:
        verdict = {"status": "HIGH_SUSPICION", "exit_code": 2,
                   "headline": "Drift detected — and a change looks malicious.",
                   "next_step": "Block. Escalate the flagged change(s) before this server is used again.",
                   "rationale": (f"Against the baseline pinned {baseline.get('pinned_at')}: "
                                 f"{total_added} added, {total_removed} removed, {total_changed} changed "
                                 "component(s)"
                                 + (" plus provenance drift" if prov_changed else "") + ". At least one "
                                 "change's new text matches tool-poisoning heuristics — not a benign "
                                 "version bump but a change that also reads as an attack."),
                   "counts": counts}
    else:
        verdict = {"status": "CHANGED", "exit_code": 1,
                   "headline": "Drift detected — needs a human decision.",
                   "next_step": "Review each change; if intended and safe, re-pin the baseline.",
                   "rationale": (f"Against the baseline pinned {baseline.get('pinned_at')}: "
                                 f"{total_added} added, {total_removed} removed, {total_changed} changed "
                                 "component(s)"
                                 + (", and provenance (commit/lockfile/entrypoint) moved" if prov_changed
                                    else "") + ". None of the new text tripped poisoning heuristics, but "
                                 "the definitions the agent trusts are no longer the approved ones."),
                   "counts": counts}

    env = {
        "box": BOX_ID, "box_name": BOX_NAME, "server_name": server_name, "mode": "validate",
        "triage": triage, "extraction": _base_extraction(extraction), "findings": all_findings,
        "provenance": cur_prov, "provenance_rows": provenance_rows, "components": components,
        "drift": {"first_review": False, "baseline_pinned_at": baseline.get("pinned_at"),
                  "counts": {"added": total_added, "removed": total_removed, "changed": total_changed}},
        "verdict": verdict,
    }
    return env, {"baseline_action": "compared", "baseline_path": str(bpath)}


# --------------------------------------------------------------------------
# mode: timeline (wrap the in-sandbox result, pin HEAD as baseline)
# --------------------------------------------------------------------------
def finalize_timeline(server_name, timeline_env, repo, baseline_dir):
    timeline_env["box_name"] = BOX_NAME
    ex = timeline_env.get("extraction", {})
    if ex.get("ok") and ex.get("tools_full"):
        comps = {"tools": ex.get("tools_full", []), "resources": [], "prompts": []}
        provenance = compute_provenance(repo)
        baseline = _write_baseline(server_name, comps, provenance, baseline_dir)
        timeline_env["provenance"] = provenance
        timeline_env["baseline_pinned"] = True
        v = timeline_env.get("verdict", {})
        v["next_step"] = (v.get("next_step", "") + "  The HEAD state has been pinned as the baseline, "
                          "so future reviews can validate drift against it.").strip()
        return timeline_env, {"baseline_action": "pinned", "baseline_path":
                              str(_baseline_path(server_name, baseline_dir))}
    return timeline_env, {"baseline_action": "none"}


# back-compat single entry (kept for the non-stream endpoint default)
def review(server_name, tools_full, extraction, triage, baseline_dir):
    ext = dict(extraction)
    ext.setdefault("tools_full", tools_full)
    p = _baseline_path(server_name, baseline_dir)
    if p.is_file():
        return review_validate(server_name, ext, triage, None, baseline_dir)
    return review_pin(server_name, ext, triage, None, baseline_dir)
