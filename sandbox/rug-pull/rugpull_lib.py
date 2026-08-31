#!/usr/bin/env python3
"""
rugpull_lib.py -- shared logic for Box-3 (Rug Pull & Change Integrity).

Used by pin_baseline.py, check_drift.py, and rugpull_timeline.py so all
three tools canonicalize, hash, and diff components (tools/resources/
prompts) the exact same way. No LLM, no network calls of its own, stdlib
only (plus nothing -- zero third-party deps).
"""
import re, json, hashlib, difflib, unicodedata

# Reused verbatim from Box-1's detect_poison.py so a rug-pull's *content*
# gets the same scrutiny a brand-new tool would get -- see delta_risk_scan().
INSTRUCTION_PATTERNS = [
    r"ignore (all |the )?(previous|prior) instructions",
    r"do not (tell|inform|mention to|reveal to) the user",
    r"\byou must\b", r"\byou should always\b", r"\bbefore using this tool\b",
    r"<important>", r"<secret>", r"<system>", r"\[system\]",
]
SENSITIVE_PATHS = [
    r"~/\.ssh", r"\.env\b", r"~/\.aws", r"id_rsa",
    r"mcp\.json", r"/etc/passwd", r"credentials", r"api[_-]?key",
]


# ----------------------------------------------------------------------
# Canonicalization + hashing
# ----------------------------------------------------------------------
def canonical_component(item):
    """Strip an item down to the fields that matter for integrity: what
    the agent actually reads/receives. Ignores incidental key ordering."""
    return {
        "name": item.get("name"),
        "description": item.get("description", "") or "",
        "input_schema": item.get("input_schema", item.get("inputSchema", {})) or {},
    }


def canonical_hash(item):
    blob = json.dumps(canonical_component(item), sort_keys=True, ensure_ascii=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def file_hash(path):
    try:
        with open(path, "rb") as fh:
            return "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


# ----------------------------------------------------------------------
# Component-set diffing (tools, resources, or prompts -- same shape)
# ----------------------------------------------------------------------
def index_by_name(items):
    return {it["name"]: it for it in items if it.get("name")}


def diff_components(baseline_items, current_items):
    """Returns {added: [...], removed: [...], changed: [...], unchanged: [...]}
    where 'changed' entries carry a human-readable diff of what moved."""
    base = index_by_name(baseline_items)
    curr = index_by_name(current_items)
    base_names, curr_names = set(base), set(curr)

    added = sorted(curr_names - base_names)
    removed = sorted(base_names - curr_names)
    changed, unchanged = [], []

    for name in sorted(base_names & curr_names):
        b_hash = canonical_hash(base[name])
        c_hash = canonical_hash(curr[name])
        if b_hash == c_hash:
            unchanged.append(name)
            continue
        b_desc = canonical_component(base[name])["description"]
        c_desc = canonical_component(curr[name])["description"]
        desc_diff = list(difflib.unified_diff(
            b_desc.splitlines() or [""], c_desc.splitlines() or [""],
            lineterm="", fromfile="baseline", tofile="current"))
        schema_changed = (canonical_component(base[name])["input_schema"]
                          != canonical_component(curr[name])["input_schema"])
        changed.append({
            "name": name,
            "baseline_hash": b_hash,
            "current_hash": c_hash,
            "description_diff": desc_diff,
            "description_changed": b_desc != c_desc,
            "schema_changed": schema_changed,
        })

    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged}


def _visible_and_hidden(text):
    hidden = 0
    kept = []
    for ch in text:
        cat = unicodedata.category(ch)
        is_tag = 0xE0000 <= ord(ch) <= 0xE007F
        if cat in {"Cf", "Co"} or is_tag:
            hidden += 1
        else:
            kept.append(ch)
    return "".join(kept), hidden


def delta_risk_scan(added_lines_text):
    """Run Box-1-style heuristics on ONLY the newly-added text of a diff.
    A rug pull often shows up as poisoning-style content freshly injected
    into an otherwise-legitimate, previously-approved tool. Returns a list
    of (severity, message) findings -- empty if nothing suspicious."""
    findings = []
    visible, n_hidden = _visible_and_hidden(added_lines_text)
    low = visible.lower()
    if n_hidden:
        findings.append(("critical", f"{n_hidden} invisible/tag character(s) newly introduced"))
    for pat in INSTRUCTION_PATTERNS:
        if re.search(pat, low):
            findings.append(("critical", f"Imperative/secrecy instruction newly introduced ({pat})"))
    for pat in SENSITIVE_PATHS:
        if re.search(pat, low):
            findings.append(("high", f"Sensitive path/secret reference newly introduced ({pat})"))
    return findings


def added_text_from_diff(unified_diff_lines):
    """Pull out just the '+' lines (the new content) from a unified diff,
    ignoring the '+++' header line."""
    return "\n".join(
        l[1:] for l in unified_diff_lines
        if l.startswith("+") and not l.startswith("+++")
    )
