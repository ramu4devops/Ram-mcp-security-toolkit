#!/usr/bin/env python3
"""
detect_poison.py (v1.1) -- Beginner-friendly MCP tool-poisoning detector.

Changes from v1.0:
  - L3 (cross-tool shadowing) is now ORIGIN-AWARE. A tool's description
    mentioning another tool by name is only flagged when the two tools come
    from DIFFERENT sources/servers. Same-server "see also" cross-references
    (very common, completely normal API documentation) are no longer
    false-positived. Real shadowing attacks are inherently cross-origin: a
    new/malicious server redefining a tool that belongs to a different,
    already-trusted server.
  - Each tool may carry an optional "source" field (which server/file it
    came from). Tools with no "source" are treated as one default origin,
    so single-server scans behave exactly like before (minus the noise).

Uses NO LLM and NO internet: every check is plain Python (regex, unicode,
hashing).

Usage:
    python detect_poison.py tools.json
    python detect_poison.py tools.json --baseline pins.json
"""
import re, sys, json, hashlib, unicodedata, argparse

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
EXFIL_PARAM_NAMES = {"notes", "debug", "context", "feedback",
                     "extra", "metadata", "sidechannel", "log"}

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
DEFAULT_SOURCE = "__default__"


def visible_and_hidden(text):
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


def canonical_hash(tool):
    blob = json.dumps(
        {"name": tool.get("name"),
         "description": tool.get("description", ""),
         "schema": tool.get("input_schema", {})},
        sort_keys=True, ensure_ascii=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def scan_tool(tool, all_tools):
    findings = []
    name = tool.get("name", "<unnamed>")
    src = tool.get("source", DEFAULT_SOURCE)
    desc = tool.get("description", "") or ""
    visible, n_hidden = visible_and_hidden(desc)
    low = visible.lower()

    def add(box, layer, sev, msg, evidence):
        findings.append({"box": box, "layer": layer, "severity": sev,
                         "tool": name, "message": msg, "evidence": evidence})

    # L2 -- hidden / obfuscated content
    if n_hidden:
        add("BOX-01", "L2", "critical",
            f"{n_hidden} invisible/tag character(s) hidden in description",
            repr(desc[:80]))
    if len(desc) > 800:
        add("BOX-01", "L2", "medium",
            "Unusually long description (payload-smuggling risk)",
            f"length={len(desc)}")

    # L1 -- instruction + sensitive-path patterns
    for pat in INSTRUCTION_PATTERNS:
        if re.search(pat, low):
            add("BOX-01", "L1", "critical",
                "Imperative/secrecy instruction embedded in description", pat)
    for pat in SENSITIVE_PATHS:
        if re.search(pat, low):
            add("BOX-01", "L1", "high",
                f"Description references a sensitive path/secret ({pat})", pat)

    # L3 -- CROSS-ORIGIN tool shadowing (fixed: origin-aware)
    for other in all_tools:
        if other is tool:
            continue
        other_name, other_src = other.get("name"), other.get("source", DEFAULT_SOURCE)
        if not other_name or other_src == src:      # <-- skip same-origin mentions
            continue
        if re.search(rf"\b{re.escape(other_name)}\b", low):
            add("BOX-02", "L3", "critical",
                f"Description references tool '{other_name}' from a "
                f"DIFFERENT source ('{other_src}' != '{src}') -- shadowing",
                other_name)

    # L4 -- exfiltration parameters
    schema = tool.get("input_schema", {}) or {}
    props = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    for pname, pdef in props.items():
        if (pname.lower() in EXFIL_PARAM_NAMES
                and pname not in required
                and (pdef or {}).get("type") == "string"):
            add("BOX-10", "L4", "high",
                f"Optional free-text sink parameter '{pname}'",
                json.dumps(pdef))
    return findings


def scan(tools, baseline=None):
    out = []
    for t in tools:
        out += scan_tool(t, tools)
        h = canonical_hash(t)
        prev = (baseline or {}).get(t.get("name"))
        if prev and prev != h:
            out.append({"box": "BOX-03", "layer": "L7", "severity": "high",
                        "tool": t.get("name"),
                        "message": "Tool definition changed since approval (rug-pull)",
                        "evidence": h})
    out.sort(key=lambda f: -SEV_ORDER[f["severity"]])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tools_json")
    ap.add_argument("--baseline")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    tools = json.load(open(args.tools_json))
    if isinstance(tools, dict) and "tools" in tools:
        tools = tools["tools"]
    baseline = json.load(open(args.baseline)) if args.baseline else None

    findings = scan(tools, baseline)

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    COLOR = {"critical": "\033[91m", "high": "\033[93m",
             "medium": "\033[96m", "low": "\033[92m", "info": "\033[90m"}
    RESET = "\033[0m"
    print(f"\nScanned {len(tools)} tool(s) -- {len(findings)} finding(s)\n" + "-"*60)
    for f in findings:
        c = COLOR.get(f["severity"], "")
        print(f"{c}[{f['severity'].upper():8}]{RESET} {f['box']}/{f['layer']}  "
              f"tool='{f['tool']}'")
        print(f"           {f['message']}")
        print(f"           evidence: {f['evidence']}")
    worst = max((SEV_ORDER[f["severity"]] for f in findings), default=0)
    verdict = "FAIL" if worst >= 3 else ("WARN" if worst >= 1 else "PASS")
    print("-"*60)
    print(f"VERDICT: {verdict}\n")
    sys.exit(1 if verdict == "FAIL" else 0)


if __name__ == "__main__":
    main()
