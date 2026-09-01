#!/usr/bin/env python3
"""
secrets_supply.py -- normalize the raw JSON from Box-6 (secrets_scan.py) and
Box-7 (supplychain_scan.py) into the shared UI envelope
{box, box_name, extraction, findings[], verdict{...,rationale}}.

The scan scripts run inside the sandbox and already emit their own findings
and a PASS/REVIEW/FAIL verdict; this is pure host-side reshaping (renaming
fields, flattening layers, and synthesizing a plain-English rationale) so the
console renders every box the same way.
"""
SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _counts(findings):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    c["total"] = len(findings)
    return c


def _top_layers(findings, n=3):
    seen = []
    for f in sorted(findings, key=lambda x: -SEV[x["severity"]]):
        lbl = f.get("layer")
        if lbl and lbl not in seen:
            seen.append(lbl)
    return seen[:n]


# ==========================================================================
# Box-6 · Secrets & Token Handling
# ==========================================================================
S6_LAYER = {
    "S1": "hardcoded credentials in the working tree",
    "S2": "credentials in git history",
    "S3": "secrets leaking into the MCP channel (stdout / return values)",
    "S4": "over-broad credential surface (whole-env reads, ~/.aws, .env)",
    "S5": "token-lifecycle hygiene (plaintext persistence, tokens in URLs)",
    "S6": "repo hygiene (.env committed, .gitignore gaps)",
}
S6_IMPACT = {
    "S3": "On a stdio MCP server, stdout IS the JSON-RPC transport and a tool's "
          "return value reaches the model's context and the LLM provider — so a "
          "stray print or a returned secret both corrupts the protocol and leaks "
          "the secret.",
}


def normalize_secrets(report, server_name):
    raw = report.get("findings", [])
    findings = []
    for f in raw:
        layer = f.get("layer", "")
        loc = f.get("file", "")
        if f.get("line"):
            loc = f"{loc}:{f['line']}"
        findings.append({
            "severity": f.get("severity", "info"),
            "box": "BOX-06", "layer": layer,
            "subject": loc or "(repo)",
            "title": f.get("title", ""),
            "evidence": f.get("evidence", ""),
            "impact": S6_IMPACT.get(layer, ""),
            "remediation": f.get("remediation", ""),
        })
    findings.sort(key=lambda x: -SEV[x["severity"]])
    v = dict(report.get("verdict", {}))
    counts = _counts(findings)
    v["counts"] = counts
    tops = _top_layers(findings)
    tlabel = "; ".join(S6_LAYER.get(t, t) for t in tops)
    status = v.get("status", "PASS")
    if status == "FAIL":
        v["rationale"] = (f"Found {counts['total']} secret-handling finding(s): "
                          f"{counts['critical']} critical, {counts['high']} high — strongest signals: "
                          f"{tlabel or 'see findings'}. A live or high-confidence credential exposure "
                          "blocks the submission until every critical/high item is rotated and removed.")
    elif status == "REVIEW":
        v["rationale"] = (f"Found {counts['total']} lower-severity secret-handling weakness(es) "
                          f"({tlabel or 'see findings'}). No usable live credential was recovered, but "
                          "the handling patterns need a human decision before approval.")
    else:
        v["rationale"] = ("None of the six secret layers (hardcoded creds, git-history leaks, "
                          "MCP-channel leakage, over-broad credential access, token hygiene, repo "
                          "hygiene) fired. Note this is a static scan — re-run on every change.")
        v.setdefault("headline", "PASS — no secret-management findings")
    stat = [
        {"cls": "s-tools", "n": counts["total"], "l": "Findings"},
        {"cls": "s-crit", "n": counts["critical"], "l": "Critical"},
        {"cls": "s-high", "n": counts["high"], "l": "High"},
        {"cls": "", "n": counts.get("medium", 0), "l": "Medium"},
    ]
    return {
        "box": "06", "box_name": "Secrets & Token Handling", "server_name": server_name,
        "extraction": {"ok": True, "method": "static (S1–S6)", "tool_count": 0, "tools_preview": []},
        "stats_tiles": stat, "findings": findings, "verdict": v,
    }


# ==========================================================================
# Shared: simple single-layer-set box normalizer (Box-5, Box-9)
# ==========================================================================
def _normalize_simple(report, server_name, box_id, box_name, method_label,
                      layer_labels, box_tag, fail_note, review_note, pass_note):
    raw = report.get("findings", [])
    findings = []
    for f in raw:
        layer = f.get("layer", "")
        loc = f.get("file", "")
        if f.get("line"):
            loc = f"{loc}:{f['line']}"
        findings.append({
            "severity": f.get("severity", "info"),
            "box": box_tag, "layer": layer,
            "subject": loc or "(repo)",
            "title": f.get("title", ""),
            "evidence": f.get("evidence", ""),
            "impact": "",
            "remediation": f.get("remediation", ""),
        })
    findings.sort(key=lambda x: -SEV[x["severity"]])
    v = dict(report.get("verdict", {}))
    counts = _counts(findings)
    v["counts"] = counts
    tops = _top_layers(findings)
    tlabel = "; ".join(layer_labels.get(t, t) for t in tops)
    status = v.get("status", "PASS")
    if status == "FAIL":
        v["rationale"] = (f"Found {counts['total']} finding(s): {counts['critical']} critical, "
                          f"{counts['high']} high — strongest signals: {tlabel or 'see findings'}. "
                          f"{fail_note}")
    elif status == "REVIEW":
        v["rationale"] = (f"Found {counts['total']} lower-severity finding(s) "
                          f"({tlabel or 'see findings'}). {review_note}")
    else:
        v["rationale"] = pass_note
        v.setdefault("headline", f"PASS — no {box_name.lower()} findings")
    stat = [
        {"cls": "s-tools", "n": counts["total"], "l": "Findings"},
        {"cls": "s-crit", "n": counts["critical"], "l": "Critical"},
        {"cls": "s-high", "n": counts["high"], "l": "High"},
        {"cls": "", "n": counts.get("medium", 0), "l": "Medium"},
    ]
    return {
        "box": box_id, "box_name": box_name, "server_name": server_name,
        "extraction": {"ok": True, "method": method_label, "tool_count": 0, "tools_preview": []},
        "stats_tiles": stat, "findings": findings, "verdict": v,
    }


# ==========================================================================
# Box-5 · Resource Exploitation
# ==========================================================================
R_LAYER = {
    "R1": "path traversal into a filesystem read",
    "R2": "unbounded resource reads",
    "R3": "SSRF-shaped resource fetch",
    "R4": "overly broad resource URI templates",
    "R5": "missing content-type/size validation on returned resource bytes",
}


def normalize_resource_exploit(report, server_name):
    return _normalize_simple(
        report, server_name, "05", "Resource Exploitation", "static (R1–R5)",
        R_LAYER, "BOX-05",
        fail_note=("A caller can plausibly reach data or hosts outside the resource's "
                   "intended scope (path traversal, an unconstrained URI template, or an "
                   "SSRF-shaped fetch) — this blocks the submission until every critical/"
                   "high finding is fixed."),
        review_note=("Nothing rose to a high-confidence traversal/SSRF, but the read/return "
                     "paths above lack the caps or checks that keep a resource handler safe "
                     "to expose — a reviewer should confirm each is intentional."),
        pass_note=("None of the five resource-exploitation layers fired (path traversal, "
                   "unbounded reads, SSRF-shaped fetch, overly broad URI templates, missing "
                   "content-type/size validation). This is a static scan of read/fetch call "
                   "sites — re-run on every change to resource handlers or URI templates."))


# ==========================================================================
# Box-9 · Confused Deputy & Authorization
# ==========================================================================
A_LAYER = {
    "A1": "a shared credential used with no per-caller authorization check",
    "A2": "a privileged operation with no authorization check",
    "A3": "a bearer/access token forwarded with no audience/scope validation",
    "A4": "a caller-supplied identity parameter trusted without a session cross-check",
    "A5": "no authorization framework detected in the codebase",
}


def normalize_confused_deputy(report, server_name):
    return _normalize_simple(
        report, server_name, "09", "Confused Deputy & Authorization", "static (A1–A5)",
        A_LAYER, "BOX-09",
        fail_note=("A privileged operation or the server's own shared credential is used "
                   "with no visible per-caller authorization check — any caller who can "
                   "reach this server inherits its full privilege. Gate the submission "
                   "until each critical/high finding is resolved."),
        review_note=("No high-confidence confused-deputy pattern was found, but the "
                     "authorization gaps above need a human decision before approval."),
        pass_note=("None of the five confused-deputy/authorization layers fired (shared-"
                   "credential misuse, unchecked privileged operations, unvalidated token "
                   "pass-through, untrusted identity parameters, missing authz framework). "
                   "This is a static scan of handler bodies — re-run on every change to "
                   "tool/resource handlers or the auth layer."))


# ==========================================================================
# Box-04 · Prompt & Template Injection
# ==========================================================================
P_LAYER = {
    "P1": "untrusted input interpolated into a prompt template",
    "P2": "server-side template injection into a prompt (SSTI)",
    "P3": "fetched resource content flowing into the instruction stream",
    "P4": "caller input interpolated next to role/turn framing (forged turns)",
    "P5": "unconstrained free-text prompt arguments",
}


def normalize_prompt_injection(report, server_name):
    return _normalize_simple(
        report, server_name, "04", "Prompt & Template Injection", "static (P1–P5)",
        P_LAYER, "BOX-04",
        fail_note=("A caller value or a fetched resource can reach the model's own instruction "
                   "flow — via a prompt template, a server-side template engine, or forged role "
                   "framing — letting it override the intended prompt. Gate the submission until "
                   "every critical/high finding is fixed."),
        review_note=("No high-confidence injection path was found, but the prompt handling above "
                     "lacks the fixed-template / delimited-data / constrained-argument discipline "
                     "that keeps it safe — a reviewer should confirm each is intentional."),
        pass_note=("None of the five prompt-injection layers fired (untrusted input in a prompt "
                   "template, template-engine SSTI, resource content into instructions, forged "
                   "role framing, unconstrained prompt arguments). Static scan of prompt handlers "
                   "and template sinks — re-run on every change to prompts."))


# ==========================================================================
# Box-13 · Audit, Telemetry & Logging
# ==========================================================================
T_LAYER = {
    "T1": "no logging framework configured on a tool-exposing server",
    "T2": "tool handlers that emit no audit line",
    "T3": "secrets or PII written into log / print calls",
    "T4": "privileged operations with no audit record",
    "T5": "debug / verbose logging left enabled in runtime code",
}


def normalize_audit(report, server_name):
    return _normalize_simple(
        report, server_name, "13", "Audit, Telemetry & Logging", "static (T1–T5)",
        T_LAYER, "BOX-13",
        fail_note=("A secret or credential is written into a log/print call — both a leak into log "
                   "storage and, on a stdio server, corruption of the JSON-RPC transport. Remove it "
                   "before approval, then close the audit-coverage gaps."),
        review_note=("No secret was found in a log call, but the audit trail has gaps (missing "
                     "logging framework, un-logged tool or privileged handlers, or debug logging "
                     "left on). A reviewer should decide whether the telemetry is sufficient for "
                     "incident investigation."),
        pass_note=("A logging framework is present, tool and privileged handlers emit audit lines, "
                   "no secrets/PII were seen in log calls, and debug logging is not left on. Static "
                   "assurance check — re-run on change."))


# ==========================================================================
# Box-14 · Shadow MCP Servers (config & manifest hygiene)
# ==========================================================================
H_LAYER = {
    "H1": "over-broad tool / capability exposure in the manifest",
    "H2": "embedded or default credentials in config",
    "H3": "insecure transport (non-TLS / verification disabled) or debug flags",
    "H4": "shadow-server indicators (remote/unpinned launch, name-squatting)",
    "H5": "manifest integrity / entrypoint hygiene gaps",
}


def normalize_config_hygiene(report, server_name):
    result = _normalize_simple(
        report, server_name, "14", "Shadow MCP Servers", "static config review (H1–H5)",
        H_LAYER, "BOX-14",
        fail_note=("A manifest embeds a secret, exposes an over-broad surface, disables TLS, or "
                   "launches a remote/unpinned payload — hallmarks of an unsafe or shadow server "
                   "masquerading as a trusted one. Pin the launch artifact, scope the surface, and "
                   "remove credentials from config before onboarding."),
        review_note=("No high-confidence shadow-server indicator, but the manifest has hygiene gaps "
                     "(default creds, debug flags, unpinned launch, broad env passthrough, or a "
                     "name resembling a well-known server). A reviewer should confirm each is "
                     "intentional."),
        pass_note=("No manifest exposed an over-broad surface, embedded credential, insecure "
                   "transport, or remote/unpinned launch, and no declared name squats a well-known "
                   "server. Static config review — re-run on any manifest change."))
    # surface the count of manifests actually inspected (helps interpret a PASS)
    mans = report.get("manifests", [])
    result["manifests"] = mans
    if not mans:
        result["verdict"].setdefault(
            "note", "No MCP manifest/config file was found in the upload — nothing to review here.")
    return result


# ==========================================================================
# Box-8 · Static Code Security (SAST)
# ==========================================================================
C_LAYER = {
    "C1": "OS command injection (caller input reaching a shell)",
    "C2": "code injection / dynamic evaluation (eval/exec/Function)",
    "C3": "insecure deserialization (pickle/marshal/unsafe yaml.load)",
    "C4": "SQL/NoSQL injection (unparameterized query construction)",
    "C5": "server-side template injection (caller input as template source)",
}


def normalize_sast(report, server_name):
    return _normalize_simple(
        report, server_name, "08", "Static Code Security (SAST)", "static (C1–C5)",
        C_LAYER, "BOX-08",
        fail_note=("A tool argument plausibly reaches a dangerous native sink -- a shell, an "
                   "interpreter's own eval, a deserializer, a raw SQL string, or a template "
                   "source -- any of which lets a caller execute code or reach data outside the "
                   "tool's intended scope. This blocks the submission until every critical/high "
                   "finding is fixed."),
        review_note=("Nothing rose to a high-confidence injection/RCE pattern, but the sinks "
                     "above lack the guard (parameterization, argv-array form, a safe loader) "
                     "that keeps them safe to expose -- a reviewer should confirm each is "
                     "intentional."),
        pass_note=("None of the five SAST layers fired (command injection, code injection/eval, "
                   "insecure deserialization, SQL/NoSQL injection, server-side template "
                   "injection). This is a static scan of source call sites -- re-run on every "
                   "change to tool/resource handlers."))


# ==========================================================================
# Box-7 · Supply Chain & Dependency Security
# ==========================================================================
def normalize_supply(report, server_name):
    findings = []

    for f in report.get("vuln_scan", {}).get("findings", []):
        cves = ", ".join(f.get("cve") or []) or "no CVE id"
        cvss = f.get("cvss")
        ver = f.get("version") or ""
        direct = "direct" if f.get("direct") else ("transitive" if f.get("direct") is False else "")
        findings.append({
            "severity": f.get("severity", "info"), "box": "BOX-07", "layer": "CVE",
            "subject": f"{f.get('ecosystem','')}:{f.get('package','')} {ver}".strip(),
            "title": f.get("title", ""),
            "evidence": (cves + (f" · CVSS {cvss}" if cvss else "") + (f" · {direct}" if direct else "")),
            "impact": f.get("impact", ""),
            "remediation": f.get("remediation") or "Upgrade to a patched version or pin/replace the dependency.",
        })
    for f in report.get("typosquat_scan", {}).get("findings", []):
        findings.append({
            "severity": f.get("severity", "medium"), "box": "BOX-07", "layer": "Typosquat",
            "subject": f"{f.get('ecosystem','')}:{f.get('package','')}",
            "title": f.get("title", ""), "evidence": "",
            "impact": "A dependency name close to a popular package is a typosquat / dependency-confusion "
                      "risk — installing the wrong name runs attacker code.",
            "remediation": "Confirm the exact package name and source; pin to the intended package.",
        })
    for f in report.get("installscript_scan", {}).get("findings", []):
        findings.append({
            "severity": f.get("severity", "high"), "box": "BOX-07", "layer": "Install script",
            "subject": f.get("source", "install hook"),
            "title": f.get("label", "install-time script"),
            "evidence": f.get("why", ""),
            "impact": "Install-time scripts run automatically on `npm install` / `pip install`, before "
                      "the server is ever started — a prime place to hide a supply-chain payload.",
            "remediation": "Review the script; use --ignore-scripts or a vetted mirror if it is not required.",
        })
    # SBOM review items (non-gating) come through combined_findings with gate=False
    for f in report.get("combined_findings", []):
        if f.get("layer") == "sbom" and not f.get("gate", True):
            findings.append({
                "severity": f.get("severity", "medium"), "box": "BOX-07", "layer": "SBOM",
                "subject": "dependency inventory", "title": f.get("summary", ""),
                "evidence": "", "impact": "",
                "remediation": "Commit a lockfile and pin dependencies for a reproducible, auditable tree.",
            })

    findings.sort(key=lambda x: -SEV[x["severity"]])
    counts = _counts(findings)

    packages = 0
    for e in report.get("sbom", {}).get("ecosystems", []):
        packages += e.get("component_count", 0) or len(e.get("components", []) or [])
    ecos = [k for k, v in report.get("ecosystems_detected", {}).items() if v]

    v = dict(report.get("verdict", {}))
    v["counts"] = counts
    status = v.get("status", "PASS")
    ch = counts["critical"] + counts["high"]
    if status == "FAIL":
        v["rationale"] = (f"Resolved {packages} package(s) across {', '.join(ecos) or 'no'} ecosystem(s) and "
                          f"raised {counts['total']} finding(s) — {ch} critical/high. High-severity known "
                          "CVEs, a typosquat, or a malicious install-time script blocks the submission until "
                          "each is patched, pinned, or replaced.")
    elif status == "REVIEW":
        v["rationale"] = (f"Resolved {packages} package(s) across {', '.join(ecos) or 'no'} ecosystem(s); "
                          f"{counts['total']} finding(s), none high-confidence-critical. Typically an "
                          "unpinned/missing-lockfile or a moderate CVE — needs a human decision before approval.")
    else:
        v["rationale"] = (f"Resolved {packages} package(s) across {', '.join(ecos) or 'no'} ecosystem(s). "
                          "No known-CVE dependency, typosquat, or malicious install script found. Re-scan on "
                          "every dependency update — a clean scan is a snapshot in time.")
        v.setdefault("headline", "PASS — no supply-chain findings")

    notes = report.get("vuln_scan", {}).get("notes", [])
    stat = [
        {"cls": "s-tools", "n": packages, "l": "Packages"},
        {"cls": "", "n": counts["total"], "l": "Findings"},
        {"cls": "s-crit", "n": counts["critical"], "l": "Critical"},
        {"cls": "s-high", "n": counts["high"], "l": "High"},
    ]
    return {
        "box": "07", "box_name": "Supply Chain & Dependency Security", "server_name": server_name,
        "extraction": {"ok": True, "method": "SBOM + CVE + typosquat + install-scripts",
                       "tool_count": 0, "tools_preview": []},
        "stats_tiles": stat, "sbom_note": "; ".join(notes[:2]) if notes else "",
        "ecosystems": ecos, "packages": packages,
        "findings": findings, "verdict": v,
    }
