#!/usr/bin/env python3
"""
config_hygiene_scan.py -- Box-14: Shadow MCP Servers.

(OWASP MCP09 "Shadow MCP Servers." Internally this is the Configuration &
Manifest Hygiene assessment: a shadow / rogue server is usually betrayed by
its manifest -- it squats a trusted server's name, launches an unpinned or
remote payload, exposes far more than it should, ships default credentials,
or turns off transport security. So we assess the server's declared surface
from its config/manifest files.)

Reads config files only; nothing from the target repo is ever executed.

Five layers:

  H1  Over-broad tool / capability exposure -- a manifest that exposes all
      tools by wildcard, grants "all"/"*" permissions, or declares no
      allow-list scoping the surface.
  H2  Embedded or default credentials -- a real-looking secret/token/key, or
      a default credential (admin/admin, changeme, "password"), sitting in a
      config value or an env block.
  H3  Insecure transport & debug flags -- a non-TLS http:// endpoint, TLS
      verification disabled (verify_ssl:false, rejectUnauthorized:false,
      NODE_TLS_REJECT_UNAUTHORIZED=0), or debug/dev/insecure flags left on.
  H4  Shadow-server indicators -- the launch command runs a remote or
      unpinned payload (npx -y unpinned pkg, uvx, a curl|sh, a bare URL), or
      the server's declared name squats a well-known trusted server. These
      are the hallmarks of a rogue/shadow server masquerading as a real one.
  H5  Manifest integrity & entrypoint -- a manifest missing name/version,
      an entrypoint/command that references a file not present in the repo,
      whole-environment passthrough into the child, or a shell-wrapped
      command (sh -c ...) that can hide behaviour.

Usage:
    python3 config_hygiene_scan.py /path/to/repo [--json] [--all]

Exit codes: 0 = PASS, 1 = REVIEW, 2 = FAIL.
"""
import os, re, sys, json, argparse
from confighyg_lib import (find_manifests, read_text, load_json, line_of,
                           iter_mcp_server_blocks, WELL_KNOWN_SERVERS)

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"


def F(layer, severity, title, path, line_no, evidence, remediation):
    return {"layer": layer, "severity": severity, "title": title,
            "file": path, "line": line_no, "evidence": evidence,
            "remediation": remediation}


# ----------------------------------------------------------------------
# regex patterns over raw config text (work for json/yaml/toml alike)
# ----------------------------------------------------------------------
WILDCARD_EXPOSURE = re.compile(
    r"(?i)(\"tools\"\s*:\s*\"\*\"|\"tools\"\s*:\s*\[\s*\"\*\"|allowAllTools|"
    r"\"permissions?\"\s*:\s*\"(?:all|\*)\"|\"scopes?\"\s*:\s*\"(?:all|\*)\"|"
    r"exposeAll|\"capabilities?\"\s*:\s*\"(?:all|\*)\"|autoApprove\"\s*:\s*true)")

SECRET_VALUE = re.compile(
    r"(?i)(\"?(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\"?\s*[:=]\s*"
    r"\"?[A-Za-z0-9_\-\.=/+]{8,}\"?)")
DEFAULT_CRED = re.compile(
    r"(?i)([\"']?(?:password|passwd|user(?:name)?|pass)[\"']?\s*[:=]\s*"
    r"[\"']?(?:admin|root|password|changeme|123456|test|default|guest)[\"']?\b)")
PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|xxxx|<[a-z_]+>|\$\{?[A-Z_]+\}?|changeme|redacted|dummy|sample)")

INSECURE_TRANSPORT = re.compile(r"(?i)(\"url\"\s*:\s*\"http://|\"endpoint\"\s*:\s*\"http://|\"baseUrl\"\s*:\s*\"http://|http://(?!localhost|127\.0\.0\.1))")
TLS_DISABLED = re.compile(
    r"(?i)(verify[_-]?ssl\"?\s*[:=]\s*false|rejectUnauthorized\"?\s*[:=]\s*false|"
    r"NODE_TLS_REJECT_UNAUTHORIZED\"?\s*[:=]\s*\"?0|insecure\"?\s*[:=]\s*true|"
    r"ssl[_-]?verify\"?\s*[:=]\s*false|check[_-]?hostname\"?\s*[:=]\s*false)")
DEBUG_FLAG = re.compile(r"(?i)(\"debug\"\s*:\s*true|\"dev(?:elopment)?\"\s*:\s*true|\"verbose\"\s*:\s*true|NODE_ENV\"?\s*[:=]\s*\"?development)")

UNPINNED_NPX = re.compile(r"(?i)npx\s+(?:-y\s+|--yes\s+)?(?!.*@\d)([@\w\-/]+)(?!@)")
REMOTE_EXEC = re.compile(r"(?i)(curl\s[^|]*\|\s*(?:sh|bash)|wget\s[^|]*\|\s*(?:sh|bash)|uvx\s+|pipx\s+run\s+|bunx\s+)")
SHELL_WRAP = re.compile(r"(?i)(\"command\"\s*:\s*\"(?:/bin/)?(?:sh|bash)\"|\bsh\b\s+-c\b|\bbash\b\s+-c\b)")
URL_COMMAND = re.compile(r"(?i)\"command\"\s*:\s*\"https?://")


# ----------------------------------------------------------------------
# scan
# ----------------------------------------------------------------------
def scan_manifest(path, rel, kind):
    findings = []
    text = read_text(path)
    if not text.strip():
        return findings
    obj, _ = load_json(path) if kind in ("json", "package.json") else (None, text)

    def add(layer, sev, title, needle, remediation, ev=None):
        findings.append(F(layer, sev, title, rel, line_of(text, needle),
                          ev if ev is not None else needle.strip()[:160], remediation))

    # ---- H1 over-broad exposure ----
    for m in WILDCARD_EXPOSURE.finditer(text):
        add("H1", "high",
            "Manifest exposes tools / permissions by wildcard or auto-approves everything — the "
            "server's surface is not scoped to an explicit allow-list",
            m.group(0),
            "Declare an explicit allow-list of exposed tools and required scopes; never expose "
            "\"*\" / all tools or auto-approve invocations.")

    # ---- H2 embedded / default credentials ----
    for m in SECRET_VALUE.finditer(text):
        val = m.group(0)
        if PLACEHOLDER.search(val):
            continue
        add("H2", "high",
            "A real-looking secret / token / key is embedded directly in a config value",
            val,
            "Never store credentials in the manifest. Reference them from a secret manager or an "
            "environment variable injected at launch; keep only non-secret references in config.")
    for m in DEFAULT_CRED.finditer(text):
        add("H2", "medium",
            "A default / weak credential (admin / root / changeme / password) is present in config",
            m.group(0),
            "Remove default credentials; require a strong, uniquely-generated secret supplied out "
            "of band before the server can start.")

    # ---- H3 insecure transport & debug ----
    for m in INSECURE_TRANSPORT.finditer(text):
        add("H3", "medium",
            "A non-TLS http:// endpoint is configured — traffic (and any token on it) is exposed "
            "in cleartext",
            m.group(0),
            "Use https:// for every remote endpoint; restrict plain http to loopback only.")
    for m in TLS_DISABLED.finditer(text):
        add("H3", "high",
            "TLS certificate verification is explicitly disabled in config — this defeats transport "
            "authentication and enables trivial MITM",
            m.group(0),
            "Never disable certificate verification. Fix the underlying trust/cert issue instead of "
            "turning verification off.")
    for m in DEBUG_FLAG.finditer(text):
        add("H3", "low",
            "A debug / development / verbose flag is enabled in config",
            m.group(0),
            "Ship production config with debug/dev flags off; gate them behind an explicit, "
            "off-by-default override.")

    # ---- H4 shadow-server indicators (launch command) ----
    server_names = []
    for name, spec in iter_mcp_server_blocks(obj or {}):
        server_names.append(name)
        cmd = spec.get("command", "")
        args = spec.get("args", [])
        joined = (str(cmd) + " " + " ".join(str(a) for a in args)) if isinstance(args, list) else str(cmd)
        if re.match(r"(?i)https?://", str(cmd)):
            add("H4", "high",
                f"Server '{name}' launches directly from a URL — a remote, unversioned payload that "
                "can change under you (classic shadow-server delivery)",
                str(cmd) or name,
                "Launch from a vendored, version-pinned local artifact; never execute a remote URL "
                "as the server command.")
        if REMOTE_EXEC.search(joined):
            add("H4", "high",
                f"Server '{name}' launch pipes a remote script into a shell (curl|sh, uvx, bunx) — "
                "arbitrary remote code at every start",
                joined[:160],
                "Install and pin the server as a local dependency; do not fetch-and-execute at "
                "launch time.")
        um = UNPINNED_NPX.search(joined)
        if um and "@" not in um.group(1):
            add("H4", "medium",
                f"Server '{name}' launches an unpinned npx package ('{um.group(1)}') — the resolved "
                "code can silently change between runs",
                joined[:160],
                "Pin the exact package version (name@x.y.z) and prefer a lockfile-backed local "
                "install over npx -y at launch.")
        if SHELL_WRAP.search(joined) or SHELL_WRAP.search(str(cmd)):
            add("H5", "medium",
                f"Server '{name}' is launched through a shell wrapper (sh -c / bash -c) — the real "
                "behaviour is hidden inside a shell string",
                joined[:160],
                "Invoke the server binary directly with an argument array; avoid sh -c wrappers that "
                "obscure and can inject additional behaviour.")
        # whole-environment passthrough
        env = spec.get("env")
        if isinstance(env, dict):
            for k, val in env.items():
                sv = str(val)
                if sv.strip() in ("${env}", "*") or re.fullmatch(r"\$\{?[A-Z_]*\*[A-Z_]*\}?", sv):
                    add("H5", "low",
                        f"Server '{name}' passes a broad/whole-environment value into its child env",
                        f"{k}={sv}",
                        "Pass only the specific environment variables the server needs, never the "
                        "entire environment.")

    # name-squatting: a declared server name that stems from a well-known server
    for name in server_names:
        stem = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
        base = stem.split("-")
        for wk in WELL_KNOWN_SERVERS:
            if wk in base and stem != wk:
                add("H4", "medium",
                    f"Declared server name '{name}' incorporates a well-known server name ('{wk}') — "
                    "a shadow server can impersonate a trusted one by name to get auto-approved",
                    str(name),
                    "Use a distinct, namespaced server name; verify the identity/source of any "
                    "server whose name resembles a trusted one before trusting it.")
                break

    # ---- H5 manifest integrity ----
    if kind == "json" and obj is not None and any(k in (obj or {}) for k in ("mcpServers", "servers", "command")):
        # a real MCP manifest with no name/version at top level
        if isinstance(obj, dict) and "command" in obj and not obj.get("name"):
            add("H5", "low",
                "MCP manifest declares a launch command but no server name — harder to audit and to "
                "distinguish from a shadow entry",
                "\"command\"",
                "Give every server manifest an explicit name and version.")

    return findings


def verdict_for_findings(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if any(f["severity"] in ("critical", "high") for f in findings):
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- shadow-server / manifest-hygiene indicators found",
                "next_step": "Resolve every critical/high finding before onboarding: an embedded "
                             "secret, a wildcard-exposed surface, disabled TLS, or a remote/"
                             "unpinned launch payload are all hallmarks of an unsafe or shadow "
                             "server. Pin the launch artifact, scope the surface, and remove "
                             "credentials from config.",
                "counts": counts}
    if findings:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- manifest-hygiene weaknesses, none high-confidence",
                "next_step": "No high-confidence shadow-server indicator, but the manifest has "
                             "hygiene gaps (default creds, debug flags, unpinned launch, broad env, "
                             "name resemblance). A reviewer should confirm each is intentional.",
                "counts": counts}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no shadow-server / manifest-hygiene findings",
            "next_step": "No manifest exposed an over-broad surface, embedded credential, insecure "
                         "transport, or remote/unpinned launch, and no declared name squats a "
                         "well-known server. Static config review -- re-run on any manifest change.",
            "counts": counts}


NAMES = {"H1": "Over-broad exposure", "H2": "Embedded / default credentials",
         "H3": "Insecure transport & debug", "H4": "Shadow-server indicators",
         "H5": "Manifest integrity & entrypoint"}


def print_report(root, findings, v, manifests, show_all):
    print(f"\nBox-14 Shadow MCP Servers (config & manifest hygiene) -- {root}")
    print("=" * 72)
    print(f"Manifests inspected: {len(manifests)}"
          + ((" — " + ", ".join(m[1] for m in manifests[:6])) if manifests else " — none found"))
    if not findings:
        print("No findings.")
    by = {}
    for f in findings:
        by.setdefault(f["layer"], []).append(f)
    for layer in ("H1", "H2", "H3", "H4", "H5"):
        fs = by.get(layer, [])
        if not fs:
            continue
        fs.sort(key=lambda f: -SEV_ORDER[f["severity"]])
        print(f"\n--- {layer}: {NAMES[layer]} ({len(fs)}) ---")
        for f in (fs if show_all else fs[:6]):
            c = COLOR.get(f["severity"], "")
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"{c}[{f['severity'].upper():8}]{RESET} {f['title']}")
            print(f"           {loc}")
            if f["evidence"]:
                print(f"           {f['evidence']}")
    print("\n" + "=" * 72)
    color = {"PASS": "\033[92m", "REVIEW": "\033[93m", "FAIL": "\033[91m"}[v["status"]]
    print(f"VERDICT: {color}{v['headline']}{RESET}\n  {v['next_step']}  (exit {v['exit_code']})\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = os.path.abspath(args.repo)
    manifests = find_manifests(root)
    findings = []
    for path, rel, kind in manifests:
        # package.json / pyproject only interesting if they carry an mcp block;
        # still text-scan them for embedded secrets & insecure flags.
        findings += scan_manifest(path, rel, kind)
    # de-dup identical (layer,file,line,title)
    seen, uniq = set(), []
    for f in findings:
        k = (f["layer"], f["file"], f["line"], f["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    findings = sorted(uniq, key=lambda f: (-SEV_ORDER[f["severity"]], f["layer"], f["file"]))
    v = verdict_for_findings(findings)
    if args.json:
        print(json.dumps({"repo": root, "manifests": [m[1] for m in manifests],
                          "findings": findings, "verdict": v}, indent=2))
    else:
        print_report(root, findings, v, manifests, args.all)
    sys.exit(v["exit_code"])


if __name__ == "__main__":
    main()
