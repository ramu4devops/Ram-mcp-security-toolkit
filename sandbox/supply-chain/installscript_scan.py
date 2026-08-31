#!/usr/bin/env python3
"""
installscript_scan.py -- Box-7, layer 4: malicious install-time script
detection.

WHY THIS IS THE HIGH-VALUE LAYER: every other layer in Box-7 looks at code
that runs when the MCP server RUNS. This layer looks at code that runs when
the MCP server is INSTALLED -- `npm install` / `pip install` -- which is
BEFORE any sandbox, seccomp profile, or runtime policy from the other boxes
ever takes effect. If the reviewer's own workstation (or a CI runner with
its own secrets) is what runs the install step, an npm "postinstall" or a
Python setup.py that phones home or reads ~/.ssh executes with the
REVIEWER'S privileges, not the MCP server's. This is not a hypothetical --
npm postinstall trojans and malicious PyPI setup.py payloads are the most
common real-world supply-chain attack pattern seen against both ecosystems.

Two things get scanned:
  1. package.json "scripts" entries named preinstall/install/postinstall/
     prepare/prepublish -- for EVERY package in the resolved dependency
     tree (node_modules), not just the root project. A malicious payload
     is far more likely to hide three levels deep in a transitive
     dependency than in the root project's own, visible package.json.
  2. setup.py content, and pyproject.toml [build-system] custom backends,
     for the pip ecosystem (Python has no separate "install script" concept
     -- setup.py IS arbitrary code that runs at install/build time).

This is PATTERN matching over source text, same discipline as Box-1's L1/L2
layers: no code is executed, nothing here can itself be poisoned by running
the very thing it's inspecting.

Usage:
    python3 installscript_scan.py /path/to/repo [--json]
    (run AFTER `npm install` / `pip install -r requirements.txt -t vendor/`
     so node_modules / the resolved packages actually exist on disk to scan)
"""
import os
import re
import sys
import json
import argparse
from supplychain_lib import COLOR, RESET, SEV_ORDER, sev_sort

INSTALL_HOOK_NAMES = {"preinstall", "install", "postinstall", "prepare", "prepublish", "postpublish"}

# Each: (id, label, compiled regex, severity, why)
SUSPICIOUS_PATTERNS = [
    ("pipe_to_shell", "Downloads and pipes content directly into a shell",
     re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b"), "critical",
     "Classic dropper pattern -- fetches a remote payload and executes it "
     "immediately, with no way for a reviewer to see what it does without "
     "re-running it against the live URL at review time."),
    ("remote_script_download", "Downloads a script/binary from a raw URL during install",
     re.compile(r"\b(curl|wget)\s+.*(https?://)"), "high",
     "Install steps have no legitimate reason to fetch arbitrary code from "
     "the internet -- npm/pip already fetched every declared dependency."),
    ("base64_exec", "Decodes a base64 blob and executes/evaluates it",
     re.compile(r"(atob|Buffer\.from\([^)]*['\"]base64|base64\.b64decode)\s*\([^)]*\)[^\n]{0,60}(eval|exec|child_process|subprocess|os\.system)"), "critical",
     "Obfuscating the actual payload as base64 defeats a human skimming the "
     "script -- this is deliberate evasion, not a coincidence."),
    ("eval_dynamic", "eval() / exec() / Function() over dynamic content",
     re.compile(r"\b(eval|new Function)\s*\(|(?<![#\w])exec\s*\(\s*[^)\"']"), "high",
     "Dynamically evaluating constructed strings during install is the same "
     "primitive Box-1 flags in tool descriptions -- code the reviewer cannot "
     "read in advance because it doesn't exist as text until runtime."),
    ("reverse_shell", "Reverse-shell / raw socket connect-back pattern",
     re.compile(r"(nc\s+-e|/dev/tcp/|socket\.socket\([^)]*\).*connect|bash\s+-i\s+>&)"), "critical",
     "No legitimate package installer opens an outbound interactive shell."),
    ("read_ssh_aws_keys", "Reads SSH / AWS / cloud credential files",
     re.compile(r"(\.ssh/id_rsa|\.ssh/id_ed25519|\.aws/credentials|\.aws/config|\.kube/config|\.npmrc|\.netrc)\b"), "critical",
     "An install script has no legitimate reason to open the developer's "
     "own SSH keys, cloud credentials, or registry auth tokens -- this "
     "is ambient-credential harvesting (the same class of risk Box-6 "
     "covers for the SERVER's own runtime, happening one step earlier)."),
    ("env_exfil", "Reads process environment and sends it to a network endpoint",
     re.compile(r"process\.env\b[^\n]{0,120}(fetch|axios|http\.request|XMLHttpRequest)|os\.environ\b[^\n]{0,120}(requests\.(post|get)|urllib)"), "critical",
     "Harvesting the whole environment and shipping it out during install "
     "is exactly how a compromised dependency steals CI/CD secrets."),
    # The single-line version above catches `process.env` and the network
    # call on the SAME statement. Real payloads routinely split this across
    # a couple of lines (assign env to a variable, THEN send it) -- an
    # env_exfil_proximity finding (found separately, see find_env_exfil()
    # below) catches that shape without requiring one giant multi-line regex.
    ("crontab_persistence", "Writes to crontab / shell profile / systemd for persistence",
     re.compile(r"(crontab\s+-|>>\s*.*\.bashrc|>>\s*.*\.bash_profile|>>\s*.*\.zshrc|/etc/systemd/system/)"), "critical",
     "Persistence mechanisms have no place in a package install step."),
    ("chmod_exec_downloaded", "Downloads a file then marks it executable",
     re.compile(r"chmod\s+\+x\s+\S+[\s\S]{0,80}(curl|wget)|((curl|wget)[\s\S]{0,80}chmod\s+\+x)"), "high",
     "Download-then-chmod-then-run is the standard shape of a dropped binary payload."),
]

# Names that show up in install scripts for entirely legitimate reasons and
# should not, by themselves, escalate severity even though they matched a
# pattern above (native addon builds are the single biggest source of noise
# here: node-gyp/prebuild-install genuinely does fetch prebuilt binaries).
KNOWN_NATIVE_BUILD_TOOLS = {"node-gyp", "prebuild-install", "node-pre-gyp",
                            "electron", "sqlite3", "puppeteer", "playwright", "playwright-core"}


ENV_READ_RE = re.compile(r"\b(process\.env\b|os\.environ\b)")
NETWORK_CALL_RE = re.compile(r"\b(fetch|axios|http\.request|https\.request|XMLHttpRequest|"
                              r"requests\.(post|get|put)|urllib\.request|urlopen)\s*\(")


def find_env_exfil_proximity(text, window_chars=250):
    """Catches the multi-statement shape a single-line regex can't:
    environment read on one line, network call a few lines later,
    connected by a variable in between (e.g. Box-6's exact concern, one
    layer earlier -- at install time instead of at tool-call time)."""
    findings = []
    lines = text.splitlines()
    for m in ENV_READ_RE.finditer(text):
        window = text[m.end(): m.end() + window_chars]
        net = NETWORK_CALL_RE.search(window)
        if net:
            line_no = text.count("\n", 0, m.start()) + 1
            net_line_no = text.count("\n", 0, m.end() + net.start()) + 1
            if net_line_no == line_no:
                continue  # already caught by the single-line SUSPICIOUS_PATTERNS rule
            snippet = (lines[line_no - 1].strip()[:100] if line_no <= len(lines) else "") + \
                      "  ...  " + (lines[net_line_no - 1].strip()[:100] if net_line_no <= len(lines) else "")
            findings.append({
                "rule": "env_exfil_proximity",
                "label": "Environment variables read, then a network call follows shortly after",
                "severity": "high",
                "why": "The environment read and the network call aren't on the same line, so this is "
                       "a weaker signal than a direct env_exfil match -- but the two are close enough "
                       "together to warrant a human reading the surrounding code before trusting it.",
                "line": line_no, "snippet": snippet,
            })
    return findings


BASE64_LITERAL_RE = re.compile(r"""["']([A-Za-z0-9+/]{16,}={0,2})["']""")
DECODED_PAYLOAD_KEYWORDS = ("curl ", "wget ", "| bash", "| sh", "subprocess", "os.system",
                            "child_process", "exec(", "eval(", "rm -rf", "nc -e", "/dev/tcp/",
                            "base64 -d", ".ssh/", ".aws/", "crontab")


def decode_and_rescan_base64_literals(text, source_label):
    """A quoted base64 string literal decodes to something readable only
    when it's ACTUALLY base64-encoded data -- most 16+ char quoted strings
    (hashes, IDs, minified identifiers) fail this decode or produce binary
    garbage and are silently skipped. When a literal DOES decode cleanly to
    text, that text is scanned the same way any other source would be --
    this is the static-analysis equivalent of Box-1's hidden-Unicode layer:
    look past one layer of deliberate obfuscation without executing it."""
    import base64
    findings = []
    for m in BASE64_LITERAL_RE.finditer(text):
        candidate = m.group(1)
        try:
            decoded = base64.b64decode(candidate, validate=True)
            decoded_text = decoded.decode("utf-8")
        except Exception:
            continue
        printable = sum(1 for c in decoded_text if c.isprintable() or c in "\n\t")
        if len(decoded_text) < 6 or printable / max(len(decoded_text), 1) < 0.85:
            continue  # decoded to noise, not text -- not a payload
        line_no = text.count("\n", 0, m.start()) + 1
        low = decoded_text.lower()
        if any(k in low for k in DECODED_PAYLOAD_KEYWORDS):
            findings.append({
                "rule": "obfuscated_payload", "severity": "critical",
                "label": "Base64 string literal decodes to shell/exec code",
                "why": "A source file that hides a shell command or exec call inside a base64-encoded "
                       "string literal is deliberately evading a human reading the file -- there is no "
                       "legitimate reason to obfuscate an install-time command this way.",
                "source": source_label, "line": line_no,
                "snippet": f"decodes to: {decoded_text.strip()[:160]}",
            })
        # nested pattern matches inside the decoded text (e.g. it itself
        # pipes a further download into a shell) -- one level of recursion,
        # not run through THIS function again (avoids runaway expansion on
        # adversarially-crafted input).
        for pid, label, rx, sev, why in SUSPICIOUS_PATTERNS:
            for pm in rx.finditer(decoded_text):
                findings.append({
                    "rule": pid, "label": label, "severity": sev, "why": why,
                    "source": f"{source_label} (base64-decoded literal)",
                    "line": line_no, "snippet": decoded_text.strip()[:160],
                })
    return findings


def scan_text_for_patterns(text, source_label):
    findings = []
    findings += decode_and_rescan_base64_literals(text, source_label)
    for pid, label, rx, sev, why in SUSPICIOUS_PATTERNS:
        for m in rx.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = text.splitlines()[line_no - 1].strip()[:160] if line_no <= len(text.splitlines()) else m.group(0)[:160]
            findings.append({
                "rule": pid, "label": label, "severity": sev, "why": why,
                "source": source_label, "line": line_no, "snippet": snippet,
            })
    for f in find_env_exfil_proximity(text):
        f["source"] = source_label
        findings.append(f)
    return findings


def scan_npm_install_hooks(repo_dir):
    """Walks every package.json under node_modules (plus the root project's
    own) looking for pre/post/install lifecycle scripts, then scans the
    hook command text itself AND, when the hook points at a local .js file,
    that file's content too."""
    findings = []
    checked_packages = 0
    node_modules = os.path.join(repo_dir, "node_modules")
    manifest_paths = [os.path.join(repo_dir, "package.json")]
    if os.path.isdir(node_modules):
        for dirpath, dirnames, filenames in os.walk(node_modules):
            if "package.json" in filenames:
                manifest_paths.append(os.path.join(dirpath, "package.json"))

    for mpath in manifest_paths:
        try:
            with open(mpath, "r", encoding="utf-8", errors="ignore") as fh:
                pkg = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        checked_packages += 1
        scripts = pkg.get("scripts") or {}
        hooks = {k: v for k, v in scripts.items() if k in INSTALL_HOOK_NAMES}
        if not hooks:
            continue
        pkg_name = pkg.get("name", os.path.dirname(mpath))
        pkg_dir = os.path.dirname(mpath)
        rel = os.path.relpath(mpath, repo_dir)

        for hook_name, cmd in hooks.items():
            hook_findings = scan_text_for_patterns(cmd, f"{rel} scripts.{hook_name}")
            if pkg_name in KNOWN_NATIVE_BUILD_TOOLS or any(t in cmd for t in KNOWN_NATIVE_BUILD_TOOLS):
                for f in hook_findings:
                    if f["rule"] in ("remote_script_download", "chmod_exec_downloaded"):
                        f["severity"] = "low"
                        f["why"] += " (downgraded: matches a known native-addon build tool pattern -- verify manually, don't rubber-stamp)"
            findings += hook_findings

            # If the hook just runs a local script (e.g. "node scripts/postinstall.js"),
            # follow it and scan the actual file content too.
            m = re.search(r"(?:node|python3?)\s+([^\s&|;]+\.(?:js|mjs|cjs|py))", cmd)
            if m:
                script_path = os.path.join(pkg_dir, m.group(1))
                if os.path.isfile(script_path):
                    try:
                        with open(script_path, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                        findings += scan_text_for_patterns(content, f"{rel} -> {m.group(1)}")
                    except OSError:
                        pass
    return findings, checked_packages


def scan_pip_install_scripts(repo_dir):
    """setup.py is executed at build/install time -- there is no separate
    'hook' concept in the classic Python packaging model, the whole file
    IS the install script. Also checks pyproject.toml for a custom (i.e.
    non-standard, non-setuptools/poetry/hatchling) build backend, since a
    custom build-backend's build_sdist/build_wheel hooks run at build time
    the same way."""
    findings = []
    setup_py = os.path.join(repo_dir, "setup.py")
    if os.path.isfile(setup_py):
        with open(setup_py, "r", encoding="utf-8", errors="ignore") as fh:
            findings += scan_text_for_patterns(fh.read(), "setup.py")

    pyproject = os.path.join(repo_dir, "pyproject.toml")
    if os.path.isfile(pyproject):
        with open(pyproject, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        m = re.search(r'build-backend\s*=\s*"([^"]+)"', text)
        if m and m.group(1) not in (
            "setuptools.build_meta", "poetry.core.masonry.api",
            "hatchling.build", "flit_core.buildapi", "pdm.backend",
        ):
            findings.append({
                "rule": "custom_build_backend", "label": f"Custom PEP 517 build backend: {m.group(1)}",
                "severity": "medium", "why": "A non-standard build backend can run arbitrary code during "
                                              "`pip install` the same way setup.py can -- locate and review "
                                              "its source before trusting it.",
                "source": "pyproject.toml", "line": text[:m.start()].count("\n") + 1,
                "snippet": m.group(0),
            })
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo_dir")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    repo_dir = os.path.abspath(args.repo_dir)

    npm_findings, checked = scan_npm_install_hooks(repo_dir)
    pip_findings = scan_pip_install_scripts(repo_dir)
    all_findings = sev_sort(npm_findings + pip_findings)

    if args.json:
        print(json.dumps({"findings": all_findings, "packages_checked": checked}, indent=2))
    else:
        print(f"Install-time script scan: {repo_dir}")
        print(f"(checked {checked} package.json manifest(s) under node_modules + root)")
        print("-" * 72)
        if not all_findings:
            print("No suspicious install-hook patterns found.")
        for f in all_findings:
            c = COLOR.get(f["severity"], "")
            print(f"{c}[{f['severity'].upper():8}]{RESET} {f['label']}")
            print(f"           {f['source']}:{f['line']}   {f['snippet']}")
            print(f"           why: {f['why']}")
        print(f"\n{len(all_findings)} finding(s)")

    crit_high = sum(1 for f in all_findings if f["severity"] in ("critical", "high"))
    sys.exit(2 if crit_high else (1 if all_findings else 0))


if __name__ == "__main__":
    main()
