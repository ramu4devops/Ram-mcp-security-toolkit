#!/usr/bin/env python3
"""
supplychain_lib.py -- shared helpers for Box-7 (Supply Chain & Dependency
Security). Stdlib only (urllib, json, re, subprocess) -- no pip install
required to RUN the scanner. The scanner shells out to `npm audit` for the
npm ecosystem (that's the real npm advisory database -- reimplementing it
would just mean shipping a stale copy of the same data) and talks to the
public PyPI JSON API directly for the Python ecosystem.

Four jobs live here:
  1. ECOSYSTEM DETECTION -- what kind of repo is this (npm / pip / mixed)?
  2. CVE LOOKUP           -- known vulnerabilities in resolved versions.
  3. TYPOSQUAT HEURISTICS -- is a dependency name suspiciously close to a
                             popular package, but not actually it?
  4. SHARED PLUMBING      -- severity ordering, redaction-safe printing,
                             file walking, verdict tiers (same 3-tier
                             language as every other Box in this product).
"""
import os
import re
import io
import json
import math
import subprocess
import urllib.request
import urllib.error

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# npm audit's own vocabulary is critical/high/moderate/low/info -- "moderate"
# where every other Box in this product (and OSV/PyPI) says "medium". Every
# npm finding is normalized through this map the moment it's read so the
# rest of the pipeline (severity ordering, verdict tiers, colored output)
# only ever has to know ONE vocabulary.
NPM_SEVERITY_MAP = {"critical": "critical", "high": "high", "moderate": "medium",
                     "low": "low", "info": "info"}
COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
         "low": "\033[92m", "info": "\033[90m"}
RESET = "\033[0m"

SKIP_DIRS = {".git", "dist", "build", "__pycache__", ".venv", "venv",
             ".mypy_cache", "target", ".next", "coverage"}


def worst_severity(findings, key="severity"):
    return max((f[key] for f in findings), key=lambda s: SEV_ORDER.get(s, 0), default="info")


def sev_sort(findings, key="severity"):
    return sorted(findings, key=lambda f: -SEV_ORDER.get(f[key], 0))


# ----------------------------------------------------------------------
# Ecosystem detection
# ----------------------------------------------------------------------
def detect_ecosystems(repo_dir):
    """Returns a dict describing which manifests were found. An MCP server
    repo can legitimately be npm-only, pip-only, or (rarer) both, e.g. a
    Python server whose repo also ships a small JS build tool."""
    eco = {"npm": None, "pip": None}

    pkg_json = os.path.join(repo_dir, "package.json")
    pkg_lock = os.path.join(repo_dir, "package-lock.json")
    if os.path.isfile(pkg_json):
        eco["npm"] = {
            "manifest": pkg_json,
            "lockfile": pkg_lock if os.path.isfile(pkg_lock) else None,
        }

    req_txt = os.path.join(repo_dir, "requirements.txt")
    pyproject = os.path.join(repo_dir, "pyproject.toml")
    poetry_lock = os.path.join(repo_dir, "poetry.lock")
    uv_lock = os.path.join(repo_dir, "uv.lock")
    pipfile_lock = os.path.join(repo_dir, "Pipfile.lock")
    if os.path.isfile(req_txt) or os.path.isfile(pyproject):
        lockfile = None
        for cand in (poetry_lock, uv_lock, pipfile_lock):
            if os.path.isfile(cand):
                lockfile = cand
                break
        eco["pip"] = {
            "manifest": req_txt if os.path.isfile(req_txt) else pyproject,
            "lockfile": lockfile,
        }
    return eco


# ----------------------------------------------------------------------
# npm: package-lock.json parsing (resolved, pinned dependency graph)
# ----------------------------------------------------------------------
def parse_npm_lock(lockfile_path):
    """Returns list of {name, version, direct, dev, integrity, resolved}.
    Handles npm lockfileVersion 2/3 ("packages" map keyed by node_modules
    path) which is what every modern npm project produces."""
    with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as fh:
        data = json.load(fh)

    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if path == "":
                continue  # the root project entry itself
            name = info.get("name")
            if not name:
                # path looks like "node_modules/foo" or ".../node_modules/@scope/foo"
                parts = path.split("node_modules/")
                name = parts[-1] if parts else path
            # NOTE: `direct` is NOT derived from path depth here. npm hoists
            # (flattens) most transitive packages to top-level node_modules/
            # whenever there's no version conflict, so "node_modules/foo"
            # (depth 1) is the common shape for BOTH a direct dependency and
            # an unrelated transitive one -- path depth is not a reliable
            # signal. direct-vs-transitive is resolved afterwards in
            # mark_direct() by cross-referencing package.json's own
            # dependency sections, which is the ground truth.
            out.append({
                "name": name,
                "version": info.get("version", "?"),
                "direct": False,
                "dev": bool(info.get("dev")),
                "integrity": info.get("integrity"),
                "resolved": info.get("resolved"),
            })
    else:
        # very old lockfileVersion 1 shape: "dependencies" nested map
        def walk(deps, direct):
            for name, info in (deps or {}).items():
                out.append({
                    "name": name, "version": info.get("version", "?"),
                    "direct": direct, "dev": bool(info.get("dev")),
                    "integrity": info.get("integrity"), "resolved": info.get("resolved"),
                })
                if info.get("dependencies"):
                    walk(info["dependencies"], False)
        walk(data.get("dependencies", {}), True)
    return out


def mark_direct(resolved_list, direct_spec_names):
    """Cross-reference the flat resolved-package list against the names
    declared directly in package.json (dependencies/devDependencies/
    optionalDependencies). This is the reliable way to know direct vs.
    transitive in a hoisted npm lockfile -- see the note in parse_npm_lock."""
    names = set(direct_spec_names)
    for d in resolved_list:
        d["direct"] = d["name"] in names
    return resolved_list


def npm_direct_deps(package_json_path):
    with open(package_json_path, "r", encoding="utf-8", errors="ignore") as fh:
        pkg = json.load(fh)
    direct = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (pkg.get(section) or {}).items():
            direct[name] = {"range": spec, "section": section}
    return pkg, direct


# ----------------------------------------------------------------------
# npm: CVE lookup via `npm audit` (the real npm advisory database)
# ----------------------------------------------------------------------
def run_npm_audit(repo_dir, timeout=90):
    """Shells to `npm audit --json`. This talks to registry.npmjs.org's own
    advisory bulk endpoint -- the same data source `npm audit` always uses,
    no extra network target to trust or maintain. Returns (findings, error).
    npm audit exits non-zero when vulnerabilities are found -- that is
    normal, not a failure of the command."""
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json"], cwd=repo_dir,
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return [], "npm is not installed / not on PATH"
    except subprocess.TimeoutExpired:
        return [], f"npm audit timed out after {timeout}s"

    raw = proc.stdout.strip()
    if not raw:
        return [], f"npm audit produced no output (stderr: {proc.stderr[:300]})"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], f"npm audit output was not valid JSON: {raw[:300]}"

    findings = []
    vulns = data.get("vulnerabilities", {})
    for pkg_name, v in vulns.items():
        sev = NPM_SEVERITY_MAP.get(v.get("severity", "info"), "info")
        via_list = v.get("via", [])
        advisories = [a for a in via_list if isinstance(a, dict)]
        if not advisories:
            # via can be a list of bare package-name strings (transitive
            # re-export with no advisory of its own attached at this node)
            findings.append({
                "ecosystem": "npm", "package": pkg_name, "version": None,
                "severity": sev, "direct": bool(v.get("isDirect")),
                "title": f"depends on vulnerable {', '.join(str(x) for x in via_list)}",
                "url": None, "cwe": [], "range": v.get("range"),
                "fix_available": bool(v.get("fixAvailable")),
            })
            continue
        for adv in advisories:
            findings.append({
                "ecosystem": "npm", "package": pkg_name,
                "version": None,
                "severity": NPM_SEVERITY_MAP.get(adv.get("severity", sev), sev),
                "direct": bool(v.get("isDirect")),
                "title": adv.get("title", "(untitled advisory)"),
                "url": adv.get("url"),
                "cwe": adv.get("cwe", []),
                "cvss_score": (adv.get("cvss") or {}).get("score"),
                "range": adv.get("range") or v.get("range"),
                "fix_available": bool(v.get("fixAvailable")),
            })
    return findings, None


# ----------------------------------------------------------------------
# pip: requirements.txt parsing + PyPI JSON API vulnerability lookup
# ----------------------------------------------------------------------
PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+]+)\s*(?:#.*)?$")
RANGE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*([<>~!=].*?)\s*(?:#.*)?$")
BARE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:#.*)?$")


def parse_requirements_txt(path):
    """Returns list of {name, version, pinned}. `version` is None when the
    requirement isn't pinned to an exact version (a floating range or a
    bare name) -- that itself is a supply-chain finding, not just noise."""
    out = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = PIN_RE.match(line)
            if m:
                name = re.sub(r"\[.*\]", "", m.group(1))
                out.append({"name": name, "version": m.group(2), "pinned": True})
                continue
            m = RANGE_RE.match(line)
            if m:
                name = re.sub(r"\[.*\]", "", m.group(1))
                out.append({"name": name, "version": None, "pinned": False, "range": m.group(2)})
                continue
            m = BARE_RE.match(line)
            if m:
                name = re.sub(r"\[.*\]", "", m.group(1))
                out.append({"name": name, "version": None, "pinned": False, "range": None})
    return out


VULN_KEYWORDS_CRITICAL = ("remote code execution", "arbitrary code execution",
                           "rce", "deserialization", "command injection",
                           "sql injection", "authentication bypass")
VULN_KEYWORDS_HIGH = ("credential", "privilege escalation", "path traversal",
                       "prototype pollution", "ssrf", "arbitrary file write",
                       "arbitrary file read")
VULN_KEYWORDS_MEDIUM = ("denial of service", "regular expression denial",
                         "redos", "information disclosure", "cross-site")


def classify_pypi_vuln_severity(description, fix_versions):
    """PyPI's JSON API deliberately does not carry a CVSS severity field.
    We derive one conservatively from the advisory text -- when in doubt
    this rounds UP (a human reviewer downgrading a false-alarm is cheap;
    a missed critical is not). Unfixed vulnerabilities are never lowered
    below MEDIUM regardless of keyword match."""
    text = (description or "").lower()
    sev = "medium"
    if any(k in text for k in VULN_KEYWORDS_CRITICAL):
        sev = "critical"
    elif any(k in text for k in VULN_KEYWORDS_HIGH):
        sev = "high"
    elif any(k in text for k in VULN_KEYWORDS_MEDIUM):
        sev = "medium"
    else:
        sev = "medium"
    if not fix_versions and SEV_ORDER[sev] < SEV_ORDER["medium"]:
        sev = "medium"
    return sev


def _http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-supplychain-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def pypi_lookup_vulns(name, version):
    """One package/version -> PyPI JSON API -> that release's 'vulnerabilities'
    array (PyPI ingests this from OSV / GHSA and republishes it -- this is
    exactly what pip-audit's default backend uses). Returns (findings, error)."""
    if not version:
        return [], "no pinned version to check (see 'unpinned dependency' findings)"
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        data = _http_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [], f"version {version} not found on PyPI (package renamed, removed, or private?)"
        return [], f"PyPI lookup failed: HTTP {e.code}"
    except Exception as e:
        return [], f"PyPI lookup failed: {e}"

    out = []
    for v in data.get("vulnerabilities", []) or []:
        if v.get("withdrawn"):
            continue
        # NOTE: PyPI's JSON API key is "fixed_in", not "fix_versions" --
        # verified against a live response (a first draft of this reader
        # used the wrong key name and every finding silently reported
        # "no fix available" even when one existed).
        fix_versions = v.get("fixed_in") or []
        sev = classify_pypi_vuln_severity(v.get("details") or v.get("summary"), fix_versions)
        details = v.get("details") or ""
        out.append({
            "ecosystem": "pip", "package": name, "version": version,
            "severity": sev, "direct": None,
            "title": (v.get("summary") or details[:120] or v.get("id")),
            "description": details,  # full, untruncated -- used for the local plain-English match
            "url": f"https://osv.dev/vulnerability/{v.get('id')}" if v.get("id") else None,
            "cwe": [], "range": None,
            "fix_available": bool(fix_versions),
            "fix_versions": fix_versions,
            "id": v.get("id"), "aliases": v.get("aliases", []),
        })
    return out, None


# ----------------------------------------------------------------------
# Plain-English impact one-liners -- so a reviewer never has to leave the
# terminal just to learn what a CVE/CWE number actually MEANS. Fully local,
# no network call required (works even where OSV enrichment, below, can't
# reach the network) -- npm audit already hands us CWE codes for free.
# ----------------------------------------------------------------------
CWE_PLAIN_ENGLISH = {
    "CWE-22": "Path traversal -- a crafted filename could let an attacker read or write files outside the intended directory.",
    "CWE-77": "Command injection -- attacker-controlled input could get interpreted as a shell command.",
    "CWE-78": "OS command injection -- attacker-controlled input could execute arbitrary commands on the host.",
    "CWE-79": "Cross-site scripting -- attacker-controlled content could execute as script in a browser context.",
    "CWE-88": "Argument injection -- attacker-controlled input could inject unexpected command-line arguments.",
    "CWE-89": "SQL injection -- attacker-controlled input could alter a database query's meaning.",
    "CWE-90": "LDAP injection -- attacker-controlled input could alter a directory-service query.",
    "CWE-94": "Code injection -- attacker-controlled input could get evaluated/executed as code.",
    "CWE-116": "Improper output encoding -- attacker-controlled data could be misinterpreted downstream (injection risk).",
    "CWE-117": "Log injection -- attacker-controlled input could forge or corrupt log entries.",
    "CWE-120": "Buffer overflow -- attacker-controlled input could overflow a fixed-size buffer, risking a crash or code execution.",
    "CWE-125": "Out-of-bounds read -- could crash the process or leak adjacent memory contents.",
    "CWE-190": "Integer overflow -- a wrapped-around number could bypass a size/permission check.",
    "CWE-193": "Off-by-one error -- can corrupt adjacent memory or produce an out-of-bounds access.",
    "CWE-200": "Information disclosure -- could expose data the caller shouldn't be able to see.",
    "CWE-201": "Information exposure through a sent data channel -- sensitive data could leak in a response.",
    "CWE-203": "Observable discrepancy -- response timing/content differences could let an attacker infer secrets.",
    "CWE-208": "Timing side-channel -- response timing differences could leak secret information (e.g. a valid vs invalid credential).",
    "CWE-215": "Debug/diagnostic information exposure -- verbose output could leak internals to an attacker.",
    "CWE-269": "Improper privilege management -- code could end up running with more privilege than intended.",
    "CWE-284": "Improper access control -- an operation could be reachable without the authorization check it needs.",
    "CWE-285": "Improper authorization -- an action could be performed by someone who shouldn't be allowed to.",
    "CWE-287": "Authentication bypass -- an attacker could get treated as authenticated without valid credentials.",
    "CWE-290": "Authentication bypass by spoofing -- a forged identity value could be accepted as genuine.",
    "CWE-295": "Improper certificate validation -- TLS/cert checks could be skipped, enabling a man-in-the-middle attack.",
    "CWE-297": "Improper hostname validation -- a certificate for the wrong host could be accepted.",
    "CWE-300": "Channel accessible by unauthorized actors -- data in transit could be exposed or tampered with.",
    "CWE-319": "Cleartext transmission -- sensitive data could be sent unencrypted and be readable in transit.",
    "CWE-326": "Weak/inadequate encryption -- data protected this way could be feasibly decrypted by an attacker.",
    "CWE-327": "Use of a broken/risky cryptographic algorithm -- protection can be defeated with known techniques.",
    "CWE-330": "Use of insufficiently random values -- generated tokens/keys could be predictable.",
    "CWE-346": "Origin validation error -- requests from an unintended origin could be accepted (CORS misconfiguration risk).",
    "CWE-347": "Improper signature verification -- a forged or tampered token/message could be accepted as valid.",
    "CWE-352": "Cross-site request forgery -- a malicious site could trigger actions using the victim's own session.",
    "CWE-367": "Time-of-check/time-of-use race condition -- a security check could be bypassed by a timing race.",
    "CWE-400": "Uncontrolled resource consumption -- a single request could exhaust memory/CPU/connections (denial of service).",
    "CWE-404": "Improper resource shutdown -- resources may leak, degrading availability over time.",
    "CWE-406": "Insufficient control of network message volume -- could enable an amplification denial-of-service.",
    "CWE-436": "Interpretation conflict -- this code and some other component parse the same URL/input differently, so a value that looks safe to one could resolve to something else downstream (SSRF or access-control bypass risk).",
    "CWE-140": "Improper neutralization of delimiters -- a crafted delimiter character could be misread by downstream code, enabling a parsing/authority-confusion attack.",
    "CWE-551": "Incorrect authorization ordering -- a security check could run against a different value than the one actually used afterward.",
    "CWE-444": "HTTP request smuggling -- ambiguous request framing could let one request be interpreted as two.",
    "CWE-502": "Insecure deserialization -- parsing attacker-controlled serialized data could execute arbitrary code.",
    "CWE-521": "Weak password requirements -- credentials protected by this code could be brute-forced.",
    "CWE-611": "XML external entity (XXE) injection -- a crafted XML document could read local files or reach internal network hosts.",
    "CWE-639": "Insecure direct object reference -- an ID could be swapped to access another user's data.",
    "CWE-668": "Exposure of a resource to the wrong sphere -- data or a file could be reachable by the wrong party.",
    "CWE-732": "Incorrect permission assignment -- a file/resource could end up more accessible than intended.",
    "CWE-770": "Allocation without limits -- a flood of requests/input could exhaust resources (denial of service).",
    "CWE-776": "XML entity expansion ('billion laughs') -- a small crafted XML payload could exhaust memory.",
    "CWE-787": "Out-of-bounds write -- attacker-controlled input could corrupt memory, risking a crash or code execution.",
    "CWE-798": "Hardcoded credentials -- a secret embedded in the package itself could be extracted and reused.",
    "CWE-834": "Excessive iteration -- attacker-controlled input could trigger unbounded looping (denial of service).",
    "CWE-835": "Infinite loop -- specific input could hang the process indefinitely.",
    "CWE-841": "Improper enforcement of behavioral workflow -- steps of a multi-step process could be skipped or reordered.",
    "CWE-918": "Server-side request forgery (SSRF) -- attacker-controlled input could make the server issue requests to internal/unintended hosts.",
    "CWE-922": "Insecure storage of sensitive information -- secrets could be recoverable from where this code stores them.",
    "CWE-1004": "Cookie missing HttpOnly -- a session cookie could be read by injected script.",
    "CWE-1021": "Improper restriction of rendered UI layers -- could enable clickjacking.",
    "CWE-1284": "Improper validation of a specified quantity in input -- a malformed size/count value could bypass a limit check.",
    "CWE-1321": "Prototype pollution -- attacker-controlled input could modify JavaScript's Object prototype, affecting unrelated code.",
    "CWE-1333": "Regular expression denial of service (ReDoS) -- a crafted input string could make a regex match take exponential time, hanging the process.",
}

# Keyword fallback for advisories with no (or an unmapped) CWE -- covers
# the pip ecosystem, where PyPI's JSON API supplies no CWE at all.
_KEYWORD_IMPACT = [
    (("remote code execution", "arbitrary code execution", "arbitrary code", " rce ", "code injection"),
     "Could allow an attacker to execute arbitrary code."),
    (("command injection", "shell injection", "os command"),
     "Attacker-controlled input could get executed as a system command."),
    (("sql injection",), "Attacker-controlled input could alter a database query's meaning."),
    (("path traversal", "directory traversal"),
     "A crafted path could let an attacker read/write files outside the intended directory."),
    (("deserializ",), "Parsing attacker-controlled serialized data could lead to code execution."),
    (("prototype pollution",), "Attacker-controlled input could modify JavaScript's Object prototype, affecting unrelated code."),
    (("denial of service", "regular expression denial", "redos", "resource exhaustion", "algorithmic complexity"),
     "A crafted request/input could hang or crash the process (denial of service)."),
    (("server-side request forgery", "ssrf"),
     "Attacker-controlled input could make the server issue requests to internal/unintended hosts."),
    (("cross-site scripting", "xss"), "Attacker-controlled content could execute as script in a browser context."),
    (("cross-site request forgery", "csrf"), "A malicious site could trigger actions using the victim's own session."),
    (("authentication bypass", "auth bypass"), "An attacker could be treated as authenticated without valid credentials."),
    (("privilege escalation",), "Could allow gaining more access/privilege than intended."),
    (("information disclosure", "leak", "expose", "exposure"),
     "Could expose data (credentials, internal state, or file contents) that should not be visible to the caller."),
    (("man-in-the-middle", "certificate valid", "tls valid"),
     "Certificate/TLS validation could be bypassed, enabling interception of supposedly-encrypted traffic."),
    (("cross-user", "cache poison"), "Could leak or mix up data between different users' requests."),
    (("host confusion", "authority delimiter", "authority introducer", "idn canonicalization"),
     "URL parsing differs from what other components expect, so a malicious URL could resolve to a different host than it appears to (SSRF / access-control bypass risk)."),
    (("prototype",), "Could let attacker-controlled input modify shared object behavior in unexpected ways."),
]


def describe_vuln(title, cwe_list=None, extra_text=None):
    """Local, network-free, one-line plain-English impact summary -- so a
    reviewer never has to leave the terminal to find out what a CWE/CVE
    number actually means for THIS finding. Tries CWE first (precise,
    free from npm audit); falls back to keyword matching over the
    title/description (covers pip, and any npm advisory with no CWE)."""
    for cwe in (cwe_list or []):
        if cwe in CWE_PLAIN_ENGLISH:
            return CWE_PLAIN_ENGLISH[cwe]
    text = f"{title or ''} {extra_text or ''}".lower()
    for keywords, impact in _KEYWORD_IMPACT:
        if any(k in text for k in keywords):
            return impact
    return "Read the advisory for exact impact -- this class of issue wasn't recognized by the local heuristics."


# ----------------------------------------------------------------------
# CVE enrichment via OSV.dev -- OPTIONAL, best-effort, network-dependent.
#
# npm audit's own JSON gives a GHSA advisory ID (in the `url` field) and a
# CWE, but NOT a CVE number -- GHSA-to-CVE resolution needs an external
# lookup. OSV.dev's public API mirrors that mapping for free, no API key.
#
# IMPORTANT: api.osv.dev is NOT reachable from every network-restricted
# environment (verified directly against the environment this toolkit was
# authored in -- an explicit egress allowlist covering registry.npmjs.org,
# pypi.org, files.pythonhosted.org, etc., did not include api.osv.dev or
# api.github.com). This enrichment step is therefore written to fail SOFT:
# any network error, timeout, or unexpected response for a given advisory
# just means that one finding keeps its GHSA id instead of a CVE number --
# it never blocks or breaks the scan. Where OSV.dev IS reachable (most
# normal developer/CI machines), this fills in real CVE numbers.
# ----------------------------------------------------------------------
GHSA_ID_RE = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}")


def extract_ghsa_id(text):
    if not text:
        return None
    m = GHSA_ID_RE.search(text)
    return m.group(0) if m else None


def osv_lookup_by_id(vuln_id, timeout=8):
    """GET https://api.osv.dev/v1/vulns/<id> -- returns the raw OSV vuln
    record (aliases/summary/details) or None on ANY failure. Never raises."""
    try:
        return _http_json(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=timeout)
    except Exception:
        return None


def local_enrich_only(findings):
    """The --no-enrich path: same per-finding fields as enrich_findings()
    (plain_english, cve, osv_id), but with NO network call at all -- the
    GHSA id is still extracted from the advisory URL npm audit already
    gave us (that's just string parsing), only the GHSA-to-CVE resolution
    step (which needs OSV.dev) is skipped."""
    for f in findings:
        f["plain_english"] = describe_vuln(f.get("title"), f.get("cwe"), f.get("description"))
        if f["ecosystem"] == "pip":
            f["cve"] = [a for a in (f.get("aliases") or []) if a.startswith("CVE-")]
            f["osv_id"] = f.get("id")
        else:
            f["cve"] = []
            f["osv_id"] = extract_ghsa_id(f.get("url") or "") or extract_ghsa_id(f.get("title") or "")
    return findings


def enrich_findings(findings, max_workers=8):
    """Adds, to every finding in place:
      - plain_english : local, always present (see describe_vuln above)
      - cve            : list of CVE ids if known; [] if not (or not looked up)
      - osv_id         : the GHSA/OSV id looked up, if any
    Then makes a best-effort OSV.dev batch lookup for npm findings (pip
    findings already carry CVE aliases straight from the PyPI JSON API --
    no extra network call needed there). Returns (findings, note) where
    `note` is a string describing what happened with OSV enrichment, or
    None if there was nothing npm-specific to enrich.
    """
    ghsa_ids = set()
    for f in findings:
        f["plain_english"] = describe_vuln(f.get("title"), f.get("cwe"), f.get("description"))
        if f["ecosystem"] == "pip":
            f["cve"] = [a for a in (f.get("aliases") or []) if a.startswith("CVE-")]
            f["osv_id"] = f.get("id")
        else:
            f["cve"] = []
            f["osv_id"] = extract_ghsa_id(f.get("url") or "") or extract_ghsa_id(f.get("title") or "")
            if f["osv_id"]:
                ghsa_ids.add(f["osv_id"])

    if not ghsa_ids:
        return findings, None

    resolved, failures = {}, 0

    def lookup(gid):
        return gid, osv_lookup_by_id(gid)

    with __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor(max_workers=max_workers) as ex:
        for gid, data in ex.map(lookup, ghsa_ids):
            if data is None:
                failures += 1
                continue
            resolved[gid] = [a for a in (data.get("aliases") or []) if a.startswith("CVE-")]

    for f in findings:
        if f["ecosystem"] != "pip" and f.get("osv_id") in resolved:
            f["cve"] = resolved[f["osv_id"]]

    if not resolved and failures:
        note = (f"OSV.dev enrichment unavailable ({failures} advisory lookup(s) failed -- likely network-"
                f"restricted here) -- npm findings above show their GHSA advisory ID instead of a CVE number. "
                f"The GHSA URL printed with each finding has the full advisory.")
    elif failures:
        note = f"OSV.dev enrichment: {len(resolved)} advisory(ies) resolved, {failures} could not be reached."
    else:
        note = f"OSV.dev enrichment: {len(resolved)} advisory(ies) resolved to CVE numbers where one exists."
    return findings, note


# ----------------------------------------------------------------------
# Typosquat / dependency-confusion heuristics
# ----------------------------------------------------------------------
# Deliberately small, high-confidence lists: the packages an attacker gets
# the most leverage from squatting on, because almost every project pulls
# them in transitively. This is a HEURISTIC layer, not a lookup against a
# live "known typosquat" feed -- it exists to catch near-misses a human
# would skim past, not to replace registry provenance checks.
TOP_NPM_PACKAGES = {
    "express", "react", "react-dom", "lodash", "axios", "chalk", "commander",
    "request", "async", "moment", "underscore", "debug", "colors", "uuid",
    "glob", "minimist", "yargs", "webpack", "babel-core", "eslint", "jest",
    "typescript", "next", "vue", "mocha", "semver", "dotenv", "cors",
    "body-parser", "socket.io", "node-fetch", "form-data", "jsonwebtoken",
    "bcrypt", "mongoose", "prisma", "@modelcontextprotocol/sdk", "zod",
    "playwright", "playwright-core", "puppeteer",
}
TOP_PYPI_PACKAGES = {
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "pyyaml", "setuptools", "pip", "wheel", "click", "certifi", "idna",
    "charset-normalizer", "cryptography", "pydantic", "fastapi", "uvicorn",
    "sqlalchemy", "pytest", "aiohttp", "jinja2", "attrs", "packaging",
    "python-dateutil", "six", "colorama", "pillow", "openai", "anthropic",
    "mcp", "fastmcp",
}


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


CONFUSABLE_SUBS = [("l", "1"), ("i", "1"), ("o", "0"), ("-", "_"), ("-", ""), ("_", "")]


def typosquat_candidates(name, popular_set, max_distance=2):
    """Returns list of (popular_name, distance) this `name` is suspiciously
    close to, excluding an exact match (that's not a typosquat, it's just
    the real thing) and excluding scoped variants of itself.

    Two guards were added after real-repo testing turned up false positives
    on ordinary short package names ("cors" ~ "colors", "jose" ~ "jest",
    "test" ~ "jest" -- generic 3-5 letter words are within edit-distance 2
    of EACH OTHER constantly, independent of any typosquat relationship):

      1. distance allowance scales DOWN for short names (<=5 chars gets
         only distance 1, not 2) -- a 2-character edit on a 4-letter word
         is close to a coin flip, not a typo signal.
      2. the first character must match. Real-world typosquats overwhelmingly
         preserve the first character (it's what a scanning eye anchors on:
         "expres"/"express", "loadash"/"lodash") -- a mismatched first
         character is far more often two unrelated short words than an
         actual typosquat attempt.
    """
    bare = name.split("/")[-1].lower()
    hits = []
    for pop in popular_set:
        pop_bare = pop.split("/")[-1].lower()
        if bare == pop_bare:
            continue
        if not bare or not pop_bare or bare[0] != pop_bare[0]:
            continue
        allowed = 1 if min(len(bare), len(pop_bare)) <= 5 else max_distance
        d = levenshtein(bare, pop_bare)
        if d <= allowed and abs(len(bare) - len(pop_bare)) <= allowed:
            hits.append((pop, d))
    hits.sort(key=lambda t: t[1])
    return hits


def registry_metadata_npm(name):
    """Existence + a couple of cheap red-flag signals from the public npm
    registry: very few versions and no repository field are both consistent
    with a freshly-squatted package (also consistent with a brand-new
    legitimate one -- this is a signal to review, not a verdict on its own)."""
    try:
        data = _http_json(f"https://registry.npmjs.org/{name}")
    except Exception as e:
        return {"exists": False, "error": str(e)}
    versions = list((data.get("versions") or {}).keys())
    return {
        "exists": True,
        "version_count": len(versions),
        "has_repository": bool(data.get("repository")),
        "maintainers": len(data.get("maintainers") or []),
        "created": (data.get("time") or {}).get("created"),
    }


def registry_metadata_pypi(name):
    try:
        data = _http_json(f"https://pypi.org/pypi/{name}/json")
    except Exception as e:
        return {"exists": False, "error": str(e)}
    info = data.get("info", {}) or {}
    releases = data.get("releases", {}) or {}
    return {
        "exists": True,
        "version_count": len(releases),
        "has_repository": bool(info.get("project_urls")),
        "author": info.get("author") or info.get("maintainer"),
    }


# ----------------------------------------------------------------------
# Verdict (same 3-tier language as every other Box)
# ----------------------------------------------------------------------
def verdict_for_findings(all_findings):
    elevated = [f for f in all_findings if f.get("severity") in ("critical", "high") and f.get("gate", True)]
    review = [f for f in all_findings if f.get("severity") in ("medium", "low") or not f.get("gate", True)]
    if elevated:
        return {"status": "FAIL", "exit_code": 2,
                "headline": "FAIL -- supply-chain findings block this submission",
                "next_step": "Resolve or formally risk-accept every CRITICAL/HIGH finding below "
                             "before this MCP server is approved.",
                "counts": {"total": len(all_findings), "elevated": len(elevated), "review": len(review)}}
    if review:
        return {"status": "REVIEW", "exit_code": 1,
                "headline": "REVIEW -- manual review required before approval",
                "next_step": "No blocking findings, but items below need a human decision "
                             "(accept, pin, patch, or replace).",
                "counts": {"total": len(all_findings), "elevated": 0, "review": len(review)}}
    return {"status": "PASS", "exit_code": 0,
            "headline": "PASS -- no supply-chain findings",
            "next_step": "Re-run this scan on every dependency update -- a clean scan today "
                         "says nothing about the lockfile after the next `npm install`.",
            "counts": {"total": len(all_findings), "elevated": 0, "review": 0}}
