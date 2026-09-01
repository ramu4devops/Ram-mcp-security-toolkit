#!/usr/bin/env python3
"""
secrets_lib.py -- shared helpers for Box-6 (Secrets Management & Token
Handling). Stdlib only.

The three jobs that belong here rather than in the scanner:
  1. REDACTION   -- a security report that prints live secrets is itself a
                    new leak. Everything shown to a human is redacted.
  2. PLACEHOLDER -- "api_key = 'your-key-here'" is documentation, not a
                    finding. This is the #1 false-positive source in every
                    secret scanner; we filter it explicitly.
  3. ENTROPY     -- distinguishes a real random credential from a short
                    English word assigned to a variable called `token`.
"""
import re, math, unicodedata

# ----------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------
def redact(secret, keep=4):
    """Show enough to locate the value in the file, never enough to use it."""
    if secret is None:
        return ""
    s = str(secret)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * min(len(s) - keep, 20) + (f"({len(s)} chars)" if len(s) > 24 else "")


def redact_line(line, secret):
    """Redact the secret inside its surrounding source line."""
    if not secret:
        return line.strip()[:160]
    return line.replace(secret, redact(secret)).strip()[:160]


# ----------------------------------------------------------------------
# Placeholder / example-value filtering
# ----------------------------------------------------------------------
PLACEHOLDER_TOKENS = {
    "changeme", "change_me", "your", "yours", "yourkey", "your_key",
    "yourtoken", "your_token", "yoursecret", "your_secret", "example",
    "placeholder", "dummy", "sample", "test", "testing", "fake", "foo",
    "bar", "baz", "none", "null", "nil", "todo", "tbd", "xxx", "xxxx",
    "abc123", "secret", "password", "mypassword", "hunter2", "redacted",
    "insert", "replace", "notreal", "dummykey", "sk-xxx", "n/a", "na",
}
PLACEHOLDER_PATTERNS = [
    r"^<.*>$",                 # <YOUR_API_KEY>
    r"^\{\{.*\}\}$",           # {{ api_key }}   (template)
    # NOTE: these are matched against the LOWERCASED value, so they must be
    # written in lowercase. An earlier build wrote this one as [A-Z_][A-Z0-9_]*
    # and it therefore never fired -- "${API_KEY}" was reported as a real
    # secret when it is only a reference to one.
    r"^\$\{?[a-z_][a-z0-9_]*\}?$",   # ${API_KEY} or $API_KEY -- indirection, not a secret
    r"^x{3,}$", r"^\*{3,}$", r"^\.{3,}$",
    r"^[a-z]+(-|_)?(key|token|secret|password)$",   # my-api-key
    r"^(key|token|secret|password)(-|_)?[a-z]*$",
    r"^\d{1,6}$",              # short numerics
    r"^[01]$", r"^(true|false)$",
]


def is_placeholder(value):
    """True if this looks like documentation/config scaffolding, not a live secret."""
    if not value:
        return True
    v = value.strip().strip("\"'").strip()
    if not v:
        return True
    low = v.lower()
    if low in PLACEHOLDER_TOKENS:
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if re.match(pat, low):
            return True
    # contains an obvious placeholder word anywhere
    for tok in ("your_", "your-", "yourkey", "changeme", "placeholder",
                "example.com", "xxxxxx", "<insert", "replace_me", "replaceme",
                "dummy", "notarealkey", "fake_"):
        if tok in low:
            return True
    # repeated single character, e.g. "aaaaaaaaaaaa"
    if len(set(low)) <= 2:
        return True
    return False


# ----------------------------------------------------------------------
# Entropy
# ----------------------------------------------------------------------
def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_random(value, min_len=16, min_entropy=3.2):
    """Heuristic: is this plausibly a machine-generated credential?
    Deliberately conservative -- we would rather a generic-assignment match
    be dropped than flood a reviewer with English-word false positives."""
    if not value:
        return False
    v = value.strip().strip("\"'")
    if len(v) < min_len:
        return False
    if is_placeholder(v):
        return False
    # A path, URL, or sentence is not a credential.
    if v.startswith(("/", "./", "../", "http://", "https://")) or " " in v:
        return False
    return shannon_entropy(v) >= min_entropy


# ----------------------------------------------------------------------
# Provider-specific credential formats (STRONG signals -- self-identifying)
# ----------------------------------------------------------------------
# Each: (id, human name, compiled regex, severity)
PROVIDER_PATTERNS = [
    ("aws_access_key_id", "AWS Access Key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("github_pat", "GitHub Personal Access Token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("slack_token", "Slack Token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "critical"),
    ("google_api_key", "Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical"),
    ("openai_key", "OpenAI-style API Key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("anthropic_key", "Anthropic-style API Key",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("stripe_key", "Stripe Secret Key",
     re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "critical"),
    ("private_key_block", "Private Key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("jwt", "JWT (may embed claims/secrets)",
     re.compile(r"\bey[A-Za-z0-9_\-]{10,}\.ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "high"),
    ("slack_webhook", "Slack Incoming Webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+_-]{20,}"), "high"),
    ("basic_auth_url", "Credentials embedded in URL",
     re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@"), "high"),
]

# Generic "assignment to a secret-ish name" -- WEAK on its own, promoted only
# when the assigned value also passes looks_random().
GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\-]*
        (?:api[_\-]?key|apikey|secret|passwd|password|passphrase|pass|pwd|
           auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|token|
           bearer|client[_\-]?secret|private[_\-]?key|credential)
     [A-Za-z0-9_.\-]*)
    \s*[:=]\s*
    (?P<q>["'])(?P<val>[^"'\n]{8,200})(?P=q)
    """
)


def scan_line_for_secrets(line):
    """Return list of dicts: {kind, name, severity, value, confidence}."""
    out = []
    for pid, label, rx, sev in PROVIDER_PATTERNS:
        for m in rx.finditer(line):
            val = m.group(0)
            # AWS publishes AKIAIOSFODNN7EXAMPLE as a documentation example.
            if "EXAMPLE" in val.upper():
                continue
            out.append({"kind": pid, "name": label, "severity": sev,
                        "value": val, "confidence": "high"})
    for m in GENERIC_ASSIGNMENT.finditer(line):
        val = m.group("val")
        if looks_random(val):
            out.append({"kind": "generic_assignment",
                        "name": f"High-entropy value assigned to '{m.group('name')}'",
                        "severity": "high", "value": val, "confidence": "medium"})
    return out


# ----------------------------------------------------------------------
# Shared file walking
# ----------------------------------------------------------------------
SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".venv",
             "venv", ".mypy_cache", "vendor", "target", ".next", "coverage"}
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
               ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
               ".so", ".dylib", ".dll", ".class", ".jar", ".wasm"}
MAX_FILE_BYTES = 2_000_000


def walk_repo(root, exts=None):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in BINARY_EXTS:
                continue
            if exts and ext not in exts:
                continue
            p = os.path.join(dirpath, f)
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []
