#!/usr/bin/env python3
"""
overview.py -- static, read-only "what is this MCP server" analyzer.

Powers the **Analyse** tab (MCP Server Overview, Tool Inventory, Resources,
Prompts, External Integrations, Authentication & Authorization) and the
**Capability & Attack Surface** tab.

Design constraints (deliberately mirrors inspect_repo.py, NOT the sandbox
detectors):

  * standard-library only (ast for Python, regex for JS/TS/everything else)
  * executes NOTHING from the target repo and opens only text source files --
    same risk profile as unzipping, so it runs in-process and works even when
    Docker is not available.
  * best-effort heuristics: it favours breadth (surface every capability the
    reviewer should look at) over precision. Everything it reports is
    evidence-anchored (file:line) so a human can confirm.

Public entry point:  analyze(repo_root) -> dict   (see build_overview docstring)
"""
import os, re, ast, json, pathlib

import inspect_repo

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__",
             ".venv", "venv", "vendor", "target", ".mypy_cache", ".next",
             "coverage", ".pytest_cache", "site-packages",
             "tests", "test", "__tests__", "__mocks__", "e2e", "examples",
             "example", "docs", "doc", "fixtures", "__fixtures__", "samples"}
# individual files that are tests/fixtures rather than server source
SKIP_FILE_RE = re.compile(r"\.(test|spec)\.[jt]sx?$|\.d\.ts$|_test\.py$|conftest\.py$", re.I)

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


# ==========================================================================
# integration signatures -- what an MCP server can talk to.
# Each entry: category, display service, import/usage markers, default auth,
# and the operations it is *capable* of (refined per-call where possible).
# ==========================================================================
INTEGRATIONS = [
    {"cat": "vcs", "service": "GitHub API",
     "markers": [r"\bfrom\s+github\b", r"\bimport\s+github\b", r"@octokit", r"PyGithub",
                 r"api\.github\.com", r"\bGithub\(", r"\bOctokit\("],
     "auth": "Personal Access Token", "ops": ["Read", "Write"]},
    {"cat": "vcs", "service": "GitLab API",
     "markers": [r"\bgitlab\b", r"python-gitlab", r"@gitbeaker"],
     "auth": "Personal Access Token", "ops": ["Read", "Write"]},
    {"cat": "database", "service": "PostgreSQL",
     "markers": [r"\bpsycopg2?\b", r"\basyncpg\b", r"\bpg8000\b", r"postgres(ql)?://",
                 r"require\(['\"]pg['\"]\)", r"\bfrom\s+['\"]pg['\"]"],
     "auth": "Connection String", "ops": ["Read", "Write", "Delete"]},
    {"cat": "database", "service": "MySQL / MariaDB",
     "markers": [r"\bpymysql\b", r"\bmysql\b", r"\bmysql2\b", r"mysql://", r"MySQLdb"],
     "auth": "Connection String", "ops": ["Read", "Write", "Delete"]},
    {"cat": "database", "service": "SQLite",
     "markers": [r"\bsqlite3\b", r"better-sqlite3", r"\.db['\"]", r"sqlite://"],
     "auth": "Local file", "ops": ["Read", "Write", "Delete"]},
    {"cat": "database", "service": "MongoDB",
     "markers": [r"\bpymongo\b", r"\bmongodb\b", r"\bmongoose\b", r"MongoClient", r"mongodb(\+srv)?://"],
     "auth": "Connection String", "ops": ["Read", "Write", "Delete"]},
    {"cat": "database", "service": "Redis",
     "markers": [r"\bredis\b", r"\bioredis\b", r"redis://"],
     "auth": "Connection String", "ops": ["Read", "Write"]},
    {"cat": "database", "service": "SQL Database (ORM)",
     "markers": [r"\bsqlalchemy\b", r"\bprisma\b", r"\btypeorm\b", r"\bsequelize\b", r"\bknex\b"],
     "auth": "Connection String", "ops": ["Read", "Write", "Delete"]},
    {"cat": "cloud", "service": "AWS",
     "markers": [r"\bboto3\b", r"\bbotocore\b", r"aws-sdk", r"@aws-sdk", r"\bBoto\b"],
     "auth": "IAM Credentials", "ops": ["Read", "Write"]},
    {"cat": "cloud", "service": "AWS S3",
     "markers": [r"\bs3\b", r"S3Client", r"boto3\.client\(['\"]s3", r"\.upload_file\(", r"putObject"],
     "auth": "IAM Credentials", "ops": ["Read", "Write"]},
    {"cat": "cloud", "service": "Google Cloud",
     "markers": [r"google\.cloud", r"googleapis", r"@google-cloud"],
     "auth": "Service Account", "ops": ["Read", "Write"]},
    {"cat": "cloud", "service": "Azure",
     "markers": [r"\bazure\b", r"@azure/"],
     "auth": "Credentials", "ops": ["Read", "Write"]},
    {"cat": "saas", "service": "Slack",
     "markers": [r"slack_sdk", r"@slack/", r"slack\.com/api", r"\bWebClient\("],
     "auth": "Bot Token", "ops": ["Read", "Write"]},
    {"cat": "saas", "service": "Stripe",
     "markers": [r"\bstripe\b"], "auth": "API Key", "ops": ["Read", "Write"]},
    {"cat": "ai", "service": "OpenAI",
     "markers": [r"\bopenai\b", r"api\.openai\.com"], "auth": "API Key", "ops": ["Read", "Write"]},
    {"cat": "ai", "service": "Anthropic",
     "markers": [r"\banthropic\b", r"api\.anthropic\.com"], "auth": "API Key", "ops": ["Read", "Write"]},
    {"cat": "comms", "service": "Email / SMTP",
     "markers": [r"\bsmtplib\b", r"nodemailer", r"sendgrid", r"\bmailgun\b"],
     "auth": "Credentials", "ops": ["Write"]},
    {"cat": "container", "service": "Docker",
     "markers": [r"\bdocker\b", r"dockerode", r"/var/run/docker\.sock"],
     "auth": "Socket", "ops": ["Read", "Write", "Delete"]},
    {"cat": "browser", "service": "Headless Browser",
     "markers": [r"\bplaywright\b", r"\bpuppeteer\b", r"\bselenium\b", r"\bwebdriver\b"],
     "auth": "None", "ops": ["Read", "Write"]},
]

# Broad HTTP / filesystem / process signals are handled separately (they are
# capabilities more than named services, but we still surface them).
HTTP_MARKERS = [r"\brequests\.\w+\(", r"\bhttpx\b", r"\burllib\b", r"\baiohttp\b",
                r"\baxios\b", r"node-fetch", r"\bfetch\(", r"\bgot\(", r"http[s]?://"]
FS_READ_MARKERS = [r"\bopen\s*\(", r"\.read_text\(", r"\.read_bytes\(", r"readFileSync",
                   r"readFile\(", r"fs\.read", r"pathlib\.", r"os\.path\."]
FS_WRITE_MARKERS = [r"\.write_text\(", r"\.write_bytes\(", r"writeFileSync", r"writeFile\(",
                    r"fs\.write", r"open\s*\([^)]*['\"][wa]"]
PROC_MARKERS = [r"\bsubprocess\b", r"os\.system\(", r"os\.popen\(", r"child_process",
                r"\bexec\(", r"execSync", r"\bspawn\(", r"\bPopen\("]
EVAL_MARKERS = [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(", r"new\s+Function\(",
                r"vm\.runIn", r"pickle\.loads", r"yaml\.load\s*\("]
# DB execution: an actual query call, OR a SQL keyword that opens a *quoted*
# statement (so English prose like "Delete a user account" is not matched).
SQL_EXEC_MARKERS = [r"\.execute(many)?\s*\(", r"\.query\s*\(", r"cursor\s*\(", r"\.raw\s*\(",
                    r"['\"`]\s*(SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|DROP\s+TABLE)\b"]

# credential / auth signals
SECRET_MARKERS = [r"os\.getenv\(", r"os\.environ", r"process\.env", r"api[_-]?key",
                  r"\btoken\b", r"\bsecret\b", r"\bcredential", r"Authorization",
                  r"Bearer\s", r"password"]
AUTHZ_MARKERS = [r"\bauthorize", r"\bauthenticate", r"\bpermission", r"\brequire_auth",
                 r"\bcheck_scope", r"\bverify_token", r"\bcurrent_user", r"\brole\b",
                 r"\bis_admin", r"\bhas_access", r"@requires", r"\bacl\b", r"\brbac\b",
                 r"\bscope\b", r"\bjwt\b"]
VALIDATION_MARKERS = [r"\bpydantic\b", r"\bzod\b", r"BaseModel", r"\bvalidate\(",
                      r"\bLiteral\[", r"\bEnum\b", r"allowlist", r"whitelist",
                      r"\bassert\b", r"raise\s+ValueError"]


def _matches(patterns, text):
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _read(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d.lower() not in SKIP_DIRS and not d.startswith(".")]
        for f in fns:
            if SKIP_FILE_RE.search(f):
                continue
            yield pathlib.Path(dp) / f


def _rel(root, path):
    try:
        return str(pathlib.Path(path).relative_to(root))
    except ValueError:
        return str(path)


# ==========================================================================
# operation / input / capability inference (shared by py + js)
# ==========================================================================
OP_BY_VERB = [
    (("delete", "remove", "drop", "destroy", "revoke", "purge", "rm_"), "DELETE"),
    (("execute", "exec", "run", "eval", "invoke", "command", "shell", "query", "sql"), "EXECUTE"),
    (("create", "add", "insert", "write", "upload", "post", "put", "send", "push", "set"), "WRITE"),
    (("update", "edit", "modify", "patch", "rename", "move"), "WRITE"),
    (("get", "read", "list", "fetch", "search", "find", "load", "view", "show",
      "snapshot", "screenshot", "describe", "inspect"), "READ"),
    (("navigate", "click", "type", "hover", "scroll", "press", "select"), "CONTROL"),
]


def infer_operation(name, body):
    low = name.lower()
    for verbs, op in OP_BY_VERB:
        if any(low.startswith(v) or ("_" + v) in low or low == v for v in verbs):
            return op
    # body-based fallback
    if _matches(EVAL_MARKERS + PROC_MARKERS, body):
        return "EXECUTE"
    if _matches(FS_WRITE_MARKERS, body) or re.search(r"INSERT|UPDATE|DELETE", body, re.I):
        return "WRITE"
    if _matches(SQL_EXEC_MARKERS + HTTP_MARKERS + FS_READ_MARKERS, body):
        return "READ"
    return "INVOKE"


def infer_capabilities(body, params):
    """Return (capability_flags, target_service_hint) for a tool body."""
    caps = []
    joined = body or ""
    if _matches(EVAL_MARKERS, joined):
        caps.append("Code Execution")
    if _matches(PROC_MARKERS, joined):
        caps.append("Command Execution")
    if _matches(SQL_EXEC_MARKERS, joined):
        caps.append("Database Access")
        if re.search(r"f['\"].*(SELECT|INSERT|UPDATE|DELETE)|%s|\+\s*\w+|\{.*\}", joined, re.I) \
                and re.search(r"execute|query", joined, re.I):
            caps.append("Arbitrary Query Execution")
    if _matches(FS_WRITE_MARKERS, joined):
        caps.append("File System Write")
    elif _matches(FS_READ_MARKERS, joined):
        caps.append("File System Access")
    if _matches(HTTP_MARKERS, joined):
        caps.append("Network Access")
    if re.search(r"['\"`]\s*(INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM)|\.write|upload|putObject|"
                 r"\.post\(|\.put\(|requests\.(post|put|delete)", joined, re.I):
        if "Write Capability" not in caps:
            caps.append("Write Capability")
    if _matches(SECRET_MARKERS, joined):
        caps.append("Credential Access")
    # unbounded / free-text input
    for p in params:
        if p.get("type") in (None, "string", "str", "any") and \
                re.search(r"query|sql|cmd|command|code|script|url|path|input|text|body|data", p["name"], re.I):
            caps.append("Untrusted Input")
            break
    # de-dup, keep order
    seen, out = set(), []
    for c in caps:
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def infer_target(body):
    """Which external system this tool primarily reaches."""
    for ig in INTEGRATIONS:
        if _matches(ig["markers"], body):
            return ig["service"]
    if _matches(PROC_MARKERS + EVAL_MARKERS, body):
        return "Host / OS process"
    if _matches(SQL_EXEC_MARKERS, body):
        return "Configured database"
    if _matches(HTTP_MARKERS, body):
        return "External HTTP endpoint"
    if _matches(FS_READ_MARKERS + FS_WRITE_MARKERS, body):
        return "Local filesystem"
    return "—"


def infer_input(params, op, caps):
    if not params:
        return "No caller-supplied parameters"
    names = [p["name"] for p in params]
    if "Arbitrary Query Execution" in caps or "Database Access" in caps:
        for n in names:
            if re.search(r"query|sql|statement", n, re.I):
                return "AI-controlled SQL query"
    if "Command Execution" in caps or "Code Execution" in caps:
        return "AI-controlled command / code string"
    if "Network Access" in caps:
        for n in names:
            if re.search(r"url|endpoint|uri|host", n, re.I):
                return "Caller-supplied URL"
    if "File System Access" in caps or "File System Write" in caps:
        for n in names:
            if re.search(r"path|file|dir|name", n, re.I):
                return "Caller-supplied file path"
    return "AI-controlled: " + ", ".join(names[:4]) + ("…" if len(names) > 4 else "")


def infer_auth(body):
    if _matches(SECRET_MARKERS, body):
        return "Required"
    return "None detected"


# Risk annotations that describe a *property* of a tool's input, NOT an
# external capability it holds. These must never be surfaced as the tool's
# primary "Capability", and are shown separately from capabilities in the UI.
RISK_FLAGS = {"Untrusted Input"}

# Sentinel shown when no real external capability could be detected. We
# deliberately return this instead of falling back to the *operation*
# (e.g. "Invoke") or to a risk flag (e.g. "Untrusted Input") — an honest
# "nothing detected" is better than a misleading or hallucinated value.
NO_CAPABILITY = "None detected"


def primary_capability_label(op, caps, target):
    """The single headline capability for the Tool Inventory 'Capability'
    column. Returns a *real external capability* (what power the tool holds),
    or NO_CAPABILITY when none is detected. It never returns the operation
    (that is a separate axis) and never returns a risk flag like
    'Untrusted Input' (that is a property of the input, not a capability)."""
    capset = set(caps)
    if "Code Execution" in capset or "Command Execution" in capset:
        return "Command / code execution"
    if "Arbitrary Query Execution" in capset:
        return "Arbitrary DB query"
    if "Database Access" in capset:
        return "Database " + ("write" if op in ("WRITE", "DELETE", "EXECUTE") else "read")
    if "Network Access" in capset:
        return "Network fetch / call"
    if "File System Write" in capset:
        return "Filesystem write"
    if "File System Access" in capset:
        return "Filesystem read"
    if "Browser / UI Control" in capset or op == "CONTROL":
        return "Browser / UI control"
    if "Credential Access" in capset:
        return "Credential access"
    if "Write Capability" in capset:
        return "Write / mutate"
    # No real external capability detected. Do NOT fall back to op.title()
    # or to caps[0] (which would surface "Untrusted Input") — be honest.
    return NO_CAPABILITY


# ==========================================================================
# Python extraction (AST)
# ==========================================================================
def _dec_kind(dec):
    """Return 'tool' | 'resource' | 'prompt' | None for an MCP decorator."""
    node = dec.func if isinstance(dec, ast.Call) else dec
    attr = None
    if isinstance(node, ast.Attribute):
        attr = node.attr
    elif isinstance(node, ast.Name):
        attr = node.id
    if attr in ("tool", "resource", "prompt"):
        return attr
    return None


def _dec_meta(dec):
    """Pull name=/description= kwargs and the first positional (uri/name)."""
    meta = {}
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg in ("name", "description", "uri", "title", "mime_type") and \
                    isinstance(kw.value, ast.Constant):
                meta[kw.arg] = kw.value.value
        if dec.args and isinstance(dec.args[0], ast.Constant):
            meta["_pos0"] = dec.args[0].value
    return meta


def _params_from_fn(node):
    out = []
    args = node.args
    for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        if a.arg in ("self", "cls", "ctx", "context"):
            continue
        t = None
        if a.annotation is not None:
            try:
                t = ast.unparse(a.annotation)
            except Exception:
                t = None
        out.append({"name": a.arg, "type": t or "string"})
    return out


def extract_python(root, path, src, items):
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return
    lines = src.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kind = None
        meta = {}
        for dec in node.decorator_list:
            k = _dec_kind(dec)
            if k:
                kind = k
                meta = _dec_meta(dec)
                break
        if not kind:
            continue
        doc = ast.get_docstring(node) or ""
        try:
            body = "\n".join(lines[node.lineno - 1: (node.end_lineno or node.lineno)])
        except Exception:
            body = ""
        params = _params_from_fn(node)
        rec = {
            "name": meta.get("name") or node.name,
            "description": (meta.get("description") or doc or "").strip(),
            "source_file": _rel(root, path),
            "source_line": node.lineno,
            "params": params,
            "body": body,
            "kind": kind,
            "uri": meta.get("uri") or meta.get("_pos0"),
            "mime": meta.get("mime_type"),
        }
        items.append(rec)


# ==========================================================================
# JS / TS extraction (regex, best-effort but covers the real-world patterns)
#
# Real MCP servers register tools several ways; we handle the common ones:
#   S1  literal-name call    server.registerTool("read_file", {description:..})
#                            server.tool("x","desc",..) / addTool / defineTool
#   S2  schema-nested        defineTool({ schema:{ name:"x", description:"y" }})   (playwright-style)
#   S3  config-object module const name="echo"; const config={description:".."};
#                            server.registerTool(name, config, handler)           (per-file tool modules)
#   S4  tool object literal  { name:"x", description:"y", inputSchema/parameters } (tool arrays / registries)
# Each candidate is only accepted when the file shows real MCP-tool context, to
# avoid matching a Server()'s own name or unrelated {name:} objects.
# ==========================================================================
JS_TOOL_CTX = re.compile(
    r"registerTool|defineTool|addTool|createTool|makeTool|\.tool\s*\(|new\s+Tool\(|"
    r"McpServer|CallToolResult|ListToolsRequestSchema|@modelcontextprotocol", re.I)
NAME_RE = r"[A-Za-z][A-Za-z0-9_\-]{1,63}"
_STR = r"""['"`]([^'"`]*)['"`]"""

# S1: a registration call whose first argument is a string literal tool name
JS_CALL_NAME = re.compile(
    r"(?:registerTool|addTool|createTool|makeTool|defineTool|\.tool)\s*\(\s*['\"`](" + NAME_RE + r")['\"`]", re.I)
# S2: schema-nested object with name + description
JS_SCHEMA_NAME = re.compile(r"schema\s*:\s*\{", re.I)
# S3/S4 name bindings and description
JS_NAME_BIND = re.compile(r"\bname\s*[:=]\s*['\"`](" + NAME_RE + r")['\"`]")
JS_RESOURCE_PATTERN = re.compile(r"(?:registerResource|\.resource)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
JS_PROMPT_PATTERN = re.compile(r"(?:registerPrompt|\.prompt)\s*\(\s*['\"`](" + NAME_RE + r")['\"`]", re.I)


def _line_of(src, idx):
    return src[:idx].count("\n") + 1


def _js_desc(block):
    """Capture a description: value, joining concatenated string literals."""
    m = re.search(r"description\s*:\s*", block, re.I)
    if not m:
        return ""
    rest = block[m.end(): m.end() + 1200]
    parts = []
    # walk leading run of  "str"  (optionally  + "str" + ...)
    pos = 0
    while True:
        sm = re.match(r"\s*\+?\s*['\"`]([^'\"`]*)['\"`]", rest[pos:])
        if not sm:
            break
        parts.append(sm.group(1))
        pos += sm.end()
        if not re.match(r"\s*\+", rest[pos:]):
            break
    return " ".join(p.strip() for p in parts).strip()


def _js_params_from(block):
    """Pull zod-object keys (name: z.something) from a schema block, best-effort."""
    out, seen = [], set()
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*z\.", block):
        n = m.group(1)
        if n in seen or n in ("z", "type"):
            continue
        seen.add(n)
        out.append({"name": n, "type": "string"})
    return out[:12]


def _add_js_tool(root, path, src, name, block, line, items, seen):
    if not name or name in seen:
        return
    seen.add(name)
    items.append({
        "name": name,
        "description": _js_desc(block),
        "source_file": _rel(root, path),
        "source_line": line,
        "params": _js_params_from(block),
        "body": block,
        "kind": "tool",
        "uri": None, "mime": None,
    })


def extract_js(root, path, src, items):
    has_ctx = bool(JS_TOOL_CTX.search(src))
    seen = set()

    # S1 — literal-name registration calls
    for m in JS_CALL_NAME.finditer(src):
        name = m.group(1)
        if name in ("default",):
            continue
        block = src[m.start(): m.start() + 900]
        _add_js_tool(root, path, src, name, block, _line_of(src, m.start()), items, seen)

    # S2 — schema:{ name, description } (defineTool / playwright style)
    for m in JS_SCHEMA_NAME.finditer(src):
        block = src[m.end(): m.end() + 900]
        nm = re.search(r"name\s*:\s*['\"`](" + NAME_RE + r")['\"`]", block)
        if nm:
            _add_js_tool(root, path, src, nm.group(1), block, _line_of(src, m.start()), items, seen)

    # S3 — per-file config-object module: const name="x"; ... description: "..."
    # Only when the file has tool context and S1/S2 found nothing here.
    if has_ctx and not seen:
        nm = JS_NAME_BIND.search(src)
        # skip if the only name looks like a server name (…-server / …_server)
        if nm and not re.search(r"server$", nm.group(1), re.I):
            desc = _js_desc(src)
            if desc or re.search(r"inputSchema|CallToolResult|registerTool", src):
                _add_js_tool(root, path, src, nm.group(1), src, _line_of(src, nm.start()), items, seen)

    # S4 — tool object literals { name:"x", ... inputSchema/parameters: ... }
    # Require a tool-specific schema key (not just description) so resource /
    # prompt object literals are not misread as tools.
    if has_ctx:
        for m in re.finditer(r"\{[^{}]{0,700}?name\s*:\s*['\"`](" + NAME_RE + r")['\"`][^{}]{0,700}?"
                             r"(?:inputSchema|input_schema|parameters)\s*:", src, re.S):
            name = m.group(1)
            if name in seen or re.search(r"server$", name, re.I):
                continue
            _add_js_tool(root, path, src, name, m.group(0), _line_of(src, m.start()), items, seen)

    # resources / prompts
    rseen = set()
    for m in JS_RESOURCE_PATTERN.finditer(src):
        if m.group(1) in rseen:
            continue
        rseen.add(m.group(1))
        items.append({"name": m.group(1), "description": _js_desc(src[m.start():m.start()+500]),
                      "source_file": _rel(root, path), "source_line": _line_of(src, m.start()),
                      "params": [], "body": src[m.start():m.start()+500], "kind": "resource",
                      "uri": m.group(1), "mime": None})
    pseen = set()
    for m in JS_PROMPT_PATTERN.finditer(src):
        if m.group(1) in pseen:
            continue
        pseen.add(m.group(1))
        items.append({"name": m.group(1), "description": _js_desc(src[m.start():m.start()+500]),
                      "source_file": _rel(root, path), "source_line": _line_of(src, m.start()),
                      "params": [], "body": src[m.start():m.start()+500], "kind": "prompt",
                      "uri": None, "mime": None})


# ==========================================================================
# build the normalized overview object
# ==========================================================================
def build_tool_record(it):
    body = it.get("body", "")
    params = it.get("params", [])
    caps = infer_capabilities(body, params)
    op = infer_operation(it["name"], body)
    target = infer_target(body)
    return {
        "name": it["name"],
        "description": it["description"] or "(no description found)",
        "source_file": it["source_file"],
        "source_line": it.get("source_line"),
        "source_ref": f"{it['source_file']}:{it.get('source_line')}",
        "operation": op,
        "target": target,
        "input": infer_input(params, op, caps),
        "authentication": infer_auth(body),
        "capabilities": caps,
        "capability_label": primary_capability_label(op, caps, target),
        "parameters": [{"name": p["name"], "type": p.get("type", "string")} for p in params],
    }


# --- capability inference from text only (for dynamically-extracted tools that
#     have no source body -- e.g. tools introspected from a running server) ----
TEXT_CAP_RULES = [
    (r"\b(exec|execute|run|command|shell|terminal|eval|evaluate|spawn|bash|powershell)\b|javascript", "Command Execution"),
    (r"\b(sql|query|database|select|insert|table)\b", "Database Access"),
    (r"\b(navigate|url|fetch|http|request|browse|download|upload|api|webhook)\b", "Network Access"),
    (r"\b(file|read|write|path|directory|filesystem|save|open)\b", "File System Access"),
    (r"\b(delete|remove|drop|write|create|update|edit|modify|set|put|post)\b", "Write Capability"),
    # NB: bare "key" is intentionally excluded — it false-matches keyboard
    # "press a key" as credential access. Require an actual secret-ish term.
    (r"\b(secret|credential|password|token|oauth|bearer)\b|api[_-]?key|access[_-]?key", "Credential Access"),
    (r"\b(click|type|press|screenshot|snapshot|hover|scroll|keyboard|mouse)\b", "Browser / UI Control"),
]


def infer_caps_from_text(name, desc, params):
    text = (name + " " + (desc or "")).lower()
    caps = []
    for pat, cap in TEXT_CAP_RULES:
        if re.search(pat, text) and cap not in caps:
            caps.append(cap)
    if params:
        caps.append("Untrusted Input")
    # collapse write into database/fs context; keep order, de-dup
    seen, out = set(), []
    for c in caps:
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def tool_record_from_extracted(t):
    """Build a tool record from a sandbox/dynamic-introspection tool object
    ({name, description, input_schema, source}) that has no source body."""
    name = t.get("name") or "tool"
    desc = (t.get("description") or "").strip()
    schema = t.get("input_schema") or t.get("inputSchema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    params = [{"name": k, "type": (v.get("type") if isinstance(v, dict) else "string") or "string"}
              for k, v in props.items()]
    caps = infer_caps_from_text(name, desc, params)
    op = infer_operation(name, desc)
    # target from capabilities/text
    target = "—"
    if "Command Execution" in caps:
        target = "Host / OS process"
    elif "Database Access" in caps:
        target = "Configured database"
    elif "Network Access" in caps:
        target = "External HTTP endpoint"
    elif "File System Access" in caps:
        target = "Local filesystem"
    return {
        "name": name, "description": desc or "(no description found)",
        "source_file": t.get("source") or "(dynamic introspection)",
        "source_line": None,
        "source_ref": t.get("source") or "dynamic introspection (tools/list)",
        "operation": op, "target": target,
        "input": infer_input(params, op, caps),
        "authentication": "Required" if "Credential Access" in caps else "None detected",
        "capabilities": caps,
        "capability_label": primary_capability_label(op, caps, target),
        "parameters": params,
        "_body": "",
    }


def detect_integrations(root, tool_items):
    """File-level + tool-level integration detection with used_by attribution."""
    found = {}  # service -> record

    def ensure(ig):
        if ig["service"] not in found:
            found[ig["service"]] = {
                "service": ig["service"], "category": ig["cat"], "auth": ig["auth"],
                "operations": set(), "used_by": set(), "evidence": None}
        return found[ig["service"]]

    # scan every source file for named integrations (evidence)
    for p in _walk(root):
        if p.suffix.lower() not in (PY_EXT | JS_EXT):
            continue
        src = _read(p)
        if not src:
            continue
        for ig in INTEGRATIONS:
            if _matches(ig["markers"], src):
                rec = ensure(ig)
                rec["operations"].update(_refine_ops(ig, src))
                if not rec["evidence"]:
                    rec["evidence"] = _first_marker_line(root, p, ig["markers"], src)

    # attribute tools to services via each tool's own body
    for t in tool_items:
        body = t.get("body", "")
        for ig in INTEGRATIONS:
            if _matches(ig["markers"], body) and ig["service"] in found:
                found[ig["service"]]["used_by"].add(t["name"])

    # broad capability "integrations" (filesystem / http / shell) as pseudo-services
    def pseudo(service, cat, auth, markers, ops):
        used, ev = set(), None
        for t in tool_items:
            if _matches(markers, t.get("body", "")):
                used.add(t["name"])
        # also file-level
        hit = False
        for p in _walk(root):
            if p.suffix.lower() not in (PY_EXT | JS_EXT):
                continue
            s = _read(p)
            if _matches(markers, s):
                hit = True
                if not ev:
                    ev = _first_marker_line(root, p, markers, s)
                break
        if hit or used:
            found.setdefault(service, {"service": service, "category": cat, "auth": auth,
                                       "operations": set(ops), "used_by": used, "evidence": ev})
            found[service]["used_by"].update(used)

    pseudo("External HTTP / APIs", "network", "Varies", HTTP_MARKERS, ["Read", "Write"])
    pseudo("Local Filesystem", "filesystem", "None (host FS)",
           FS_READ_MARKERS + FS_WRITE_MARKERS, ["Read"])
    pseudo("OS / Shell (subprocess)", "process", "None (host privilege)",
           PROC_MARKERS, ["Execute"])

    out = []
    for rec in found.values():
        rec["operations"] = sorted(rec["operations"]) or ["Read"]
        rec["used_by"] = sorted(rec["used_by"])
        out.append(rec)
    # order: named services first, then broad capabilities; more-used first
    order = {"filesystem": 8, "process": 9, "network": 7}
    out.sort(key=lambda r: (order.get(r["category"], 0), -len(r["used_by"])))
    return out


def _refine_ops(ig, src):
    ops = set()
    if ig["cat"] == "database":
        if re.search(r"SELECT\s|\.find\(|\.query\(|\.get\(", src, re.I):
            ops.add("Read")
        if re.search(r"INSERT\s|UPDATE\s|\.insert\(|\.update\(|\.save\(", src, re.I):
            ops.add("Write")
        if re.search(r"DELETE\s|DROP\s|\.delete\(|\.remove\(", src, re.I):
            ops.add("Delete")
    if not ops:
        ops.update(ig["ops"])
    return ops


def _first_marker_line(root, path, markers, src):
    for i, line in enumerate(src.splitlines(), 1):
        if _matches(markers, line):
            return f"{_rel(root, path)}:{i}"
    return _rel(root, path)


def analyze_auth(root, tools):
    """Authentication & authorization posture."""
    mechanisms = set()
    notes = []
    blob = ""
    for p in _walk(root):
        if p.suffix.lower() in (PY_EXT | JS_EXT):
            blob += _read(p) + "\n"

    if _matches([r"os\.getenv\(|os\.environ|process\.env"], blob):
        mechanisms.add("Environment-variable credentials")
    if re.search(r"\bBearer\b|Authorization", blob):
        mechanisms.add("Bearer / token headers")
    if re.search(r"\bjwt\b|jsonwebtoken|PyJWT", blob, re.I):
        mechanisms.add("JWT")
    if re.search(r"\boauth", blob, re.I):
        mechanisms.add("OAuth")
    if _matches(AUTHZ_MARKERS, blob):
        mechanisms.add("Authorization checks")
    has_authz = _matches(AUTHZ_MARKERS, blob)

    per_tool = []
    for t in tools:
        body = t.get("_body", "")
        auth = t["authentication"] == "Required"
        # authorization verb inside this tool's body?
        authz = "None"
        if _matches(AUTHZ_MARKERS, body):
            authz = "Enforced (in-handler check)"
        elif t["operation"] in ("DELETE",) or "Command Execution" in t["capabilities"] \
                or "Code Execution" in t["capabilities"]:
            authz = "Admin-level (no check found)"
        elif "Write Capability" in t["capabilities"] or "Database Access" in t["capabilities"]:
            authz = "Write (no check found)"
        else:
            authz = "Read / user"
        per_tool.append({"tool": t["name"], "auth": auth, "authorization": authz,
                         "unknown": (not auth and authz in ("Read / user",) and not has_authz)})

    if not has_authz and tools:
        notes.append("No explicit authorization/permission check was detected in any handler — "
                     "for a local stdio server every tool runs with the host user's full privilege.")
    if "Environment-variable credentials" in mechanisms:
        notes.append("Credentials are read from environment variables; a compromised tool can reach "
                     "every service those credentials unlock (shared-credential / confused-deputy risk).")
    if not mechanisms:
        mechanisms.add("None detected")
        notes.append("No authentication mechanism was detected — this may be expected for a purely "
                     "local server, but confirm no privileged capability is exposed unauthenticated.")

    summary = ("This server enforces authorization inside its handlers."
               if has_authz else
               "No per-caller authorization layer was detected; access control relies entirely on "
               "who is allowed to launch the server.")
    return {"mechanisms": sorted(mechanisms), "summary": summary,
            "has_authz": has_authz, "tools": per_tool, "notes": notes}


# ==========================================================================
# capability & attack surface
# ==========================================================================
DOMAIN_CATALOG = [
    {"name": "Code & Command Execution", "level": "CRITICAL", "caps": {"Code Execution", "Command Execution"},
     "desc": "Run arbitrary code, shell commands, or OS processes in the server process."},
    {"name": "Database Access", "level": "HIGH", "caps": {"Database Access", "Arbitrary Query Execution"},
     "desc": "Read, write, or query the configured database, sometimes with caller-shaped SQL."},
    {"name": "Network & External Access", "level": "HIGH", "caps": {"Network Access"},
     "desc": "Reach external URLs, internal services, and third-party APIs from the host."},
    {"name": "File Access & Transfer", "level": "HIGH", "caps": {"File System Write", "File System Access"},
     "desc": "Read from and write to the host filesystem the server runs on."},
    {"name": "Credential & Identity", "level": "HIGH", "caps": {"Credential Access"},
     "desc": "Read secrets/tokens and act with the server's own privileged credentials."},
    {"name": "Write & State Change", "level": "MEDIUM", "caps": {"Write Capability"},
     "desc": "Mutate state in an external system (create / update / delete)."},
    {"name": "Untrusted Input Surface", "level": "MEDIUM", "caps": {"Untrusted Input"},
     "desc": "Free-text, model-controlled parameters that flow into a sensitive operation."},
]
DOMAIN_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def build_attack_surface(server_name, tools, integrations, auth):
    # capability domains
    domains = []
    for d in DOMAIN_CATALOG:
        matched = [t for t in tools if set(t["capabilities"]) & d["caps"]]
        if matched:
            domains.append({"name": d["name"], "level": d["level"], "tool_count": len(matched),
                            "desc": d["desc"], "tools": [t["name"] for t in matched]})
    domains.sort(key=lambda x: -DOMAIN_RANK[x["level"]])

    # external surfaces (map leaf nodes) from integrations
    CAT_LABEL = {"database": "Databases", "network": "Network Endpoints",
                 "filesystem": "Local Filesystem", "process": "Host OS / Shell",
                 "vcs": "Source Control", "cloud": "Cloud Services", "saas": "SaaS APIs",
                 "ai": "AI Providers", "comms": "Messaging", "container": "Containers",
                 "browser": "Browser / Web"}
    surfaces = []
    for ig in integrations:
        surfaces.append({"name": ig["service"], "group": CAT_LABEL.get(ig["category"], "External"),
                         "tool_count": len(ig["used_by"]), "ops": ig["operations"]})

    # high-impact paths: tools with critical/high capability -> target -> impact
    IMPACT = [
        ({"Code Execution", "Command Execution"}, "CRITICAL", "Remote code / command execution on the host"),
        ({"Arbitrary Query Execution"}, "HIGH", "Arbitrary database read/write via caller-shaped query"),
        ({"Credential Access"}, "HIGH", "Privileged credential reused across callers (confused deputy)"),
        ({"File System Write"}, "HIGH", "Write to arbitrary host paths"),
        ({"Network Access"}, "HIGH", "SSRF / exfiltration to caller-chosen destination"),
        ({"Database Access"}, "MEDIUM", "Database read/write"),
        ({"File System Access"}, "MEDIUM", "Read arbitrary host files"),
    ]
    paths = []
    for t in tools:
        cs = set(t["capabilities"])
        for caps, sev, impact in IMPACT:
            if cs & caps:
                paths.append({"severity": sev, "tool": t["name"], "target": t["target"],
                              "impact": impact,
                              "chain": ["AI Agent", t["name"], t["target"], impact]})
                break
    paths.sort(key=lambda p: -DOMAIN_RANK[p["severity"]])

    # trust boundaries (only those that apply)
    boundaries = [{"a": "AI Agent", "b": "MCP Server",
                   "note": "Model-controlled tool calls and arguments cross into the server as trusted input."}]
    cats = {ig["category"] for ig in integrations}
    if cats & {"network", "vcs", "cloud", "saas", "ai", "comms"}:
        boundaries.append({"a": "MCP Server", "b": "External Services",
                           "note": "The server reaches third-party / internet endpoints with its own credentials."})
    if "database" in cats:
        boundaries.append({"a": "MCP Server", "b": "Database",
                           "note": "The server holds a database connection usable by any exposed tool."})
    if "filesystem" in cats:
        boundaries.append({"a": "MCP Server", "b": "Host Filesystem",
                           "note": "Read/write access to the host filesystem the server process owns."})
    if "process" in cats:
        boundaries.append({"a": "MCP Server", "b": "Host OS",
                           "note": "The server can spawn OS processes with the launching user's privilege."})

    # detected controls (best-effort)
    controls = _detect_controls(tools, auth)

    highest = "LOW"
    for d in domains:
        if DOMAIN_RANK[d["level"]] > DOMAIN_RANK[highest]:
            highest = d["level"]

    return {
        "server_name": server_name,
        "stats": {"tools": len(tools), "domains": len(domains),
                  "boundaries": len(boundaries), "high_impact_paths": len(paths)},
        "highest_level": highest,
        "domains": domains,
        "surfaces": surfaces,
        "high_impact_paths": paths,
        "trust_boundaries": boundaries,
        "detected_controls": controls,
    }


def _detect_controls(tools, auth):
    controls = []
    controls.append({"name": "Per-caller authorization", "enabled": auth["has_authz"],
                     "note": "In-handler permission / scope checks" if auth["has_authz"]
                     else "No authorization check detected in any handler"})
    any_validation = any(re.search("|".join(VALIDATION_MARKERS), t.get("_body", ""), re.I) for t in tools)
    controls.append({"name": "Input validation / constraints", "enabled": any_validation,
                     "note": "Schema / enum / assertion validation present" if any_validation
                     else "Tool arguments appear unconstrained (free-text)"})
    exec_tools = [t for t in tools if {"Code Execution", "Command Execution"} & set(t["capabilities"])]
    controls.append({"name": "No arbitrary code/command sink", "enabled": not exec_tools,
                     "note": "No eval/exec/subprocess sink found" if not exec_tools
                     else f"{len(exec_tools)} tool(s) reach an exec/shell sink"})
    net_tools = [t for t in tools if "Network Access" in t["capabilities"]]
    controls.append({"name": "Network egress scoping", "enabled": False if net_tools else True,
                     "note": "No outbound network capability" if not net_tools
                     else "Outbound calls present — confirm host allowlisting"})
    return controls


# ==========================================================================
# top-level
# ==========================================================================
def build_overview(root, server_name=None, injected=None):
    """Return the full normalized overview object. See module docstring.

    `injected` (optional) carries tools/resources/prompts obtained from the
    sandbox extractor or dynamic `tools/list` introspection — used only when
    in-process static parsing finds no tools (e.g. a server whose tools live in
    a compiled dependency). Shape:
        {"tools":[{name,description,input_schema,source}], "resources":[...],
         "prompts":[...], "method":"dynamic introspection (tools/list)"}"""
    root = pathlib.Path(root)
    base = inspect_repo.inspect(root)

    # ---- extract tools / resources / prompts (in-process static) ----
    items = []
    for p in _walk(root):
        ext = p.suffix.lower()
        src = _read(p)
        if not src:
            continue
        if ext in PY_EXT:
            extract_python(root, p, src, items)
        elif ext in JS_EXT:
            extract_js(root, p, src, items)

    tool_items = [i for i in items if i["kind"] == "tool"]
    resource_items = [i for i in items if i["kind"] == "resource"]
    prompt_items = [i for i in items if i["kind"] == "prompt"]

    extraction_method = "static source analysis"
    tools = [build_tool_record(i) for i in tool_items]
    for t, i in zip(tools, tool_items):
        t["_body"] = i.get("body", "")

    # ---- fallback: no tools in source, use injected sandbox/dynamic tools ----
    if not tools and injected and injected.get("tools"):
        extraction_method = injected.get("method") or "sandbox extraction"
        tools = [tool_record_from_extracted(t) for t in injected["tools"]]
        tool_items = []  # no bodies for integration attribution
        if injected.get("resources") and not resource_items:
            resource_items = [{"name": r.get("name") or r.get("uri"), "uri": r.get("uri") or r.get("name"),
                               "description": r.get("description", ""), "mime": r.get("mime_type") or r.get("mime"),
                               "source_file": r.get("source") or "(dynamic)", "source_line": None}
                              for r in injected["resources"]]
        if injected.get("prompts") and not prompt_items:
            prompt_items = [{"name": p.get("name"), "description": p.get("description", ""),
                             "params": [{"name": a} for a in (p.get("arguments") or p.get("args") or [])],
                             "source_file": p.get("source") or "(dynamic)", "source_line": None}
                            for p in injected["prompts"]]

    resources = [{
        "name": i["name"], "uri": i.get("uri") or i["name"],
        "description": i["description"] or "(no description)",
        "mime": i.get("mime"), "source_file": i["source_file"],
        "source_ref": (f"{i['source_file']}:{i.get('source_line')}" if i.get("source_line")
                       else i.get("source_file", "")),
    } for i in resource_items]

    prompts = [{
        "name": i["name"], "description": i["description"] or "(no description)",
        "arguments": [p["name"] for p in i.get("params", [])],
        "source_file": i["source_file"],
        "source_ref": (f"{i['source_file']}:{i.get('source_line')}" if i.get("source_line")
                       else i.get("source_file", "")),
    } for i in prompt_items]

    integrations = detect_integrations(root, tool_items)
    auth = analyze_auth(root, tools)
    attack = build_attack_surface(server_name or base.get("name"), tools, integrations, auth)

    # transport heuristic
    transport = _detect_transport(root)

    # strip private bodies
    for t in tools:
        t.pop("_body", None)

    server = {
        "name": server_name or base.get("name"),
        "version": base.get("version"),
        "about": base.get("about"),
        "primary_language": base.get("primary_language"),
        "languages": base.get("languages", []),
        "source_files": base.get("source_files"),
        "dependencies": base.get("dependencies"),
        "mcp_sdk": base.get("mcp_sdk"),
        "manifest": base.get("manifest"),
        "entry_point": base.get("entry_point"),
        "transport": transport,
        "tool_count": len(tools),
        "resource_count": len(resources),
        "prompt_count": len(prompts),
        "integration_count": len(integrations),
        "capability_domains": len(attack["domains"]),
        "highest_capability": attack["highest_level"],
        "extraction_method": extraction_method,
    }

    return {
        "server": server,
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
        "integrations": integrations,
        "auth": auth,
        "attack_surface": attack,
        # convenience: repo_info shape the existing security-report code expects
        "repo_info": base,
    }


def _detect_transport(root):
    blob = ""
    for name in ("server.py", "main.py", "index.js", "index.ts", "server.js", "server.ts"):
        p = root / name
        if p.is_file():
            blob += _read(p)
    for p in list(_walk(root))[:400]:
        if p.suffix.lower() in (PY_EXT | JS_EXT):
            blob += _read(p)
    if re.search(r"streamable[_-]?http|StreamableHTTP|sse|EventSource|uvicorn|fastapi|express\(", blob, re.I):
        if re.search(r"\bsse\b|EventSource", blob, re.I):
            return "HTTP / SSE"
        return "HTTP"
    if re.search(r"stdio|StdioServerTransport|run\(\)|FastMCP", blob):
        return "stdio (local)"
    return "stdio (local)"


if __name__ == "__main__":
    import sys
    r = sys.argv[1] if len(sys.argv) > 1 else "."
    name = sys.argv[2] if len(sys.argv) > 2 else None
    print(json.dumps(build_overview(r, name), indent=2, default=str))
