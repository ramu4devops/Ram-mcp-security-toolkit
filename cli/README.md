# `mcp-review` — Local MCP Security Review CLI

Run the sandboxed MCP security **review modules** against a local MCP server
repo — a folder, a `.zip`, or a git URL — from your terminal or a CI job. Every
module runs inside a hardened, disposable Docker image; submitted code is never
executed on the host.

> Full walkthrough + FAQ: **`mcp-cli-user-guide.html`**.

## Prerequisites

- **Docker Desktop** running (`docker info` succeeds).
- **Python 3.10+**.
- First run builds the scanner image once (handled by `scripts/review.sh`).

## Usage

```bash
# every module, on a repo directory — writes ./mcp-report/
./scripts/review.sh ~/code/acme-mcp

# a single module (see names below)
./scripts/review.sh ~/Downloads/acme-mcp.zip --module secrets

# a few modules
./scripts/review.sh ~/code/acme-mcp --module secrets,sast,supply-chain

# straight from GitHub (a full clone → enables the rug-pull commit timeline)
./scripts/review.sh https://github.com/acme/acme-mcp

# read all findings in the terminal (no need to open the report)
./scripts/review.sh ~/code/acme-mcp --details

# list every module and its accepted names
./scripts/review.sh --list
```

## Review modules

Pass any of these names to `--module` (comma-separated for several). Omit
`--module` to run them all.

| Module (`--module` value) | What it reviews | OWASP |
|---|---|---|
| `tool-poisoning` | Tool descriptions that manipulate the model | MCP03/06 |
| `rug-pull` | Post-approval changes to tools/resources | MCP03 |
| `prompt-injection` | Caller input reaching the instruction stream | MCP06/10 |
| `resource` | Path traversal / SSRF / unbounded resource reads | MCP10 |
| `secrets` | Hardcoded creds, token handling, channel leakage | MCP01 |
| `supply-chain` | Dependency CVEs, typosquats, install scripts¹ | MCP04 |
| `sast` | Command/code/SQL injection, unsafe deserialization | MCP05 |
| `confused-deputy` | Missing per-caller authorization | MCP02/07 |
| `audit` | Audit/telemetry/logging coverage | MCP08 |
| `shadow` | Manifest hygiene & shadow-server indicators | MCP09 |

¹ `supply-chain` runs `npm audit` / `npm ci`, so it needs the Docker sandbox
(it's skipped under `--no-sandbox`).

Each module also accepts a couple of synonyms (e.g. `authz` → `confused-deputy`,
`deps` → `supply-chain`); run `--list` to see them.

## Options

| Option | Default | Purpose |
|---|---|---|
| `-m`, `--module a,b,c` | all | which review modules to run (or `all`) |
| `--all` | — | run every module (same as omitting `--module`) |
| `--name NAME` | repo/dir name | server name used in the report |
| `--out DIR` | `./mcp-report` | where reports are written |
| `-d`, `--details` | off | print full findings for every module in the terminal |
| `--rug-pull-mode pin\|timeline\|auto` | auto | Rug Pull: pin a baseline, or walk the last 3 commits (needs `.git`) |
| `--fail-on block\|review\|never` | block | CI gate: which verdict makes the exit code non-zero |
| `--no-sandbox` | off | run the static modules with host `python3`, no container (no isolation) |
| `--quiet` | off | terse output |
| `--list` | — | list modules and exit |

**Exit codes:** `0` clean · `1` needs review · `2` blocking finding · `3` error.

## Output (in `--out`, default `./mcp-report/`)

| File | For |
|---|---|
| `<server>.report.html` | the human review / approval record (Print → Save as PDF) |
| `<server>.report.sarif` | combined SARIF 2.1.0 for CI / GitHub code scanning |
| `<server>.report.json` | machine-readable summary (verdicts + counts) |
| `<server>.<module>.json` | full result for one module (e.g. `acme.secrets.json`) |
| `<server>.<module>.sarif` | per-module SARIF |

## Configuration (env vars)

`MCP_SCANNER_IMAGE`, `MCP_ALLOW_DYNAMIC`, `MCP_SCAN_WORKDIR`, `MCP_BASELINE_DIR`,
`MCP_SCAN_TIMEOUT`, `MCP_INSTALL_TIMEOUT`.
