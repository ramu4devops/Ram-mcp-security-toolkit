#!/usr/bin/env python3
"""
build_email.py -- turn the combined review report into notification bodies.

Reads  <report_dir>/*.report.json  (written by the review CLI) and writes:
  <report_dir>/email-subject.txt   one-line email subject
  <report_dir>/email-body.html     compact HTML email body (summary + top findings)
  <report_dir>/pr-comment.md       markdown for the sticky PR comment

Context comes from env (set by the workflow): PR_NUMBER, PR_TITLE, PR_AUTHOR,
REPO, RUN_URL. All optional -- the script degrades gracefully when run locally.

Zero third-party dependencies (stdlib only), so it runs on any runner.
"""
import os
import sys
import glob
import json
import html

BADGE = {
    "DO NOT PROCEED": ("#c02a20", "\U0001F534"),   # red circle
    "NEEDS REVIEW":   ("#9a6b00", "\U0001F7E1"),   # yellow circle
    "CLEAR TO PROCEED": ("#1a7f4b", "\U0001F7E2"),  # green circle
}
BLOCK_STATUSES = {"FAIL", "HIGH_SUSPICION", "HIGH SUSPICION", "ERROR"}
REVIEW_STATUSES = {"REVIEW", "CHANGED", "NEEDS_DYNAMIC", "NEEDS DYNAMIC",
                   "NO_BASELINE", "EXTRACTED"}


def _load(report_dir):
    hits = sorted(glob.glob(os.path.join(report_dir, "*.report.json")))
    if not hits:
        raise SystemExit(f"No *.report.json found in {report_dir}")
    with open(hits[0]) as fh:
        return json.load(fh)


def _status_mark(status):
    s = (status or "").upper().replace("-", "_")
    if s in {x.replace(" ", "_") for x in BLOCK_STATUSES}:
        return "❌"      # cross
    if s in {x.replace(" ", "_") for x in REVIEW_STATUSES}:
        return "⚠️"  # warning
    return "✅"          # check


def _md_status(status):
    s = (status or "").upper().replace("-", "_")
    if s in {x.replace(" ", "_") for x in BLOCK_STATUSES}:
        return f"❌ **{html.escape(status)}**"
    if s in {x.replace(" ", "_") for x in REVIEW_STATUSES}:
        return f"⚠️ {html.escape(status)}"
    return f"✅ {html.escape(status)}"


def main():
    report_dir = sys.argv[1] if len(sys.argv) > 1 else "mcp-report"
    data = _load(report_dir)

    server = data.get("server_name", "mcp-server")
    reco = data.get("recommendation", "NEEDS REVIEW")
    modules = data.get("modules", [])
    total = sum(m.get("counts", {}).get("total", 0) for m in modules)
    crit = sum(m.get("counts", {}).get("critical", 0) for m in modules)
    high = sum(m.get("counts", {}).get("high", 0) for m in modules)
    blocking = [m for m in modules
                if (m.get("status") or "").upper().replace("-", "_")
                in {x.replace(" ", "_") for x in BLOCK_STATUSES}]

    pr = os.environ.get("PR_NUMBER", "")
    pr_title = os.environ.get("PR_TITLE", "")
    author = os.environ.get("PR_AUTHOR", "")
    repo = os.environ.get("REPO", "")
    run_url = os.environ.get("RUN_URL", "")
    color, dot = BADGE.get(reco, ("#9a6b00", "\U0001F7E1"))

    # ---------------- email subject ----------------
    pr_tag = f"PR #{pr}" if pr else "review"
    subj = f"[MCP Security] {reco} — {server} {pr_tag}"
    if crit or high:
        subj += f" ({crit} critical / {high} high)"

    # ---------------- module rows ----------------
    def _rows_html():
        out = []
        for m in modules:
            c = m.get("counts", {})
            out.append(
                f'<tr><td style="padding:6px 10px;border-bottom:1px solid #e4e7ec">'
                f'<b>{html.escape(m.get("name",""))}</b></td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #e4e7ec">'
                f'{_status_mark(m.get("status"))} {html.escape(str(m.get("status","")))}</td>'
                f'<td align="center" style="padding:6px 10px;border-bottom:1px solid #e4e7ec">{c.get("total",0)}</td>'
                f'<td align="center" style="padding:6px 10px;border-bottom:1px solid #e4e7ec">{c.get("critical",0)}</td>'
                f'<td align="center" style="padding:6px 10px;border-bottom:1px solid #e4e7ec">{c.get("high",0)}</td></tr>')
        return "".join(out)

    def _rows_md():
        out = ["| Module | Verdict | Findings | Critical | High |",
               "|---|---|--:|--:|--:|"]
        for m in modules:
            c = m.get("counts", {})
            out.append(f"| **{m.get('name','')}** | "
                       f"{_md_status(m.get('status'))} | {c.get('total',0)} | "
                       f"{c.get('critical',0)} | {c.get('high',0)} |")
        return "\n".join(out)

    # ---------------- email body (HTML) ----------------
    block_line = ""
    if blocking:
        names = ", ".join(m.get('name','') for m in blocking)
        block_line = (f'<p style="margin:10px 0;color:#c02a20"><b>Blocking modules:</b> '
                      f'{html.escape(names)}</p>')
    body = f"""<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
color:#151a23;max-width:640px">
<div style="border-left:4px solid {color};padding:10px 16px;background:#f5f7fa;border-radius:6px">
<div style="font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:#616d80">MCP Security Review</div>
<div style="font-size:20px;font-weight:700;color:{color};margin-top:2px">{dot} {html.escape(reco)}</div>
</div>
<p style="margin:14px 0 4px"><b>Server:</b> {html.escape(server)}
{f'&nbsp;·&nbsp; <b>PR:</b> #{html.escape(pr)} {html.escape(pr_title)}' if pr else ''}
{f'&nbsp;·&nbsp; <b>Requestor:</b> @{html.escape(author)}' if author else ''}</p>
<p style="margin:4px 0"><b>{total}</b> findings &nbsp;·&nbsp; <b style="color:#c02a20">{crit}</b> critical
&nbsp;·&nbsp; <b style="color:#c02a20">{high}</b> high &nbsp;·&nbsp; {len(modules)} modules</p>
{block_line}
<table style="border-collapse:collapse;width:100%;font-size:13px;margin:12px 0">
<thead><tr style="background:#eef1f7">
<th align="left" style="padding:6px 10px">Module</th>
<th align="left" style="padding:6px 10px">Verdict</th>
<th style="padding:6px 10px">Findings</th>
<th style="padding:6px 10px">Critical</th>
<th style="padding:6px 10px">High</th></tr></thead>
<tbody>{_rows_html()}</tbody></table>
<p style="margin:12px 0;font-size:13px;color:#616d80">
The full HTML report is attached. {'View the run and artifacts: ' if run_url else ''}
{f'<a href="{html.escape(run_url)}">{html.escape(run_url)}</a>' if run_url else ''}</p>
<p style="font-size:12px;color:#8b96a8;border-top:1px solid #e4e7ec;padding-top:10px">
Automated by the MCP Security Review gate. A blocking verdict fails the required
status check and holds the merge until the critical/high findings are resolved.
A static scan is a snapshot — re-run on every change.</p>
</div>"""

    # ---------------- PR comment (markdown) ----------------
    md = [f"### {dot} MCP Security Review — {reco}",
          "",
          f"**Server:** `{server}`  ·  **{total}** findings  ·  "
          f"**{crit}** critical  ·  **{high}** high  ·  {len(modules)} modules",
          ""]
    if blocking:
        names = ", ".join(f"`{m.get('name','')}`" for m in blocking)
        md += [f"> ❌ **Merge blocked** — blocking modules: {names}. "
               "Resolve every critical/high finding, then push to re-run.", ""]
    elif reco == "NEEDS REVIEW":
        md += ["> ⚠️ **Not blocking, but a human decision is needed** — see the review-flagged "
               "modules below.", ""]
    else:
        md += ["> ✅ **Clear to proceed** — every module came back clean.", ""]
    md.append(_rows_md())
    md += ["",
           f"📎 Full report: **Actions → this run → Artifacts → `mcp-security-report`**"
           + (f"  ·  [run log]({run_url})" if run_url else ""),
           "🔎 Inline findings: **Security → Code scanning** (annotated on the diff).",
           "",
           "<sub>Automated by the MCP Security Review gate · a static scan is a snapshot in "
           "time — re-run on every change.</sub>"]

    os.makedirs(report_dir, exist_ok=True)
    # Always end with a trailing newline: the workflow appends these files into
    # $GITHUB_OUTPUT using a `cat file; echo '__EOF__'` heredoc, and if the file's
    # last line has no newline, the closing delimiter gets glued onto that line
    # (e.g. "</div>__EOF__") instead of standing on its own -- which makes GitHub's
    # multiline-output parser fail with "Matching delimiter not found".
    with open(os.path.join(report_dir, "email-subject.txt"), "w") as fh:
        fh.write(subj + "\n")
    with open(os.path.join(report_dir, "email-body.html"), "w") as fh:
        fh.write(body + "\n")
    with open(os.path.join(report_dir, "pr-comment.md"), "w") as fh:
        fh.write("\n".join(md) + "\n")
    print(f"subject: {subj}")
    print(f"wrote email-subject.txt, email-body.html, pr-comment.md to {report_dir}/")


if __name__ == "__main__":
    main()
