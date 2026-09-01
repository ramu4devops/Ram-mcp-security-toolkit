#!/usr/bin/env python3
"""
reporting.py -- turn box results into artifacts an engineer / a CI job / an
approval record can consume:

  * <box>.json   -- the raw normalized envelope per module (machine-readable)
  * <box>.sarif  -- SARIF 2.1.0 per module, for GitHub code-scanning / CI
  * report.sarif -- one combined SARIF across every module run
  * report.json  -- combined summary (verdicts + counts + findings)
  * report.html  -- a single self-contained review report (approval artifact)

The HTML mirrors the web console's report: an executive-summary recommendation
banner derived from every module's verdict, then one section per module with
its verdict, rationale, next step, stat tiles, and every finding (evidence /
why-it-matters / remediation). Nothing is summarized away.
"""
import re
import html
import json
import datetime

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}

# verdict -> (css class, banner word)
BLOCK = {"FAIL", "HIGH_SUSPICION", "HIGH SUSPICION", "ERROR"}
REVIEWY = {"REVIEW", "CHANGED", "NEEDS_DYNAMIC", "NEEDS DYNAMIC", "NO_BASELINE", "EXTRACTED"}


def _slug(s):
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", (s or "server")).strip("-") or "server"


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------
def _sarif_run(box_results, tool_name="MCP Security Review"):
    rules, rule_index, results = [], {}, []
    for br in box_results:
        res = br.get("result") or {}
        box_name = br.get("name", br.get("box"))
        for f in res.get("findings", []):
            layer = f.get("layer") or ""
            rule_id = f"{br['module']}/{layer}" if layer else br["module"]
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": re.sub(r"[^A-Za-z0-9]+", "", f"{br['module']}{layer}") or br["module"],
                    "shortDescription": {"text": f"{box_name} · {layer}".strip(" ·")},
                    "fullDescription": {"text": f.get("impact") or box_name},
                    "properties": {"module": br["module"], "owasp": br.get("owasp", "")},
                })
            subject = f.get("subject") or "(repo)"
            loc_file, loc_line = subject, None
            m = re.match(r"^(.*):(\d+)$", subject)
            if m:
                loc_file, loc_line = m.group(1), int(m.group(2))
            phys = {"artifactLocation": {"uri": loc_file}}
            if loc_line:
                phys["region"] = {"startLine": loc_line}
            msg = f.get("title") or box_name
            if f.get("evidence"):
                msg += f"\nEvidence: {f['evidence']}"
            if f.get("remediation"):
                msg += f"\nRemediation: {f['remediation']}"
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": SARIF_LEVEL.get(f.get("severity", "info"), "note"),
                "message": {"text": msg},
                "locations": [{"physicalLocation": phys}],
                "properties": {"severity": f.get("severity"), "module": br["module"]},
            })
    return {
        "tool": {"driver": {"name": tool_name, "informationUri":
                            "https://owasp.org/www-project-mcp-top-10/",
                            "version": "1.0.0", "rules": rules}},
        "results": results,
    }


def sarif_document(box_results, tool_name="MCP Security Review"):
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0", "runs": [_sarif_run(box_results, tool_name)]}


# --------------------------------------------------------------------------
# combined JSON summary
# --------------------------------------------------------------------------
def summary_json(server_name, box_results, repo_info, recommendation):
    mods = []
    for br in box_results:
        v = (br.get("result") or {}).get("verdict", {})
        mods.append({
            "module": br["module"], "name": br["name"],
            "owasp": br.get("owasp", ""),
            "status": br.get("status"), "counts": br.get("counts", {}),
            "error": br.get("error"),
        })
    return {
        "server_name": server_name,
        "generated_at": _now(),
        "recommendation": recommendation,
        "repo": {k: repo_info.get(k) for k in
                 ("name", "version", "description", "primary_language",
                  "dependency_count", "entry_point") if k in repo_info},
        "modules": mods,
    }


def recommendation(box_results):
    """DO NOT PROCEED / NEEDS REVIEW / CLEAR TO PROCEED (console parity)."""
    statuses = [(br.get("status") or "").upper().replace("-", "_") for br in box_results]
    if any(s in BLOCK for s in statuses):
        return ("DO NOT PROCEED", "block",
                "At least one module returned a blocking verdict (FAIL / HIGH SUSPICION / ERROR).")
    if any(s in REVIEWY for s in statuses):
        return ("NEEDS REVIEW", "review",
                "Nothing blocking, but at least one module needs a human decision before approval.")
    return ("CLEAR TO PROCEED", "clear",
            "Every module included in this review came back clean.")


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _sev_pill(sev):
    return f'<span class="sev sev-{_esc(sev)}">{_esc(sev)}</span>'


def _verdict_class(status):
    s = (status or "").upper().replace("-", "_")
    if s in BLOCK:
        return "v-fail"
    if s in REVIEWY:
        return "v-review"
    return "v-pass"


def _findings_table(findings):
    if not findings:
        return '<p class="none">No findings for this module.</p>'
    rows = []
    for f in sorted(findings, key=lambda x: -SEV_ORDER.get(x.get("severity", "info"), 0)):
        parts = [f'<div class="f-head">{_sev_pill(f.get("severity"))}'
                 f'<span class="f-layer">{_esc(f.get("layer"))}</span>'
                 f'<span class="f-title">{_esc(f.get("title"))}</span></div>',
                 f'<div class="f-subj"><b>Where:</b> <code>{_esc(f.get("subject"))}</code></div>']
        if f.get("evidence"):
            parts.append(f'<div class="f-ev"><b>Evidence:</b> <code>{_esc(f.get("evidence"))}</code></div>')
        if f.get("impact"):
            parts.append(f'<div class="f-imp"><b>Why it matters:</b> {_esc(f.get("impact"))}</div>')
        if f.get("remediation"):
            parts.append(f'<div class="f-rem"><b>Remediation:</b> {_esc(f.get("remediation"))}</div>')
        rows.append('<div class="finding">' + "".join(parts) + "</div>")
    return "".join(rows)


def _stat_tiles(tiles):
    if not tiles:
        return ""
    cells = "".join(f'<div class="tile"><div class="tile-n">{_esc(t.get("n"))}</div>'
                    f'<div class="tile-l">{_esc(t.get("l"))}</div></div>' for t in tiles)
    return f'<div class="tiles">{cells}</div>'


def _module_section(br):
    res = br.get("result") or {}
    v = res.get("verdict", {})
    status = br.get("status", "ERROR")
    vc = _verdict_class(status)
    head = _esc(v.get("headline") or status)
    body = [f'<section class="module">',
            f'<h2><span class="mid">{_esc(br.get("owasp",""))}</span> {_esc(br["name"])}'
            f'<span class="owasp">{_esc(br.get("owasp",""))}</span></h2>',
            f'<div class="verdict {vc}"><span class="badge">{_esc(status)}</span>'
            f'<span class="vhead">{head}</span></div>']
    if br.get("error"):
        body.append(f'<p class="err">Module error: {_esc(br["error"])}</p>')
    if v.get("rationale"):
        body.append(f'<p class="rationale">{_esc(v.get("rationale"))}</p>')
    if v.get("next_step"):
        body.append(f'<p class="next"><b>Next step:</b> {_esc(v.get("next_step"))}</p>')
    if v.get("note"):
        body.append(f'<p class="note-line">{_esc(v.get("note"))}</p>')
    body.append(_stat_tiles(res.get("stats_tiles")))
    body.append('<div class="findings">' + _findings_table(res.get("findings", [])) + '</div>')
    body.append("</section>")
    return "".join(body)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a1f2b;--mut:#5b6472;--line:#e4e7ec;
--accent:#2d5bff;--pass:#1a7f4b;--passbg:#e7f6ee;--rev:#9a6b00;--revbg:#fdf3dc;
--fail:#b3261e;--failbg:#fbe7e6;--code:#f0f2f5;--pill:#eef1f6;}
:root[data-theme="dark"],:root:not([data-theme="light"]){}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0f1218;--card:#161b24;--ink:#e8ecf3;--mut:#9aa4b2;--line:#252c38;
--accent:#6b8cff;--pass:#4cd08a;--passbg:#12301f;--rev:#e6b64c;--revbg:#31280f;
--fail:#ff6b61;--failbg:#331612;--code:#0d1119;--pill:#1d2430;}}
:root[data-theme="dark"]{--bg:#0f1218;--card:#161b24;--ink:#e8ecf3;--mut:#9aa4b2;
--line:#252c38;--accent:#6b8cff;--pass:#4cd08a;--passbg:#12301f;--rev:#e6b64c;
--revbg:#31280f;--fail:#ff6b61;--failbg:#331612;--code:#0d1119;--pill:#1d2430;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px 80px}
header.rpt{border-bottom:2px solid var(--line);padding-bottom:18px;margin-bottom:8px}
header.rpt h1{margin:0 0 4px;font-size:24px;letter-spacing:-.01em}
.sub{color:var(--mut);font-size:13px}
.reco{margin:22px 0;padding:18px 20px;border-radius:12px;border:1px solid var(--line);
display:flex;gap:14px;align-items:center}
.reco .word{font-size:20px;font-weight:750;letter-spacing:.01em}
.reco.block{background:var(--failbg)}.reco.block .word{color:var(--fail)}
.reco.review{background:var(--revbg)}.reco.review .word{color:var(--rev)}
.reco.clear{background:var(--passbg)}.reco.clear .word{color:var(--pass)}
.reco .why{color:var(--mut);font-size:13.5px}
.metrics{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 26px}
.metric{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:10px 16px;min-width:96px}
.metric .n{font-size:22px;font-weight:700}.metric .l{color:var(--mut);font-size:12px}
table.sum{width:100%;border-collapse:collapse;margin:8px 0 30px;font-size:13.5px;
background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
table.sum th,table.sum td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
table.sum th{background:var(--pill);font-weight:600}
.st{font-weight:700;font-size:12px;padding:2px 8px;border-radius:20px;white-space:nowrap}
.st.v-pass{color:var(--pass);background:var(--passbg)}
.st.v-review{color:var(--rev);background:var(--revbg)}
.st.v-fail{color:var(--fail);background:var(--failbg)}
.module{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px 22px;margin:16px 0}
.module h2{font-size:17px;margin:0 0 12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.mid{font-size:11px;font-weight:700;color:var(--accent);background:var(--pill);
padding:2px 8px;border-radius:6px}
.owasp{margin-left:auto;font-size:11px;color:var(--mut);font-weight:500}
.verdict{display:flex;align-items:center;gap:12px;margin:6px 0 12px}
.badge{font-weight:750;font-size:13px;padding:4px 12px;border-radius:8px}
.verdict.v-pass .badge{color:var(--pass);background:var(--passbg)}
.verdict.v-review .badge{color:var(--rev);background:var(--revbg)}
.verdict.v-fail .badge{color:var(--fail);background:var(--failbg)}
.vhead{color:var(--mut);font-size:13.5px}
.rationale{margin:6px 0}.next,.note-line{color:var(--mut);font-size:13.5px;margin:6px 0}
.err{color:var(--fail);font-size:13.5px}
.tiles{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.tile{background:var(--pill);border-radius:8px;padding:8px 14px;min-width:74px;text-align:center}
.tile-n{font-size:18px;font-weight:700}.tile-l{font-size:11px;color:var(--mut)}
.finding{border:1px solid var(--line);border-left:3px solid var(--accent);
border-radius:8px;padding:11px 13px;margin:9px 0;font-size:13.5px}
.f-head{display:flex;align-items:center;gap:9px;margin-bottom:5px;flex-wrap:wrap}
.f-layer{font-size:11px;color:var(--mut);font-weight:600}
.f-title{font-weight:650}
.f-subj,.f-ev,.f-imp,.f-rem{margin:3px 0;color:var(--ink)}
.f-imp,.f-rem{color:var(--mut)}
code{background:var(--code);padding:1px 6px;border-radius:5px;font-size:12.5px;
word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.sev{font-size:10.5px;font-weight:750;padding:2px 8px;border-radius:20px;text-transform:uppercase}
.sev-critical{color:#fff;background:var(--fail)}
.sev-high{color:var(--fail);background:var(--failbg);border:1px solid var(--fail)}
.sev-medium{color:var(--rev);background:var(--revbg)}
.sev-low{color:var(--mut);background:var(--pill)}
.sev-info{color:var(--mut);background:var(--pill)}
.none{color:var(--mut);font-style:italic}
.toolbar{position:sticky;top:0;background:var(--bg);padding:10px 0;margin:-8px 0 8px;
display:flex;gap:8px;z-index:5}
button{font:inherit;padding:7px 14px;border-radius:8px;border:1px solid var(--line);
background:var(--card);color:var(--ink);cursor:pointer}
button:hover{border-color:var(--accent)}
footer{color:var(--mut);font-size:12px;margin-top:30px;border-top:1px solid var(--line);
padding-top:14px}
@media print{.toolbar{display:none}body{background:#fff}.module,.metric,table.sum{break-inside:avoid}}
"""


def html_report(server_name, box_results, repo_info, reco):
    word, cls, why = reco
    total_f = sum(br.get("counts", {}).get("total", 0) for br in box_results)
    crit = sum(br.get("counts", {}).get("critical", 0) for br in box_results)
    high = sum(br.get("counts", {}).get("high", 0) for br in box_results)
    sum_rows = []
    for br in box_results:
        vc = _verdict_class(br.get("status"))
        c = br.get("counts", {})
        sum_rows.append(
            f'<tr><td><b>{_esc(br["name"])}</b></td>'
            f'<td><span class="st {vc}">{_esc(br.get("status"))}</span></td>'
            f'<td>{_esc(c.get("total",0))}</td><td>{_esc(c.get("critical",0))}</td>'
            f'<td>{_esc(c.get("high",0))}</td><td>{_esc(br.get("owasp",""))}</td></tr>')
    modules_html = "".join(_module_section(br) for br in box_results)
    rn = _esc(repo_info.get("name") or server_name)
    rdesc = _esc(repo_info.get("description") or "")
    rlang = _esc(repo_info.get("primary_language") or "unknown")
    rver = _esc(repo_info.get("version") or "—")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Security Review — {rn}</title><style>{CSS}</style></head><body>
<div class="wrap">
<div class="toolbar"><button onclick="window.print()">🖨️ Print / Save as PDF</button>
<button onclick="document.documentElement.setAttribute('data-theme',
document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark')">◐ Theme</button></div>
<header class="rpt"><h1>MCP Security Review — {rn}</h1>
<div class="sub">Server: <b>{_esc(server_name)}</b> · Version {rver} · {rlang} ·
Generated {_now()} · Local sandboxed review (OWASP MCP Top 10 aligned)</div></header>
<div class="reco {cls}"><div class="word">{_esc(word)}</div><div class="why">{_esc(why)}</div></div>
<div class="metrics">
<div class="metric"><div class="n">{len(box_results)}</div><div class="l">Modules</div></div>
<div class="metric"><div class="n">{total_f}</div><div class="l">Findings</div></div>
<div class="metric"><div class="n">{crit}</div><div class="l">Critical</div></div>
<div class="metric"><div class="n">{high}</div><div class="l">High</div></div></div>
{'<p class="sub">'+rdesc+'</p>' if rdesc else ''}
<table class="sum"><thead><tr><th>Module</th><th>Verdict</th><th>Findings</th>
<th>Critical</th><th>High</th><th>OWASP</th></tr></thead><tbody>{''.join(sum_rows)}</tbody></table>
{modules_html}
<footer>Generated by the MCP Security Review CLI. Every module runs the same
detector logic and verdict language as the web console. A static scan is a
snapshot in time — re-run on every change. This is one layer of defence-in-depth,
not a guarantee.</footer>
</div></body></html>"""


# --------------------------------------------------------------------------
# Markdown report (readable in the PR, the Actions Job Summary, or any editor
# -- no download, no HTML rendering needed)
# --------------------------------------------------------------------------
def _md_field(label, text):
    if not text:
        return ""
    return f"  - **{label}:** {str(text).replace(chr(10), ' ')}\n"


def markdown_report(server_name, box_results, repo_info, reco):
    word, cls, why = reco
    badge = {"block": "🔴", "review": "🟡", "clear": "🟢"}.get(cls, "⚪")
    lines = [
        f"# MCP Security Review — {_esc(server_name) if False else server_name}",
        "",
        f"{badge} **{word}** — {why}",
        "",
        f"_Generated {_now()}_",
        "",
        "| Module | Verdict | Findings | Critical | High | OWASP |",
        "|---|---|---|---|---|---|",
    ]
    for br in box_results:
        counts = br.get("counts") or (br.get("result") or {}).get("verdict", {}).get("counts", {}) or {}
        lines.append(
            f"| {br.get('name','')} | {br.get('status','')} | "
            f"{counts.get('total', 0)} | {counts.get('critical', 0)} | "
            f"{counts.get('high', 0)} | {br.get('owasp','')} |"
        )
    lines.append("")

    for br in box_results:
        res = br.get("result") or {}
        v = res.get("verdict", {})
        status = br.get("status", "ERROR")
        name = br.get("name", "")
        owasp = br.get("owasp", "")
        counts = br.get("counts") or v.get("counts", {}) or {}
        lines.append(f"## {name} — `{status}` ({owasp})")
        lines.append("")
        if br.get("error"):
            lines.append(f"> ⚠️ **error:** {br['error']}")
            lines.append("")
            continue
        if v.get("rationale"):
            lines.append(f"> {v['rationale']}")
            lines.append("")
        if v.get("note"):
            lines.append(f"> {v['note']}")
            lines.append("")
        lines.append(
            f"**Findings:** {counts.get('total', 0)}  ·  "
            f"**Critical:** {counts.get('critical', 0)}  ·  "
            f"**High:** {counts.get('high', 0)}  ·  "
            f"**Medium:** {counts.get('medium', 0)}"
        )
        lines.append("")
        findings = sorted(res.get("findings", []),
                           key=lambda x: -SEV_ORDER.get(x.get("severity", "info"), 0))
        if not findings:
            lines.append("✓ no findings for this module")
            lines.append("")
            continue
        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "info").upper()
            layer = f.get("layer", "")
            title = f.get("title", "")
            lines.append(f"**{i}. [{sev}]{' ' + layer if layer else ''} — {title}**")
            lines.append("")
            for fl in (_md_field("where", f.get("subject")),
                       _md_field("evidence", f.get("evidence")),
                       _md_field("why", f.get("impact")),
                       _md_field("fix", f.get("remediation"))):
                if fl:
                    lines.append(fl.rstrip("\n"))
            lines.append("")

    lines.append("---")
    lines.append("_Generated by the MCP Security Review CLI. Every module runs the same detector "
                  "logic and verdict language as the web console. A static scan is a snapshot in "
                  "time — re-run on every change. This is one layer of defence-in-depth, not a "
                  "guarantee._")
    return "\n".join(l for l in lines if l is not None)


def write_all(out_dir, server_name, box_results, repo_info):
    """Write every artifact into out_dir. Returns dict of written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = _slug(server_name)
    written = {"per_box": {}}
    # per-box json + sarif  (build names as strings — with_suffix() would eat ".boxNN")
    for br in box_results:
        p_json = out_dir / f"{slug}.{br['module']}.json"
        p_sarif = out_dir / f"{slug}.{br['module']}.sarif"
        p_json.write_text(
            json.dumps({"meta": {"module": br["module"], "name": br["name"],
                                 "status": br.get("status"), "owasp": br.get("owasp")},
                        "result": br.get("result"), "error": br.get("error"),
                        "runlog": br.get("runlog", [])}, indent=2))
        p_sarif.write_text(json.dumps(sarif_document([br]), indent=2))
        written["per_box"][br["module"]] = str(p_json)
    reco = recommendation(box_results)
    # combined
    p_sarif = out_dir / f"{slug}.report.sarif"
    p_sarif.write_text(json.dumps(sarif_document(box_results), indent=2))
    p_json = out_dir / f"{slug}.report.json"
    p_json.write_text(json.dumps(summary_json(server_name, box_results, repo_info, reco[0]), indent=2))
    p_html = out_dir / f"{slug}.report.html"
    p_html.write_text(html_report(server_name, box_results, repo_info, reco))
    p_md = out_dir / f"{slug}.report.md"
    p_md.write_text(markdown_report(server_name, box_results, repo_info, reco))
    written.update({"sarif": str(p_sarif), "summary": str(p_json),
                    "html": str(p_html), "markdown": str(p_md), "recommendation": reco})
    return written
