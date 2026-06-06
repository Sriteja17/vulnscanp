"""HTML report generator with embedded styling, charts, and filtering."""
import os
import html as html_lib
from vulnscan5g.models.scan_result import ScanResult


def _row(i: int, f) -> str:
    sev = f.severity.value
    fname = f.file_path.replace("\\", "/").split("/")[-1]
    desc_escaped = html_lib.escape(f.description)
    rec_escaped = html_lib.escape(f.recommendation)
    return (
        f'<tr class="row-{sev}" data-sev="{sev}">'
        f"<td>{i}</td>"
        f'<td><span class="sev sev-{sev}">{sev}</span></td>'
        f"<td>{f.rule_id}</td><td>{f.cwe_id}</td>"
        f"<td>{fname}</td><td>{f.line}</td>"
        f"<td>{html_lib.escape(f.vuln_type)}</td>"
        f"<td>{rec_escaped}</td>"
        f"<td>{f.detector}</td>"
        f"</tr>"
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan5G Report</title>
<style>
:root {{
  --bg: #0f172a; --surface: #1e293b; --border: #334155;
  --text: #e2e8f0; --dim: #94a3b8;
  --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #38bdf8; --info: #64748b;
}}
* {{ margin:0; padding:0; box-sizing:border-box }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem }}
h1 {{ font-size:1.8rem; margin-bottom:.3rem; color:#38bdf8 }}
.subtitle {{ color:var(--dim); margin-bottom:1.5rem; font-size:.9rem }}

/* Summary Cards */
.summary {{ display:flex; gap:.8rem; margin:1.2rem 0; flex-wrap:wrap }}
.card {{ background:var(--surface); border-radius:12px; padding:1rem 1.5rem; min-width:110px;
         text-align:center; border:1px solid var(--border); cursor:pointer; transition: all .2s }}
.card:hover {{ transform:translateY(-2px); box-shadow:0 4px 20px rgba(0,0,0,.3) }}
.card.active {{ border-width:2px }}
.card .num {{ font-size:2rem; font-weight:700 }}
.card.critical .num {{ color:var(--critical) }} .card.critical.active {{ border-color:var(--critical) }}
.card.high .num {{ color:var(--high) }} .card.high.active {{ border-color:var(--high) }}
.card.medium .num {{ color:var(--medium) }} .card.medium.active {{ border-color:var(--medium) }}
.card.low .num {{ color:var(--low) }} .card.low.active {{ border-color:var(--low) }}
.card.all .num {{ color:#38bdf8 }} .card.all.active {{ border-color:#38bdf8 }}

/* Severity Bar */
.sev-bar {{ display:flex; height:8px; border-radius:4px; overflow:hidden; margin:1rem 0 }}
.sev-bar span {{ height:100% }}

/* Search */
.controls {{ display:flex; gap:1rem; margin:1rem 0; align-items:center }}
.search {{ background:var(--surface); border:1px solid var(--border); color:var(--text);
           padding:.5rem 1rem; border-radius:8px; font-size:.9rem; width:300px }}
.search:focus {{ outline:none; border-color:#38bdf8 }}
.count {{ color:var(--dim); font-size:.85rem }}

/* Table */
table {{ width:100%; border-collapse:collapse; margin-top:.5rem; background:var(--surface);
         border-radius:12px; overflow:hidden }}
th {{ background:#334155; padding:.7rem 1rem; text-align:left; font-size:.8rem;
      text-transform:uppercase; letter-spacing:.05em; position:sticky; top:0 }}
td {{ padding:.6rem 1rem; border-bottom:1px solid var(--border); font-size:.85rem }}
tr:hover td {{ background:#263347 }}
tr.hidden {{ display:none }}
.sev {{ padding:2px 10px; border-radius:6px; font-weight:600; font-size:.75rem; text-transform:uppercase }}
.sev-critical {{ background:#7f1d1d; color:#fca5a5 }}
.sev-high {{ background:#7c2d12; color:#fdba74 }}
.sev-medium {{ background:#713f12; color:#fde047 }}
.sev-low {{ background:#164e63; color:#67e8f9 }}
.sev-info {{ background:#1e293b; color:#94a3b8 }}

footer {{ margin-top:2rem; color:var(--dim); font-size:.8rem; text-align:center }}
</style></head><body>

<h1>&#128737; VulnScan5G — Vulnerability Report</h1>
<p class="subtitle">Target: {target} &nbsp;|&nbsp; Files: {files_scanned} &nbsp;|&nbsp; Duration: {duration}s</p>

<div class="sev-bar">
  <span style="width:{crit_pct}%;background:var(--critical)"></span>
  <span style="width:{high_pct}%;background:var(--high)"></span>
  <span style="width:{med_pct}%;background:var(--medium)"></span>
  <span style="width:{low_pct}%;background:var(--low)"></span>
</div>

<div class="summary">
  <div class="card all active" onclick="filterSev('all')"><div class="num">{total}</div><div>All</div></div>
  <div class="card critical" onclick="filterSev('critical')"><div class="num">{critical}</div><div>Critical</div></div>
  <div class="card high" onclick="filterSev('high')"><div class="num">{high}</div><div>High</div></div>
  <div class="card medium" onclick="filterSev('medium')"><div class="num">{medium}</div><div>Medium</div></div>
  <div class="card low" onclick="filterSev('low')"><div class="num">{low}</div><div>Low</div></div>
</div>

<div class="controls">
  <input type="text" class="search" id="search" placeholder="Search by file, CWE, rule..." oninput="filterSearch()">
  <span class="count" id="count">Showing {total} findings</span>
</div>

<table>
<thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>CWE</th><th>File</th><th>Line</th><th>Vulnerability</th><th>Recommendation</th><th>Detector</th></tr></thead>
<tbody id="tbody">{rows}</tbody>
</table>

<footer>Generated by VulnScan5G v1.0.0 &nbsp;|&nbsp; 3 detectors: regex + pycparser AST + tree-sitter</footer>

<script>
let activeSev = 'all';

function filterSev(sev) {{
  activeSev = sev;
  document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
  document.querySelector('.card.' + sev).classList.add('active');
  applyFilters();
}}

function filterSearch() {{ applyFilters(); }}

function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  let shown = 0;
  document.querySelectorAll('#tbody tr').forEach(row => {{
    const sevMatch = activeSev === 'all' || row.dataset.sev === activeSev;
    const textMatch = !q || row.textContent.toLowerCase().includes(q);
    const visible = sevMatch && textMatch;
    row.classList.toggle('hidden', !visible);
    if (visible) shown++;
  }});
  document.getElementById('count').textContent = 'Showing ' + shown + ' findings';
}}
</script>
</body></html>"""


def save_html(result: ScanResult, output_path: str):
    s = result.summary()
    rows = "\n".join(_row(i, f) for i, f in enumerate(result.findings, 1))
    total = s["total_findings"] or 1
    html = _TEMPLATE.format(
        target=html_lib.escape(str(s["target"])),
        files_scanned=s["files_scanned"],
        duration=s["duration_seconds"],
        total=s["total_findings"],
        critical=s["critical"], high=s["high"], medium=s["medium"], low=s["low"],
        crit_pct=round(s["critical"] / total * 100),
        high_pct=round(s["high"] / total * 100),
        med_pct=round(s["medium"] / total * 100),
        low_pct=round(s["low"] / total * 100),
        rows=rows,
    )
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
