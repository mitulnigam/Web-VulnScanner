"""
report.py — write scan results as JSON and as a self-contained HTML report.

The HTML report has no external dependencies (CSS is inline, charts are drawn
with plain CSS bars), so it opens anywhere and is easy to share.
"""

import json
import html
from collections import Counter

SEV_COLOR = {"High": "#e5484d", "Medium": "#f5a623", "Low": "#4a9eda", "Info": "#8b93a7"}
SEV_RANK = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}


def build_summary(findings):
    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(by_sev),
        "by_category": dict(by_cat),
    }


def write_json(scan_data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2)


def _esc(s):
    return html.escape(str(s or ""))


def _severity_bar(by_severity):
    total = sum(by_severity.values()) or 1
    segments = ""
    for sev in ("High", "Medium", "Low", "Info"):
        n = by_severity.get(sev, 0)
        if n:
            pct = 100 * n / total
            segments += (f'<div style="width:{pct:.1f}%;background:{SEV_COLOR[sev]}" '
                         f'title="{sev}: {n}"></div>')
    return f'<div class="sevbar">{segments}</div>'


def write_html(scan_data, path):
    findings = sorted(scan_data["findings"],
                      key=lambda f: SEV_RANK.get(f["severity"], 0), reverse=True)
    s = scan_data["summary"]
    by_sev = s["by_severity"]

    cards = ""
    for sev in ("High", "Medium", "Low", "Info"):
        cards += (f'<div class="card"><div class="n" style="color:{SEV_COLOR[sev]}">'
                  f'{by_sev.get(sev, 0)}</div><div class="l">{sev}</div></div>')

    rows = ""
    for f in findings:
        color = SEV_COLOR.get(f["severity"], "#8b93a7")
        evidence = (f'<code>{_esc(f["evidence"])}</code>' if f["evidence"] else "")
        payload = (f'<div class="pl">payload: <code>{_esc(f["payload"])}</code></div>'
                   if f["payload"] else "")
        rows += f"""
        <tr>
          <td><span class="sev" style="background:{color}22;color:{color};border-color:{color}55">{_esc(f['severity'])}</span></td>
          <td><strong>{_esc(f['type'])}</strong><div class="cat">{_esc(f['category'])}</div></td>
          <td class="url">{_esc(f['url'])}</td>
          <td>{_esc(f['detail'])}{payload}{(' ' + evidence) if evidence else ''}</td>
        </tr>"""

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report — {_esc(scan_data['target'])}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --border:#2a3140;
           --text:#e6edf3; --muted:#8b93a7; --mono:ui-monospace,Menlo,Consolas,monospace; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:1000px; margin:0 auto; padding:32px 24px 60px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .target {{ font-family:var(--mono); color:#58a6ff; font-size:14px; }}
  .meta {{ color:var(--muted); font-size:13px; margin:6px 0 24px; }}
  .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px; text-align:center; }}
  .card .n {{ font-size:34px; font-weight:700; line-height:1; }}
  .card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; margin-top:6px; }}
  .sevbar {{ display:flex; height:12px; border-radius:6px; overflow:hidden; border:1px solid var(--border); margin-bottom:26px; }}
  .sevbar div {{ height:100%; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); padding:12px; background:var(--panel2); }}
  td {{ padding:13px 12px; border-top:1px solid var(--border); vertical-align:top; font-size:14px; }}
  .sev {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:700; border:1px solid; }}
  .cat {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.5px; margin-top:3px; }}
  .url {{ font-family:var(--mono); font-size:12px; color:#58a6ff; word-break:break-all; max-width:230px; }}
  code {{ font-family:var(--mono); font-size:12px; background:#0000003d; border:1px solid var(--border); border-radius:5px; padding:1px 6px; word-break:break-all; }}
  .pl {{ color:var(--muted); font-size:12px; margin-top:5px; }}
  .empty {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:30px; text-align:center; color:#3fb950; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:24px; text-align:center; }}
</style></head>
<body><div class="wrap">
  <h1>Web Security Scan Report</h1>
  <div class="target">{_esc(scan_data['target'])}</div>
  <div class="meta">Scanned {_esc(scan_data['scan_time'])} &middot; {scan_data['pages_scanned']} page(s) &middot; {s['total']} finding(s)</div>
  <div class="cards">{cards}</div>
  {_severity_bar(by_sev)}
  {('<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Detail</th></tr></thead><tbody>' + rows + '</tbody></table>') if findings else '<div class="empty">No issues detected.</div>'}
  <footer>Generated by web-vuln-scanner &middot; for authorized testing only</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
