## Web Security Scanner

A Python web security scanner that crawls a target and runs both **active** and
**passive** checks, then produces a styled HTML report and a JSON report.

- **Active checks** (send test payloads): SQL injection and reflected XSS, on
  both HTML forms and URL query parameters.
- **Passive checks** (inspect responses only): missing HTTP security headers,
  insecure cookie flags, and forms with no CSRF token.

It began as a form-only SQLi/XSS tester and was extended into a broader
security-posture scanner, with higher-accuracy detection and a shareable report.

## Features

- Crawls internal links, discovers forms (with field types) and injectable URL parameters
- **SQL injection** — error-based, with a **baseline comparison** so a page that
  already shows a DB-style string isn't falsely flagged
- **Reflected XSS** — confirmed by checking that a marker with `< " >` is
  reflected **unescaped**, not merely echoed
- **Security headers** — flags missing CSP, HSTS (HTTPS only), X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, plus `Server`/`X-Powered-By` disclosure
- **Cookies** — flags missing HttpOnly, Secure (HTTPS), and SameSite
- **CSRF** — flags POST forms with no hidden token field
- **Reports** — a self-contained HTML report (severity summary + findings table)
  and a JSON report; optional Matplotlib PNG charts
- Polite by default: custom User-Agent, request delay, and form de-duplication

## Project structure

- `scanner.py` — CLI entry point; orchestrates the scan and writes reports
- `crawler.py` — page fetching, form discovery, URL-parameter extraction
- `checks.py` — active (SQLi, XSS) and passive (headers, cookies, CSRF) checks
- `report.py` — JSON and HTML report generation
- `visualize_results.py` — optional Matplotlib charts from the JSON report
- `payloads/sqli.txt`, `payloads/xss.txt` — payload lists (one per line)
- `reports/` — generated output (git-ignored)

## Setup

```bash
git clone https://github.com/mitulnigam/web-vuln-scanner.git
cd web-vuln-scanner

python -m venv venv
# Windows:  venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
# full scan (active + passive)
python scanner.py http://testphp.vulnweb.com

# limit crawl depth, choose an output folder
python scanner.py https://example.com --max-pages 20 --output-dir reports

# passive posture check only (no payloads sent)
python scanner.py https://example.com --passive-only
```

Options: `--max-pages N`, `--delay SECONDS`, `--output-dir DIR`,
`--passive-only`, `--active-only`.

Reports are written to `reports/scan_report.html` and `reports/scan_report.json`.
Open the HTML file in a browser to view the results.

### Optional charts

```bash
python visualize_results.py                 # reads reports/scan_report.json
# saves reports/chart_types.png and reports/chart_severity.png
```

## How detection avoids false positives

- **SQLi**: the scanner first fetches a clean baseline response. A finding is
  raised only when a database-error signature appears in the injected response
  **and was not** in the baseline. The signature list uses specific phrases
  (e.g. "you have an error in your sql syntax"), not broad words like "warning".
- **XSS**: the marker contains `< " >`. It is reported only if those characters
  come back **unencoded**, which indicates the output isn't being escaped.

## Report format (JSON)

```json
{
  "target": "http://127.0.0.1:5055",
  "scan_time": "2026-11-24 06:24:16",
  "pages_scanned": 4,
  "findings": [
    {
      "category": "injection",
      "type": "SQL Injection",
      "severity": "High",
      "url": "http://127.0.0.1:5055/product",
      "detail": "Parameter 'id' returned a database error when injected.",
      "evidence": "You have an error in your SQL syntax",
      "payload": "' OR '1'='1"
    }
  ],
  "summary": { "total": 26, "by_severity": {"High": 1, "Medium": 8, "Low": 13, "Info": 4} }
}
```

## Notes and limitations

- SQLi detection is error-based; it does not cover blind/boolean or time-based
  injection. XSS detection covers reflected XSS, not stored or DOM-based.
- Only internal links (same domain as the start URL) are crawled.
- This is a learning/triage tool, not a replacement for a professional scanner.

## Responsible use

Scan only:
- Applications you own
- Applications you have explicit permission to test
- Intentionally vulnerable labs such as DVWA, bWAPP, and the OWASP/Acunetix test sites
