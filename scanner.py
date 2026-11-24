#!/usr/bin/env python3
"""
scanner.py — Web Security Scanner (CLI entry point).

Crawls a target, then runs both ACTIVE checks (SQL injection, reflected XSS on
forms and URL parameters) and PASSIVE checks (security headers, cookie flags,
CSRF tokens). Writes a JSON report and a self-contained HTML report.

Usage:
    python3 scanner.py http://testphp.vulnweb.com
    python3 scanner.py https://example.com --max-pages 20 --output-dir reports
    python3 scanner.py https://example.com --passive-only

Only scan systems you own or are explicitly authorized to test.
"""

import os
import sys
import argparse
from datetime import datetime

import crawler
import checks
import report

HERE = os.path.dirname(os.path.abspath(__file__))


def load_payloads(name):
    path = os.path.join(HERE, "payloads", name)
    try:
        with open(path, encoding="utf-8") as f:
            return [line for line in f.read().splitlines() if line.strip()]
    except OSError:
        return []


def run(target, max_pages, delay, active, passive):
    session = crawler.make_session()
    sqli_payloads = load_payloads("sqli.txt")

    findings = []
    pages = 0
    seen_forms = set()

    print(f"[*] Target: {target}")
    for page in crawler.crawl(session, target, max_pages=max_pages, delay=delay):
        pages += 1
        print(f"  [+] {page['url']}")

        if passive:
            findings += checks.check_security_headers(page["response"], page["url"])
            findings += checks.check_cookies(page["response"], page["url"])
            for form in page["forms"]:
                findings += checks.check_csrf(form, page["url"])

        if active:
            # Forms
            for form in page["forms"]:
                key = (form["action"], form["method"],
                       tuple(sorted(i["name"] for i in form["inputs"])))
                if key in seen_forms or not form["inputs"]:
                    continue
                seen_forms.add(key)
                base = {i["name"]: "test" for i in form["inputs"]}
                findings += checks.test_sqli(session, form["action"], form["method"],
                                             base, sqli_payloads)
                findings += checks.test_xss(session, form["action"], form["method"], base)
            # URL query parameters
            for base_url, params in page["param_targets"]:
                findings += checks.test_sqli(session, base_url, "get", params, sqli_payloads)
                findings += checks.test_xss(session, base_url, "get", params)

    scan_data = {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pages_scanned": pages,
        "findings": findings,
    }
    scan_data["summary"] = report.build_summary(findings)
    return scan_data


def main():
    ap = argparse.ArgumentParser(description="Web security scanner (active + passive).")
    ap.add_argument("target", help="Target URL, e.g. https://example.com")
    ap.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl (default 10)")
    ap.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds")
    ap.add_argument("--output-dir", default="reports", help="Where to write reports")
    ap.add_argument("--passive-only", action="store_true", help="Skip active injection tests")
    ap.add_argument("--active-only", action="store_true", help="Skip passive checks")
    args = ap.parse_args()

    if not args.target.startswith(("http://", "https://")):
        args.target = "http://" + args.target

    active = not args.passive_only
    passive = not args.active_only

    scan = run(args.target, args.max_pages, args.delay, active, passive)

    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "scan_report.json")
    html_path = os.path.join(args.output_dir, "scan_report.html")
    report.write_json(scan, json_path)
    report.write_html(scan, html_path)

    s = scan["summary"]
    print(f"\n[*] Done. {s['total']} finding(s): "
          + ", ".join(f"{k} {v}" for k, v in sorted(s['by_severity'].items())))
    print(f"[*] JSON: {json_path}")
    print(f"[*] HTML: {html_path}")


if __name__ == "__main__":
    main()
