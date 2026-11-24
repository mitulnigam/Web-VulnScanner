"""
visualize_results.py — optional Matplotlib charts from a scan report.

Reads reports/scan_report.json and saves two PNGs (no GUI needed):
  reports/chart_types.png      findings by type
  reports/chart_severity.png   findings by severity

The HTML report (scan_report.html) already includes a visual summary; this is
here for anyone who wants standalone chart images.
"""

import os
import sys
import json
from collections import Counter

import matplotlib
matplotlib.use("Agg")  # headless: render to file, never open a window
import matplotlib.pyplot as plt

REPORT = sys.argv[1] if len(sys.argv) > 1 else "reports/scan_report.json"
OUT_DIR = os.path.dirname(REPORT) or "."

SEV_COLORS = {"High": "#e5484d", "Medium": "#f5a623", "Low": "#4a9eda", "Info": "#8b93a7"}

with open(REPORT, encoding="utf-8") as f:
    data = json.load(f)

findings = data.get("findings", [])
if not findings:
    print("No findings to chart.")
    sys.exit(0)

types = Counter(f["type"] for f in findings)
severities = Counter(f["severity"] for f in findings)

# Bar chart — findings by type
plt.figure(figsize=(9, 4.5))
plt.bar(list(types.keys()), list(types.values()), color="#58a6ff")
plt.title("Findings by type")
plt.ylabel("Count")
plt.xticks(rotation=30, ha="right")
plt.tight_layout()
bar_path = os.path.join(OUT_DIR, "chart_types.png")
plt.savefig(bar_path, dpi=120)

# Pie chart — findings by severity
order = [s for s in ("High", "Medium", "Low", "Info") if s in severities]
plt.figure(figsize=(5, 5))
plt.pie([severities[s] for s in order], labels=order,
        colors=[SEV_COLORS[s] for s in order], autopct="%1.0f%%", startangle=90)
plt.title("Findings by severity")
plt.tight_layout()
pie_path = os.path.join(OUT_DIR, "chart_severity.png")
plt.savefig(pie_path, dpi=120)

print(f"Saved {bar_path}")
print(f"Saved {pie_path}")
