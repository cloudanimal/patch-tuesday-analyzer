#!/usr/bin/env python3
"""Generate a Patch Tuesday triage briefing from the MSRC CVRF API.

The MSRC data is organized for document publishing, not triage. This inverts
it: exploitation status first, severity second, everything else after.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone

import requests

API = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
HEADERS = {"Accept": "application/json"}

# Threat 'Type' 1 entries carry exploitation status in their Description
EXPLOITED_MARKERS = ("Exploitation Detected", "Exploitation More Likely")


def fetch(month: str) -> dict:
    resp = requests.get(API.format(month=month), headers=HEADERS, timeout=60)
    if resp.status_code == 404:
        sys.exit(f"error: no release found for {month} (format: YYYY-MMM, e.g. 2025-Jun)")
    resp.raise_for_status()
    return resp.json()


def parse_vulns(doc: dict) -> list[dict]:
    vulns = []
    for vuln in doc.get("Vulnerability", []):
        cve = vuln.get("CVE", "")
        if not cve:
            continue
        title = (vuln.get("Title") or {}).get("Value", "")

        severity = ""
        exploitation = ""
        publicly_disclosed = False
        exploited_in_wild = False
        for threat in vuln.get("Threats", []):
            desc = (threat.get("Description") or {}).get("Value", "")
            if threat.get("Type") == 3 and not severity:  # Severity
                severity = desc
            if threat.get("Type") == 1:  # Exploit status
                if "Exploitation" in desc:
                    exploitation = desc
                if "Exploited:Yes" in desc.replace(" ", ""):
                    exploited_in_wild = True
                if "PubliclyDisclosed:Yes" in desc.replace(" ", ""):
                    publicly_disclosed = True

        cvss = 0.0
        for score_set in vuln.get("CVSSScoreSets", []):
            cvss = max(cvss, float(score_set.get("BaseScore", 0)))

        vulns.append({
            "cve": cve,
            "title": title,
            "severity": severity or "Unknown",
            "cvss": cvss,
            "exploitation": exploitation,
            "exploited": exploited_in_wild or "Exploitation Detected" in exploitation,
            "disclosed": publicly_disclosed,
        })
    return vulns


def product_families(doc: dict) -> Counter:
    counts: Counter = Counter()
    tree = doc.get("ProductTree", {}).get("Branch", [])
    # The first branch level groups by product family
    for branch in tree:
        for family in branch.get("Items", []):
            name = family.get("Name", "Other")
            counts[name] = len(family.get("Items", []))
    return counts


def render_text(month: str, vulns: list[dict], families: Counter) -> str:
    crits = [v for v in vulns if v["severity"] == "Critical"]
    hot = [v for v in vulns if v["exploited"] or v["disclosed"]]
    top = sorted(
        (v for v in crits if "More Likely" in v["exploitation"] or v["exploited"]),
        key=lambda v: -v["cvss"],
    )

    lines = [
        f"Patch Tuesday Briefing - {month}",
        "=" * 33,
        f"Total CVEs: {len(vulns)}    Critical: {len(crits)}    "
        f"Zero-day/disclosed: {len(hot)}",
        "",
    ]
    if hot:
        lines.append("ZERO-DAYS / EXPLOITED:")
        for v in sorted(hot, key=lambda v: -v["cvss"]):
            flags = []
            if v["exploited"]:
                flags.append("Exploitation Detected")
            if v["disclosed"]:
                flags.append("Publicly Disclosed")
            lines.append(f"  {v['cve']}  {v['title']} - {', '.join(flags)}")
        lines.append("")
    if top:
        lines.append("TOP PRIORITY (Critical + likely/active exploitation):")
        for v in top[:10]:
            lines.append(f"  {v['cve']}  {v['title'][:50]:<50} CVSS {v['cvss']:.1f}")
        lines.append("")
    if families:
        lines.append("BY PRODUCT FAMILY:")
        for name, count in families.most_common(8):
            lines.append(f"  {name:<30} {count}")
    return "\n".join(lines)


def render_markdown(month: str, vulns: list[dict], families: Counter) -> str:
    crits = [v for v in vulns if v["severity"] == "Critical"]
    hot = [v for v in vulns if v["exploited"] or v["disclosed"]]
    lines = [
        f"# {month} Patch Tuesday Briefing",
        "",
        f"**{len(vulns)} CVEs** | **{len(crits)} Critical** | "
        f"**{len(hot)} zero-day/disclosed**",
        "",
    ]
    if hot:
        lines += ["## Patch first", "", "| CVE | Issue | Status | CVSS |", "|---|---|---|---|"]
        for v in sorted(hot, key=lambda v: -v["cvss"]):
            status = "Exploited" if v["exploited"] else "Disclosed"
            lines.append(f"| {v['cve']} | {v['title']} | {status} | {v['cvss']:.1f} |")
        lines.append("")
    lines += ["## Critical CVEs", ""]
    for v in sorted(crits, key=lambda v: -v["cvss"]):
        lines.append(f"- **{v['cve']}** — {v['title']} (CVSS {v['cvss']:.1f})")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--month", default=datetime.now(timezone.utc).strftime("%Y-%b"),
                        help="release month, e.g. 2025-Jun (default: current month)")
    parser.add_argument("--format", choices=["text", "markdown"], default="text")
    args = parser.parse_args()

    doc = fetch(args.month)
    vulns = parse_vulns(doc)
    families = product_families(doc)

    renderer = render_markdown if args.format == "markdown" else render_text
    print(renderer(args.month, vulns, families))


if __name__ == "__main__":
    main()
