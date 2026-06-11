# Patch Tuesday Analyzer

Pull Microsoft's monthly security release from the [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/) and generate a prioritized briefing: CVE counts by severity, zero-days, actively exploited vulnerabilities, and the products that need attention first.

Built to answer the question every security leader gets on the second Tuesday of the month: **"What do we need to patch *now*?"**

## Usage

```bash
pip install -r requirements.txt

# Current month
python analyze.py

# Specific month
python analyze.py --month 2025-Jun

# Markdown briefing (ready to paste into Slack/Teams/LinkedIn)
python analyze.py --month 2025-Jun --format markdown > briefing.md
```

No API key required — the MSRC CVRF API is public.

## Example output

```
Patch Tuesday Briefing - 2025-Jun
=================================
Total CVEs: 66    Critical: 9    Important: 56

ZERO-DAYS / EXPLOITED:
  CVE-2025-33053  WebDAV RCE - Exploitation Detected
  CVE-2025-33073  SMB Client EoP - Publicly Disclosed

TOP PRIORITY (Critical + Exploitation More Likely):
  CVE-2025-xxxxx  Windows KDC Proxy RCE        CVSS 8.1
  ...

BY PRODUCT FAMILY:
  Windows         48
  Office          11
  ...
```

## Why this exists

Patch Tuesday summaries are scattered across vendor blogs and paywalled feeds. The raw data is free in the MSRC API — it's just shaped badly for triage (CVRF XML/JSON keyed by document structure, not by "what should I do"). This tool inverts it: exploitation status first, severity second, noise last.

## License

MIT
