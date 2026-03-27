# Security Prioritizer

Correlates vulnerability data from Tenable, Wiz, CISA KEV, and phpIPAM to produce a ranked risk report.

## When to use
Use when the user asks to:
- Prioritize findings or generate a risk report
- Identify the top vulnerabilities to fix
- Show CISA KEV findings that are externally visible
- Correlate Tenable and Wiz findings

## Steps

1. Read `workflows/security-prioritizer.md` for the full SQL query and scoring model.
2. Execute the query using the `postgres-mcp-server` MCP tool.
3. For each result in the top findings, explain **why** it ranked high:
   - "In CISA KEV and externally visible — patch immediately"
   - "Confirmed by both Tenable and Wiz on a management subnet"
   - "Flagged malicious by VirusTotal — active exploitation likely"
4. Default output: top 20 findings. Apply user-requested filters (e.g. "only CISA KEV", "only cloud") by adding a `WHERE` clause before the `ORDER BY`.

## Scoring Model

| Criteria | Points |
|---|---|
| Base CVSS score | 0–10 |
| CISA KEV | +100 |
| External visibility (ASM) | +50 |
| VirusTotal malicious (≥5 vendors) | +50 |
| Management/OOB subnet (phpIPAM) | +30 |
| Gateway device (phpIPAM) | +20 |
| Cross-tool confirmation (Tenable AND Wiz) | +20 |

## Required Tables
`tenable_findings`, `tenable_assets`, `tenable_asm_assets`, `wiz_vulnerabilities`, `wiz_inventory`, `cisa_kev`, `phpipam_assets`, `vt_results`
