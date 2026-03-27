---
name: security-prioritizer
description: Security data correlation and prioritization for Tenable, Wiz, CISA KEV, and phpIPAM data. Use when the user wants to identify the highest risk findings based on exploitation status, visibility, and network context.
---

# Security Prioritizer

This skill enables Gemini CLI to act as a security analyst by correlating vulnerability data from multiple sources (Tenable, Wiz, CISA KEV, phpIPAM) to provide a prioritized action report.

## Prerequisites

- PostgreSQL MCP server connected with the following tables:
  - `public.tenable_findings`
  - `public.tenable_assets`
  - `public.tenable_asm_assets`
  - `public.wiz_vulnerabilities`
  - `public.wiz_inventory`
  - `public.cisa_kev`
  - `public.phpipam_assets`
  - `public.vt_results` (columns: `target`, `malicious` — populated by the `virustotal-checker` skill)

## Workflows

### Generating a Prioritization Report

When asked to prioritize findings or generate a risk report:

1.  **Load Logic**: Reference [references/logic.md](references/logic.md) for the prioritization scoring system and SQL query.
2.  **Execute Query**: Use the `mcp_postgresql_execute_sql` tool to run the query.
3.  **Synthesize Results**: Present the top results (usually top 10-20) with a clear explanation of why they are prioritized (e.g., "This CVE is in CISA KEV and is externally visible").

## Scoring Model

- **Base**: CVSS Score (0-10)
- **CISA KEV**: +100
- **External Visibility (ASM)**: +50
- **VirusTotal Malicious (5+ vendors)**: +50
- **Management/OOB Subnet (phpIPAM)**: +30
- **Gateway Device (phpIPAM)**: +20
- **Cross-Tool Confirmation (Tenable + Wiz)**: +20

## Example Requests

- "Give me the top 10 security findings I should work on today."
- "Show me all CISA KEV vulnerabilities that are externally visible."
- "Correlate Tenable and Wiz findings to see what's confirmed by both."
