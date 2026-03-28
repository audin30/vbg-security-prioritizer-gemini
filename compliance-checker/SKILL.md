---
name: compliance-checker
description: Analyzes assets and resources for violations of compliance standards (CIS, NIST, SOC2, HIPAA, PCI, GDPR). Use when asked to check for non-compliant resources or compliance benchmark failures.
---

# Compliance Checker

This skill enables Gemini CLI to act as a compliance auditor by identifying non-compliant resources across cloud and on-premise environments.

## Prerequisites

- PostgreSQL MCP server connected with the following tables:
  - `public.wiz_issues`
  - `public.wiz_inventory`

## Workflows

### Identifying Compliance Violations

When asked to check for compliance failures or non-compliant resources:

1.  **Load Logic**: Reference [references/logic.md](references/logic.md) for the compliance detection logic and SQL query.
2.  **Execute Query**: Use the `mcp_postgresql_execute_sql` tool to run the query.
3.  **Synthesize Results**: Present the violations, grouped by standard (if applicable) and prioritized by severity.

## Example Requests

- "Are there any resources in violation of CIS benchmarks?"
- "Show me all non-compliant assets in my environment."
- "List all open SOC2 compliance issues."
- "What NIST SP 800-53 controls are currently failing?"
