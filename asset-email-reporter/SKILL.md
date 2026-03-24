---
name: asset-email-reporter
description: Sends a human-readable security summary of a specific asset to an email address. Use when the user wants to report or alert on specific assets like TelemetryLauncher.
---

# Asset Email Reporter

This skill allows Gemini CLI to send a formatted security report for a specific asset via email.

## Prerequisites

- **Environment Variables**: The following must be set for the email script to work:
  - `SMTP_HOST`: The SMTP server host.
  - `SMTP_PORT`: The SMTP server port (e.g., 587 or 465).
  - `SMTP_USER`: The sender email address.
  - `SMTP_PASS`: The password or App Password.
- **Dependencies**: The `nodemailer` package must be available in the environment.

## Workflow

### Sending an Asset Report

When asked to email asset data (e.g., "Email the data for TelemetryLauncher to juan.janolo@cloud.com"):

1.  **Gather Data**: Research the asset in `wiz_inventory`, `wiz_issues`, and `wiz_vulnerabilities`.
2.  **Summarize**: Create a concise, senior-level summary of the asset's security posture, including:
    - **Asset Profile**: Name, OS, Region, Public IP (if any).
    - **Exposure**: Open ports, internet-facing status.
    - **Critical Findings**: Top issues and vulnerabilities (CVEs).
    - **Credentials**: Any exposed keys or secrets.
3.  **Execute**: Run the `scripts/send_email.cjs` script with the target email, subject, and summary.

```bash
node scripts/send_email.cjs "recipient@example.com" "Security Report: [Asset Name]" "[Summary Text]"
```

4.  **Confirm**: Notify the user of success or failure based on the script output.
