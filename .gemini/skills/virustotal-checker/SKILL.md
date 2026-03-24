---
name: virustotal-checker
description: Queries VirusTotal for IPv4 or Domain (hostname) reputation reports. Use when the user wants to check if an asset is malicious or flagged by security vendors.
---

# VirusTotal Checker Skill

This skill allows Gemini CLI to query VirusTotal for threat reputation and security analysis on IP addresses and domains.

## Prerequisites

- **API Key**: You must have a VirusTotal API key set as the environment variable `VIRUSTOTAL_API_KEY`.
- **Connectivity**: Requires internet access to reach `www.virustotal.com`.

## Usage

When a user asks to check an IP or domain on VirusTotal:

1.  **Identify Target**: Determine if it's an IP address or a hostname/domain.
2.  **Execute Lookup**: Run the `vt_lookup.cjs` script with the target type and address.

## Example Workflow

- User: "Check 8.8.8.8 on VirusTotal"
- Action: `node virustotal-checker/scripts/vt_lookup.cjs ip 8.8.8.8`

- User: "Is google.com flagged on VirusTotal?"
- Action: `node virustotal-checker/scripts/vt_lookup.cjs domain google.com`

## Script Location

The lookup script is located at: `virustotal-checker/scripts/vt_lookup.cjs`.
