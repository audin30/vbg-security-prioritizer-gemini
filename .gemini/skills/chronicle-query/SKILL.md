---
name: chronicle-query
description: Queries Google Chronicle SIEM for security detections and UDM events. Use when asked to "check Chronicle for an IP/hostname," "find SIEM alerts," or "search for activity related to a vulnerability/indicator."
---

# Chronicle Query

This skill enables Gemini CLI to query Google Chronicle for security alerts and raw UDM events.

## Prerequisites

- **Chronicle Service Account**: A JSON key for a service account with the `chronicle-backstory` scope.
- **CHRONICLE_CUSTOMER_ID**: Your unique Chronicle customer identifier.
- **GOOGLE_APPLICATION_CREDENTIALS**: Path to your Service Account JSON.

## Workflows

### 1. Check for Detections (Alerts)
Query Chronicle to see if there are any active detections or alerts associated with a specific entity.

- **Trigger**: "Show detections for 192.168.1.100" or "Any alerts in Chronicle for this host?"
- **Action**: Run the `query_chronicle.cjs` script with the `detection` argument.

### 2. Search UDM Events
Perform a raw search of Universal Data Model (UDM) events to correlate activity.

- **Trigger**: "Search Chronicle logs for 1.2.3.4" or "What activity has this IP shown in the last 24 hours?"
- **Action**: Run the `query_chronicle.cjs` script with the `udm` argument.

## Example Commands

```bash
node scripts/query_chronicle.cjs detection 192.168.1.100
node scripts/query_chronicle.cjs udm 10.0.0.5
```

## Note on Timeframes
By default, the UDM search query covers the **last 24 hours**. For specific time ranges, the script parameters should be adjusted.
