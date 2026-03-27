# Workflow: Chronicle SIEM Query

Triggered when the user asks to check Chronicle for an IP or hostname, find SIEM alerts, or search for activity related to a vulnerability or indicator.

> **Note:** Requires `CHRONICLE_CUSTOMER_ID` and `GOOGLE_APPLICATION_CREDENTIALS` (service account JSON path) set in the environment.

## Scripts

```bash
# Search UDM events for an IP or hostname (last 24 hours)
node chronicle-query/scripts/query_chronicle.cjs udm <ip_or_hostname>

# Fetch recent detections (alerts) — returns latest 10, not yet filtered by target
node chronicle-query/scripts/query_chronicle.cjs detection <ip_or_hostname>
```

Output is raw JSON from the Chronicle API. Parse and summarize the relevant fields.

## UDM Query Details

The UDM search uses this filter:
```
principal.ip = "<target>" OR target.ip = "<target>" OR principal.hostname = "<target>"
```
Time window: last 24 hours by default.

## Known Limitations

- The `detection` mode currently fetches the latest 10 detections globally (no target filter yet — pending Chronicle API access for testing).
- Dependencies (`googleapis`, `axios`) must be installed: `npm install`.
