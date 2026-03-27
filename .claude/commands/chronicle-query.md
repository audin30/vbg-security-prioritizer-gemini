# Chronicle Query

Queries Google Chronicle SIEM for security detections and UDM events related to an IP or hostname.

## When to use
Use when the user asks to:
- Check Chronicle for alerts or detections on an IP or host
- Search SIEM logs for activity related to a vulnerability or indicator
- Correlate a prioritized finding against Chronicle events

## Prerequisites
- `CHRONICLE_CUSTOMER_ID` must be set in the environment
- `GOOGLE_APPLICATION_CREDENTIALS` must point to a service account JSON key file (see `.env.example`)

## Workflow modes

### UDM search (raw event logs — last 24 hours)
Searches for events where the target is a principal IP, target IP, or hostname.
```bash
node chronicle-query/scripts/query_chronicle.cjs udm <ip_or_hostname>
```
Filter used: `principal.ip = "<target>" OR target.ip = "<target>" OR principal.hostname = "<target>"`

### Detection search (active alerts)
Fetches the latest 10 detections from Chronicle.
```bash
node chronicle-query/scripts/query_chronicle.cjs detection <ip_or_hostname>
```
> **Note:** Detection mode currently returns the latest 10 global detections — target filtering is pending API access for full testing.

## Steps

1. Determine whether the user wants detections, raw UDM events, or both.
2. Run the appropriate script via Bash.
3. Parse the JSON output and summarize:
   - Event types observed (network connection, process execution, etc.)
   - Source/destination IPs and hostnames
   - Timestamps and volumes
   - Any associated detection rule names or severities
4. If detections are found for a prioritized finding, recommend immediate escalation.

## Integration tip
When used alongside `/security-prioritizer`, run the Chronicle query for any top-ranked asset to check for active SIEM activity before presenting the final report.
