# VirusTotal Checker

Queries VirusTotal for reputation data on an IP address or domain.

## When to use
Use when the user asks to:
- Check an IP or domain on VirusTotal
- See how many security vendors flag an indicator as malicious
- Determine if an asset is flagged before adding it to the prioritization score

## Prerequisites
- `VIRUSTOTAL_API_KEY` must be set in the environment (see `.env.example`)

## Steps

1. Identify the indicator type: `ip` or `domain`.
2. Run the lookup via Bash:
   ```bash
   node virustotal-checker/scripts/vt_lookup.cjs <ip|domain> <target>
   ```
3. Parse the JSON output and summarize:
   - Total malicious vendor count
   - Harmless / suspicious / undetected counts
   - Any notable vendor detections
4. **Optional — persist to database** for use in prioritization scoring:
   ```sql
   INSERT INTO public.vt_results (target, malicious)
   VALUES ('<target>', <malicious_count>)
   ON CONFLICT (target) DO UPDATE SET malicious = EXCLUDED.malicious;
   ```
   Ask the user if they want to save the result before inserting.

## Examples
```bash
node virustotal-checker/scripts/vt_lookup.cjs ip 8.8.8.8
node virustotal-checker/scripts/vt_lookup.cjs domain badsite.com
```
