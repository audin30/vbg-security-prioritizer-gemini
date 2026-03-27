# GreyNoise Community

Queries GreyNoise to classify an IP as internet background noise, a known benign bot, or a malicious scanner.

## When to use
Use when the user asks to:
- Check if an IP is "just noise"
- Filter out known benign scanners before escalating an alert
- Determine if an IP is a RIOT (Rule It Out) address — e.g. Google, Microsoft, Shodan

## Prerequisites
- `GREYNOISE_API_KEY` must be set in the environment (see `.env.example`)
- Supports **IPv4 addresses only**

## Steps

1. Run the lookup via Bash:
   ```bash
   node greynoise-community/scripts/greynoise_lookup.cjs <ip_address>
   ```
2. Parse the JSON output and summarize the classification:

   | Classification | Meaning | Action |
   |---|---|---|
   | **malicious** | Actively scanning/attacking | Escalate — high priority |
   | **benign** | Known safe scanner (GoogleBot, Shodan, etc.) | Deprioritize |
   | **riot** | Common business service (CDN, cloud provider) | Rule it out |
   | **unknown** | Observed as noise, unclassified | Investigate further |

3. If the IP is **malicious**, suggest running a full enrichment (`/ti-master-enricher`) to corroborate.

## Examples
```bash
node greynoise-community/scripts/greynoise_lookup.cjs 8.8.8.8
node greynoise-community/scripts/greynoise_lookup.cjs 185.156.177.12
```
