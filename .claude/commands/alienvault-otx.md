# AlienVault OTX

Queries AlienVault Open Threat Exchange for pulse correlations and threat context on IPs, domains, hostnames, and file hashes.

## When to use
Use when the user asks to:
- Look up an indicator on OTX or AlienVault
- See what threat collections (Pulses) are associated with an IP, domain, or hash
- Get threat context from the open-source threat community

## Prerequisites
- `OTX_API_KEY` must be set in the environment (see `.env.example`)

## Supported indicator types
| Type | Example |
|---|---|
| `ip` | IPv4 address |
| `domain` | `malicious-site.com` |
| `hostname` | `sub.malicious-site.com` |
| `hash` | SHA256, MD5 |

## Steps

1. Identify the indicator type from the user's request.
2. Run the lookup via Bash:
   ```bash
   node alienvault-otx/scripts/otx_lookup.cjs <type> <indicator>
   ```
3. Parse the JSON output and summarize:
   - Number of Pulses referencing this indicator
   - Associated threat campaign names or malware families
   - Country of origin (for IPs)
   - Any tags or threat categories

## Scoring contribution (when used in full enrichment)
OTX contributes up to **10 points** to the master confidence score: `pulse_count × 2`, capped at 10.

## Examples
```bash
node alienvault-otx/scripts/otx_lookup.cjs ip 8.8.8.8
node alienvault-otx/scripts/otx_lookup.cjs domain malicious-site.net
node alienvault-otx/scripts/otx_lookup.cjs hash 44d88612fea8a8f36de82e1278abb02f
```
