---
name: alienvault-otx
description: Queries AlienVault Open Threat Exchange (OTX) for threat intelligence data on IPs, domains, hostnames, and file hashes. Use when asked to "look up an IP on OTX," "see what pulses are connected to this domain," or "get the threat context for a hash."
---

# AlienVault OTX

This skill enables Gemini CLI to query AlienVault OTX to retrieve threat intelligence data and pulse correlation for network and file indicators.

## Prerequisites

- **OTX API Key**: A free key from your AlienVault OTX account.
- **OTX_API_KEY**: Set this environment variable.

## Workflows

### 1. Look Up Indicator Context
Retrieve the threat context, including "Pulses" (threat collections) associated with a specific IP, domain, hostname, or file hash.

- **Trigger**: "Look up 1.2.3.4 on AlienVault OTX," "What threats are connected to this domain?", or "Check this hash on OTX."
- **Action**: Run `node scripts/otx_lookup.cjs <type> <indicator>`.

## Indicator Types

- **ip**: IPv4 addresses.
- **domain**: Domains (e.g., example.com).
- **hostname**: Specific hostnames.
- **hash**: File hashes (SHA256, MD5, etc.).

## Example Commands

```bash
node scripts/otx_lookup.cjs ip 8.8.8.8
node scripts/otx_lookup.cjs domain malicious-site.net
node scripts/otx_lookup.cjs hash 44d88612fea8a8f36de82e1278abb02f
```
