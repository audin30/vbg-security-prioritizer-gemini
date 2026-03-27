---
name: greynoise-community
description: Queries GreyNoise Community API to identify internet background noise and benign vs malicious scanners. Use when asked to "check if an IP is noise," "filter scanners," or "see if an IP is a known benign bot."
---

# GreyNoise Community

This skill enables Gemini CLI to query GreyNoise to determine if an IP address is part of "Internet Background Noise" or a known "RIOT" (Rule It Out) IP (e.g., Google, Microsoft, Amazon).

## Prerequisites

- **GreyNoise API Key**: A free Community API key.
- **GREYNOISE_API_KEY**: Set this environment variable.

## Workflows

### 1. Check if IP is Noise
Determine if an IP is mass-scanning the internet or has a specific classification.

- **Trigger**: "Is this IP just noise?", "Check 1.2.3.4 on GreyNoise," or "Is this a known scanner?"
- **Action**: Run `node scripts/greynoise_lookup.cjs <ip_address>`.

## Understanding Classifications

- **Benign**: Known safe scanners (e.g., GoogleBot, Shodan).
- **Malicious**: IPs observed engaging in potentially harmful activity.
- **Unknown**: No classification yet, but still observed as noise.
- **RIOT**: "Rule It Out" - IPs belonging to common business services (CDNs, Cloud Providers) that are highly unlikely to be the source of a targeted attack.

## Example Commands

```bash
node scripts/greynoise_lookup.cjs 8.8.8.8
node scripts/greynoise_lookup.cjs 185.156.177.12
```
