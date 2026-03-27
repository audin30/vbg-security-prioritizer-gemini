# Talos Intelligence

Queries Cisco Talos for reputation and disposition data on IPs, domains, and file hashes.

## When to use
Use when the user asks to:
- Check an IP's reputation on Talos
- Look up a domain or URL categorization
- Get the threat disposition of a SHA256 file hash

## Prerequisites
- `TALOS_CLIENT_ID` and `TALOS_CLIENT_SECRET` must be set in the environment (see `.env.example`)
- Uses OIDC authentication — credentials are exchanged for a bearer token at runtime

## Supported indicator types
| Type | Command | Notes |
|---|---|---|
| `ip` | `talos_lookup.cjs ip <address>` | IPv4 |
| `domain` | `talos_lookup.cjs domain <domain>` | Domain or URL |
| `hash` | `talos_lookup.cjs hash <sha256>` | SHA256 only |

## Steps

1. Identify the indicator type from the user's request.
2. Run the lookup via Bash:
   ```bash
   node talos-intelligence/scripts/talos_lookup.cjs <type> <indicator>
   ```
3. Parse the JSON output and summarize:
   - Reputation score / disposition (e.g. Trusted, Neutral, Untrusted, Malicious)
   - Threat categories or blacklist membership
   - Spam reputation (for IPs)

## Examples
```bash
node talos-intelligence/scripts/talos_lookup.cjs ip 8.8.8.8
node talos-intelligence/scripts/talos_lookup.cjs domain malware.com
node talos-intelligence/scripts/talos_lookup.cjs hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
