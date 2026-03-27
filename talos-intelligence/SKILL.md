---
name: talos-intelligence
description: Queries Cisco Talos Intelligence for reputation data on IP addresses, domains, and file hashes. Use when asked to "check the reputation of an IP," "look up a domain on Talos," or "get the disposition of a file hash."
---

# Talos Intelligence

This skill enables Gemini CLI to query the Cisco Talos Intelligence API to retrieve reputation and disposition data for network indicators and files.

## Prerequisites

- **OIDC Credentials**: A Client ID and Client Secret from your Cisco Talos account.
- **TALOS_CLIENT_ID**: Your OIDC Client ID.
- **TALOS_CLIENT_SECRET**: Your OIDC Client Secret.

## Workflows

### 1. Check IP Reputation
Query Talos to see if an IP address is associated with malicious activity, spam, or known blacklists.

- **Trigger**: "What is the Talos reputation for 1.2.3.4?" or "Check this IP on Talos."
- **Action**: Run `node scripts/talos_lookup.cjs ip <ip_address>`.

### 2. Check Domain/URL Reputation
Retrieve the categorization and malicious flags for a specific domain.

- **Trigger**: "Look up example.com on Talos" or "Is this domain malicious according to Talos?"
- **Action**: Run `node scripts/talos_lookup.cjs domain <domain_name>`.

### 3. Check File Hash (SHA256)
Get the disposition and threat classification for a specific file hash.

- **Trigger**: "Check this hash on Talos: <hash>" or "What does Talos say about this SHA256?"
- **Action**: Run `node scripts/talos_lookup.cjs hash <sha256_hash>`.

## Example Commands

```bash
node scripts/talos_lookup.cjs ip 8.8.8.8
node scripts/talos_lookup.cjs domain malware.com
node scripts/talos_lookup.cjs hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
