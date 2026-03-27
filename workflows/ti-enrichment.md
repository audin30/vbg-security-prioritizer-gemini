# Workflow: Threat Intelligence Enrichment

Triggered when the user asks to enrich an IP, domain, or file hash across threat intelligence sources.

## Scripts (run via Bash)

All scripts output structured JSON. They require environment variables to be loaded from `.env`.

| Script | Command | Supports |
|---|---|---|
| VirusTotal | `node virustotal-checker/scripts/vt_lookup.cjs <ip\|domain> <target>` | IP, domain |
| GreyNoise | `node greynoise-community/scripts/greynoise_lookup.cjs <ip>` | IP only |
| AlienVault OTX | `node alienvault-otx/scripts/otx_lookup.cjs <ip\|domain\|hostname\|hash> <target>` | IP, domain, hostname, hash |
| Cisco Talos | `node talos-intelligence/scripts/talos_lookup.cjs <ip\|domain\|hash> <target>` | IP, domain, hash |
| Master Enricher | `node ti-master-enricher/scripts/enrich_master.cjs <ip\|domain\|hash> <target>` | Runs GreyNoise + OTX + VT together |

## Scoring (ti-master-enricher)

| Source | Weight | Signal |
|---|---|---|
| VirusTotal | up to 20 pts | `malicious` engine count (capped at 20) |
| AlienVault OTX | up to 10 pts | pulse count × 2 (capped at 10) |
| GreyNoise | +10 / −5 | malicious = +10; benign/RIOT = −5 |

Confidence score = `(score / maxScore) * 100`%

## Workflow

### Single-source check
Run the appropriate script directly. Parse the JSON output and summarize the key fields.

### Full enrichment ("check across all sources")
Run `enrich_master.cjs` — it calls GreyNoise (IP only), OTX, and VirusTotal in sequence and returns a unified report.

### Store VT result in database
If the user wants to persist a VirusTotal result for use in the security prioritizer scoring:

```sql
INSERT INTO public.vt_results (target, malicious)
VALUES ('<ip_or_hostname>', <malicious_count>)
ON CONFLICT (target) DO UPDATE SET malicious = EXCLUDED.malicious;
```

## GreyNoise Classifications

- **malicious** — actively scanning/attacking, treat as high priority
- **benign** / **riot** — known safe actors (CDNs, cloud providers, Shodan); deprioritize
- **unknown** — observed as noise but unclassified
