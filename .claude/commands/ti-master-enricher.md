# TI Master Enricher

Orchestrates threat intelligence lookups across GreyNoise, AlienVault OTX, and VirusTotal to produce a unified confidence score for any indicator.

## When to use
Use when the user asks to:
- Run a "full enrichment" on an indicator
- Get a multi-source threat verdict
- Correlate an IP, domain, or hash across all TI sources at once

## Prerequisites
All three API keys must be set (see `.env.example`):
- `VIRUSTOTAL_API_KEY`
- `GREYNOISE_API_KEY` (IPs only)
- `OTX_API_KEY`

## Supported indicator types
| Type | VT | GreyNoise | OTX |
|---|---|---|---|
| `ip` | Yes | Yes | Yes |
| `domain` | Yes | No | Yes |
| `hash` | No | No | Yes |

## Steps

1. Run the master enricher via Bash — it executes all applicable sources in sequence:
   ```bash
   node ti-master-enricher/scripts/enrich_master.cjs <ip|domain|hash> <indicator>
   ```
2. Alternatively, run each source individually for finer control:
   ```bash
   node virustotal-checker/scripts/vt_lookup.cjs <ip|domain> <target>
   node greynoise-community/scripts/greynoise_lookup.cjs <ip>
   node alienvault-otx/scripts/otx_lookup.cjs <ip|domain|hostname|hash> <target>
   node talos-intelligence/scripts/talos_lookup.cjs <ip|domain|hash> <target>
   ```
3. Synthesize a confidence score and verdict:

   | Source | Weight | Signal |
   |---|---|---|
   | VirusTotal | up to 20 pts | malicious engine count (capped at 20) |
   | AlienVault OTX | up to 10 pts | pulse count × 2 (capped at 10) |
   | GreyNoise | +10 / −5 | malicious = +10; benign/riot = −5 |

   `Confidence = (total_score / max_score) × 100%`

4. Present a verdict:
   - **High confidence malicious** (≥70%): recommend blocking, escalation
   - **Medium** (40–69%): flag for investigation
   - **Low / Clean** (<40%): deprioritize, note any noise sources

5. **Optional — persist VT result** for use in security prioritization scoring:
   ```sql
   INSERT INTO public.vt_results (target, malicious)
   VALUES ('<target>', <malicious_count>)
   ON CONFLICT (target) DO UPDATE SET malicious = EXCLUDED.malicious;
   ```
   Ask the user before inserting.

## Examples
```bash
node ti-master-enricher/scripts/enrich_master.cjs ip 8.8.8.8
node ti-master-enricher/scripts/enrich_master.cjs domain badsite.com
node ti-master-enricher/scripts/enrich_master.cjs hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
