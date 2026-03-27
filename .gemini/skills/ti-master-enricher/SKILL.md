---
name: ti-master-enricher
description: Coordinates threat intelligence lookups across GreyNoise, AlienVault OTX, and VirusTotal to provide a unified confidence score for any IP, domain, or file hash. Use when asked for "full enrichment," "multi-source threat correlation," or "a final verdict on an indicator."
---

# Master TI Enricher

This skill acts as an orchestrator, leveraging the individual lookup skills for GreyNoise, AlienVault OTX, and VirusTotal to provide a consolidated threat report.

## Prerequisites

- **Installed Skills**: `greynoise-community`, `alienvault-otx`, and `virustotal-checker`.
- **API Keys**: Valid keys for each respective service set as environment variables.

## Workflows

### 1. Perform Multi-Source Correlation
Get a final verdict on an indicator based on consensus across all available threat intelligence sources.

- **Trigger**: "Give me a full enrichment report for 1.2.3.4," "Check this hash across all sources," or "What's the consensus on this domain?"
- **Action**: Run `node scripts/enrich_master.cjs <type> <indicator>`.

## Consensus Scoring Model

- **VirusTotal (50%)**: Multi-engine scanner consensus.
- **AlienVault OTX (25%)**: Real-world threat collections (Pulses).
- **GreyNoise (25% / Noise Filter)**: Classification of malicious vs. benign internet background noise.

## Example Commands

```bash
node scripts/enrich_master.cjs ip 8.8.8.8
node scripts/enrich_master.cjs domain badsite.com
node scripts/enrich_master.cjs hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
