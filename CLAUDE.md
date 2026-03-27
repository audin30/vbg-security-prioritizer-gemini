# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

A collection of Gemini CLI skills for security vulnerability prioritization. It correlates findings from Tenable, Wiz, CISA KEV, and phpIPAM, enriches indicators via threat intelligence APIs, and stores data in a local PostgreSQL database (`vuln_db`).

## Architecture

### Claude Code (this project)
Workflows are documented in `workflows/`. Claude reads the relevant workflow file before acting. MCP tools (PostgreSQL, Wiz) are called directly — no wrapper scripts needed. External APIs without MCPs (VirusTotal, GreyNoise, OTX, Talos, Chronicle) are called via the existing Node.js scripts in their respective subdirectories.

### Gemini CLI (legacy)
Each skill is a self-contained directory with a `SKILL.md` (Gemini CLI manifest) and a `scripts/` folder. Skills are installed via `gemini skills install ./<name>.skill --scope user` and reloaded with `/skills reload`. The `.gemini/skills/` directory mirrors the root skill directories — both must be kept in sync when editing scripts.

### Skills

| Skill / Workflow | Claude Code approach | Gemini skill |
|---|---|---|
| Security prioritization | PostgreSQL MCP + `workflows/security-prioritizer.md` | `security-prioritizer` skill |
| TI enrichment (multi-source) | Bash scripts + `workflows/ti-enrichment.md` | `ti-master-enricher` skill |
| VirusTotal lookup | `node virustotal-checker/scripts/vt_lookup.cjs` | `virustotal-checker` skill |
| GreyNoise lookup | `node greynoise-community/scripts/greynoise_lookup.cjs` | `greynoise-community` skill |
| AlienVault OTX lookup | `node alienvault-otx/scripts/otx_lookup.cjs` | `alienvault-otx` skill |
| Cisco Talos lookup | `node talos-intelligence/scripts/talos_lookup.cjs` | `talos-intelligence` skill |
| Chronicle SIEM query | `node chronicle-query/scripts/query_chronicle.cjs` | `chronicle-query` skill |
| CSV export | `node csv-writer/scripts/json_to_csv.cjs` + `workflows/csv-export.md` | `csv-writer` skill |

## Claude Code Workflows

Before performing any workflow, read the corresponding file in `workflows/`:

- **Prioritize findings / risk report** → read `workflows/security-prioritizer.md`, then run SQL via PostgreSQL MCP
- **Enrich an IP/domain/hash** → read `workflows/ti-enrichment.md`, then run the appropriate script(s) via Bash
- **Check Chronicle SIEM** → read `workflows/chronicle.md`, then run the script via Bash
- **Export to CSV** → read `workflows/csv-export.md`, then run the csv-writer script via Bash

When the user asks about an indicator (IP, domain, hash) in the context of a prioritized finding, combine both workflows: run TI enrichment first, then optionally persist the VT result to `public.vt_results` and re-run the prioritization query.

### Prioritization Scoring Model (`security-prioritizer`)

The SQL in `security-prioritizer/references/logic.md` is the ground truth. Scores:
- Base CVSS: 0–10
- CISA KEV: +100
- External (ASM): +50
- VirusTotal malicious (≥5 vendors, via `public.vt_results`): +50
- Management/OOB subnet (phpIPAM): +30
- Gateway device (phpIPAM): +20
- Cross-tool confirmation (both Tenable AND Wiz): +20

### Required PostgreSQL Tables

`tenable_findings`, `tenable_assets`, `tenable_asm_assets`, `wiz_vulnerabilities`, `wiz_inventory`, `cisa_kev`, `phpipam_assets`, `vt_results` (columns: `target`, `malicious`)

## Environment Variables

See `.env.example` for all required keys. Key groups:
- `WIZ_*` — Wiz GraphQL API
- `TENABLE_*` — Tenable VM + ASM
- `DB_*` — PostgreSQL (`localhost:5432`, db: `vuln_db`)
- `VIRUSTOTAL_API_KEY` — VirusTotal v3
- `GREYNOISE_API_KEY` — GreyNoise Community
- `OTX_API_KEY` — AlienVault OTX
- `TALOS_CLIENT_ID` / `TALOS_CLIENT_SECRET` — Cisco Talos OIDC
- `CHRONICLE_CUSTOMER_ID` / `GOOGLE_APPLICATION_CREDENTIALS` — Chronicle service account

## Node.js Dependencies

Run `npm install` from the repo root. Dependencies: `axios`, `googleapis`, `google-auth-library`.

## Security Restrictions

The `settings.json` sandbox blocks:
- Reading credential files: `.env`, `.pem`, `.key`, `.p12`, SSH/cloud credential dirs
- Network tools: `curl`, `wget`, `nc`, `ncat`, `netcat`, `telnet`, `nmap`, `ssh`, `scp`, `ftp`

## Available MCP Servers

Key servers from `settings.json`:
- **wiz**, **splunk**, **sentry**, **postgres-mcp-server** — core data sources
- **microsoft-sentinel-data-exploration**, **cloudtrail-mcp-server**, **cloudwatch-mcp-server** — cloud audit
- **iam-mcp-server**, **github-mcp**, **atlassian** — IAM, code, ticketing
