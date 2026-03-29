# 🤖 Gemini CLI: Security Prioritizer & TI Skills Workspace

This project is a centralized repository for specialized **Gemini CLI Skills** focused on security operations, threat intelligence, and vulnerability prioritization. These skills empower the Gemini CLI to act as a security analyst by correlating data across multiple platforms and providing actionable insights directly in the terminal.

## 📁 Project Architecture

The workspace is organized into discrete skill directories, each containing its own logic, documentation, and implementation scripts.

- **Root Skill Directories**: Source directories for each skill (e.g., `security-prioritizer/`, `virustotal-checker/`).
- **`.skill` Files**: Compressed zip archives of the skill directories, used for installation via `gemini skills install`.
- **`.gemini/skills/`**: The local "active" directory where skills are mirrored and loaded by the Gemini CLI within this workspace.

### Core Skills & Their Functions

| Skill Name | Purpose | Key Data Sources |
| :--- | :--- | :--- |
| **`security-prioritizer`** | Correlates & ranks vulnerabilities based on risk. | Tenable, Wiz, CISA KEV, phpIPAM |
| **`ti-master-enricher`** | Orchestrates multi-source TI lookups (Consensus). | GreyNoise, OTX, VirusTotal |
| **`virustotal-checker`** | Threat reputation for IPs and Domains. | VirusTotal API v3 |
| **`greynoise-community`** | Identifies internet background noise/scanners. | GreyNoise Community API |
| **`alienvault-otx`** | Checks indicators against threat pulses. | AlienVault OTX API |
| **`chronicle-query`** | Queries SIEM events and detections. | Google Chronicle API |
| **`talos-intelligence`** | Reputation lookups from Cisco Talos. | Talos Intelligence |
| **`vulnerability-validator`** | Validates vulnerabilities via active scans. | Nuclei, Nmap |
| **`csv-writer`** | Exports JSON data to CSV files. | Local Node.js Script |

---

## 🛠️ Development Workflow

### 1. Adding/Updating a Skill
1.  Modify the logic in the skill's source directory (e.g., `virustotal-checker/scripts/vt_lookup.cjs`).
2.  Update the `SKILL.md` file in that directory to reflect changes in behavior or triggers.
3.  **Repackage**: Update the root-level `.skill` zip file by zipping the directory contents (ensure `SKILL.md` is at the root of the zip).
4.  **Mirror**: If testing locally in this workspace, ensure the changes are reflected in `.gemini/skills/<skill-name>/`.

### 2. Installing a Skill
To install a skill globally or at the user level:
```bash
gemini skills install ./<skill-name>.skill --scope user
```

### 3. Activating Changes
After installing or modifying a skill, reload the engine:
```bash
/skills reload
```

---

## 🔍 Security Analysis Workflows

Before performing any workflow, you can refer to the corresponding file in `workflows/`:

- **Prioritize findings / risk report** → read `workflows/security-prioritizer.md`, then run SQL via PostgreSQL MCP.
- **Enrich an IP/domain/hash** → read `workflows/ti-enrichment.md`, then run the appropriate script(s).
- **Check Chronicle SIEM** → read `workflows/chronicle.md`, then run the script.
- **Export to CSV** → read `workflows/csv-export.md`, then run the csv-writer script.

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

---

## 🔑 Prerequisites & Configuration

Most skills in this workspace require API keys or specific environment variables:

- **Security APIs**: `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`.
- **Infrastructure**: The `security-prioritizer` skill requires a connection to a **PostgreSQL MCP Server** (`vuln_db`).
- **Runtime**: All script-based skills run on **Node.js**. Ensure `node` is available in your path and run `npm install` in the root.

## 📝 Conventions

- **Naming**: Use kebab-case for skill names and file names.
- **Triggers**: Define clear, natural-language triggers in `SKILL.md`.
- **Output**: Scripts should provide concise, human-readable summaries while also allowing for raw JSON output if requested by the orchestrator.
- **Security**: Never hardcode API keys; always use `process.env`.
