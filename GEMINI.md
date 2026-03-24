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

## 🔑 Prerequisites & Configuration

Most skills in this workspace require API keys or specific environment variables:

- **Security APIs**: `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`.
- **Infrastructure**: The `security-prioritizer` skill requires a connection to a **PostgreSQL MCP Server** containing specific table schemas for Tenable, Wiz, and CISA KEV data (see `security-prioritizer/SKILL.md` for details).
- **Runtime**: All script-based skills run on **Node.js**. Ensure `node` is available in your path.

## 📝 Conventions

- **Naming**: Use kebab-case for skill names and file names.
- **Triggers**: Define clear, natural-language triggers in `SKILL.md`.
- **Output**: Scripts should provide concise, human-readable summaries while also allowing for raw JSON output if requested by the orchestrator.
- **Security**: Never hardcode API keys; always use `process.env`.
