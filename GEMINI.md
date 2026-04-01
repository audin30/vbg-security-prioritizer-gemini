# 🤖 VBG CLI: Security Prioritizer & TI Skills Workspace

This project is a centralized repository for specialized **VBG CLI Skills** focused on security operations, threat intelligence, and vulnerability prioritization. These skills empower the VBG CLI to act as a security analyst by correlating data across multiple platforms and providing actionable insights directly in the terminal.

## 📁 Project Architecture

The workspace is organized into discrete skill directories, each containing its own logic, documentation, and implementation scripts.

- **Root Skill Directories**: Source directories for each skill (e.g., `security-prioritizer/`, `virustotal-checker/`).
- **`.skill` Files**: Compressed zip archives of the skill directories, used for installation via `gemini skills install`.
- **`.gemini/skills/`**: The local "active" directory where skills are mirrored and loaded by the VBG CLI within this workspace.

### Core Skills & Their Functions

| Component | Type | Purpose | Key Data Sources |
| :--- | :--- | :--- | :--- |
| **`Security Chat UI`** | Front-End | Interactive web-based SOC dashboard. | React / Node.js API |
| **`security-prioritizer`** | Skill/SQL | Correlates & ranks vulnerabilities (V3 Model). | Tenable, Wiz, CISA KEV |
| **`auto-analyst`** | Orchestrator | Autonomous daily risk analysis & alerting. | GitHub Actions / Cron |
| **`vulnerability-validator`** | Skill/Scan | Validates vulnerabilities via active scans. | Nuclei, Nmap |
| **`ti-master-enricher`** | Skill/Orch | Multi-source TI consensus lookup. | GreyNoise, OTX, VT |

---

## 🛠️ Development & Operations

### 1. Autonomous Pipeline (`auto-analyst`)
The system is designed to run autonomously via GitHub Actions (`.github/workflows/auto-analyst.yml`) or Cron.
- **Schedule**: Twice daily (08:00 and 20:00 UTC).
- **Logic**: Executes Dynamic Risk V3, deduplicates findings via `public.notification_state`, and dispatches Email/Chat alerts.
- **Triggers**: `node scripts/auto_analyst.cjs`.

### 2. Interactive Dashboard (`Security Chat UI`)
A web-based conversational interface for analysts.
- **Launch**: `npm start` (Runs on port 3001).
- **Features**: Intent mapping to security scripts, rich markdown rendering, and direct report links.

---

## 🔍 Security Analysis Logic (V3 Model)

The prioritization logic in `scripts/generate_report.cjs` and `scripts/auto_analyst.cjs` uses a **Dynamic Risk Model**:

### Scoring Weights
- **Base Score**: `GREATEST(CVSS, VPR)` (0–10).
- **Asset Criticality (ACR)**: Scales base score by `(ACR / 5.0)`.
- **Malware Exploitable**: **+150 points** (Known malware association).
- **CISA KEV Match**: **+100 points** (Known exploited vulnerability).
- **Public Exposure**: **+100 points** (Internet reachable via Wiz/ASM).
- **Sensitive Data (PII)**: **+100 points** (Wiz Data Security finding).
- **Exploit Available**: **+50 points** (Functional exploit code exists).
- **Critical BU**: **+30 points** (e.g., Citrix, Netscaler).

### Toxic Combination Detection
Assets meeting the following criteria are flagged as **Critical (Score > 300)**:
`Internet Exposed` + `Sensitive Data Found` + `High Threat Vulnerability (KEV/Malware)`

---

## 🔑 Prerequisites & Configuration

- **Environment**: `.env` requires DB, SMTP, and Security API keys.
- **Database**: `vuln_db` (PostgreSQL) with `public.notification_state` for alert tracking.
- **Messaging**: `GOOGLE_CHAT_WEBHOOK` for real-time security channel alerts.
- **Runtime**: Node.js (v18+) and Python (3.9+).


## 📝 Conventions

- **Naming**: Use kebab-case for skill names and file names.
- **Triggers**: Define clear, natural-language triggers in `SKILL.md`.
- **Output**: Scripts should provide concise, human-readable summaries while also allowing for raw JSON output if requested by the orchestrator.
- **Security**: Never hardcode API keys; always use `process.env`.
