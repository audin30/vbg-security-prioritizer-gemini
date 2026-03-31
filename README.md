# 🤖 Security Prioritizer & TI Skills Workspace

> Built with Gemini CLI

This project is a centralized repository for specialized security operations skills focused on threat intelligence and vulnerability prioritization. These skills empower **Gemini CLI** to act as a security analyst by correlating data across multiple platforms and providing actionable insights directly in the terminal.

## 🚀 Quick Start (First Steps)

If you have just downloaded or cloned this repository, follow these steps to get started:

### 1. Install Dependencies
Ensure you have **Node.js (v18+)** and **Python (3.9+)** installed, then run:

**Node.js Modules:**
```bash
npm install
```

**Python Modules:**
*Note: If you are using Python-based MCP servers or scripts:*
```bash
# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install requirements (if provided)
pip install -r requirements.txt
```

### 2. Configure Your Environment
Create a `.env` file from the provided example and add your API keys (Wiz, Tenable, VirusTotal, etc.):
```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Install Gemini CLI Skills
Install the specialized security skills into your Gemini CLI environment:
```bash
# Example: Install the prioritizer and TI enricher
gemini skills install ./security-prioritizer.skill --scope user
gemini skills install ./ti-master-enricher.skill --scope user
```
*Note: You can install any of the `.skill` files found in the root directory.*

### 4. Initialize the Engine
Reload the Gemini CLI to activate the newly installed skills:
```bash
/skills reload
```

### 5. Generate Your First Report
Run the prioritization script to correlate your data and generate a `security_report.html`:
```bash
node scripts/generate_report.cjs
```

---

## 🛠️ Featured Skills

| Skill Name | Purpose | Key Data Sources |
| :--- | :--- | :--- |
| **`security-prioritizer`** | Correlates & ranks vulnerabilities based on risk. | Tenable, Wiz, CISA KEV, phpIPAM |
| **`vulnerability-validator`** | Validates vulnerabilities via active scans. | Nuclei, Nmap |
| **`ti-master-enricher`** | Orchestrates multi-source TI lookups (Consensus). | GreyNoise, OTX, VirusTotal |
| **`virustotal-checker`** | Threat reputation for IPs and Domains. | VirusTotal API v3 |
| **`greynoise-community`** | Identifies internet background noise/scanners. | GreyNoise Community API |
| **`alienvault-otx`** | Checks indicators against threat pulses. | AlienVault OTX API |
| **`chronicle-query`** | Queries SIEM events and detections. | Google Chronicle API |
| **`talos-intelligence`** | Reputation lookups from Cisco Talos. | Talos Intelligence |
| **`asset-email-reporter`** | Sends automated remediation alerts via SMTP. | Node.js / Nodemailer |

## 📖 Documentation

- **[ONBOARDING.md](ONBOARDING.md)**: New user "Quick Start" and common troubleshooting.
- **[GEMINI.md](GEMINI.md)**: Detailed architecture, scoring models, and development workflows.
- **`workflows/`**: Step-by-step playbooks for specific security tasks.

---

🤖 Generated with Gemini CLI
