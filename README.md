# 🤖 Gemini CLI: Security Prioritizer & TI Skills Workspace

This project is a centralized repository for specialized **Gemini CLI Skills** focused on security operations, threat intelligence, and vulnerability prioritization. These skills empower the Gemini CLI to act as a security analyst by correlating data across multiple platforms and providing actionable insights directly in the terminal.

## 🚀 Featured Skills

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
| **`csv-writer`** | Exports JSON data to CSV files. | Local Node.js Script |

## 🛠️ Getting Started

1.  **Install a skill**:
    ```bash
    gemini skills install ./<skill-name>.skill --scope user
    ```
2.  **Activate**:
    Reload the engine in your interactive session:
    ```bash
    /skills reload
    ```

For detailed architecture and development workflows, see [GEMINI.md](GEMINI.md).
