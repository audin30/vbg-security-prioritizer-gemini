# 🛡️ Security Prioritizer Skill

The **Security Prioritizer** is a specialized AI agent skill for the Gemini CLI. It correlates vulnerability and asset data across multiple security platforms to help security teams identify their most critical risks instantly.

## 🚀 Quickstart Guide

### 1. Installation
If you haven't already, install the skill at the user level:
```bash
gemini skills install ./security-prioritizer.skill --scope user
```

### 2. Activation
You **must** reload the skills engine in your active session to enable the new logic:
```bash
/skills reload
```

### 3. Usage
Simply ask Gemini CLI to run reports using natural language:
- `"Show me my top 10 security findings."`
- `"Are there any CISA KEV vulnerabilities that are externally visible?"`
- `"Which vulnerabilities are confirmed by both Tenable and Wiz?"`
- `"Prioritize my internal vulnerabilities by CVSS score."`

---

## 📊 How It Works

This skill uses a weighted scoring model to rank vulnerabilities:

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Base Score** | 0-10 | The maximum CVSS score found for the CVE. |
| **CISA KEV** | +100 | Finding is in the CISA Known Exploited Vulnerabilities catalog. |
| **External Visibility** | +50 | The asset is found in Tenable ASM (Attack Surface Management). |
| **Management Subnet** | **+30** | **Asset is in a MGMT or OOB subnet (from phpIPAM).** |
| **Gateway Device** | **+20** | **Asset is identified as a Network Gateway in phpIPAM.** |
| **Cross-Tool Confirmation** | +20 | Finding is detected by both Tenable AND Wiz. |

### Data Sources Correlated:
- **Tenable.io/Vulnerability Management**: Internal findings and asset data.
- **Tenable ASM**: External attack surface visibility.
- **Wiz**: Cloud security findings and inventory.
- **CISA KEV**: Threat intelligence on actively exploited vulnerabilities.
- **phpIPAM**: Internal IP address management and subnet context.

---

## 🛠️ Requirements

- **PostgreSQL MCP Server**: Must be connected to the database containing the security data.
- **Table Schemas**: Expects tables named `tenable_findings`, `tenable_assets`, `tenable_asm_assets`, `wiz_vulnerabilities`, `wiz_inventory`, and `cisa_kev`.
- **Optimization**: The skill automatically utilizes the specialized indexes we created to ensure sub-second performance across millions of records.
