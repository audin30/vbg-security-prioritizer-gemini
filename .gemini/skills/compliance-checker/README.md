# ⚖️ Compliance Checker Skill

The **Compliance Checker** is a specialized Gemini CLI skill designed to monitor and report on resource compliance status against industry standards like CIS, NIST, SOC2, and more.

## 🚀 Quickstart Guide

### 1. Installation
Install the skill at the user level:
```bash
gemini skills install ./compliance-checker.skill --scope user
```

### 2. Activation
Reload the skills engine to enable the logic:
```bash
/skills reload
```

### 3. Usage
Query compliance status using natural language:
- `"Are there any CIS benchmark violations?"`
- `"Show me all resources failing HIPAA compliance."`
- `"List all non-compliant resources with CRITICAL severity."`
- `"Give me a compliance audit report for my GCP project."`

---

## 📊 How It Works

The skill scans the `wiz_issues` table for findings that are flagged as compliance-related violations and are currently in an `OPEN` state. It correlates these findings with resource metadata from `wiz_inventory` to provide context on what exactly is non-compliant.

### Standards Supported (via keyword search):
- **CIS Benchmarks**
- **NIST SP 800-53**
- **SOC2**
- **HIPAA**
- **PCI-DSS**
- **GDPR**

---

## 🛠️ Requirements

- **PostgreSQL MCP Server**: Connected to the database containing `wiz_issues` and `wiz_inventory`.
- **Wiz Data Sync**: Ensure your Wiz findings are synchronized to the PostgreSQL database for accurate reporting.
