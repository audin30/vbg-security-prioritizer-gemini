# 🚀 Onboarding Guide: Getting Started with VBG Security Analyst

Welcome! This guide will help you move from initial installation to your first automated security insights in under 10 minutes.

---

## 🎯 1. The "Golden Prompts" (Cheat Sheet)

VBG CLI works best when you use natural language triggers defined in the `.skill` files. Try these "Golden Prompts" once your skills are installed:

| Goal | Ask VBG... |
| :--- | :--- |
| **Risk Prioritization** | "Generate a risk-prioritized report of our top 10 assets." |
| **Threat Intelligence** | "Give me a full TI enrichment report for IP [IP_ADDRESS]." |
| **Data Sensitivity** | "Identify assets with a 'Toxic Combination' of internet exposure and PII." |
| **Remediation** | "Email a critical remediation alert for [hostname] to [email@example.com]." |
| **Validation** | "Run a validation scan on [IP_ADDRESS] to see if it is actually exploitable." |

## 💬 2. The Security Chat UI (Dashboard)

If you prefer a web-based interface over the CLI, you can launch the **VBG Security Chat UI**. This provides a conversational SOC dashboard.

### Starting the UI
1. Run the start command:
   ```bash
   npm start
   ```
2. Open your browser to: **http://localhost:3001**

### Why use the Chat UI?
* **Live Analysis**: Ask questions and get formatted markdown responses with tables.
* **Integrated Reporting**: View the full HTML security report directly through the UI links.
* **One-Click Skills**: Trigger complex analysis (like TI enrichment or Priority reports) without knowing specific CLI flags.

---

## ⚙️ 3. Connecting Your Data (MCP Configuration)

The `security-prioritizer` and `compliance-checker` skills require a connection to your PostgreSQL database (`vuln_db`).

Add this to your VBG CLI `config.json` (usually located in `~/.config/gemini-cli/config.json` or managed via `/settings`):

```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://postgres:[PASSWORD]@localhost:5432/vuln_db"
      ]
    }
  }
}
```

---

## 📊 3. The "Big Picture" (Data Flow)

Understanding how data moves through this workspace:

1.  **Ingestion**: Scripts in `scripts/` (e.g., `wiz_reingest.cjs`) pull data from Wiz/Tenable into **PostgreSQL**.
2.  **Orchestration**: You ask **VBG CLI** a question in the terminal.
3.  **Analysis**: VBG uses **Skills** (SQL queries + Logic) to correlate vulnerabilities with business context.
4.  **Action**: VBG generates an **HTML Report**, sends an **Email Alert**, or runs a **Validation Scan**.

---

## 🛠️ 4. Troubleshooting "Common Gotchas"

| Issue | Solution |
| :--- | :--- |
| **"Module Not Found"** | Run `npm install` in the project root. Some scripts require `axios`, `pg`, or `nodemailer`. |
| **Email Fails to Send** | If using Gmail, you **must** use an **App Password**. Standard passwords will be blocked. |
| **Database Timeouts** | If reports take >5 minutes, ensure you have indexes on `asset_name` and `ip_address` in your SQL tables. |
| **Skill Not Triggering** | Run `/skills reload` after installing any `.skill` file to refresh the engine. |

---

## 📚 Next Steps
- Read **[GEMINI.md](GEMINI.md)** for detailed scoring models and SQL logic.
- Check the **`workflows/`** directory for step-by-step security playbooks.
