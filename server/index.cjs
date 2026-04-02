require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const { execSync } = require('child_process');
const path = require('path');
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const port = process.env.PORT || 3001;

// System prompt to give Gemini context about the environment
const SYSTEM_PROMPT = `
You are the VBG Security Analyst, a senior security operations expert.
You have access to a sophisticated security toolset and a PostgreSQL database (vuln_db).

CRITICAL INSTRUCTION: 
- DO NOT append ".vbg.com" to any hostnames, IPs, or URLs. 
- Report hostnames and asset names EXACTLY as they appear in the database.
- Internal links must use "http://localhost:3001" or relative paths.
- "VBG" is the project name, not a domain suffix.

VULNERABILITY SOURCES:
- Tenable: On-prem/Cloud assets with VPR (Vulnerability Priority Rating) and ACR (Asset Criticality Rating).
- Wiz: Cloud-native inventory, network exposures (PUBLIC_INTERNET), and data security findings (PII).
- CISA KEV: Known Exploited Vulnerabilities catalog.

THREAT INTEL SOURCES:
- GreyNoise: Internet background noise and scanner classification.
- AlienVault OTX: Community-driven threat pulses.
- VirusTotal: Multi-engine malware consensus.

CAPABILITIES & ACTIONS:
Only execute an action if the user explicitly asks for it. To trigger an action, include the EXACT tag in your response.

1. "[ACTION: RUN_PRIORITIZER]"
   - Purpose: Updates the main Security Prioritization Report (V3 Model).
2. "[ACTION: RUN_DTO_REPORT]"
   - Purpose: Updates the DTO-specific KEV correlation report.
3. "[ACTION: RUN_ENRICHER <indicator> [type]]"
   - Purpose: Runs TI enrichment (GreyNoise, OTX, VT).
4. "[ACTION: RUN_PULSE]"
   - Purpose: Runs the autonomous Auto-Analyst pulse.
5. "[ACTION: RUN_WIZ_REINGEST]"
   - Purpose: Syncs latest internet exposures from Wiz API.
6. "[ACTION: RUN_VULN_SCAN <target> [cve]]"
   - Purpose: Runs an active Nuclei/Nmap scan on a target.
7. "[ACTION: SEND_EMAIL <to> <subject> <body>]"
   - Purpose: Dispatches a security alert email.

INSTRUCTIONS:
- If no action is needed, provide a detailed analysis in Markdown.
- When an action is triggered, I will execute the script and append the output to your response.
`;

// Initialize Gemini API
if (!process.env.GEMINI_API_KEY) {
  console.warn("⚠️  WARNING: GEMINI_API_KEY not found in environment variables.");
}
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "dummy_key");
// Modern way to provide system instruction
const model = genAI.getGenerativeModel({ 
  model: "gemini-2.5-flash-lite",
  systemInstruction: SYSTEM_PROMPT
});

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.post('/api/chat', async (req, res) => {
  const { message, history = [] } = req.body;
  
  if (!process.env.GEMINI_API_KEY) {
    return res.json({ role: 'assistant', content: "⚠️ Gemini API Key is missing. Please add `GEMINI_API_KEY` to your .env file." });
  }

  try {
    // Map history and ensure it starts with 'user' role
    let mappedHistory = history.map(m => ({ 
      role: m.role === 'user' ? 'user' : 'model', 
      parts: [{ text: m.content }] 
    }));

    // FIX: Google Generative AI requires history to start with 'user'
    while (mappedHistory.length > 0 && mappedHistory[0].role !== 'user') {
      mappedHistory.shift();
    }

    const chat = model.startChat({
      history: mappedHistory,
      generationConfig: { maxOutputTokens: 2000 },
    });

    const result = await chat.sendMessage(message);
    
    let responseText = result.response.text();
    let finalContent = responseText;
    let toolOutputs = [];

    // Action Handlers
    if (responseText.includes("[ACTION: RUN_PRIORITIZER]")) {
      const scriptPath = path.join(__dirname, '..', 'scripts/generate_report.cjs');
      execSync(`node ${scriptPath}`, { env: process.env });
      toolOutputs.push("✅ **Priority analysis complete.** Live report updated [here](http://localhost:3001/report).");
      finalContent = finalContent.replace("[ACTION: RUN_PRIORITIZER]", "");
    }

    if (responseText.includes("[ACTION: RUN_DTO_REPORT]")) {
      const scriptPath = path.join(__dirname, '..', 'scripts/generate_dto_report.cjs');
      execSync(`node ${scriptPath}`, { env: process.env });
      toolOutputs.push("✅ **DTO KEV report complete.** View the report [here](http://localhost:3001/dto-report).");
      finalContent = finalContent.replace("[ACTION: RUN_DTO_REPORT]", "");
    }

    const enrichMatch = responseText.match(/\[ACTION: RUN_ENRICHER\s+([^\s\]]+)(?:\s+([^\s\]]+))?\]/);
    if (enrichMatch) {
      const indicator = enrichMatch[1];
      const type = enrichMatch[2] || 'ip';
      const scriptPath = path.join(__dirname, '..', 'scripts/ti_proxy.cjs');
      const output = execSync(`node ${scriptPath} ${indicator} ${type}`, { env: process.env, encoding: 'utf8' });
      toolOutputs.push(`### TI Enrichment Result: ${indicator}\n\`\`\`json\n${output}\n\`\`\``);
      finalContent = finalContent.replace(/\[ACTION: RUN_ENRICHER\s+[^\]]+\]/, "");
    }

    if (responseText.includes("[ACTION: RUN_PULSE]")) {
      const scriptPath = path.join(__dirname, '..', 'scripts/auto_analyst.cjs');
      const output = execSync(`node ${scriptPath}`, { env: process.env, encoding: 'utf8' });
      toolOutputs.push("✅ **Autonomous pulse complete.**\n\n" + output);
      finalContent = finalContent.replace("[ACTION: RUN_PULSE]", "");
    }

    if (responseText.includes("[ACTION: RUN_WIZ_REINGEST]")) {
      const scriptPath = path.join(__dirname, '..', 'scripts/wiz_reingest.cjs');
      const output = execSync(`node ${scriptPath}`, { env: process.env, encoding: 'utf8' });
      toolOutputs.push("✅ **Wiz re-ingestion complete.**\n\n" + output);
      finalContent = finalContent.replace("[ACTION: RUN_WIZ_REINGEST]", "");
    }

    const scanMatch = responseText.match(/\[ACTION: RUN_VULN_SCAN\s+([^\s\]]+)(?:\s+([^\s\]]+))?\]/);
    if (scanMatch) {
      const target = scanMatch[1];
      const cve = scanMatch[2] || '';
      const scriptPath = path.join(__dirname, '..', 'vulnerability-validator/scripts/scan_vuln.cjs');
      const output = execSync(`node ${scriptPath} ${target} ${cve}`, { env: process.env, encoding: 'utf8' });
      toolOutputs.push(`### Scan Result: ${target}\n\`\`\`json\n${output}\n\`\`\``);
      finalContent = finalContent.replace(/\[ACTION: RUN_VULN_SCAN\s+[^\]]+\]/, "");
    }

    const emailMatch = responseText.match(/\[ACTION: SEND_EMAIL\s+([^\s\]]+)\s+"([^"]+)"\s+"([^"]+)"\]/);
    if (emailMatch) {
      const to = emailMatch[1];
      const subject = emailMatch[2];
      const body = emailMatch[3];
      const scriptPath = path.join(__dirname, '..', 'asset-email-reporter/scripts/send_email.cjs');
      const output = execSync(`node ${scriptPath} "${to}" "${subject}" "${body}"`, { env: process.env, encoding: 'utf8' });
      toolOutputs.push(`✅ **Email dispatched.**\n${output}`);
      finalContent = finalContent.replace(/\[ACTION: SEND_EMAIL\s+[^\]]+\]/, "");
    }

    if (toolOutputs.length > 0) {
      finalContent += "\n\n---\n" + toolOutputs.join("\n\n");
    }

    res.json({ role: 'assistant', content: finalContent.trim() });

  } catch (error) {
    console.error("Gemini API Error:", error.message);
    res.json({ role: 'assistant', content: `⚠️ **Error from Analyst Engine:** ${error.message}` });
  }
});

app.get('/report', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'security_report.html'));
});

app.get('/dto-report', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dto_report.html'));
});

app.listen(port, () => {
  console.log(`VBG Security Engine (AI-Powered) running at http://localhost:${port}`);
});
