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

// Initialize Gemini API
if (!process.env.GEMINI_API_KEY) {
  console.warn("⚠️  WARNING: GEMINI_API_KEY not found in environment variables.");
}
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "dummy_key");
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'vuln_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || process.env.DB_PASSWORD,
};

// System prompt to give Gemini context about the environment
const SYSTEM_PROMPT = `
You are the VBG Security Analyst, an expert AI agent for vulnerability management.
You have access to a PostgreSQL database (vuln_db) with Tenable, Wiz, and CISA KEV data.

CRITICAL INSTRUCTION: Only execute tools if the user explicitly asks for an action (e.g. "generate a report", "run a pulse", "enrich this IP"). 
For general questions or analysis of existing data, do NOT trigger a tool.

To trigger a tool, you MUST include the exact string in your response:
1. "[ACTION: RUN_PRIORITIZER]" - To update the security report.
2. "[ACTION: RUN_ENRICHER <ip>]" - To check threat intelligence for an IP.
3. "[ACTION: RUN_PULSE]" - To run the autonomous auto-analyst check.

If you are not running a tool, simply answer the user's question in Markdown.
`;

app.post('/api/chat', async (req, res) => {
  const { message, history = [] } = req.body;
  
  if (!process.env.GEMINI_API_KEY) {
    return res.json({ role: 'assistant', content: "⚠️ Gemini API Key is missing. Please add `GEMINI_API_KEY` to your .env file." });
  }

  try {
    const chat = model.startChat({
      history: history.map(m => ({ role: m.role === 'user' ? 'user' : 'model', parts: [{ text: m.content }] })),
      generationConfig: { maxOutputTokens: 2000 },
    });

    const result = await chat.sendMessage([
      { text: SYSTEM_PROMPT },
      { text: message }
    ]);
    
    let responseText = result.response.text();
    let finalContent = responseText;

    // 1. RUN_PRIORITIZER
    if (responseText.includes("[ACTION: RUN_PRIORITIZER]")) {
      console.log("Triggering Prioritizer via Gemini...");
      const scriptPath = path.join(__dirname, '..', 'scripts/generate_report.cjs');
      execSync(`node ${scriptPath}`, { env: process.env });
      finalContent = responseText.replace("[ACTION: RUN_PRIORITIZER]", "") + 
        "\n\n✅ **Priority analysis complete.** You can view the live report [here](http://localhost:3001/report).";
    }

    // 2. RUN_ENRICHER
    const enrichMatch = responseText.match(/\[ACTION: RUN_ENRICHER\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (enrichMatch) {
      const ip = enrichMatch[1];
      console.log(`Triggering TI Enrichment for ${ip} via Gemini...`);
      const scriptPath = path.join(__dirname, '..', 'scripts/ti_proxy.cjs');
      const output = execSync(`node ${scriptPath} ${ip}`, { env: process.env, encoding: 'utf8' });
      finalContent = responseText.replace(/\[ACTION: RUN_ENRICHER\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]/, "") + "\n\n" + output;
    }

    // 3. RUN_PULSE
    if (responseText.includes("[ACTION: RUN_PULSE]")) {
      console.log("Triggering Auto-Analyst Pulse via Gemini...");
      const scriptPath = path.join(__dirname, '..', 'scripts/auto_analyst.cjs');
      const output = execSync(`node ${scriptPath}`, { env: process.env, encoding: 'utf8' });
      finalContent = responseText.replace("[ACTION: RUN_PULSE]", "") + 
        "\n\n✅ **Autonomous pulse complete.** Alerts have been dispatched if critical risks were found.\n\n" + output;
    }

    res.json({ role: 'assistant', content: finalContent.trim() });

  } catch (error) {
    console.error("Gemini API Error:", error.message);
    res.json({ role: 'assistant', content: `Error from Gemini AI: ${error.message}` });
  }
});

app.get('/report', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'security_report.html'));
});

app.listen(port, () => {
  console.log(`VBG Security Engine (AI-Powered) running at http://localhost:${port}`);
});
