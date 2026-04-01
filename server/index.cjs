const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const port = process.env.PORT || 3001;

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

// Intent Mapping (Golden Prompts)
const SKILL_MAP = [
  { trigger: /top 10|prioritize|risk report/i, script: 'scripts/generate_report.cjs', description: 'Generating Priority Report...' },
  { trigger: /enrich|reputation|check ip/i, script: 'scripts/ti_proxy.cjs', description: 'Enriching Indicator...' },
  { trigger: /auto analyst|pulse/i, script: 'scripts/auto_analyst.cjs', description: 'Running Autonomous Analysis...' },
];

app.post('/api/chat', async (req, res) => {
  const { message } = req.body;
  console.log(`User: ${message}`);

  let handled = false;

  for (const skill of SKILL_MAP) {
    if (skill.trigger.test(message)) {
      handled = true;
      
      let command = `node ${path.join(__dirname, '..', skill.script)}`;
      
      // Special handling for TI Enrichment to extract indicator
      if (skill.script.includes('ti_proxy')) {
        const ipMatch = message.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
        if (ipMatch) {
          command += ` ${ipMatch[0]}`;
        } else {
          return res.json({ role: 'assistant', content: "I'd be happy to enrich that for you. Could you please provide the IP address, Domain, or Hash you'd like me to check?" });
        }
      }

      exec(command, { env: process.env }, (error, stdout, stderr) => {
        if (error) {
          return res.json({ role: 'assistant', content: `Error executing analysis: ${error.message}` });
        }
        
        if (skill.script.includes('generate_report')) {
          res.json({ role: 'assistant', content: `Analysis complete. I have updated the security report. You can view it [here](http://localhost:3001/report).` });
        } else {
          try {
            // Attempt to parse JSON output for a cleaner chat response
            const json = JSON.parse(stdout);
            let content = `### Analysis for ${json.indicator || 'Target'}\n`;
            content += `**Confidence Score:** ${json.confidence_score || 'N/A'}\n\n`;
            if (json.consensus_findings) {
              json.consensus_findings.forEach(f => content += `- ${f}\n`);
            }
            res.json({ role: 'assistant', content: content || stdout });
          } catch (e) {
            res.json({ role: 'assistant', content: stdout || stderr });
          }
        }
      });
      break;
    }
  }

  if (!handled) {
    res.json({ 
      role: 'assistant', 
      content: `I'm your VBG Security Analyst. I can help you prioritize vulnerabilities, enrich IPs, or run autonomous pulses. Try asking: "What are my top 10 risks?"` 
    });
  }
});

// Serve the static report
app.get('/report', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'security_report.html'));
});

app.listen(port, () => {
  console.log(`Backend API running at http://localhost:${port}`);
});
