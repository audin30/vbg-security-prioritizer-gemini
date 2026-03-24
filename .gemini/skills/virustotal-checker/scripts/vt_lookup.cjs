const https = require('https');

/**
 * VirusTotal API v3 lookup script for IPv4 and Domains.
 * Usage: node vt_lookup.cjs <type: ip|domain> <target>
 * Expects VIRUSTOTAL_API_KEY environment variable.
 */

const apiKey = process.env.VIRUSTOTAL_API_KEY;
if (!apiKey) {
  console.error('Error: VIRUSTOTAL_API_KEY environment variable not set.');
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length < 2) {
  console.error('Usage: node vt_lookup.cjs <type: ip|domain> <target>');
  process.exit(1);
}

const type = args[0].toLowerCase(); // 'ip' or 'domain'
const target = args[1];

let endpoint = '';
if (type === 'ip' || type === 'ipv4') {
  endpoint = `/api/v3/ip_addresses/${target}`;
} else if (type === 'domain' || type === 'hostname') {
  endpoint = `/api/v3/domains/${target}`;
} else {
  console.error('Error: Type must be "ip" or "domain".');
  process.exit(1);
}

const options = {
  hostname: 'www.virustotal.com',
  port: 443,
  path: endpoint,
  method: 'GET',
  headers: {
    'x-apikey': apiKey,
    'Accept': 'application/json'
  }
};

const req = https.get(options, (res) => {
  let body = '';

  res.on('data', (chunk) => {
    body += chunk;
  });

  res.on('end', () => {
    if (res.statusCode === 200) {
      try {
        const json = JSON.parse(body);
        const stats = json.data.attributes.last_analysis_stats;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const malicious = stats.malicious;

        console.log(`\nVirusTotal Analysis for ${target}:`);
        console.log(`-----------------------------------`);
        console.log(`Malicious: ${malicious}`);
        console.log(`Suspicious: ${stats.suspicious}`);
        console.log(`Undetected: ${stats.undetected}`);
        console.log(`Harmless: ${stats.harmless}`);
        console.log(`Total Scanners: ${total}`);
        console.log(`Reputation: ${json.data.attributes.reputation}`);
        console.log(`Report Link: https://www.virustotal.com/gui/${type === 'ip' ? 'ip-address' : 'domain'}/${target}`);
        
        if (malicious > 0) {
            console.log(`\n[ALERT] This asset has been flagged by ${malicious} security vendors.`);
        } else {
            console.log(`\n[CLEAN] No malicious detections found.`);
        }

      } catch (e) {
        console.error(`Error parsing JSON response: ${e.message}`);
      }
    } else if (res.statusCode === 401) {
       console.error('Error 401: Invalid VirusTotal API Key.');
    } else if (res.statusCode === 404) {
       console.error(`Error 404: Resource ${target} not found in VirusTotal.`);
    } else if (res.statusCode === 429) {
       console.error('Error 429: VirusTotal API rate limit exceeded.');
    } else {
       console.error(`Error ${res.statusCode}: ${res.statusMessage}`);
    }
  });
});

req.on('error', (e) => {
  console.error(`Request error: ${e.message}`);
});
