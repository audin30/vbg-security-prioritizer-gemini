/**
 * TI Proxy Script for VBG Security Chat
 * This script runs the enrich_master.cjs or individual TI scripts.
 */
'use strict';

require('dotenv').config();
const { execSync } = require('child_process');
const path = require('path');

const indicator = process.argv[2];
const type = process.argv[3] || 'ip';

if (!indicator) {
  console.log("Please provide an indicator (IP, Domain, or Hash).");
  process.exit(0);
}

try {
  // Use the local TI Master Enricher skill script
  const masterScript = path.join(__dirname, '..', 'ti-master-enricher/scripts/enrich_master.cjs');
  
  // Execute and return JSON output
  const output = execSync(`node ${masterScript} ${type} ${indicator}`, {
    env: process.env,
    encoding: 'utf8'
  });

  console.log(output);
} catch (e) {
  console.error(`TI Enrichment failed: ${e.message}`);
}
