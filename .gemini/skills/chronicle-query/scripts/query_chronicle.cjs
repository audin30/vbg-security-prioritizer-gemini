const { google } = require('googleapis');
<<<<<<< HEAD
const axios = require('axios');

/**
 * Chronicle Query Script for Gemini CLI
 *
 * Requirements:
 * - googleapis
=======
const { auth } = require('google-auth-library');
const axios = require('axios');
const fs = require('fs');

/**
 * Chronicle Query Script for Gemini CLI
 * 
 * Requirements:
 * - googleapis
 * - google-auth-library
>>>>>>> 2717368 (Updated 031826)
 * - axios
 * 
 * Environment Variables:
 * - CHRONICLE_CUSTOMER_ID: Your Chronicle Customer ID
 * - GOOGLE_APPLICATION_CREDENTIALS: Path to your Service Account JSON file
 */

const REGION = 'us'; // Defaulting to US region as requested
const API_BASE_URL = `https://${REGION}-backstory.googleapis.com`;

async function getAccessToken() {
  const authClient = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/chronicle-backstory'],
  });
  return await authClient.getAccessToken();
}

async function queryDetections(customerId, target) {
  const token = await getAccessToken();
  const url = `${API_BASE_URL}/v1/projects/${customerId}/locations/${REGION}/instances/${customerId}/detections`;
  
  // Example filter for detections related to an IP or Hostname
  // Note: Actual filtering logic depends on the specific detection schema
  const response = await axios.get(url, {
    headers: { Authorization: `Bearer ${token}` },
    params: { page_size: 10 }
  });
  
  return response.data;
}

async function searchUdm(customerId, target) {
  const token = await getAccessToken();
  const url = `${API_BASE_URL}/v1/projects/${customerId}/locations/${REGION}/instances/${customerId}/udmSearch`;
  
  const payload = {
    query: `principal.ip = "${target}" OR target.ip = "${target}" OR principal.hostname = "${target}"`,
    start_time: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Last 24 hours
    end_time: new Date().toISOString()
  };

  const response = await axios.post(url, payload, {
    headers: { Authorization: `Bearer ${token}` }
  });
  
  return response.data;
}

async function main() {
  const args = process.argv.slice(2);
  const type = args[0]; // 'detection' or 'udm'
  const target = args[1]; // IP or Hostname
  const customerId = process.env.CHRONICLE_CUSTOMER_ID;

  if (!customerId) {
    console.error('Error: CHRONICLE_CUSTOMER_ID environment variable is not set.');
    process.exit(1);
  }

  if (!type || !target) {
    console.log('Usage: node query_chronicle.cjs <detection|udm> <target>');
    process.exit(1);
  }

  try {
    let results;
    if (type === 'detection') {
      results = await queryDetections(customerId, target);
    } else if (type === 'udm') {
      results = await searchUdm(customerId, target);
    } else {
      console.error('Invalid query type. Use "detection" or "udm".');
      process.exit(1);
    }

    console.log(JSON.stringify(results, null, 2));
  } catch (error) {
    console.error('Error querying Chronicle:', error.response ? error.response.data : error.message);
    process.exit(1);
  }
}

main();
