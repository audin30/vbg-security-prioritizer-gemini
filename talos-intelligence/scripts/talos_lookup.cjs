const axios = require('axios');

/**
 * Cisco Talos Intelligence API Lookup Script
 * 
 * Authentication: OIDC (OAuth2 Client Credentials)
 * Environment Variables:
 * - TALOS_CLIENT_ID: Your OIDC Client ID
 * - TALOS_CLIENT_SECRET: Your OIDC Client Secret
 */

const AUTH_URL = 'https://id.cisco.com/oauth2/default/v1/token';
const API_BASE_URL = 'https://api.talosintelligence.com/v2';

async function getAccessToken() {
    const clientId = process.env.TALOS_CLIENT_ID;
    const clientSecret = process.env.TALOS_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
        throw new Error('TALOS_CLIENT_ID and TALOS_CLIENT_SECRET must be set.');
    }

    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('scope', 'talos:reputation_read');

    const authHeader = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await axios.post(AUTH_URL, params, {
        headers: {
            'Authorization': `Basic ${authHeader}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    return response.data.access_token;
}

async function queryTalos(type, value) {
    const token = await getAccessToken();
    let endpoint = '';

    switch (type.toLowerCase()) {
        case 'ip':
            endpoint = `/reputation/ip/${value}`;
            break;
        case 'domain':
            endpoint = `/reputation/domain/${value}`;
            break;
        case 'hash':
            endpoint = `/reputation/hash/${value}`;
            break;
        default:
            throw new Error('Invalid type. Use "ip", "domain", or "hash".');
    }

    const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json'
        }
    });

    return response.data;
}

async function main() {
    const args = process.argv.slice(2);
    const type = args[0];
    const value = args[1];

    if (!type || !value) {
        console.log('Usage: node talos_lookup.cjs <ip|domain|hash> <value>');
        process.exit(1);
    }

    try {
        const result = await queryTalos(type, value);
        console.log(JSON.stringify(result, null, 2));
    } catch (error) {
        const errorMsg = error.response ? JSON.stringify(error.response.data) : error.message;
        console.error(`Error querying Talos: ${errorMsg}`);
        process.exit(1);
    }
}

main();
