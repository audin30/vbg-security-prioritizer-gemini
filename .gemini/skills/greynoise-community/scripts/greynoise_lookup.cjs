const axios = require('axios');

/**
 * GreyNoise Community API Lookup Script
 * 
 * Authentication: API Key (Header 'key')
 * Environment Variables:
 * - GREYNOISE_API_KEY: Your GreyNoise Community API Key
 */

const API_BASE_URL = 'https://api.greynoise.io/v3/community';

async function queryGreyNoise(ip) {
    const apiKey = process.env.GREYNOISE_API_KEY;

    if (!apiKey) {
        throw new Error('GREYNOISE_API_KEY must be set.');
    }

    const response = await axios.get(`${API_BASE_URL}/${ip}`, {
        headers: {
            'key': apiKey,
            'Accept': 'application/json'
        }
    });

    return response.data;
}

async function main() {
    const args = process.argv.slice(2);
    const ip = args[0];

    if (!ip) {
        console.log('Usage: node greynoise_lookup.cjs <ip_address>');
        process.exit(1);
    }

    try {
        const result = await queryGreyNoise(ip);
        
        // Pretty format the response for the LLM
        const summary = {
            ip: result.ip,
            noise: result.noise,
            riot: result.riot,
            classification: result.classification,
            name: result.name || 'Unknown Actor',
            message: result.message
        };

        console.log(JSON.stringify(summary, null, 2));
    } catch (error) {
        const errorMsg = error.response ? JSON.stringify(error.response.data) : error.message;
        console.error(`Error querying GreyNoise: ${errorMsg}`);
        process.exit(1);
    }
}

main();
