const axios = require('axios');

/**
 * AlienVault OTX API Lookup Script
 * 
 * Authentication: API Key (Header 'X-OTX-API-KEY')
 * Environment Variables:
 * - OTX_API_KEY: Your AlienVault OTX API Key
 */

const API_BASE_URL = 'https://otx.alienvault.com/api/v1/indicators';

async function queryOTX(type, indicator) {
    const apiKey = process.env.OTX_API_KEY;

    if (!apiKey) {
        throw new Error('OTX_API_KEY must be set.');
    }

    let endpoint = '';
    switch (type.toLowerCase()) {
        case 'ipv4':
        case 'ip':
            endpoint = `IPv4/${indicator}/general`;
            break;
        case 'domain':
            endpoint = `domain/${indicator}/general`;
            break;
        case 'hostname':
            endpoint = `hostname/${indicator}/general`;
            break;
        case 'file':
        case 'hash':
            endpoint = `file/${indicator}/general`;
            break;
        default:
            throw new Error('Invalid type. Use "ip", "domain", "hostname", or "hash".');
    }

    const response = await axios.get(`${API_BASE_URL}/${endpoint}`, {
        headers: {
            'X-OTX-API-KEY': apiKey,
            'Accept': 'application/json'
        }
    });

    return response.data;
}

async function main() {
    const args = process.argv.slice(2);
    const type = args[0];
    const indicator = args[1];

    if (!type || !indicator) {
        console.log('Usage: node otx_lookup.cjs <ip|domain|hostname|hash> <value>');
        process.exit(1);
    }

    try {
        const result = await queryOTX(type, indicator);
        
        // Summarize results for the LLM
        const summary = {
            indicator: result.indicator,
            type: result.type,
            pulse_count: result.pulse_info ? result.pulse_info.count : 0,
            pulses: result.pulse_info ? result.pulse_info.pulses.slice(0, 5).map(p => ({
                name: p.name,
                description: p.description,
                tags: p.tags,
                references: p.references.slice(0, 2)
            })) : [],
            base_indicator: result.base_indicator
        };

        console.log(JSON.stringify(summary, null, 2));
    } catch (error) {
        const errorMsg = error.response ? JSON.stringify(error.response.data) : error.message;
        console.error(`Error querying AlienVault OTX: ${errorMsg}`);
        process.exit(1);
    }
}

main();
