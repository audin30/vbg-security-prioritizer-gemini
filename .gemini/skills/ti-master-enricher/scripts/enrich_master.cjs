<<<<<<< HEAD
const { execFileSync } = require('child_process');
=======
const { execSync } = require('child_process');
>>>>>>> 2717368 (Updated 031826)

/**
 * Master TI Enricher Script
 * 
 * This script coordinates lookups across:
 * 1. GreyNoise (Noise Filter)
 * 2. AlienVault OTX (Threat Pulses)
 * 3. VirusTotal (Multi-Engine Consensus)
 * 
 * It calculates a unified Confidence Score based on the overlap of these sources.
 */

function runSkillScript(scriptPath, args) {
    try {
<<<<<<< HEAD
        const output = execFileSync('node', [scriptPath, ...args], { encoding: 'utf8' });
=======
        const output = execSync(`node ${scriptPath} ${args.join(' ')}`, { encoding: 'utf8' });
>>>>>>> 2717368 (Updated 031826)
        return JSON.parse(output);
    } catch (error) {
        return { error: error.message };
    }
}

async function main() {
    const args = process.argv.slice(2);
    const type = args[0]; // ip, domain, or hash
    const indicator = args[1];

    if (!type || !indicator) {
        console.log('Usage: node enrich_master.cjs <ip|domain|hash> <indicator>');
        process.exit(1);
    }

    console.log(`[*] Enriching ${type}: ${indicator}...`);

    // Paths to the individual skill scripts (assuming they are installed in the workspace)
    const scripts = {
        greynoise: '../greynoise-community/scripts/greynoise_lookup.cjs',
        otx: '../alienvault-otx/scripts/otx_lookup.cjs',
        vt: '../virustotal-checker/scripts/vt_lookup.cjs' // Assuming standard path
    };

    const results = {
        greynoise: type === 'ip' ? runSkillScript(scripts.greynoise, [indicator]) : null,
        otx: runSkillScript(scripts.otx, [type, indicator]),
        vt: runSkillScript(scripts.vt, [type, indicator])
    };

    // --- Scoring Logic ---
    let score = 0;
    let maxScore = 0;
    const findings = [];

    // GreyNoise Scoring (IP only)
    if (results.greynoise && !results.greynoise.error) {
        maxScore += 10;
        if (results.greynoise.classification === 'malicious') {
            score += 10;
            findings.push('GreyNoise: Malicious');
        } else if (results.greynoise.classification === 'benign' || results.greynoise.riot) {
            score -= 5; // Reduce priority for known benign noise
            findings.push('GreyNoise: Benign/RIOT (Noise Filter Applied)');
        }
    }

    // OTX Scoring
    if (results.otx && !results.otx.error) {
        maxScore += 10;
        if (results.otx.pulse_count > 0) {
            const weight = Math.min(results.otx.pulse_count, 5) * 2;
            score += weight;
            findings.push(`OTX: Connected to ${results.otx.pulse_count} pulses`);
        }
    }

<<<<<<< HEAD
    // VT Scoring
    if (results.vt && !results.vt.error) {
        maxScore += 20;
        if (results.vt.malicious > 0) {
            score += Math.min(results.vt.malicious, 20);
            findings.push(`VirusTotal: ${results.vt.malicious} engines flagged`);
=======
    // VT Scoring (Simplified for this script)
    if (results.vt && !results.vt.error) {
        maxScore += 20;
        // Logic depends on the VT script output format, usually look for positives
        if (results.vt.positives > 0) {
            score += Math.min(results.vt.positives, 20);
            findings.push(`VirusTotal: ${results.vt.positives} engines flagged`);
>>>>>>> 2717368 (Updated 031826)
        }
    }

    const confidence = maxScore > 0 ? Math.max(0, (score / maxScore) * 100).toFixed(0) : 0;

    const report = {
        indicator,
        type,
        confidence_score: `${confidence}%`,
        consensus_findings: findings,
        raw_summaries: {
            greynoise: results.greynoise ? results.greynoise.classification : 'N/A',
            otx_pulses: results.otx ? results.otx.pulse_count : 'N/A',
<<<<<<< HEAD
            vt_malicious: results.vt ? results.vt.malicious : 'N/A'
=======
            vt_positives: results.vt ? results.vt.positives : 'N/A'
>>>>>>> 2717368 (Updated 031826)
        }
    };

    console.log(JSON.stringify(report, null, 2));
}

main();
