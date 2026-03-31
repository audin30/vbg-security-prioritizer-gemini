#!/usr/bin/env node
'use strict';

const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'vuln_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || process.env.DB_PASSWORD || '',
};

const OUTPUT_FILE = process.argv[2] || path.join(__dirname, '..', 'security_report.html');

async function queryDB(client, sql) {
  const res = await client.query(sql);
  return res.rows;
}

async function main() {
  const client = new Client(DB_CONFIG);
  await client.connect();
  console.log('Connected to database. Running Dynamic Risk queries...');

  // 1. Summary counts
  const summary = await queryDB(client, `
    SELECT
      (SELECT COUNT(DISTINCT ipv4) FROM public.tenable_assets WHERE last_seen >= NOW() - INTERVAL '90 days') as active_tenable_assets,
      (SELECT COUNT(*) FROM public.tenable_findings) as total_findings,
      (SELECT COUNT(*) FROM public.cisa_kev) as kev_entries,
      (SELECT COUNT(*) FROM public.tenable_findings WHERE exploited_by_malware = true) as malware_exploitable,
      (SELECT COUNT(*) FROM public.wiz_vulnerabilities WHERE status NOT IN ('RESOLVED','REJECTED')) as active_wiz_vulns,
      (SELECT COUNT(*) FROM public.dto_assets) as total_enriched_assets,
      (SELECT COUNT(DISTINCT exposed_entity_id) FROM public.wiz_network_exposures WHERE exposure_type = 'PUBLIC_INTERNET') as public_cloud_entities
  `);

  // 2. Top prioritized assets with Dynamic Risk Logic
  const topAssets = await queryDB(client, `
    WITH 
      -- 1. Aggregate vulnerabilities with Threat Intel (VPR, Exploit status)
      asset_vuln_summary AS (
          SELECT 
              hostname, ip_address, 
              MAX(GREATEST(cvss_score, vpr_score)) as max_threat_score,
              COUNT(DISTINCT cve_id) as total_cves,
              STRING_AGG(DISTINCT source, ', ') as sources,
              BOOL_OR(is_kev) as has_kev,
              BOOL_OR(exploit_available) as has_exploit,
              BOOL_OR(exploited_by_malware) as has_malware,
              MAX(acr_score) as max_acr
          FROM (
              SELECT 
                ta.hostname, ta.ipv4 as ip_address, 
                tf.cvss_score, COALESCE(tf.vpr_score, 0) as vpr_score,
                tf.cve as cve_id, 'Tenable' as source, 
                EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = tf.cve) as is_kev,
                COALESCE(tf.exploit_available, false) as exploit_available,
                COALESCE(tf.exploited_by_malware, false) as exploited_by_malware,
                COALESCE(ta.acr_score, 5) as acr_score
              FROM public.tenable_findings tf
              JOIN public.tenable_assets ta ON tf.asset_id = ta.id
              WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
              
              UNION ALL
              
              SELECT 
                wi.name as hostname, NULL as ip_address, 
                wv.cvss_score, 0 as vpr_score,
                wv.cve_id, 'Wiz' as source, 
                EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = wv.cve_id) as is_kev,
                false as exploit_available,
                false as exploited_by_malware,
                7 as acr_score -- Default importance for cloud resources
              FROM public.wiz_vulnerabilities wv
              JOIN public.wiz_inventory wi ON wv.resource_id = wi.id
              WHERE wv.status NOT IN ('RESOLVED', 'REJECTED')
          ) t
          GROUP BY hostname, ip_address
      ),
      -- 2. Check for active Wiz Detections
      active_threats AS (
          SELECT primary_resource_id, COUNT(*) as detection_count
          FROM public.wiz_detections
          WHERE ignored = false AND created_at >= NOW() - INTERVAL '7 days'
          GROUP BY primary_resource_id
      ),
      -- 3. Environmental context
      exposure AS (
          SELECT name as hostname, 1 as is_exposed FROM public.wiz_inventory i
          WHERE EXISTS (SELECT 1 FROM public.wiz_network_exposures ne WHERE ne.exposed_entity_id = i.id AND ne.exposure_type = 'PUBLIC_INTERNET')
          UNION
          SELECT hostname, 1 as is_exposed FROM public.tenable_asm_assets WHERE last_seen >= NOW() - INTERVAL '30 days'
      ),
      sensitivity AS (
          SELECT resource_name as hostname, 1 as has_pii FROM public.wiz_data_findings WHERE severity IN ('CRITICAL', 'HIGH')
      )
    SELECT 
        b.hostname, b.ip_address, b.max_threat_score, b.total_cves, b.sources, b.has_kev, b.has_exploit, b.has_malware, b.max_acr,
        COALESCE(e.is_exposed, 0) = 1 as is_exposed,
        COALESCE(s.has_pii, 0) = 1 as has_pii,
        ac.business_unit as bu, ac.owner,
        (
            (COALESCE(b.max_threat_score, 0) * (COALESCE(b.max_acr, 5) / 5.0)) + -- Scale base score by ACR
            (CASE WHEN b.has_kev THEN 100 ELSE 0 END) + 
            (CASE WHEN b.has_malware THEN 150 ELSE 0 END) + -- Malware association is critical
            (CASE WHEN b.has_exploit THEN 50 ELSE 0 END) + 
            (CASE WHEN e.is_exposed = 1 THEN 100 ELSE 0 END) + 
            (CASE WHEN s.has_pii = 1 THEN 100 ELSE 0 END) + 
            (CASE WHEN ac.business_unit IN ('citrix', 'netscaler') THEN 30 ELSE 0 END)
        ) as priority_score
    FROM asset_vuln_summary b
    LEFT JOIN (SELECT hostname, MAX(is_exposed) as is_exposed FROM exposure GROUP BY hostname) e ON e.hostname = b.hostname
    LEFT JOIN (SELECT hostname, MAX(has_pii) as has_pii FROM sensitivity GROUP BY hostname) s ON s.hostname = b.hostname
    LEFT JOIN public.dto_assets ac ON ac.asset_name = b.hostname
    ORDER BY priority_score DESC
    LIMIT 25
  `);

  await client.end();
  console.log('Queries complete. Generating HTML...');

  const reportDate = new Date().toLocaleString();
  const s = summary[0];

  const scoreColor = (score) => {
    if (score >= 400) return '#7f1d1d'; // Deepest Red
    if (score >= 300) return '#991b1b'; 
    if (score >= 200) return '#dc2626'; 
    if (score >= 100) return '#ea580c'; 
    return '#6b7280';
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dynamic Security Report — ${reportDate}</title>
  <style>
    body { font-family: 'Inter', system-ui, sans-serif; background: #f1f5f9; color: #334155; margin: 0; padding: 20px; }
    .container { max-width: 1300px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    h1 { color: #0f172a; margin: 0; }
    .model-badge { background: #1e293b; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; vertical-align: middle; margin-left: 10px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 25px 0; }
    .stat-card { background: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; }
    .stat-val { font-size: 22px; font-weight: bold; color: #2563eb; }
    .stat-label { font-size: 11px; color: #64748b; text-transform: uppercase; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { text-align: left; background: #f8fafc; padding: 12px; border-bottom: 2px solid #e2e8f0; font-size: 11px; color: #64748b; }
    td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
    .badge { padding: 3px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; color: white; margin-right: 4px; }
    .score-pill { padding: 4px 10px; border-radius: 6px; color: white; font-weight: bold; font-family: monospace; }
    .toxic { background: #fff1f2; border-left: 4px solid #ef4444; }
    .footer { margin-top: 40px; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 20px; }
  </style>
</head>
<body>
<div class="container">
  <h1>Security Prioritization <span class="model-badge">DYNAMIC RISK MODEL V3</span></h1>
  <p style="color:#64748b; font-size: 12px;">Generated: ${reportDate} | Incorporating Tenable VPR/ACR + Wiz Exposure + Malware Intel</p>

  <div class="stats">
    <div class="stat-card"><div class="stat-val">${s.active_tenable_assets}</div><div class="stat-label">Active Assets</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#dc2626">${s.malware_exploitable}</div><div class="stat-label">Malware Exploitable</div></div>
    <div class="stat-card"><div class="stat-val">${s.kev_entries}</div><div class="stat-label">CISA KEV</div></div>
    <div class="stat-card"><div class="stat-val">${s.public_cloud_entities}</div><div class="stat-label">Public (Cloud)</div></div>
    <div class="stat-card"><div class="stat-val">${s.total_enriched_assets}</div><div class="stat-label">Business Enriched</div></div>
  </div>

  <h2>🏆 Top Remediation Targets</h2>
  <table>
    <thead>
      <tr>
        <th>Asset / IP</th>
        <th>Owner / BU</th>
        <th>Score</th>
        <th>Risk Modifiers</th>
        <th>Max Threat / ACR</th>
        <th>Sources</th>
      </tr>
    </thead>
    <tbody>
      ${topAssets.map(r => `
      <tr class="${r.has_malware || (r.is_exposed && r.has_pii) ? 'toxic' : ''}">
        <td><strong>${r.hostname || 'Unknown'}</strong><br><small style="color:#64748b">${r.ip_address || 'Cloud Resource'}</small></td>
        <td>${r.owner || 'Unassigned'}<br><small>${r.bu || 'N/A'}</small></td>
        <td><span class="score-pill" style="background:${scoreColor(r.priority_score)}">${Math.round(r.priority_score)}</span></td>
        <td>
          ${r.has_malware ? '<span class="badge" style="background:#000">MALWARE</span>' : ''}
          ${r.has_kev ? '<span class="badge" style="background:#7c3aed">KEV</span>' : ''}
          ${r.has_exploit ? '<span class="badge" style="background:#dc2626">EXPLOIT</span>' : ''}
          ${r.is_exposed ? '<span class="badge" style="background:#ea580c">PUBLIC</span>' : ''}
          ${r.has_pii ? '<span class="badge" style="background:#db2777">PII</span>' : ''}
        </td>
        <td><strong>${r.max_threat_score}</strong> / <span style="color:#2563eb">ACR ${r.max_acr}</span></td>
        <td><small>${r.sources}</small></td>
      </tr>`).join('')}
    </tbody>
  </table>

  <div class="footer">
    <strong>Scoring Model:</strong> (Max(CVSS, VPR) * (ACR/5)) + KEV(100) + Malware(150) + Exploit(50) + Public(100) + SensitiveData(100) + BU_Factor(30)
  </div>
</div>
</body>
</html>`;

  fs.writeFileSync(OUTPUT_FILE, html, 'utf8');
  console.log(`\nReport saved to: ${OUTPUT_FILE}`);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
