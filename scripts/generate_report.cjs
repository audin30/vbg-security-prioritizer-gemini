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
  console.log('Connected to database. Running queries...');

  // 1. Summary counts
  const summary = await queryDB(client, `
    SELECT
      (SELECT COUNT(DISTINCT ipv4) FROM public.tenable_assets WHERE last_seen >= NOW() - INTERVAL '90 days') as active_tenable_assets,
      (SELECT COUNT(*) FROM public.tenable_findings) as total_findings,
      (SELECT COUNT(*) FROM public.cisa_kev) as kev_entries,
      (SELECT COUNT(DISTINCT ip_address) FROM public.tenable_asm_assets WHERE last_seen >= NOW() - INTERVAL '30 days') as active_asm_assets,
      (SELECT COUNT(*) FROM public.wiz_vulnerabilities WHERE status NOT IN ('RESOLVED','REJECTED')) as active_wiz_vulns,
      (SELECT COUNT(*) FROM public.dto_assets) as total_enriched_assets,
      (SELECT COUNT(DISTINCT exposed_entity_id) FROM public.wiz_network_exposures WHERE exposure_type = 'PUBLIC_INTERNET') as public_cloud_entities
  `);

  // 2. Top prioritized assets with "Toxic Combination" logic
  // Score = CVSS + KEV(+100) + Public(+100) + SensitiveData(+100) + CriticalBU(+30) + CrossTool(+20)
  const topAssets = await queryDB(client, `
    WITH 
      -- 1. Identify assets and their basic risk factors (KEV matches)
      asset_base AS (
          SELECT 
              hostname, ip_address, 
              MAX(cvss_score) as max_cvss,
              COUNT(DISTINCT cve_id) as total_cves,
              STRING_AGG(DISTINCT source, ', ') as sources,
              BOOL_OR(is_kev) as has_kev
          FROM (
              SELECT ta.hostname, ta.ipv4 as ip_address, tf.cvss_score, tf.cve as cve_id, 'Tenable' as source, EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = tf.cve) as is_kev
              FROM public.tenable_findings tf
              JOIN public.tenable_assets ta ON tf.asset_id = ta.id
              WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
              UNION ALL
              SELECT wi.name as hostname, NULL as ip_address, wv.cvss_score, wv.cve_id, 'Wiz' as source, EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = wv.cve_id) as is_kev
              FROM public.wiz_vulnerabilities wv
              JOIN public.wiz_inventory wi ON wv.resource_id = wi.id
              WHERE wv.status NOT IN ('RESOLVED', 'REJECTED')
          ) t
          GROUP BY hostname, ip_address
      ),
      -- 2. Environmental context (Public Exposure)
      exposure AS (
          SELECT name as hostname, 1 as is_exposed
          FROM public.wiz_inventory i
          WHERE EXISTS (SELECT 1 FROM public.wiz_network_exposures ne WHERE ne.exposed_entity_id = i.id AND ne.exposure_type = 'PUBLIC_INTERNET')
          UNION
          SELECT hostname, 1 as is_exposed FROM public.tenable_asm_assets WHERE last_seen >= NOW() - INTERVAL '30 days'
          UNION
          SELECT ip_address as hostname, 1 as is_exposed FROM public.tenable_asm_assets WHERE last_seen >= NOW() - INTERVAL '30 days'
      ),
      -- 3. Data Sensitivity
      sensitivity AS (
          SELECT resource_name as hostname, 1 as has_pii
          FROM public.wiz_data_findings
          WHERE severity IN ('CRITICAL', 'HIGH')
      )
    SELECT 
        b.hostname, b.ip_address, b.max_cvss, b.total_cves, b.sources, b.has_kev,
        COALESCE(e.is_exposed, 0) = 1 as is_exposed,
        COALESCE(s.has_pii, 0) = 1 as has_pii,
        ac.business_unit as bu, ac.owner,
        (
            COALESCE(b.max_cvss, 0) + 
            (CASE WHEN b.has_kev THEN 100 ELSE 0 END) + 
            (CASE WHEN e.is_exposed = 1 THEN 100 ELSE 0 END) + 
            (CASE WHEN s.has_pii = 1 THEN 100 ELSE 0 END) + 
            (CASE WHEN ac.business_unit IN ('citrix', 'netscaler') THEN 30 ELSE 0 END) + 
            (CASE WHEN b.sources LIKE '%Tenable%' AND b.sources LIKE '%Wiz%' THEN 20 ELSE 0 END)
        ) as priority_score
    FROM asset_base b
    LEFT JOIN (SELECT hostname, MAX(is_exposed) as is_exposed FROM exposure GROUP BY hostname) e ON e.hostname = b.hostname
    LEFT JOIN (SELECT hostname, MAX(has_pii) as has_pii FROM sensitivity GROUP BY hostname) s ON s.hostname = b.hostname
    LEFT JOIN public.dto_assets ac ON ac.asset_name = b.hostname
    ORDER BY priority_score DESC
    LIMIT 25
  `);

  // 3. Top 10 CVEs by frequency and risk
  const topCVEs = await queryDB(client, `
    SELECT 
      cve_id, 
      COUNT(*) as occurrence_count, 
      MAX(cvss_score) as cvss,
      EXISTS (SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = t.cve_id) as in_cisa_kev
    FROM (
      SELECT cve as cve_id, cvss_score FROM public.tenable_findings
      UNION ALL
      SELECT cve_id, cvss_score FROM public.wiz_vulnerabilities WHERE status NOT IN ('RESOLVED','REJECTED')
    ) t
    GROUP BY cve_id
    ORDER BY in_cisa_kev DESC, cvss DESC, occurrence_count DESC
    LIMIT 10
  `);

  await client.end();
  console.log('Queries complete. Generating HTML...');

  const reportDate = new Date().toLocaleString();
  const s = summary[0];

  const scoreColor = (score) => {
    if (score >= 300) return '#991b1b'; // Dark Red (Toxic Combo)
    if (score >= 200) return '#dc2626'; // Red
    if (score >= 100) return '#ea580c'; // Orange
    if (score >= 50) return '#d97706';  // Amber
    return '#6b7280';
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Prioritization Report — ${reportDate}</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f1f5f9; color: #334155; margin: 0; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    h1 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .stat-card { background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; text-align: center; }
    .stat-val { font-size: 24px; font-weight: bold; color: #2563eb; }
    .stat-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 5px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { text-align: left; background: #f8fafc; padding: 12px; border-bottom: 2px solid #e2e8f0; font-size: 12px; }
    td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; }
    .exposed { background: #ef4444; }
    .internal { background: #10b981; }
    .score-pill { padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; }
    .toxic { border: 2px solid #ef4444; background: #fee2e2; }
    .footer { margin-top: 40px; font-size: 11px; color: #94a3b8; text-align: center; }
  </style>
</head>
<body>
<div class="container">
  <h1>Security Prioritization Report</h1>
  <p><strong>Generated:</strong> ${reportDate} | <strong>Model:</strong> Toxic Combination v2</p>

  <div class="stats">
    <div class="stat-card"><div class="stat-val">${s.active_tenable_assets}</div><div class="stat-label">Active Assets</div></div>
    <div class="stat-card"><div class="stat-val">${s.kev_entries}</div><div class="stat-label">CISA KEV</div></div>
    <div class="stat-card"><div class="stat-val">${s.active_asm_assets}</div><div class="stat-label">Public (ASM)</div></div>
    <div class="stat-card"><div class="stat-val">${s.public_cloud_entities}</div><div class="stat-label">Public (Cloud)</div></div>
    <div class="stat-card"><div class="stat-val">${s.total_enriched_assets}</div><div class="stat-label">Enriched Assets</div></div>
  </div>

  <h2>Top 25 Critical Assets</h2>
  <table>
    <thead>
      <tr>
        <th>Asset / IP</th>
        <th>Owner / BU</th>
        <th>Score</th>
        <th>Risk Factors</th>
        <th>Max CVSS</th>
        <th>Sources</th>
      </tr>
    </thead>
    <tbody>
      ${topAssets.map(r => `
      <tr class="${r.is_exposed && r.has_pii ? 'toxic' : ''}">
        <td><strong>${r.hostname || 'Unknown'}</strong><br><small>${r.ip_address || 'Cloud Resource'}</small></td>
        <td>${r.owner || 'Unowned'}<br><small>${r.bu || 'N/A'}</small></td>
        <td><span class="score-pill" style="background:${scoreColor(r.priority_score)}">${r.priority_score}</span></td>
        <td>
          ${r.has_kev ? '<span class="badge" style="background:#7c3aed">KEV</span>' : ''}
          ${r.is_exposed ? '<span class="badge exposed">EXPOSED</span>' : '<span class="badge internal">INTERNAL</span>'}
          ${r.has_pii ? '<span class="badge" style="background:#db2777">SENSITIVE DATA</span>' : ''}
        </td>
        <td>${r.max_cvss}</td>
        <td><small>${r.sources}</small></td>
      </tr>`).join('')}
    </tbody>
  </table>

  <h2>Top Critical Vulnerabilities</h2>
  <table>
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>KEV</th><th>Global Occurrence</th></tr></thead>
    <tbody>
      ${topCVEs.map(r => `
      <tr>
        <td><strong>${r.cve_id}</strong></td>
        <td>${r.cvss}</td>
        <td>${r.in_cisa_kev ? '✅ Yes' : '—'}</td>
        <td>${r.occurrence_count} assets</td>
      </tr>`).join('')}
    </tbody>
  </table>

  <div class="footer">
    Priority Score = CVSS + KEV(+100) + Public(+100) + SensitiveData(+100) + CriticalBU(+30) + CrossTool(+20)
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
