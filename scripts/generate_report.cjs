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
  password: process.env.DB_PASSWORD || '',
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
      (SELECT COUNT(*) FROM public.wiz_vulnerabilities WHERE status NOT IN ('RESOLVED','REJECTED')) as active_wiz_vulns
  `);

  // 2. Top prioritized public-facing assets with vuln counts
  const topAssets = await queryDB(client, `
    WITH public_asset_ips AS (
      SELECT DISTINCT
        ta.ipv4 as ip_address,
        MAX(ta.hostname) as hostname,
        MAX(ta.last_seen) as tenable_last_seen,
        MAX(ta.exposure_score) as exposure_score,
        MAX(ta.os) as os,
        COALESCE(
          STRING_AGG(DISTINCT CASE WHEN asm.port IS NOT NULL THEN CAST(asm.port AS TEXT) || '/' || COALESCE(asm.service,'?') END, ', '),
          'No port data'
        ) as exposed_ports,
        MAX(asm.last_seen) as asm_last_seen,
        MIN(asm.severity_ranking) as asm_severity
      FROM public.tenable_assets ta
      JOIN public.tenable_asm_assets asm ON (asm.ip_address = ta.ipv4 OR asm.hostname = ta.hostname)
      WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
        AND asm.last_seen >= NOW() - INTERVAL '30 days'
      GROUP BY ta.ipv4
    ),
    vuln_summary AS (
      SELECT
        pai.ip_address, pai.hostname, pai.exposed_ports, pai.asm_severity,
        pai.exposure_score, pai.os,
        pai.asm_last_seen::date as asm_last_seen,
        pai.tenable_last_seen::date as tenable_last_seen,
        COUNT(DISTINCT tf.cve) as total_cves,
        COUNT(DISTINCT CASE WHEN ck.cve_id IS NOT NULL THEN tf.cve END) as kev_cves,
        COUNT(DISTINCT CASE WHEN tf.cvss_score >= 9 THEN tf.cve END) as critical_cves,
        COUNT(DISTINCT CASE WHEN tf.cvss_score >= 7 AND tf.cvss_score < 9 THEN tf.cve END) as high_cves,
        MAX(tf.cvss_score) as max_cvss,
        STRING_AGG(DISTINCT CASE WHEN ck.cve_id IS NOT NULL THEN tf.cve END, ', ') as kev_cve_list
      FROM public_asset_ips pai
      JOIN public.tenable_assets ta ON ta.ipv4 = pai.ip_address
      JOIN public.tenable_findings tf ON tf.asset_id = ta.id
      LEFT JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
      GROUP BY pai.ip_address, pai.hostname, pai.exposed_ports, pai.asm_severity,
               pai.exposure_score, pai.os, pai.asm_last_seen, pai.tenable_last_seen
    )
    SELECT *,
      (
        COALESCE(max_cvss, 0) +
        (kev_cves * 100) + 50 +
        (critical_cves * 2) + (high_cves * 1) +
        (CASE WHEN exposure_score > 500 THEN 30 WHEN exposure_score > 200 THEN 15 ELSE 0 END)
      ) as priority_score
    FROM vuln_summary
    ORDER BY priority_score DESC, kev_cves DESC, total_cves DESC
    LIMIT 20
  `);

  // 3. Top 10 CVEs by priority score
  const topCVEs = await queryDB(client, `
    WITH all_vulns AS (
      SELECT tf.cve as cve_id, ta.hostname, ta.ipv4 as ip_address, 'Tenable' as source, tf.cvss_score
      FROM public.tenable_findings tf
      JOIN public.tenable_assets ta ON tf.asset_id = ta.id
    ),
    prioritized AS (
      SELECT
        v.cve_id, v.hostname, v.ip_address,
        MAX(v.cvss_score) as max_cvss,
        STRING_AGG(DISTINCT v.source, ', ') as sources,
        EXISTS (SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = v.cve_id) as in_cisa_kev,
        EXISTS (SELECT 1 FROM public.tenable_asm_assets asm WHERE asm.hostname = v.hostname OR asm.ip_address = v.ip_address) as in_asm
      FROM all_vulns v
      GROUP BY v.cve_id, v.hostname, v.ip_address
    )
    SELECT
      p.cve_id, ck.vulnerability_name, p.hostname, p.ip_address, p.sources,
      COALESCE(p.max_cvss::text, 'N/A') as cvss,
      p.in_cisa_kev, p.in_asm,
      (COALESCE(p.max_cvss,0) + (CASE WHEN p.in_cisa_kev THEN 100 ELSE 0 END) + (CASE WHEN p.in_asm THEN 50 ELSE 0 END)) as score
    FROM prioritized p
    LEFT JOIN public.cisa_kev ck ON p.cve_id = ck.cve_id
    ORDER BY score DESC
    LIMIT 10
  `);

  // 4. High-risk port exposures
  const highRiskPorts = await queryDB(client, `
    SELECT DISTINCT ip_address, hostname, port, service, severity_ranking, last_seen::date as last_seen
    FROM public.tenable_asm_assets
    WHERE port IN (22, 23, 25, 3389, 5900, 3306, 5432, 1433, 27017, 6379, 8080, 8443)
      AND last_seen >= NOW() - INTERVAL '30 days'
    ORDER BY port, ip_address
    LIMIT 50
  `);

  // 5. ASM severity breakdown
  const asmSeverity = await queryDB(client, `
    SELECT severity_ranking, COUNT(DISTINCT ip_address) as unique_ips, COUNT(*) as records
    FROM public.tenable_asm_assets
    WHERE last_seen >= NOW() - INTERVAL '30 days'
    GROUP BY severity_ranking
    ORDER BY CASE severity_ranking WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
  `);

  await client.end();
  console.log('Queries complete. Generating HTML...');

  const reportDate = new Date().toLocaleString();
  const s = summary[0];

  const severityBadge = (sev) => {
    const colors = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d', none: '#6b7280' };
    const color = colors[sev] || colors.none;
    return `<span style="background:${color};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">${sev || 'none'}</span>`;
  };

  const kevBadge = (val) => val
    ? `<span style="background:#7c3aed;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">KEV</span>`
    : `<span style="color:#9ca3af;font-size:12px">—</span>`;

  const scoreColor = (score) => {
    if (score >= 150) return '#dc2626';
    if (score >= 100) return '#ea580c';
    if (score >= 70) return '#d97706';
    return '#6b7280';
  };

  const portRisk = (port) => {
    const risks = {
      3389: 'RDP — top ransomware vector',
      5900: 'VNC — remote desktop exposed',
      23: 'Telnet — plaintext protocol',
      22: 'SSH',
      3306: 'MySQL — DB exposed',
      5432: 'PostgreSQL — DB exposed',
      1433: 'MSSQL — DB exposed',
      27017: 'MongoDB — DB exposed',
      6379: 'Redis — cache exposed',
    };
    return risks[port] || `Port ${port}`;
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Prioritization Report — ${reportDate}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; font-size: 13px; }
    .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
    h1 { font-size: 24px; font-weight: 700; color: #0f172a; }
    h2 { font-size: 16px; font-weight: 700; color: #0f172a; margin: 32px 0 12px; border-left: 4px solid #3b82f6; padding-left: 10px; }
    h3 { font-size: 13px; font-weight: 600; color: #475569; margin-bottom: 4px; }
    .subtitle { color: #64748b; font-size: 12px; margin-top: 4px; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 24px; }
    .header-meta { display: flex; gap: 24px; margin-top: 12px; flex-wrap: wrap; }
    .meta-item { font-size: 12px; color: #64748b; }
    .meta-item strong { color: #1e293b; }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 8px; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
    .card-value { font-size: 28px; font-weight: 700; color: #1e293b; }
    .card-label { font-size: 11px; color: #64748b; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
    .card.red .card-value { color: #dc2626; }
    .card.orange .card-value { color: #ea580c; }
    .card.blue .card-value { color: #2563eb; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; border: 1px solid #e2e8f0; }
    th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-size: 11px; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #e2e8f0; }
    td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f8fafc; }
    .mono { font-family: 'Courier New', monospace; font-size: 12px; }
    .score-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 13px; color: white; }

    /* Priority row highlights */
    .pri-critical td { background: #fef2f2 !important; }
    .pri-high td { background: #fff7ed !important; }

    /* Section note */
    .note { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: #1e40af; margin: 8px 0 16px; }
    .warn { background: #fef9c3; border: 1px solid #fde68a; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: #92400e; margin: 8px 0 16px; }

    .tag { display: inline-block; font-size: 11px; padding: 1px 6px; border-radius: 3px; margin: 1px; background: #e2e8f0; color: #475569; }

    .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }

    @media print {
      body { background: white; }
      .page { padding: 16px; }
      h2 { page-break-before: auto; }
      table { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <h1>Security Prioritization Report</h1>
    <p class="subtitle">Correlating Tenable VM, Tenable ASM, Wiz, and CISA KEV data</p>
    <div class="header-meta">
      <div class="meta-item"><strong>Generated:</strong> ${reportDate}</div>
      <div class="meta-item"><strong>Database:</strong> vuln_db @ localhost:5432</div>
      <div class="meta-item"><strong>Scoring:</strong> CVSS + KEV (+100) + External (+50) + MGMT subnet (+30) + Gateway (+20) + VT malicious (+50)</div>
    </div>
  </div>

  <!-- Summary Cards -->
  <h2>Data Summary</h2>
  <div class="cards">
    <div class="card blue">
      <div class="card-value">${Number(s.active_tenable_assets).toLocaleString()}</div>
      <div class="card-label">Active Tenable Assets</div>
    </div>
    <div class="card">
      <div class="card-value">${Number(s.total_findings).toLocaleString()}</div>
      <div class="card-label">Total Findings</div>
    </div>
    <div class="card red">
      <div class="card-value">${Number(s.kev_entries).toLocaleString()}</div>
      <div class="card-label">CISA KEV Entries</div>
    </div>
    <div class="card orange">
      <div class="card-value">${Number(s.active_asm_assets).toLocaleString()}</div>
      <div class="card-label">Active ASM Assets (30d)</div>
    </div>
    <div class="card">
      <div class="card-value">${Number(s.active_wiz_vulns).toLocaleString()}</div>
      <div class="card-label">Active Wiz Findings</div>
    </div>
  </div>

  <!-- ASM Severity Breakdown -->
  <h2>Attack Surface Severity Breakdown</h2>
  <div class="note">Assets seen in Tenable ASM within the last 30 days, grouped by exposure severity.</div>
  <table>
    <thead><tr><th>Severity</th><th>Unique IPs</th><th>Total Records</th></tr></thead>
    <tbody>
      ${asmSeverity.map(r => `
      <tr>
        <td>${severityBadge(r.severity_ranking)}</td>
        <td><strong>${Number(r.unique_ips).toLocaleString()}</strong></td>
        <td>${Number(r.records).toLocaleString()}</td>
      </tr>`).join('')}
    </tbody>
  </table>

  <!-- Top Prioritized Public Assets -->
  <h2>Top Prioritized Assets — Active & Publicly Exposed</h2>
  <div class="note">Assets confirmed active in Tenable (last 90 days) AND present in ASM (last 30 days). Score = CVSS + KEV×100 + Exposure bonus + Criticality.</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>IP Address</th>
        <th>Score</th>
        <th>Total CVEs</th>
        <th>KEV CVEs</th>
        <th>Critical</th>
        <th>High</th>
        <th>Max CVSS</th>
        <th>Exposure Score</th>
        <th>ASM Severity</th>
        <th>Exposed Ports/Services</th>
        <th>ASM Last Seen</th>
        <th>KEV CVE List</th>
      </tr>
    </thead>
    <tbody>
      ${topAssets.map((r, i) => {
        const score = Number(r.priority_score);
        const rowClass = score >= 500 ? 'pri-critical' : score >= 100 ? 'pri-high' : '';
        return `
      <tr class="${rowClass}">
        <td><strong>${i + 1}</strong></td>
        <td class="mono"><strong>${r.ip_address}</strong>${r.hostname ? `<br><span style="color:#64748b;font-size:11px">${r.hostname}</span>` : ''}</td>
        <td><span class="score-badge" style="background:${scoreColor(score)}">${score}</span></td>
        <td style="text-align:center">${r.total_cves}</td>
        <td style="text-align:center"><strong style="color:${r.kev_cves > 0 ? '#dc2626' : 'inherit'}">${r.kev_cves}</strong></td>
        <td style="text-align:center">${r.critical_cves}</td>
        <td style="text-align:center">${r.high_cves}</td>
        <td style="text-align:center">${r.max_cvss || 'N/A'}</td>
        <td style="text-align:center">${r.exposure_score || '0'}</td>
        <td>${severityBadge(r.asm_severity)}</td>
        <td class="mono" style="font-size:11px">${r.exposed_ports || '—'}</td>
        <td style="font-size:11px">${r.asm_last_seen || '—'}</td>
        <td style="font-size:11px;max-width:200px">${r.kev_cve_list ? r.kev_cve_list.split(',').map(c => `<span class="tag">${c.trim()}</span>`).join('') : '—'}</td>
      </tr>`;
      }).join('')}
    </tbody>
  </table>

  <!-- Top 10 CVEs -->
  <h2>Top 10 Vulnerabilities by Priority Score</h2>
  <div class="note">Highest-scoring CVEs across all sources. Score = CVSS + KEV (+100) + External ASM (+50).</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>CVE ID</th>
        <th>Vulnerability Name</th>
        <th>IP Address</th>
        <th>CVSS</th>
        <th>KEV</th>
        <th>In ASM</th>
        <th>Source</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>
      ${topCVEs.map((r, i) => {
        const score = Number(r.score);
        const rowClass = score >= 150 ? 'pri-critical' : score >= 100 ? 'pri-high' : '';
        return `
      <tr class="${rowClass}">
        <td><strong>${i + 1}</strong></td>
        <td class="mono" style="white-space:nowrap"><strong>${r.cve_id || '—'}</strong></td>
        <td>${r.vulnerability_name || '<span style="color:#9ca3af">No name in KEV</span>'}</td>
        <td class="mono">${r.ip_address || r.hostname || '—'}</td>
        <td style="text-align:center">${r.cvss}</td>
        <td style="text-align:center">${kevBadge(r.in_cisa_kev)}</td>
        <td style="text-align:center">${r.in_asm ? '✓' : '—'}</td>
        <td><span class="tag">${r.sources}</span></td>
        <td><span class="score-badge" style="background:${scoreColor(score)}">${score}</span></td>
      </tr>`;
      }).join('')}
    </tbody>
  </table>

  <!-- High-Risk Port Exposures -->
  <h2>High-Risk Port Exposures (Active Last 30 Days)</h2>
  <div class="warn">The following services are exposed on high-risk ports and were seen in ASM within the last 30 days. Ports like RDP (3389), SSH (22), and database ports should never be directly internet-facing.</div>
  ${highRiskPorts.length === 0
    ? '<p style="color:#64748b;padding:12px">No high-risk port exposures found in the last 30 days.</p>'
    : `<table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Hostname</th>
        <th>Port</th>
        <th>Service</th>
        <th>Risk</th>
        <th>ASM Severity</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
      ${highRiskPorts.map(r => `
      <tr${r.port === 3389 || r.port === 5900 ? ' class="pri-critical"' : r.port === 23 ? ' class="pri-high"' : ''}>
        <td class="mono">${r.ip_address || '—'}</td>
        <td style="font-size:11px">${r.hostname || '—'}</td>
        <td class="mono"><strong>${r.port}</strong></td>
        <td style="font-size:11px">${r.service || '—'}</td>
        <td style="font-size:11px;color:#dc2626;font-weight:600">${portRisk(r.port)}</td>
        <td>${severityBadge(r.severity_ranking)}</td>
        <td style="font-size:11px">${r.last_seen}</td>
      </tr>`).join('')}
    </tbody>
  </table>`}

  <!-- Footer -->
  <div class="footer">
    Security Prioritization Report &bull; Generated ${reportDate} &bull; vuln_db &bull; Tenable + ASM + Wiz + CISA KEV
  </div>

</div>
</body>
</html>`;

  fs.writeFileSync(OUTPUT_FILE, html, 'utf8');
  console.log(`\nReport saved to: ${OUTPUT_FILE}`);
  console.log('Open in a browser and use File > Print > Save as PDF to export to PDF.');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
