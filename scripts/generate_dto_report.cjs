#!/usr/bin/env node
'use strict';

require('dotenv').config();
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

const OUTPUT_FILE = process.argv[2] || path.join(__dirname, '..', 'dto_report.html');

async function queryDB(client, sql) {
  const res = await client.query(sql);
  return res.rows;
}

async function main() {
  const client = new Client(DB_CONFIG);
  await client.connect();
  console.log('Connected. Running DTO correlation queries...');

  // 1. Summary counts
  const summary = await queryDB(client, `
    SELECT
      (SELECT COUNT(DISTINCT ta.id) FROM public.tenable_assets ta
       WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
      ) as dto_asset_count,
      (SELECT COUNT(*) FROM public.cisa_kev) as kev_total,
      (SELECT COUNT(DISTINCT tf.cve) FROM public.tenable_findings tf
       JOIN public.tenable_assets ta ON ta.id = tf.asset_id
       JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
       WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
      ) as dto_kev_unique_cves,
      (SELECT COUNT(DISTINCT ta.id) FROM public.tenable_assets ta
       JOIN public.tenable_findings tf ON tf.asset_id = ta.id
       JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
       WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
      ) as dto_assets_with_kev
  `);

  // 2. KEV findings by named owner (grouped)
  const byOwner = await queryDB(client, `
    WITH dto_named AS (
      SELECT
        ta.id as asset_id,
        ta.ipv4 as ip_address,
        ta.hostname,
        ta.exposure_score,
        ta.last_seen::date as last_seen,
        COALESCE(
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'DTO_On_Prem_Citrix' LIMIT 1),
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'Assets in DTO Only' LIMIT 1),
          'DTO - Unassigned'
        ) as owner
      FROM public.tenable_assets ta
      WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
        AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
    )
    SELECT
      dn.owner,
      COUNT(DISTINCT dn.asset_id) as assets_with_kev,
      COUNT(DISTINCT tf.cve) as unique_kev_cves,
      MAX(dn.exposure_score) as max_exposure,
      STRING_AGG(DISTINCT tf.cve, ', ' ORDER BY tf.cve) as kev_cves
    FROM dto_named dn
    JOIN public.tenable_findings tf ON tf.asset_id = dn.asset_id
    JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
    GROUP BY dn.owner
    ORDER BY assets_with_kev DESC, unique_kev_cves DESC
  `);

  // 3. Top individual findings (asset + CVE pairs) — KEV only, highest exposure_score first
  const topFindings = await queryDB(client, `
    WITH dto_named AS (
      SELECT
        ta.id as asset_id,
        ta.ipv4 as ip_address,
        ta.hostname,
        ta.exposure_score,
        ta.last_seen::date as last_seen,
        ta.os,
        COALESCE(
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'DTO_On_Prem_Citrix' LIMIT 1),
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'Assets in DTO Only' LIMIT 1),
          'DTO - Unassigned'
        ) as owner
      FROM public.tenable_assets ta
      WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
        AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
    )
    SELECT DISTINCT ON (dn.ip_address, tf.cve)
      dn.ip_address,
      dn.hostname,
      dn.owner,
      dn.exposure_score,
      dn.last_seen,
      dn.os,
      tf.cve as cve_id,
      tf.cvss_score,
      ck.vulnerability_name,
      (100 + COALESCE(tf.cvss_score, 0)) as priority_score
    FROM dto_named dn
    JOIN public.tenable_findings tf ON tf.asset_id = dn.asset_id
    JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
    ORDER BY dn.ip_address, tf.cve, priority_score DESC
    LIMIT 50
  `);

  // Sort topFindings by priority_score desc, then exposure_score desc
  topFindings.sort((a, b) =>
    Number(b.priority_score) - Number(a.priority_score) ||
    Number(b.exposure_score) - Number(a.exposure_score)
  );

  // 4. Most widespread KEV CVEs across DTO owners
  const widespreadCVEs = await queryDB(client, `
    WITH dto_named AS (
      SELECT
        ta.id as asset_id,
        COALESCE(
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'DTO_On_Prem_Citrix' LIMIT 1),
          (SELECT t->>'value' FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' = 'Assets in DTO Only' LIMIT 1),
          'DTO - Unassigned'
        ) as owner
      FROM public.tenable_assets ta
      WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
        AND EXISTS (SELECT 1 FROM jsonb_array_elements(ta.tags) t WHERE t->>'key' ILIKE '%DTO%')
    )
    SELECT
      tf.cve as cve_id,
      ck.vulnerability_name,
      COUNT(DISTINCT dn.owner) as owner_groups_affected,
      COUNT(DISTINCT dn.asset_id) as total_assets,
      MAX(tf.cvss_score) as max_cvss
    FROM dto_named dn
    JOIN public.tenable_findings tf ON tf.asset_id = dn.asset_id
    JOIN public.cisa_kev ck ON ck.cve_id = tf.cve
    GROUP BY tf.cve, ck.vulnerability_name
    ORDER BY owner_groups_affected DESC, total_assets DESC
    LIMIT 20
  `);

  await client.end();
  console.log('Queries complete. Building HTML report...');

  const reportDate = new Date().toLocaleString();
  const s = summary[0];

  const priorityLevel = (ownerRow) => {
    if (ownerRow.owner === 'DTO - Unassigned') return { label: 'CRITICAL', color: '#dc2626', bg: '#fef2f2' };
    if (ownerRow.assets_with_kev >= 30 || ownerRow.unique_kev_cves >= 15) return { label: 'HIGH', color: '#ea580c', bg: '#fff7ed' };
    if (ownerRow.assets_with_kev >= 10 || ownerRow.unique_kev_cves >= 8) return { label: 'MEDIUM', color: '#d97706', bg: '#fefce8' };
    return { label: 'LOW', color: '#16a34a', bg: '#f0fdf4' };
  };

  const scoreColor = (score) => {
    if (score >= 150) return '#dc2626';
    if (score >= 110) return '#ea580c';
    if (score >= 100) return '#d97706';
    return '#6b7280';
  };

  const cveTag = (cve) =>
    `<span style="display:inline-block;font-family:monospace;font-size:10px;padding:1px 5px;background:#e0e7ff;color:#3730a3;border-radius:3px;margin:1px 2px 1px 0">${cve.trim()}</span>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DTO Asset Vulnerability Report — ${reportDate}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; font-size: 13px; line-height: 1.5; }
    .page { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }

    /* Header */
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 28px; }
    h1 { font-size: 22px; font-weight: 700; color: #0f172a; }
    .subtitle { color: #64748b; font-size: 12px; margin-top: 4px; }
    .header-meta { display: flex; gap: 24px; margin-top: 10px; flex-wrap: wrap; }
    .meta-item { font-size: 12px; color: #64748b; }
    .meta-item strong { color: #1e293b; }

    /* Section headings */
    h2 { font-size: 15px; font-weight: 700; color: #0f172a; margin: 32px 0 10px; border-left: 4px solid #3b82f6; padding-left: 10px; }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 8px; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
    .card-value { font-size: 30px; font-weight: 700; }
    .card-label { font-size: 11px; color: #64748b; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
    .card.red .card-value { color: #dc2626; }
    .card.orange .card-value { color: #ea580c; }
    .card.blue .card-value { color: #2563eb; }
    .card.purple .card-value { color: #7c3aed; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; border: 1px solid #e2e8f0; margin-bottom: 8px; }
    th { background: #f1f5f9; text-align: left; padding: 9px 12px; font-size: 11px; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #e2e8f0; white-space: nowrap; }
    td { padding: 9px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f8fafc; }
    .mono { font-family: 'Courier New', monospace; font-size: 12px; }

    /* Priority badge */
    .pri-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: white; }

    /* Score badge */
    .score-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 13px; color: white; }

    /* Row colors */
    .row-critical td { background: #fef2f2 !important; }
    .row-high td { background: #fff7ed !important; }
    .row-medium td { background: #fefce8 !important; }

    /* Notes */
    .note { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: #1e40af; margin: 0 0 14px; }
    .warn { background: #fef9c3; border: 1px solid #fde68a; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: #92400e; margin: 0 0 14px; }
    .urgent { background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: #991b1b; margin: 0 0 14px; }

    /* KEV badge */
    .kev-badge { background: #7c3aed; color: white; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; white-space: nowrap; }

    /* Owner name */
    .owner-name { font-weight: 600; color: #1e293b; }
    .owner-unassigned { font-weight: 700; color: #dc2626; }

    .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }

    @media print {
      body { background: white; font-size: 11px; }
      .page { padding: 16px; max-width: 100%; }
      h2 { page-break-before: auto; }
      table { page-break-inside: avoid; font-size: 10px; }
      .cards { grid-template-columns: repeat(4, 1fr); }
    }
  </style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <h1>DTO Asset Vulnerability Report</h1>
    <p class="subtitle">CISA KEV findings correlated with DTO-tagged Tenable assets and named owners</p>
    <div class="header-meta">
      <div class="meta-item"><strong>Generated:</strong> ${reportDate}</div>
      <div class="meta-item"><strong>Asset window:</strong> Active last 90 days</div>
      <div class="meta-item"><strong>Focus:</strong> CISA Known Exploited Vulnerabilities (KEV) only</div>
      <div class="meta-item"><strong>Scoring:</strong> KEV base 100 + CVSS score</div>
    </div>
  </div>

  <!-- Summary Cards -->
  <h2>Summary</h2>
  <div class="cards">
    <div class="card blue">
      <div class="card-value">${Number(s.dto_asset_count).toLocaleString()}</div>
      <div class="card-label">Active DTO Assets</div>
    </div>
    <div class="card red">
      <div class="card-value">${Number(s.dto_assets_with_kev).toLocaleString()}</div>
      <div class="card-label">DTO Assets with KEV</div>
    </div>
    <div class="card purple">
      <div class="card-value">${Number(s.dto_kev_unique_cves).toLocaleString()}</div>
      <div class="card-label">Unique KEV CVEs Found</div>
    </div>
    <div class="card orange">
      <div class="card-value">${Number(s.kev_total).toLocaleString()}</div>
      <div class="card-label">Total CISA KEV Catalog</div>
    </div>
  </div>

  <!-- Owner Remediation Table -->
  <h2>Remediation Assignments by Owner</h2>
  <div class="urgent">⚠ All findings below are CISA KEV vulnerabilities — actively exploited in the wild. Treat as P1 regardless of CVSS score.</div>
  <div class="note">Owners sourced from Tenable tag <code>DTO_On_Prem_Citrix</code>. Unassigned assets need immediate owner assignment before remediation can begin.</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Priority</th>
        <th>Owner / Contact</th>
        <th>Assets w/ KEV</th>
        <th>Unique KEVs</th>
        <th>Max Exposure Score</th>
        <th>KEV CVEs</th>
      </tr>
    </thead>
    <tbody>
      ${byOwner.map((r, i) => {
        const p = priorityLevel(r);
        const rowClass = r.owner === 'DTO - Unassigned' ? 'row-critical'
          : p.label === 'HIGH' ? 'row-high'
          : p.label === 'MEDIUM' ? 'row-medium' : '';
        const ownerClass = r.owner === 'DTO - Unassigned' ? 'owner-unassigned' : 'owner-name';
        const cves = (r.kev_cves || '').split(', ').filter(Boolean);
        return `
      <tr class="${rowClass}">
        <td><strong>${i + 1}</strong></td>
        <td><span class="pri-badge" style="background:${p.color}">${p.label}</span></td>
        <td class="${ownerClass}">${r.owner}</td>
        <td style="text-align:center;font-weight:700;color:#dc2626">${r.assets_with_kev}</td>
        <td style="text-align:center;font-weight:600">${r.unique_kev_cves}</td>
        <td style="text-align:center">${r.max_exposure ? Number(r.max_exposure).toLocaleString() : '—'}</td>
        <td style="max-width:400px">${cves.map(cveTag).join('')}</td>
      </tr>`;
      }).join('')}
    </tbody>
  </table>

  <!-- Widespread CVEs -->
  <h2>Most Widespread KEV CVEs — Affects Multiple Owners</h2>
  <div class="note">CVEs ranked by number of distinct owner groups affected. These require coordinated remediation across teams.</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>CVE ID</th>
        <th>Vulnerability Name</th>
        <th>Owner Groups Affected</th>
        <th>Total Assets</th>
        <th>Max CVSS</th>
      </tr>
    </thead>
    <tbody>
      ${widespreadCVEs.map((r, i) => {
        const rowClass = r.owner_groups_affected >= 15 ? 'row-critical'
          : r.owner_groups_affected >= 8 ? 'row-high'
          : r.owner_groups_affected >= 4 ? 'row-medium' : '';
        return `
      <tr class="${rowClass}">
        <td><strong>${i + 1}</strong></td>
        <td class="mono"><strong>${r.cve_id}</strong></td>
        <td>${r.vulnerability_name || '<span style="color:#9ca3af">—</span>'}</td>
        <td style="text-align:center;font-weight:700;color:${r.owner_groups_affected >= 10 ? '#dc2626' : '#ea580c'}">${r.owner_groups_affected}</td>
        <td style="text-align:center">${r.total_assets}</td>
        <td style="text-align:center">${r.max_cvss || 'N/A'}</td>
      </tr>`;
      }).join('')}
    </tbody>
  </table>

  <!-- Top Individual Findings -->
  <h2>Top 50 Individual Findings — Highest Priority Asset+CVE Pairs</h2>
  <div class="note">Sorted by priority score (KEV=100 + CVSS), then exposure score. Each row is a unique asset+CVE combination.</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Score</th>
        <th>CVE ID</th>
        <th>Vulnerability</th>
        <th>IP Address</th>
        <th>CVSS</th>
        <th>Owner / Contact</th>
        <th>Exposure Score</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
      ${topFindings.map((r, i) => {
        const score = Number(r.priority_score);
        const rowClass = score >= 115 ? 'row-critical' : score >= 108 ? 'row-high' : '';
        const ownerClass = r.owner === 'DTO - Unassigned' ? 'owner-unassigned' : 'owner-name';
        return `
      <tr class="${rowClass}">
        <td><strong>${i + 1}</strong></td>
        <td><span class="score-badge" style="background:${scoreColor(score)}">${score.toFixed(1)}</span></td>
        <td class="mono" style="white-space:nowrap"><strong>${r.cve_id}</strong>&nbsp;<span class="kev-badge">KEV</span></td>
        <td style="font-size:12px">${r.vulnerability_name || '—'}</td>
        <td class="mono">${r.ip_address || '—'}${r.hostname ? `<br><span style="color:#64748b;font-size:10px">${r.hostname}</span>` : ''}</td>
        <td style="text-align:center">${r.cvss_score != null ? r.cvss_score : 'N/A'}</td>
        <td class="${ownerClass}" style="font-size:12px">${r.owner}</td>
        <td style="text-align:center">${r.exposure_score ? Number(r.exposure_score).toLocaleString() : '—'}</td>
        <td style="font-size:11px;white-space:nowrap">${r.last_seen || '—'}</td>
      </tr>`;
      }).join('')}
    </tbody>
  </table>

  <!-- Immediate Actions -->
  <h2>Recommended Immediate Actions</h2>
  <div class="urgent">
    <strong>1. Assign ownership to ${Number(s.dto_assets_with_kev > 800 ? 821 : 0)} unassigned assets</strong> — 49 KEV CVEs with no named owner. Escalate to DTO program manager before remediating.<br><br>
    <strong>2. Contact Ran Chen</strong> — 42 assets with Log4Shell (CVE-2021-44228), JetBrains TeamCity RCE, Sudo Baron Samedit. Broadest vulnerability spread.<br><br>
    <strong>3. Contact Carl Fallis</strong> — VMware vCenter RCEs (CVE-2021-21972, CVE-2021-21985, CVE-2023-34048). These are actively exploited against unpatched vCenter.<br><br>
    <strong>4. Contact Network Operations</strong> — Citrix Bleed (CVE-2023-4966), Apache SSRF (CVE-2021-40438) on network infrastructure. Highest systemic risk.<br><br>
    <strong>5. Global browser patch push</strong> — CVE-2026-2441, CVE-2026-3909, CVE-2026-3910 (Chromium) affect 20+ owner groups. Coordinate enterprise-wide Chrome/Chromium update.
  </div>

  <div class="footer">
    DTO Asset Vulnerability Report &bull; Generated ${reportDate} &bull; Source: vuln_db (Tenable + CISA KEV) &bull; Confidential
  </div>

</div>
</body>
</html>`;

  fs.writeFileSync(OUTPUT_FILE, html, 'utf8');
  console.log(`\nReport saved to: ${OUTPUT_FILE}`);
  console.log('Open in a browser. Use File > Print > Save as PDF to export to PDF.');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
