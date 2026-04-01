#!/usr/bin/env node
/**
 * VBG Auto-Analyst Orchestrator
 * 
 * This script runs autonomously to:
 * 1. Identify high-risk assets using Dynamic Risk Model V3.
 * 2. Deduplicate findings against notification_state.
 * 3. Dispatch Email and Google Chat alerts.
 * 4. Update state to prevent alert fatigue.
 */

'use strict';

require('dotenv').config();
const { Client } = require('pg');
const { execSync } = require('child_process');

const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'vuln_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || process.env.DB_PASSWORD,
};

const CRITICAL_THRESHOLD = 300; // Only alert on highest priority
const NOTIFY_EMAIL = "jjanolo@gmail.com"; // Default security contact

async function main() {
  const client = new Client(DB_CONFIG);
  await client.connect();
  console.log(`[${new Date().toISOString()}] Starting Auto-Analyst Pulse...`);

  try {
    // 1. Query for High Risk Assets (> 300 Score)
    const sql = `
      WITH 
        asset_vuln_summary AS (
            SELECT 
                hostname, ip_address, 
                MAX(GREATEST(cvss_score, vpr_score)) as max_threat_score,
                MAX(acr_score) as max_acr,
                BOOL_OR(is_kev) as has_kev,
                BOOL_OR(exploited_by_malware) as has_malware
            FROM (
                SELECT ta.hostname, ta.ipv4 as ip_address, tf.cvss_score, COALESCE(tf.vpr_score, 0) as vpr_score,
                       COALESCE(ta.acr_score, 5) as acr_score, EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = tf.cve) as is_kev,
                       COALESCE(tf.exploited_by_malware, false) as exploited_by_malware
                FROM public.tenable_findings tf
                JOIN public.tenable_assets ta ON tf.asset_id = ta.id
                WHERE ta.last_seen >= NOW() - INTERVAL '90 days'
                UNION ALL
                SELECT wi.name as hostname, NULL as ip_address, wv.cvss_score, 0 as vpr_score, 7 as acr_score,
                       EXISTS(SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = wv.cve_id) as is_kev, false as exploited_by_malware
                FROM public.wiz_vulnerabilities wv
                JOIN public.wiz_inventory wi ON wv.resource_id = wi.id
                WHERE wv.status NOT IN ('RESOLVED', 'REJECTED')
            ) t
            GROUP BY hostname, ip_address
        ),
        exposure AS (
            SELECT name as hostname, 1 as is_exposed FROM public.wiz_inventory i
            WHERE EXISTS (SELECT 1 FROM public.wiz_network_exposures ne WHERE ne.exposed_entity_id = i.id AND ne.exposure_type = 'PUBLIC_INTERNET')
        ),
        sensitivity AS (
            SELECT resource_name as hostname, 1 as has_pii FROM public.wiz_data_findings WHERE severity IN ('CRITICAL', 'HIGH')
        )
      SELECT 
          b.hostname, b.ip_address, b.max_threat_score, b.max_acr, b.has_malware, b.has_kev,
          COALESCE(e.is_exposed, 0) = 1 as is_exposed,
          COALESCE(s.has_pii, 0) = 1 as has_pii,
          ac.owner, ac.business_unit,
          (
              (COALESCE(b.max_threat_score, 0) * (COALESCE(b.max_acr, 5) / 5.0)) + 
              (CASE WHEN b.has_kev THEN 100 ELSE 0 END) + 
              (CASE WHEN b.has_malware THEN 150 ELSE 0 END) + 
              (CASE WHEN e.is_exposed = 1 THEN 100 ELSE 0 END) + 
              (CASE WHEN s.has_pii = 1 THEN 100 ELSE 0 END)
          ) as priority_score
      FROM asset_vuln_summary b
      LEFT JOIN exposure e ON e.hostname = b.hostname
      LEFT JOIN sensitivity s ON s.hostname = b.hostname
      LEFT JOIN public.dto_assets ac ON ac.asset_name = b.hostname
      WHERE (
          (COALESCE(b.max_threat_score, 0) * (COALESCE(b.max_acr, 5) / 5.0)) + 
          (CASE WHEN b.has_kev THEN 100 ELSE 0 END) + 
          (CASE WHEN b.has_malware THEN 150 ELSE 0 END) + 
          (CASE WHEN e.is_exposed = 1 THEN 100 ELSE 0 END) + 
          (CASE WHEN s.has_pii = 1 THEN 100 ELSE 0 END)
      ) >= ${CRITICAL_THRESHOLD}
      ORDER BY priority_score DESC;
    `;

    const findings = await client.query(sql);
    console.log(`Found ${findings.rows.length} critical assets.`);

    for (const asset of findings.rows) {
      // 2. Deduplication: Has this asset been notified in the last 24 hours?
      const stateCheck = await client.query(
        "SELECT 1 FROM public.notification_state WHERE hostname = $1 AND last_notified >= NOW() - INTERVAL '24 hours'",
        [asset.hostname]
      );

      if (stateCheck.rows.length > 0) {
        console.log(`Skipping ${asset.hostname} (Already notified recently).`);
        continue;
      }

      // 3. Prepare Alert Payload
      const riskFactors = [
        asset.has_malware ? "MALWARE EXPLOITABLE" : null,
        asset.is_exposed ? "INTERNET EXPOSED" : null,
        asset.has_pii ? "SENSITIVE DATA FOUND" : null,
        asset.has_kev ? "CISA KEV MATCH" : null
      ].filter(Boolean).join(", ");

      const alertBody = `🚨 CRITICAL SECURITY ALERT: ${asset.hostname}
Score: ${Math.round(asset.priority_score)}
Risk Factors: ${riskFactors}
Owner: ${asset.owner || 'Unassigned'}
Business Unit: ${asset.business_unit || 'Unknown'}

Remediation Recommendation:
Immediately restrict internet access and patch critical vulnerabilities.
Coded by Gemini CLI.`;

      // 4. Dispatch Notifications
      try {
        // Email Alert
        console.log(`Sending Email Alert for ${asset.hostname}...`);
        execSync(`node asset-email-reporter/scripts/send_email.cjs "${NOTIFY_EMAIL}" "AUTO-ALERT: Critical Risk - ${asset.hostname}" "${alertBody}"`);
        
        // Google Chat Alert (if webhook provided)
        if (process.env.GOOGLE_CHAT_WEBHOOK) {
          console.log(`Sending Google Chat Alert for ${asset.hostname}...`);
          // Use a shorter version for Chat
          const chatMessage = `*🚨 CRITICAL SECURITY ALERT: ${asset.hostname}*\n*Score:* ${Math.round(asset.priority_score)}\n*Risk:* ${riskFactors}\n*Owner:* ${asset.owner || 'Unassigned'}\n*Action:* Immediately restrict internet access and patch.`;
          execSync(`node scripts/send_chat.cjs "${process.env.GOOGLE_CHAT_WEBHOOK}" "${chatMessage}"`);
        }
      } catch (e) { console.error("Notification Dispatch Failed:", e.message); }

      // 5. Update Notification State
      await client.query(
        "INSERT INTO public.notification_state (hostname, priority_score, risk_factors) VALUES ($1, $2, $3)",
        [asset.hostname, asset.priority_score, riskFactors]
      );
      console.log(`State updated for ${asset.hostname}.`);
    }

  } catch (error) {
    console.error("Auto-Analyst Error:", error.message);
  } finally {
    await client.end();
    console.log("Pulse Complete.");
  }
}

main();
