/**
 * Wiz Re-ingestion Script — Internet Exposures
 *
 * Fetches all PUBLIC_INTERNET network exposures from Wiz and stores them in
 * public.wiz_internet_exposures. This is the correct source for internet-facing
 * resources with their public IPs, since wiz_inventory does not carry IP data.
 *
 * Environment Variables (from .env):
 *   WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_URL
 *   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS
 *
 * Usage:
 *   node scripts/wiz_reingest.cjs
 *   node scripts/wiz_reingest.cjs --dry-run   (fetch only, no DB writes)
 */

require('dotenv').config();
const axios = require('axios');
const { Pool } = require('pg');

const DRY_RUN    = process.argv.includes('--dry-run');
const RESUME_ARG = process.argv.find(a => a.startsWith('--resume='));
const RESUME_CURSOR = RESUME_ARG ? RESUME_ARG.split('=')[1] : null;
const PAGE_SIZE  = 500;
const AUTH_URL   = 'https://auth.app.wiz.io/oauth/token';

const GQL_QUERY = `
  query GetInternetExposures($first: Int, $after: String) {
    networkExposures(first: $first, after: $after, filterBy: { type: [PUBLIC_INTERNET] }) {
      pageInfo {
        hasNextPage
        endCursor
      }
      totalCount
      nodes {
        id
        sourceIpRange
        destinationIpRange
        portRange
        networkProtocols
        type
        exposedEntity {
          id
          name
          type
          properties
        }
      }
    }
  }
`;

async function getToken() {
  console.log('[auth] Requesting Wiz token...');
  const params = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     process.env.WIZ_CLIENT_ID,
    client_secret: process.env.WIZ_CLIENT_SECRET,
    audience:      'wiz-api',
  });
  const { data } = await axios.post(AUTH_URL, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  console.log('[auth] Token acquired.');
  return data.access_token;
}

async function fetchPage(token, after) {
  const { data } = await axios.post(
    process.env.WIZ_API_URL,
    { query: GQL_QUERY, variables: { first: PAGE_SIZE, after: after || null } },
    { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
  );
  if (data.errors) throw new Error(`Wiz GraphQL error: ${JSON.stringify(data.errors)}`);
  return data.data.networkExposures;
}

function extractIp(range) {
  if (!range || range === '-') return null;
  return range.replace('/32', '').replace('/128', '');
}

function mapNode(node) {
  const props = node.exposedEntity?.properties || {};
  return {
    id:                       node.id,
    entity_id:                node.exposedEntity?.id || null,
    entity_name:              node.exposedEntity?.name || null,
    entity_type:              node.exposedEntity?.type || null,
    entity_native_type:       props.nativeType || null,
    cloud_platform:           props.cloudPlatform || null,
    region:                   props.region || null,
    subscription_name:        props.subscriptionExternalId || null,
    source_ip_range:          node.sourceIpRange || null,
    destination_ip:           extractIp(node.destinationIpRange),
    port_range:               node.portRange || null,
    protocols:                node.networkProtocols || [],
    open_to_all_internet:     props.openToAllInternet ?? null,
    accessible_from_internet: props['accessibleFrom.internet'] ?? null,
    cloud_provider_url:       props.cloudProviderURL || null,
  };
}

async function upsertBatch(pool, records) {
  if (!records.length) return;
  for (const r of records) {
    await pool.query(`
      INSERT INTO public.wiz_internet_exposures
        (id, entity_id, entity_name, entity_type, entity_native_type, cloud_platform,
         region, subscription_name, source_ip_range, destination_ip, port_range,
         protocols, open_to_all_internet, accessible_from_internet, cloud_provider_url, ingested_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now())
      ON CONFLICT (id) DO UPDATE SET
        entity_name              = EXCLUDED.entity_name,
        destination_ip           = EXCLUDED.destination_ip,
        open_to_all_internet     = EXCLUDED.open_to_all_internet,
        accessible_from_internet = EXCLUDED.accessible_from_internet,
        ingested_at              = now()
    `, [
      r.id, r.entity_id, r.entity_name, r.entity_type, r.entity_native_type,
      r.cloud_platform, r.region, r.subscription_name, r.source_ip_range,
      r.destination_ip, r.port_range, r.protocols, r.open_to_all_internet,
      r.accessible_from_internet, r.cloud_provider_url,
    ]);
  }
}

async function main() {
  if (!process.env.WIZ_CLIENT_ID || !process.env.WIZ_CLIENT_SECRET || !process.env.WIZ_API_URL) {
    console.error('Error: WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, and WIZ_API_URL must be set.');
    process.exit(1);
  }
  if (DRY_RUN) console.log('[mode] DRY RUN — no database writes.');

  const pool = DRY_RUN ? null : new Pool({
    host:     process.env.DB_HOST,
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
  });

  const token = await getToken();

  // Support resuming from a saved cursor on connection reset
  let cursor = RESUME_CURSOR || null;
  if (cursor) console.log(`[resume] Starting from saved cursor.`);

  let page   = 0;
  let total  = 0;
  let withIp = 0;

  do {
    page++;
    const result = await fetchPage(token, cursor);
    if (page === 1) console.log(`[info] Total exposures reported by Wiz: ${result.totalCount}`);

    const records = result.nodes.map(mapNode);
    withIp += records.filter(r => r.destination_ip).length;
    total  += records.length;

    if (!DRY_RUN) await upsertBatch(pool, records);

    console.log(`[page ${page}] fetched: ${records.length} | with_ip: ${records.filter(r => r.destination_ip).length} | cumulative: ${total}`);

    const nextCursor = result.pageInfo.hasNextPage ? result.pageInfo.endCursor : null;
    if (nextCursor) process.stderr.write(`\r[cursor] ${nextCursor}`); // overwrite line for visibility
    cursor = nextCursor;
  } while (cursor);

  if (pool) await pool.end();

  console.log(`\nDone.`);
  console.log(`  Total exposures fetched:  ${total}`);
  console.log(`  With a destination IP:    ${withIp}`);
  if (DRY_RUN) console.log('  (dry run — nothing written to DB)');
}

main().catch(err => {
  const msg = err.response?.data || err.message;
  console.error('\nFatal:', msg);
  if (err.code === 'ECONNRESET' || String(msg).includes('ECONNRESET')) {
    console.error('\nConnection was reset by Wiz API (common on long-running sessions).');
    console.error('Re-run with upsert — already-written records will be skipped automatically.');
    console.error('  node scripts/wiz_reingest.cjs');
  }
  process.exit(1);
});
