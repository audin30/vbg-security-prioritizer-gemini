const { Client } = require('pg');

const config = {
  host: 'localhost',
  port: 5432,
  database: 'vuln_db',
  user: 'postgres',
};

async function run() {
  const client = new Client(config);
  await client.connect();

  const tables = ['dto_assets', 'wiz_network_exposures', 'wiz_data_findings', 'wiz_data_resources', 'wiz_sbom', 'wiz_compliance_frameworks', 'wiz_detections', 'wiz_inventory', 'wiz_threat_items', 'sync_state'];

  for (const table of tables) {
    console.log(`\n--- TABLE: ${table} ---`);
    try {
      // Schema
      const schema = await client.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = '${table}'
        ORDER BY ordinal_position;
      `);
      console.log('Schema:');
      schema.rows.forEach(r => console.log(`  ${r.column_name}: ${r.data_type}`));

      // Sample
      const sample = await client.query(`SELECT * FROM ${table} LIMIT 3;`);
      console.log('Sample (3 rows):');
      console.log(JSON.stringify(sample.rows, null, 2));
    } catch (e) {
      console.log(`Error reading ${table}: ${e.message}`);
    }
  }

  await client.end();
}

run();
