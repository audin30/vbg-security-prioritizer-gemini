
const { Client } = require('pg');

const DB_CONFIG = {
  host: 'localhost',
  port: 5432,
  database: 'vuln_db',
  user: 'postgres',
  password: 'csg2025',
};

async function main() {
  const tablesToInspect = process.argv.slice(2);
  if (tablesToInspect.length === 0) {
    console.error('Please provide table names as arguments');
    process.exit(1);
  }

  const client = new Client(DB_CONFIG);
  try {
    await client.connect();

    for (const table of tablesToInspect) {
      console.log(`\n--- ${table} ---`);
      
      // Get schema
      const schemaRes = await client.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1
        ORDER BY ordinal_position;
      `, [table]);
      console.log('Schema:');
      console.log(JSON.stringify(schemaRes.rows, null, 2));

      // Get sample rows
      try {
        const sampleRes = await client.query(`SELECT * FROM ${table} LIMIT 3;`);
        console.log('Sample Rows:');
        console.log(JSON.stringify(sampleRes.rows, null, 2));
      } catch (err) {
        console.log(`Error getting sample rows for ${table}: ${err.message}`);
      }
    }

  } catch (err) {
    console.error(err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

main();
