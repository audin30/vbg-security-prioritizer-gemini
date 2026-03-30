
const { Client } = require('pg');

const DB_CONFIG = {
  host: 'localhost',
  port: 5432,
  database: 'vuln_db',
  user: 'postgres',
  password: 'csg2025',
};

async function main() {
  const client = new Client(DB_CONFIG);
  try {
    await client.connect();
    const res = await client.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name;
    `);
    console.log(JSON.stringify(res.rows, null, 2));
  } catch (err) {
    console.error(err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

main();
