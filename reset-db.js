import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL mancante");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function resetDb() {
  console.log("Reset Nexus database...");

  await pool.query(`DROP TABLE IF EXISTS messages CASCADE;`);
  await pool.query(`DROP TABLE IF EXISTS conversations CASCADE;`);
  await pool.query(`DROP TABLE IF EXISTS users CASCADE;`);

  console.log("✅ Database pulito. Ora riavvia il backend.");
  await pool.end();
}

resetDb().catch((err) => {
  console.error("❌ Reset fallito:", err);
  process.exit(1);
});
