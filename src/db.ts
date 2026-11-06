import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  statement_timeout: 10_000,
  query_timeout: 10_000,
  connectionTimeoutMillis: 5_000,
});

pool.on("error", (err) => {
  // Internal log only — never sent to clients.
  console.error(JSON.stringify({ level: "error", msg: "pg_pool_error", err: String(err) }));
});

export async function readinessCheck(): Promise<void> {
  await pool.query("SELECT 1");
}

export default pool;
