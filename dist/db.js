"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readinessCheck = readinessCheck;
const pg_1 = require("pg");
const pool = new pg_1.Pool({
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
async function readinessCheck() {
    await pool.query("SELECT 1");
}
exports.default = pool;
