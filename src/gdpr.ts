import pool from "./db.js";
import { FilesystemBackend } from "./storage.js";
import path from "node:path";
import { rm } from "node:fs/promises";
import { sha256Hex, BLOBS_DIR } from "./storage.js";

// Thorough GDPR deletion: removes all personal data for an account.
export async function deleteAccountData(accountId: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [accountId]);
    // Capture files for disk cleanup.
    const files = await client.query("SELECT sha256 FROM cloud_files WHERE account_id = $1", [accountId]);
    // Anonymize audit + rtdn (keep records, drop PII).
    await client.query("UPDATE admin_audit SET account_id = NULL WHERE account_id = $1", [accountId]);
    await client.query("UPDATE rtdn_events SET account_id = NULL WHERE account_id = $1", [accountId]);
    // Delete user row (cascades entitlements, quotas, cloud_files, cloud_pointers, purchases, notifications).
    await client.query("DELETE FROM users WHERE account_id = $1", [accountId]);
    await client.query("COMMIT");
    // Disk cleanup (best-effort).
    const store = new FilesystemBackend();
    for (const row of files.rows as { sha256: string }[]) {
      await store.remove(accountId, row.sha256).catch(() => undefined);
    }
    await rm(path.join(BLOBS_DIR, ".chunks", sha256Hex(accountId)), { recursive: true, force: true }).catch(() => undefined);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

// GDPR data export (right to access).
export async function exportAccountData(accountId: string): Promise<Record<string, unknown>> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [accountId]);
    const user = await client.query("SELECT account_id, google_sub, trial_used, trial_started_at, created_at, last_seen_at, banned FROM users WHERE account_id = $1", [accountId]);
    const entitlements = await client.query("SELECT features, expires_at, updated_at FROM entitlements WHERE account_id = $1", [accountId]);
    const quota = await client.query("SELECT used_bytes, updated_at FROM quotas WHERE account_id = $1", [accountId]);
    const files = await client.query("SELECT sha256, size_bytes, mime, created_at FROM cloud_files WHERE account_id = $1", [accountId]);
    const pointers = await client.query("SELECT name, sha256, updated_at FROM cloud_pointers WHERE account_id = $1", [accountId]);
    const purchases = await client.query("SELECT product_id, status, is_subscription, expires_at, verified_at, created_at FROM purchases WHERE account_id = $1", [accountId]);
    const notifications = await client.query("SELECT title, body, type, read, created_at FROM notifications WHERE account_id = $1", [accountId]);
    await client.query("COMMIT");
    return {
      exportedAt: new Date().toISOString(),
      user: user.rows[0] ?? null,
      entitlements: entitlements.rows,
      quota: quota.rows[0] ?? null,
      cloudFiles: files.rows,
      cloudPointers: pointers.rows,
      purchases: purchases.rows,
      notifications: notifications.rows,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}
