import { Router } from "express";
import type { Request, Response } from "express";
import { z } from "zod";
import pool from "./db.js";
import { errorBody } from "./middleware.js";
import { authSubOf, requireAuth } from "./auth.js";
import { trialGrantFor } from "./trial.js";
import { deleteAccountData, exportAccountData } from "./gdpr.js";
import { FilesystemBackend, sha256Hex, BLOBS_DIR } from "./storage.js";
import path from "node:path";
import { rm } from "node:fs/promises";

const router = Router();

// Whitelist: ids only (no free text). Strict: unknown fields rejected.
const accountIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._@|-]+$/);
const featuresSchema = z.array(z.string().min(1).max(64)).max(32).default([]);

const registerSchema = z.strictObject({ accountId: accountIdSchema });
const entitlementsQuerySchema = z.strictObject({ accountId: accountIdSchema });
const simulateSchema = z.strictObject({
  accountId: accountIdSchema,
  action: z.enum(["grant", "revoke", "expire"]),
  features: featuresSchema,
});

function isProRow(row: { features: string[]; expires_at: string | null } | undefined): boolean {
  if (!row) return false;
  if (!row.features || row.features.length === 0) return false;
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) return false;
  return true;
}

// POST /v1/users/register — idempotent account registration, Phase 3 authenticated:
// Bearer Firebase ID token required; verified sub must equal accountId (binding).
router.post("/users/register", requireAuth, async (req: Request, res: Response) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  const sub = authSubOf(req);
  if (sub !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    const r = await client.query(
      "INSERT INTO users(account_id, google_sub) VALUES ($1, $2) ON CONFLICT (account_id) DO NOTHING RETURNING account_id",
      [parsed.data.accountId, sub],
    );
    await client.query("UPDATE users SET google_sub = $2 WHERE account_id = $1 AND google_sub IS DISTINCT FROM $2", [
      parsed.data.accountId,
      sub,
    ]);
    await client.query("COMMIT");
    if (r.rowCount === 0) {
      res.status(200).json({ accountId: parsed.data.accountId, created: false });
    } else {
      res.status(201).json({ accountId: parsed.data.accountId, created: true });
    }
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    await client.query("ROLLBACK").catch(() => undefined);
    res.status(500).json(errorBody("INTERNAL_ERROR", "Registration failed.", req));
  } finally {
    client.release();
  }
});

// GET /v1/entitlements?accountId= — fail-closed: unknown/expired -> pro:false.
// Phase 3: verified sub must own the queried account.
router.get("/entitlements", requireAuth, async (req: Request, res: Response) => {
  const parsed = entitlementsQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (authSubOf(req) !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    const r = await client.query("SELECT features, expires_at FROM entitlements WHERE account_id = $1", [
      parsed.data.accountId,
    ]);
    const u = await client.query("SELECT trial_used, banned, banned_reason FROM users WHERE account_id = $1", [parsed.data.accountId]);
    await client.query("COMMIT");
    const trialUsed = u.rows[0]?.trial_used === true;
    const banned = u.rows[0]?.banned === true;
    const bannedReason = u.rows[0]?.banned_reason ?? null;
    const row = r.rows[0] as { features: string[]; expires_at: string | null } | undefined;
    // Beta trial: exactly one server-configured account can receive time-boxed features.
    const trial = trialGrantFor(parsed.data.accountId);
    if (banned) {
      res.status(200).json({ pro: false, features: [], expiresAt: null, trialUsed, banned: true, bannedReason });
      return;
    }
    if (trial.active) {
      res.status(200).json({ pro: true, features: trial.features, expiresAt: trial.expiresAt, trialUsed, banned: false });
      return;
    }
    if (!isProRow(row)) {
      res.status(200).json({ pro: false, features: [], expiresAt: null, trialUsed, banned: false });
      return;
    }
    res.status(200).json({ pro: true, features: row!.features, expiresAt: row!.expires_at, trialUsed, banned: false });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    await client.query("ROLLBACK").catch(() => undefined);
    res.status(200).json({ pro: false, features: [], expiresAt: null, trialUsed: false, banned: false });
  } finally {
    client.release();
  }
});

// POST /v1/test/simulate — TEST_MODE=true (server-side env) only, else 403.
// Defense in depth (security): even in TEST_MODE, require a verified Firebase bearer
// that owns the target account. Never allow unauthenticated simulation.
router.post("/test/simulate", requireAuth, async (req: Request, res: Response) => {
  if (process.env.TEST_MODE !== "true") {
    res.status(403).json(errorBody("TEST_MODE_DISABLED", "Test simulation is disabled.", req));
    return;
  }
  // ownership is enforced after body parse below; gate here too for missing token clarity

  const parsed = simulateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid simulation payload.", req));
    return;
  }
  if (authSubOf(req) !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  const { accountId, action } = parsed.data;
  try {
    const u = await pool.query("SELECT 1 FROM users WHERE account_id = $1", [accountId]);
    if (u.rowCount === 0) {
      res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
      return;
    }
    if (action === "grant") {
      const features = parsed.data.features.length > 0 ? parsed.data.features : ["folders"];
      await pool.query(
        `INSERT INTO entitlements(account_id, features, expires_at, updated_at)
         VALUES ($1, $2, now() + interval '30 days', now())
         ON CONFLICT (account_id) DO UPDATE SET features = EXCLUDED.features, expires_at = EXCLUDED.expires_at, updated_at = now()`,
        [accountId, features],
      );
    } else if (action === "revoke") {
      await pool.query("DELETE FROM entitlements WHERE account_id = $1", [accountId]);
    } else {
      await pool.query("UPDATE entitlements SET expires_at = now() - interval '1 day', updated_at = now() WHERE account_id = $1", [
        accountId,
      ]);
    }
    res.status(200).json({ ok: true, action });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Simulation failed.", req));
  }
});

// POST /v1/trial/start — records that the account has consumed its trial (server-side truth).
// Phase 6: idempotent; flipped once. Fail-closed ownership: verified sub must own account.
router.post("/trial/start", requireAuth, async (req: Request, res: Response) => {
  const parsed = z.strictObject({ accountId: accountIdSchema }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (authSubOf(req) !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    const u = await client.query("SELECT 1 FROM users WHERE account_id = $1", [parsed.data.accountId]);
    if (u.rowCount === 0) {
      await client.query("ROLLBACK");
      client.release();
      res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
      return;
    }
    await client.query(
      "UPDATE users SET trial_used = TRUE, trial_started_at = COALESCE(trial_started_at, now()) WHERE account_id = $1",
      [parsed.data.accountId],
    );
    await client.query("COMMIT");
    res.status(200).json({ ok: true, trialUsed: true });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    await client.query("ROLLBACK").catch(() => undefined);
    res.status(500).json(errorBody("INTERNAL_ERROR", "Trial start failed.", req));
  } finally {
    client.release();
  }
});

// DELETE /v1/account?accountId= — best-effort cloud wipe: blobs, chunks, then cascade row delete.
// Phase 6: idempotent; 200 even if the account was already gone.
// GET /v1/account/export?accountId= — GDPR right to access (data portability).
router.get("/account/export", requireAuth, async (req: Request, res: Response) => {
  const parsed = z.strictObject({ accountId: accountIdSchema }).safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (authSubOf(req) !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  try {
    const data = await exportAccountData(parsed.data.accountId);
    res.setHeader("Content-Disposition", `attachment; filename="nota-data-${parsed.data.accountId}.json"`);
    res.json(data);
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Data export failed.", req));
  }
});

router.delete("/account", requireAuth, async (req: Request, res: Response) => {
  const parsed = z.strictObject({ accountId: accountIdSchema }).safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (authSubOf(req) !== parsed.data.accountId) {
    res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
    return;
  }
  const accountId = parsed.data.accountId;
  try {
    await deleteAccountData(accountId);
    res.status(200).json({ ok: true });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Account deletion failed.", req));
  }
});

export default router;
