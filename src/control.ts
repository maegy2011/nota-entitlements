import { Router } from "express";
import type { Request, Response } from "express";
import { z } from "zod";
import pool from "./db.js";
import { errorBody } from "./middleware.js";
import { authSubOf, requireAuth } from "./auth.js";

const router = Router();

const accountIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9._@|-]+$/);

// ---------- Public: remote config + active announcements ----------
router.get("/config", async (_req: Request, res: Response) => {
  try {
    const cfg = await pool.query("SELECT key, value FROM remote_config");
    const config: Record<string, string> = {};
    for (const row of cfg.rows) config[row.key] = row.value;
    const ann = await pool.query(
      `SELECT id, title, body, type, starts_at, ends_at
       FROM announcements
       WHERE active = TRUE AND starts_at <= now() AND (ends_at IS NULL OR ends_at > now())
       ORDER BY created_at DESC`,
    );
    res.json({ config, announcements: ann.rows });
  } catch {
    res.status(500).json(errorBody("INTERNAL_ERROR", "Config load failed.", _req));
  }
});

// ---------- Public: list notifications for account ----------
router.get("/notifications", requireAuth, async (req: Request, res: Response) => {
  const parsed = z.strictObject({ accountId: accountIdSchema }).safeParse(req.query);
  if (!parsed.success) { res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req)); return; }
  if (authSubOf(req) !== parsed.data.accountId) { res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req)); return; }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    const r = await client.query(
      "SELECT id, title, body, type, read, created_at FROM notifications WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100",
      [parsed.data.accountId],
    );
    await client.query("COMMIT");
    res.json({ notifications: r.rows });
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    res.status(500).json(errorBody("INTERNAL_ERROR", "Notifications list failed.", req));
  } finally {
    client.release();
  }
});

// ---------- Public: mark notification read ----------
router.post("/notifications/read", requireAuth, async (req: Request, res: Response) => {
  const schema = z.strictObject({ accountId: accountIdSchema, ids: z.array(z.number().int().positive()).max(100).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid payload.", req)); return; }
  if (authSubOf(req) !== parsed.data.accountId) { res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req)); return; }
  const client2 = await pool.connect();
  try {
    await client2.query("BEGIN");
    await client2.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    if (parsed.data.ids && parsed.data.ids.length > 0) {
      await client2.query("UPDATE notifications SET read = TRUE WHERE account_id = $1 AND id = ANY($2)", [parsed.data.accountId, parsed.data.ids]);
    } else {
      await client2.query("UPDATE notifications SET read = TRUE WHERE account_id = $1", [parsed.data.accountId]);
    }
    await client2.query("COMMIT");
    res.json({ ok: true });
  } catch {
    await client2.query("ROLLBACK").catch(() => undefined);
    res.status(500).json(errorBody("INTERNAL_ERROR", "Mark read failed.", req));
  } finally {
    client2.release();
  }
});

// ---------- Public: request data deletion ----------
router.post("/account/delete-request", requireAuth, async (req: Request, res: Response) => {
  const parsed = z.strictObject({ accountId: accountIdSchema, reason: z.string().max(512).optional() }).safeParse(req.body);
  if (!parsed.success) { res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid payload.", req)); return; }
  if (authSubOf(req) !== parsed.data.accountId) { res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req)); return; }
  const client3 = await pool.connect();
  try {
    await client3.query("BEGIN");
    await client3.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
    const u = await client3.query("SELECT 1 FROM users WHERE account_id = $1", [parsed.data.accountId]);
    if (u.rowCount === 0) {
      await client3.query("ROLLBACK");
      client3.release();
      res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
      return;
    }
    const r = await client3.query(
      "INSERT INTO data_deletion_requests (account_id, reason) VALUES ($1, $2) RETURNING id, status, requested_at",
      [parsed.data.accountId, parsed.data.reason ?? null],
    );
    await client3.query("COMMIT");
    res.status(201).json({ ok: true, request: r.rows[0] });
  } catch {
    await client3.query("ROLLBACK").catch(() => undefined);
    res.status(500).json(errorBody("INTERNAL_ERROR", "Deletion request failed.", req));
  } finally {
    client3.release();
  }
});

export default router;
