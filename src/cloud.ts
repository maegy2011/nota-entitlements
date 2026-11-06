import { Router } from "express";
import type { Request, Response } from "express";
import express from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import path from "node:path";
import { access, mkdir, open, rm, stat, writeFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import pool from "./db.js";
import { errorBody, getClientIp } from "./middleware.js";
import { authSubOf, requireAuth } from "./auth.js";
import { trialGrantFor } from "./trial.js";
import {
  BLOBS_DIR,
  DiskFullError,
  FilesystemBackend,
  MAX_FILE_BYTES,
  quotaForAccount,
  sha256Hex,
} from "./storage.js";

// Nota Cloud Phase A: quota-metered blob store (registrations only, fail-closed).
// Auth posture matches the rest of /v1: accountId must be registered.
// Real idToken verification lands in Phase 3 — noted, not blocking.

const router = Router();
const store = new FilesystemBackend();

function accountHashDir(accountId: string): string {
  return sha256Hex(accountId);
}

function chunkDir(accountId: string, sha: string): string {
  return path.join(BLOBS_DIR, ".chunks", accountHashDir(accountId), sha);
}

function partialPath(accountId: string, sha: string): string {
  return path.join(chunkDir(accountId, sha), "partial");
}

async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(filePath);
    s.on("data", (c) => h.update(c));
    s.on("end", () => resolve(h.digest("hex")));
    s.on("error", reject);
  });
}

async function writeChunk(accountId: string, sha: string, offset: number, bytes: Buffer): Promise<void> {
  const dir = chunkDir(accountId, sha);
  await mkdir(dir, { recursive: true });
  const partial = partialPath(accountId, sha);
  try {
    await access(partial);
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    await writeFile(partial, Buffer.alloc(0));
  }
  const fh = await open(partial, "r+");
  try {
    await fh.write(bytes, 0, bytes.length, offset);
  } finally {
    await fh.close();
  }
}

const accountIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._@|-]+$/);
const shaSchema = z.string().regex(/^[0-9a-f]{64}$/);
const mimeSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9/+.\-]*$/)
  .default("application/octet-stream");

// ملاحظة 22 سبتمبر: z.object (strip) لا strictObject للـ query/params — أي باراميتر إضافي
// (مثل mime في رفع الـ blobs) كان يُسقط التحقق كله بـ VALIDATION_ERROR رغم سلامة الحقول
const accountQuery = z.object({ accountId: accountIdSchema });
const shaParams = z.object({ sha: shaSchema });
const pointerParams = z.object({ name: z.string().regex(/^[a-z_]{1,32}$/) });
const pointerQuery = z.object({ accountId: accountIdSchema, sha: shaSchema });
const chunkQuery = z.object({ accountId: accountIdSchema, offset: z.coerce.number().int().min(0), mime: mimeSchema.optional() });

// Uploads are expensive: stricter than the global 120/min limiter.
const uploadLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    res.status(429).json(errorBody("RATE_LIMITED", "Too many uploads.", req));
  },
});

// Plan of record: same fail-closed rule as /v1/entitlements — a fresh row with features = pro.
function planOf(
  row: { features: string[]; expires_at: string | null } | undefined,
  accountId: string,
): {
  isPro: boolean;
  features: string[];
} {
  // Beta trial: exactly one server-configured account can receive time-boxed features.
  const trial = trialGrantFor(accountId);
  if (trial.active) return { isPro: true, features: trial.features };
  const features = (row?.features ?? []) as string[];
  const fresh = !row?.expires_at || new Date(row.expires_at).getTime() > Date.now();
  return { isPro: !!row && features.length > 0 && fresh, features };
}

async function registered(accountId: string): Promise<boolean> {
  const r = await pool.query("SELECT 1 FROM users WHERE account_id = $1", [accountId]);
  return (r.rowCount ?? 0) > 0;
}

async function quotaState(accountId: string): Promise<{ quotaBytes: number; usedBytes: number }> {
  const e = await pool.query("SELECT features, expires_at FROM entitlements WHERE account_id = $1", [accountId]);
  const { isPro, features } = planOf(
    e.rows[0] as { features: string[]; expires_at: string | null } | undefined,
    accountId,
  );
  const quotaBytes = quotaForAccount(isPro, features);
  await pool.query("INSERT INTO quotas(account_id) VALUES ($1) ON CONFLICT (account_id) DO NOTHING", [accountId]);
  const q = await pool.query("SELECT used_bytes FROM quotas WHERE account_id = $1", [accountId]);
  const usedBytes = Number(q.rows[0]?.used_bytes ?? 0);
  return { quotaBytes, usedBytes };
}

// Phase 3: verified sub must own the account in every account-scoped route.
function owns(req: Request, accountId: string): boolean {
  return authSubOf(req) === accountId;
}
function forbidden(res: Response, req: Request): void {
  res.status(403).json(errorBody("FORBIDDEN", "Token does not own this account.", req));
}

// GET /v1/cloud/quota?accountId= — always allowed for registered accounts (never locks data out).
router.get("/cloud/quota", requireAuth, async (req: Request, res: Response) => {
  const parsed = accountQuery.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (!owns(req, parsed.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    if (!(await registered(parsed.data.accountId))) {
      res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
      return;
    }
    const { quotaBytes, usedBytes } = await quotaState(parsed.data.accountId);
    res.status(200).json({ quotaBytes, usedBytes, freeBytes: Math.max(0, quotaBytes - usedBytes) });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Quota check failed.", req));
  }
});

// PUT /v1/cloud/blobs/:sha?accountId= — raw bytes, hash must match the path.
// ترتيب الوسائط: المصادقة أولًا قبل قراءة الجسم — وإلا استنزف مهاجم بلا توكن
// ذاكرة السيرفر برفع أجسام 32MB مرفوضة لاحقًا (تضخيم DoS).
router.put(
  "/cloud/blobs/:sha",
  requireAuth,
  uploadLimiter,
  express.raw({ type: "application/octet-stream", limit: MAX_FILE_BYTES + 1024 }),
  async (req: Request, res: Response) => {
    const qp = accountQuery.safeParse(req.query);
    const pp = shaParams.safeParse(req.params);
    if (!qp.success || !pp.success) {
      res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId or sha256.", req));
      return;
    }
    if (!owns(req, qp.data.accountId)) {
      forbidden(res, req);
      return;
    }
    const { accountId } = qp.data;
    const { sha } = pp.data;
    const bytes = req.body as Buffer;
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
      res.status(400).json(errorBody("VALIDATION_ERROR", "Empty body.", req));
      return;
    }
    if (bytes.length > MAX_FILE_BYTES) {
      res.status(413).json(errorBody("FILE_TOO_LARGE", "File exceeds the per-file limit.", req));
      return;
    }
    if (sha256Hex(bytes) !== sha) {
      res.status(400).json(errorBody("HASH_MISMATCH", "Body does not match the sha256 path.", req));
      return;
    }
    const mp = z.object({ mime: mimeSchema }).safeParse(req.query);
    const mime = mp.success ? mp.data.mime : "application/octet-stream";
    try {
      if (!(await registered(accountId))) {
        res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
        return;
      }
      // Same bytes twice: no charge, no rewrite.
      const dup = await pool.query("SELECT 1 FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [
        accountId,
        sha,
      ]);
      if ((dup.rowCount ?? 0) > 0) {
        const { usedBytes, quotaBytes } = await quotaState(accountId);
        res.status(200).json({ sha256: sha, sizeBytes: bytes.length, dedupe: true, usedBytes, quotaBytes });
        return;
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.current_account_id', $1, true)", [accountId]);
        // Dedupe re-check inside the transaction (race safety): if the blob was
        // registered concurrently, do not charge quota a second time.
        const dupTx = await client.query("SELECT 1 FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [accountId, sha]);
        if ((dupTx.rowCount ?? 0) > 0) {
          await client.query("ROLLBACK");
          const { usedBytes, quotaBytes } = await quotaState(accountId);
          res.status(200).json({ sha256: sha, sizeBytes: bytes.length, dedupe: true, usedBytes, quotaBytes });
          return;
        }
        await client.query("INSERT INTO quotas(account_id) VALUES ($1) ON CONFLICT (account_id) DO NOTHING", [
          accountId,
        ]);
        const q = await client.query("SELECT used_bytes FROM quotas WHERE account_id = $1 FOR UPDATE", [accountId]);
        const e = await client.query("SELECT features, expires_at FROM entitlements WHERE account_id = $1", [accountId]);
        const { isPro, features } = planOf(
          e.rows[0] as { features: string[]; expires_at: string | null } | undefined,
          accountId,
        );
        const quotaBytes = quotaForAccount(isPro, features);
        const usedBytes = Number(q.rows[0]?.used_bytes ?? 0);
        if (usedBytes + bytes.length > quotaBytes) {
          await client.query("ROLLBACK");
          res.status(413).json({
            ...errorBody("QUOTA_EXCEEDED", "Storage quota exceeded.", req),
            quotaBytes,
            usedBytes,
            upgradeRequired: true,
          });
          return;
        }
        try {
          await store.put(accountId, sha, bytes);
        } catch (err) {
          await client.query("ROLLBACK");
          if (err instanceof DiskFullError) {
            res.status(507).json(errorBody("DISK_FULL", "Server storage full, try again later.", req));
          } else {
            res.status(500).json(errorBody("INTERNAL_ERROR", "Upload failed.", req));
          }
          return;
        }
        const ins = await client.query(
          "INSERT INTO cloud_files(account_id, sha256, size_bytes, mime) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING size_bytes",
          [accountId, sha, bytes.length, mime],
        );
        if ((ins.rowCount ?? 0) > 0) {
          await client.query("UPDATE quotas SET used_bytes = used_bytes + $2, updated_at = now() WHERE account_id = $1", [
            accountId,
            bytes.length,
          ]);
        }
        await client.query("COMMIT");
        res.status(201).json({ sha256: sha, sizeBytes: bytes.length, usedBytes: usedBytes + bytes.length, quotaBytes });
      } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
        await client.query("ROLLBACK").catch(() => undefined);
        await store.remove(accountId, sha);
        res.status(500).json(errorBody("INTERNAL_ERROR", "Upload failed.", req));
      } finally {
        client.release();
      }
    } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
      res.status(500).json(errorBody("INTERNAL_ERROR", "Upload failed.", req));
    }
  },
);

// GET /v1/cloud/blobs/:sha?accountId= — downloads are always allowed (no data lock-in, ever).
router.get("/cloud/blobs/:sha", requireAuth, async (req: Request, res: Response) => {
  const qp = accountQuery.safeParse(req.query);
  const pp = shaParams.safeParse(req.params);
  if (!qp.success || !pp.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId or sha256.", req));
    return;
  }
  if (!owns(req, qp.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    const r = await pool.query("SELECT mime FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [
      qp.data.accountId,
      pp.data.sha,
    ]);
    if ((r.rowCount ?? 0) === 0) {
      res.status(404).json(errorBody("NOT_FOUND", "Blob not found.", req));
      return;
    }
    const bytes = await store.get(qp.data.accountId, pp.data.sha);
    if (!bytes) {
      res.status(404).json(errorBody("NOT_FOUND", "Blob not found.", req));
      return;
    }
    // Force download (attachment) to prevent stored XSS via crafted MIME types.
    res.setHeader("Content-Disposition", `attachment; filename="${pp.data.sha}.bin"`);
    res.type("application/octet-stream").send(bytes);
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Download failed.", req));
  }
});

// DELETE /v1/cloud/blobs/:sha?accountId= — frees quota immediately.
router.delete("/cloud/blobs/:sha", requireAuth, async (req: Request, res: Response) => {
  const qp = accountQuery.safeParse(req.query);
  const pp = shaParams.safeParse(req.params);
  if (!qp.success || !pp.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId or sha256.", req));
    return;
  }
  if (!owns(req, qp.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
        await client.query("SELECT set_config('app.current_account_id', $1, true)", [qp.data.accountId]);
      const d = await client.query(
        "DELETE FROM cloud_files WHERE account_id = $1 AND sha256 = $2 RETURNING size_bytes",
        [qp.data.accountId, pp.data.sha],
      );
      if ((d.rowCount ?? 0) === 0) {
        await client.query("ROLLBACK");
        res.status(404).json(errorBody("NOT_FOUND", "Blob not found.", req));
        return;
      }
      const freed = Number(d.rows[0].size_bytes);
      await client.query(
        "UPDATE quotas SET used_bytes = GREATEST(0, used_bytes - $2), updated_at = now() WHERE account_id = $1",
        [qp.data.accountId, freed],
      );
      await client.query("COMMIT");
      await store.remove(qp.data.accountId, pp.data.sha);
      res.status(200).json({ ok: true, freedBytes: freed });
    } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
      await client.query("ROLLBACK").catch(() => undefined);
      res.status(500).json(errorBody("INTERNAL_ERROR", "Delete failed.", req));
    } finally {
      client.release();
    }
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Delete failed.", req));
  }
});

// POST /v1/cloud/reconcile?accountId= — recompute the meter from the registry (the meter can drift; this is truth).
router.post("/cloud/reconcile", requireAuth, async (req: Request, res: Response) => {
  const parsed = accountQuery.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId.", req));
    return;
  }
  if (!owns(req, parsed.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    if (!(await registered(parsed.data.accountId))) {
      res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
      return;
    }
    const r = await pool.query(
      `UPDATE quotas q SET used_bytes = COALESCE(s.sum, 0), updated_at = now()
       FROM (SELECT COALESCE(SUM(size_bytes), 0)::bigint AS sum FROM cloud_files WHERE account_id = $1) s
       WHERE q.account_id = $1 RETURNING q.used_bytes,
       (SELECT count(*) FROM cloud_files WHERE account_id = $1) AS file_count`,
      [parsed.data.accountId],
    );
    if ((r.rowCount ?? 0) === 0) {
      // No quota row yet (never uploaded): create it at zero.
      await pool.query("INSERT INTO quotas(account_id, used_bytes) VALUES ($1, 0) ON CONFLICT DO NOTHING", [
        parsed.data.accountId,
      ]);
      res.status(200).json({ usedBytes: 0, fileCount: 0 });
      return;
    }
    res.status(200).json({ usedBytes: Number(r.rows[0].used_bytes), fileCount: Number(r.rows[0].file_count) });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Reconcile failed.", req));
  }
});

// Named pointers (backup_latest, ...) — any device finds the newest blob without listing.

// PUT /v1/cloud/pointers/:name?accountId=&sha= — upsert pointer (blob must exist: no dangling pointers).
router.put("/cloud/pointers/:name", requireAuth, async (req: Request, res: Response) => {
  const qp = pointerQuery.safeParse(req.query);
  const pp = pointerParams.safeParse(req.params);
  if (!qp.success || !pp.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId, name or sha256.", req));
    return;
  }
  if (!owns(req, qp.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    const b = await pool.query("SELECT 1 FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [
      qp.data.accountId,
      qp.data.sha,
    ]);
    if ((b.rowCount ?? 0) === 0) {
      res.status(404).json(errorBody("NOT_FOUND", "Blob not found.", req));
      return;
    }
    await pool.query(
      `INSERT INTO cloud_pointers(account_id, name, sha256, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (account_id, name) DO UPDATE SET sha256 = EXCLUDED.sha256, updated_at = now()`,
      [qp.data.accountId, pp.data.name, qp.data.sha],
    );
    res.status(200).json({ ok: true, name: pp.data.name, sha256: qp.data.sha });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Pointer update failed.", req));
  }
});

// GET /v1/cloud/pointers/:name?accountId= — resolve pointer (404 = no backup yet, not an error).
router.get("/cloud/pointers/:name", requireAuth, async (req: Request, res: Response) => {
  const qp = accountQuery.safeParse(req.query);
  const pp = pointerParams.safeParse(req.params);
  if (!qp.success || !pp.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId or name.", req));
    return;
  }
  if (!owns(req, qp.data.accountId)) {
    forbidden(res, req);
    return;
  }
  try {
    const r = await pool.query("SELECT sha256, updated_at FROM cloud_pointers WHERE account_id = $1 AND name = $2", [
      qp.data.accountId,
      pp.data.name,
    ]);
    if ((r.rowCount ?? 0) === 0) {
      res.status(404).json(errorBody("NOT_FOUND", "No backup yet.", req));
      return;
    }
    res.status(200).json({ name: pp.data.name, sha256: r.rows[0].sha256, updatedAt: r.rows[0].updated_at });
  } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
    res.status(500).json(errorBody("INTERNAL_ERROR", "Pointer lookup failed.", req));
  }
});

// PUT /v1/cloud/blobs/:sha/chunks?accountId=&offset= — resumable chunked upload.
// Accumulates chunks into a partial file; finalizes (registers blob + charges quota) once
// the assembled file's sha256 matches the path. Idempotent and resumable across restarts.
router.put(
  "/cloud/blobs/:sha/chunks",
  requireAuth,
  uploadLimiter,
  express.raw({ type: "application/octet-stream", limit: MAX_FILE_BYTES + 1024 }),
  async (req: Request, res: Response) => {
    const qp = chunkQuery.safeParse(req.query);
    const pp = shaParams.safeParse(req.params);
    if (!qp.success || !pp.success) {
      res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid accountId, sha256 or offset.", req));
      return;
    }
    if (!owns(req, qp.data.accountId)) {
      forbidden(res, req);
      return;
    }
    const { accountId } = qp.data;
    const { sha } = pp.data;
    const offset = qp.data.offset;
    const bytes = req.body as Buffer;
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
      res.status(400).json(errorBody("VALIDATION_ERROR", "Empty chunk.", req));
      return;
    }
    if (offset + bytes.length > MAX_FILE_BYTES) {
      res.status(413).json(errorBody("FILE_TOO_LARGE", "File exceeds the per-file limit.", req));
      return;
    }
    try {
      if (!(await registered(accountId))) {
        res.status(404).json(errorBody("NOT_FOUND", "Account not found.", req));
        return;
      }
      // Already finalized: no charge, no rewrite.
      const dup = await pool.query("SELECT 1 FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [accountId, sha]);
      if ((dup.rowCount ?? 0) > 0) {
        res.status(200).json({ sha256: sha, dedupe: true });
        return;
      }
      try {
        await writeChunk(accountId, sha, offset, bytes);
      } catch (err) {
        if (err instanceof DiskFullError) {
          res.status(507).json(errorBody("DISK_FULL", "Server storage full, try again later.", req));
          return;
        }
        res.status(500).json(errorBody("INTERNAL_ERROR", "Chunk upload failed.", req));
        return;
      }
      const partial = partialPath(accountId, sha);
      let sizeBytes = 0;
      try {
        sizeBytes = (await stat(partial)).size;
      } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
        res.status(500).json(errorBody("INTERNAL_ERROR", "Chunk state lost.", req));
        return;
      }
      if (sizeBytes > MAX_FILE_BYTES) {
        await rm(chunkDir(accountId, sha), { recursive: true, force: true }).catch(() => undefined);
        res.status(413).json(errorBody("FILE_TOO_LARGE", "File exceeds the per-file limit.", req));
        return;
      }
      // Finalize only when the assembled file matches the claimed sha256.
      const hash = await sha256File(partial);
      if (hash !== sha) {
        res.status(200).json({ sha256: sha, offset: offset + bytes.length, complete: false });
        return;
      }
      // Finalize: quota check + move + register + charge.
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.current_account_id', $1, true)", [accountId]);
        // Re-check dedupe inside the transaction (race safety).
        const dup2 = await client.query("SELECT 1 FROM cloud_files WHERE account_id = $1 AND sha256 = $2", [accountId, sha]);
        if ((dup2.rowCount ?? 0) > 0) {
          await client.query("ROLLBACK");
          await rm(chunkDir(accountId, sha), { recursive: true, force: true }).catch(() => undefined);
          res.status(200).json({ sha256: sha, dedupe: true });
          return;
        }
        await client.query("INSERT INTO quotas(account_id) VALUES ($1) ON CONFLICT (account_id) DO NOTHING", [accountId]);
        const q = await client.query("SELECT used_bytes FROM quotas WHERE account_id = $1 FOR UPDATE", [accountId]);
        const e = await client.query("SELECT features, expires_at FROM entitlements WHERE account_id = $1", [accountId]);
        const { isPro, features } = planOf(
          e.rows[0] as { features: string[]; expires_at: string | null } | undefined,
          accountId,
        );
        const quotaBytes = quotaForAccount(isPro, features);
        const usedBytes = Number(q.rows[0]?.used_bytes ?? 0);
        if (usedBytes + sizeBytes > quotaBytes) {
          await client.query("ROLLBACK");
          res.status(413).json({
            ...errorBody("QUOTA_EXCEEDED", "Storage quota exceeded.", req),
            quotaBytes,
            usedBytes,
            upgradeRequired: true,
          });
          return;
        }
        const fileBytes = await readFile(partial);
        try {
          await store.put(accountId, sha, fileBytes);
        } catch (err) {
          await client.query("ROLLBACK");
          if (err instanceof DiskFullError) {
            res.status(507).json(errorBody("DISK_FULL", "Server storage full, try again later.", req));
          } else {
            res.status(500).json(errorBody("INTERNAL_ERROR", "Upload failed.", req));
          }
          return;
        }
        const chunkMime = qp.data.mime ?? "application/octet-stream";
        await client.query(
          "INSERT INTO cloud_files(account_id, sha256, size_bytes, mime) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
          [accountId, sha, sizeBytes, chunkMime],
        );
        await client.query("UPDATE quotas SET used_bytes = used_bytes + $2, updated_at = now() WHERE account_id = $1", [
          accountId,
          sizeBytes,
        ]);
        await client.query("COMMIT");
        await rm(chunkDir(accountId, sha), { recursive: true, force: true }).catch(() => undefined);
        res.status(201).json({ sha256: sha, sizeBytes, usedBytes: usedBytes + sizeBytes, quotaBytes, complete: true });
      } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
        await client.query("ROLLBACK").catch(() => undefined);
        await store.remove(accountId, sha).catch(() => undefined);
        res.status(500).json(errorBody("INTERNAL_ERROR", "Chunk finalization failed.", req));
      } finally {
        client.release();
      }
    } catch (err) { console.error(JSON.stringify({ level: "error", msg: "handler_error", path: "", err: String(err) }));
      res.status(500).json(errorBody("INTERNAL_ERROR", "Chunk upload failed.", req));
    }
  },
);

export default router;
