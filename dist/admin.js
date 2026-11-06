"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const db_js_1 = __importDefault(require("./db.js"));
const middleware_js_1 = require("./middleware.js");
const trial_js_1 = require("./trial.js");
const play = __importStar(require("./play.js"));
const gdpr_js_1 = require("./gdpr.js");
const storage_js_1 = require("./storage.js");
const node_fs_1 = require("node:fs");
const node_path_1 = __importDefault(require("node:path"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const router = (0, express_1.Router)();
const adminLimiter = (0, express_rate_limit_1.default)({ windowMs: 60_000, limit: 60, standardHeaders: "draft-7", legacyHeaders: false, keyGenerator: (req) => req.ip ?? "unknown" });
router.use("/v1/admin", adminLimiter);
router.use("/admin", adminLimiter);
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN ?? "").trim();
const loginAttempts = new Map();
async function adminAuth(req, res) {
    const h = req.headers.authorization;
    const q = typeof req.query.token === "string" ? req.query.token : null;
    const provided = h?.startsWith("Bearer ") ? h.slice(7).trim() : q;
    if (!provided) {
        res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Missing admin token.", req));
        return false;
    }
    // Legacy superadmin token (env) — full access.
    if (ADMIN_TOKEN !== "" && provided === ADMIN_TOKEN) {
        req.adminResolved = null;
        req.adminIsSuper = true;
        return true;
    }
    // Session token (RBAC).
    const { resolveSession } = await import("./rbac.js");
    const resolved = await resolveSession(provided);
    if (!resolved) {
        console.warn(JSON.stringify({ level: "warn", msg: "admin_auth_reject", ip: (0, middleware_js_1.getClientIp)(req), path: req.path }));
        res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Invalid or expired session.", req));
        return false;
    }
    req.adminResolved = resolved;
    req.adminIsSuper = false;
    return true;
}
async function audit(action, accountId, req, detail) {
    try {
        await db_js_1.default.query("INSERT INTO admin_audit (action, account_id, actor_ip, detail) VALUES ($1, $2, $3, $4)", [action, accountId, (0, middleware_js_1.getClientIp)(req), detail ? JSON.stringify(detail) : null]);
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "audit_write_failed", err: String(err) }));
    }
}
const accountIdSchema = zod_1.z.string().min(1).max(128).regex(/^[A-Za-z0-9._@|-]+$/);
const featuresSchema = zod_1.z.array(zod_1.z.string().min(1).max(64)).max(32).default([]);
const shaSchema = zod_1.z.string().regex(/^[0-9a-f]{64}$/);
// ---------- Overview ----------
router.get("/v1/admin/overview", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const u = await db_js_1.default.query("SELECT count(*)::int AS n, count(*) FILTER (WHERE trial_used) AS trial_used FROM users");
        const e = await db_js_1.default.query("SELECT count(*)::int AS n FROM entitlements WHERE features IS NOT NULL AND array_length(features,1) > 0 AND (expires_at IS NULL OR expires_at > now())");
        const q = await db_js_1.default.query("SELECT COALESCE(SUM(used_bytes),0)::bigint AS used FROM quotas");
        let diskFree = 0;
        let diskTotal = 0;
        try {
            const st = (0, node_fs_1.statfsSync)(storage_js_1.BLOBS_DIR);
            diskFree = st.bavail * st.bsize;
            diskTotal = st.blocks * st.bsize;
        }
        catch {
            // ignore
        }
        res.json({
            users: u.rows[0].n,
            trialUsed: Number(u.rows[0].trial_used ?? 0),
            proAccounts: e.rows[0].n,
            usedBytes: Number(q.rows[0].used),
            diskFreeBytes: diskFree,
            diskTotalBytes: diskTotal,
            freeQuotaBytes: storage_js_1.FREE_QUOTA_BYTES,
            proQuotaBytes: storage_js_1.PRO_QUOTA_BYTES,
            blobsDir: storage_js_1.BLOBS_DIR,
            trialConfigured: Boolean((process.env.TRIAL_ACCOUNT_ID ?? "").trim()),
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_overview_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Overview failed.", req));
    }
});
// ---------- Users list ----------
router.get("/v1/admin/users", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    try {
        const status = typeof req.query.status === "string" ? req.query.status : "all";
        const params = [];
        const conds = [];
        if (search) {
            params.push(`%${search}%`);
            conds.push(`u.account_id ILIKE $${params.length}`);
        }
        if (status === "paid") {
            conds.push(`(e.features IS NOT NULL AND array_length(e.features,1) > 0 AND (e.expires_at IS NULL OR e.expires_at > now()))`);
        }
        if (status === "free") {
            conds.push(`(e.features IS NULL OR array_length(e.features,1) IS NULL OR array_length(e.features,1) = 0 OR (e.expires_at IS NOT NULL AND e.expires_at <= now()))`);
        }
        if (status === "trial") {
            conds.push(`u.trial_used = TRUE`);
        }
        if (status === "new") {
            conds.push(`u.created_at > now() - interval '30 days'`);
        }
        if (status === "active") {
            conds.push(`u.last_seen_at IS NOT NULL AND u.last_seen_at > now() - interval '30 days'`);
        }
        if (status === "inactive") {
            conds.push(`(u.last_seen_at IS NULL OR u.last_seen_at <= now() - interval '30 days') AND u.created_at <= now() - interval '30 days'`);
        }
        const where = conds.length ? "WHERE " + conds.join(" AND ") : "";
        // total count (separate, for pagination) — must mirror where (with u. prefix stripped for users-only cols)
        const countSql = `SELECT count(*)::int AS n FROM users u LEFT JOIN entitlements e ON e.account_id = u.account_id ${where}`;
        const cr = await db_js_1.default.query(countSql, params.slice(0, params.length)); // params before limit/offset
        // remove limit/offset not yet pushed; params currently has only filter params
        const total = cr.rows[0].n;
        params.push(limit, offset);
        const r = await db_js_1.default.query(`SELECT u.account_id, u.google_sub, u.trial_used, u.trial_started_at, u.created_at, u.last_seen_at,
              e.features, e.expires_at, q.used_bytes,
              CASE WHEN (e.features IS NOT NULL AND array_length(e.features,1) > 0 AND (e.expires_at IS NULL OR e.expires_at > now())) THEN TRUE ELSE FALSE END AS pro
       FROM users u
       LEFT JOIN entitlements e ON e.account_id = u.account_id
       LEFT JOIN quotas q ON q.account_id = u.account_id
       ${where}
       ORDER BY u.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
        res.json({
            total,
            limit,
            offset,
            users: r.rows.map((row) => ({
                accountId: row.account_id,
                googleSub: row.google_sub,
                trialUsed: row.trial_used === true,
                trialStartedAt: row.trial_started_at,
                createdAt: row.created_at,
                features: row.features ?? [],
                expiresAt: row.expires_at,
                usedBytes: Number(row.used_bytes ?? 0),
                lastSeenAt: row.last_seen_at,
                pro: row.pro === true,
                trialGrant: (0, trial_js_1.trialGrantFor)(row.account_id).active,
            })),
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_users_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Users list failed.", req));
    }
});
// ---------- User detail ----------
router.get("/v1/admin/users/:accountId", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const parsed = accountIdSchema.safeParse(req.params.accountId);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId.", req));
        return;
    }
    try {
        const u = await db_js_1.default.query("SELECT * FROM users WHERE account_id = $1", [parsed.data]);
        if (u.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Account not found.", req));
            return;
        }
        const e = await db_js_1.default.query("SELECT features, expires_at, updated_at FROM entitlements WHERE account_id = $1", [parsed.data]);
        const q = await db_js_1.default.query("SELECT used_bytes, updated_at FROM quotas WHERE account_id = $1", [parsed.data]);
        const files = await db_js_1.default.query("SELECT sha256, size_bytes, mime, created_at FROM cloud_files WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100", [parsed.data]);
        const pointers = await db_js_1.default.query("SELECT name, sha256, updated_at FROM cloud_pointers WHERE account_id = $1", [parsed.data]);
        res.json({
            user: u.rows[0],
            entitlement: e.rows[0] ?? null,
            quota: q.rows[0] ?? null,
            trialGrant: (0, trial_js_1.trialGrantFor)(parsed.data),
            files: files.rows,
            pointers: pointers.rows,
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_user_detail_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "User detail failed.", req));
    }
});
// ---------- Grant ----------
router.post("/v1/admin/grant", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema, features: featuresSchema, days: zod_1.z.number().int().min(1).max(3650).default(30) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid grant payload.", req));
        return;
    }
    const { accountId, features, days } = parsed.data;
    try {
        const u = await db_js_1.default.query("SELECT 1 FROM users WHERE account_id = $1", [accountId]);
        if (u.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Account not found.", req));
            return;
        }
        await db_js_1.default.query(`INSERT INTO entitlements(account_id, features, expires_at, updated_at)
       VALUES ($1, $2, now() + ($3 || ' days')::interval, now())
       ON CONFLICT (account_id) DO UPDATE SET features = EXCLUDED.features, expires_at = EXCLUDED.expires_at, updated_at = now()`, [accountId, features, String(days)]);
        console.log(JSON.stringify({ level: "info", msg: "admin_grant", accountId, features, days }));
        await audit("grant", accountId, req, { features, days });
        res.json({ ok: true, accountId, features, days });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_grant_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Grant failed.", req));
    }
});
// ---------- Revoke ----------
router.post("/v1/admin/revoke", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid revoke payload.", req));
        return;
    }
    try {
        await db_js_1.default.query("DELETE FROM entitlements WHERE account_id = $1", [parsed.data.accountId]);
        console.log(JSON.stringify({ level: "info", msg: "admin_revoke", accountId: parsed.data.accountId }));
        await audit("revoke", parsed.data.accountId, req);
        res.json({ ok: true, accountId: parsed.data.accountId });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_revoke_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Revoke failed.", req));
    }
});
// ---------- Trial toggle ----------
router.post("/v1/admin/trial", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema, used: zod_1.z.boolean() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid trial payload.", req));
        return;
    }
    try {
        await db_js_1.default.query("UPDATE users SET trial_used = $2 WHERE account_id = $1", [parsed.data.accountId, parsed.data.used]);
        console.log(JSON.stringify({ level: "info", msg: "admin_trial", accountId: parsed.data.accountId, used: parsed.data.used }));
        await audit("trial", parsed.data.accountId, req, { used: parsed.data.used });
        res.json({ ok: true, accountId: parsed.data.accountId, used: parsed.data.used });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_trial_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Trial update failed.", req));
    }
});
// ---------- Delete account (admin) ----------
router.delete("/v1/admin/account", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema });
    const fromQuery = schema.safeParse(req.query);
    const fromBody = schema.safeParse(req.body);
    const accountId = fromQuery.success ? fromQuery.data.accountId : fromBody.success ? fromBody.data.accountId : null;
    if (!accountId) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId.", req));
        return;
    }
    try {
        const files = await db_js_1.default.query("SELECT sha256 FROM cloud_files WHERE account_id = $1", [accountId]);
        await db_js_1.default.query("DELETE FROM users WHERE account_id = $1", [accountId]);
        const { FilesystemBackend } = await import("./storage.js");
        const store = new FilesystemBackend();
        for (const row of files.rows) {
            await store.remove(accountId, row.sha256).catch(() => undefined);
        }
        const { rm } = await import("node:fs/promises");
        const { sha256Hex: _h, BLOBS_DIR: _b } = await import("./storage.js");
        await rm(node_path_1.default.join(_b, ".chunks", _h(accountId)), { recursive: true, force: true }).catch(() => undefined);
        console.log(JSON.stringify({ level: "info", msg: "admin_delete_account", accountId }));
        await audit("delete_account", accountId, req);
        res.json({ ok: true, accountId });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_delete_account_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Delete failed.", req));
    }
});
// ---------- Reconcile quota (admin) ----------
router.post("/v1/admin/reconcile", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema });
    const parsed = schema.safeParse(req.body ?? req.query);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId.", req));
        return;
    }
    try {
        const r = await db_js_1.default.query(`UPDATE quotas q SET used_bytes = COALESCE(s.sum, 0), updated_at = now()
       FROM (SELECT COALESCE(SUM(size_bytes), 0)::bigint AS sum FROM cloud_files WHERE account_id = $1) s
       WHERE q.account_id = $1 RETURNING q.used_bytes`, [parsed.data.accountId]);
        if ((r.rowCount ?? 0) === 0) {
            await db_js_1.default.query("INSERT INTO quotas(account_id, used_bytes) VALUES ($1, 0) ON CONFLICT DO NOTHING", [parsed.data.accountId]);
            await audit("reconcile", parsed.data.accountId, req, { usedBytes: 0 });
            res.json({ ok: true, usedBytes: 0 });
            return;
        }
        await audit("reconcile", parsed.data.accountId, req, { usedBytes: Number(r.rows[0].used_bytes) });
        res.json({ ok: true, usedBytes: Number(r.rows[0].used_bytes) });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_reconcile_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Reconcile failed.", req));
    }
});
// ---------- Health ----------
router.get("/v1/admin/health", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const started = process.uptime();
    try {
        const db = await db_js_1.default.query("SELECT 1, version() AS v");
        const counts = await db_js_1.default.query("SELECT (SELECT count(*) FROM users)::int AS users, (SELECT count(*) FROM cloud_files)::int AS files, (SELECT COALESCE(SUM(used_bytes),0) FROM quotas)::bigint AS used, (SELECT count(*) FROM purchases)::int AS purchases, (SELECT count(*) FROM plans)::int AS plans");
        let diskFree = 0, diskTotal = 0, blobsExists = false;
        try {
            const st = (0, node_fs_1.statfsSync)(storage_js_1.BLOBS_DIR);
            diskFree = st.bavail * st.bsize;
            diskTotal = st.blocks * st.bsize;
            blobsExists = true;
        }
        catch { }
        const { existsSync } = await import("node:fs");
        res.json({
            ok: true,
            db: db.rowCount === 1 ? "up" : "down",
            dbVersion: String(db.rows[0].v).split(" ").slice(0, 2).join(" "),
            uptimeSeconds: Math.floor(started),
            nodeVersion: process.version,
            pid: process.pid,
            users: counts.rows[0].users,
            cloudFiles: counts.rows[0].files,
            purchases: counts.rows[0].purchases,
            plans: counts.rows[0].plans,
            usedBytes: Number(counts.rows[0].used),
            diskFreeBytes: diskFree,
            diskTotalBytes: diskTotal,
            blobsDir: storage_js_1.BLOBS_DIR,
            blobsDirExists: blobsExists,
            memoryRss: process.memoryUsage().rss,
            memoryHeapUsed: process.memoryUsage().heapUsed,
            config: {
                firebaseConfigured: Boolean(process.env.FIREBASE_PROJECT_ID),
                testMode: process.env.TEST_MODE === "true",
                adminEnabled: Boolean((process.env.ADMIN_TOKEN ?? "").trim()),
                trialConfigured: Boolean((process.env.TRIAL_ACCOUNT_ID ?? "").trim()),
            },
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_health_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Health check failed.", req));
    }
});
// ---------- Cloud files list (admin) ----------
router.get("/v1/admin/cloud/files", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const accountId = typeof req.query.accountId === "string" ? req.query.accountId : null;
    if (!accountId || !accountIdSchema.safeParse(accountId).success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId.", req));
        return;
    }
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const r = await db_js_1.default.query("SELECT sha256, size_bytes, mime, created_at FROM cloud_files WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", [accountId, limit, offset]);
        const c = await db_js_1.default.query("SELECT count(*)::int AS n FROM cloud_files WHERE account_id = $1", [accountId]);
        res.json({ total: c.rows[0].n, limit, offset, files: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_cloud_files_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Cloud files list failed.", req));
    }
});
// ---------- Admin delete a cloud blob ----------
router.delete("/v1/admin/cloud/blob", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const accountId = typeof req.query.accountId === "string" ? req.query.accountId : req.body?.accountId;
    const sha = typeof req.query.sha === "string" ? req.query.sha : req.body?.sha;
    if (!accountId || !accountIdSchema.safeParse(accountId).success || !sha || !shaSchema.safeParse(sha).success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId or sha.", req));
        return;
    }
    try {
        const client = await db_js_1.default.connect();
        try {
            await client.query("BEGIN");
            const d = await client.query("DELETE FROM cloud_files WHERE account_id = $1 AND sha256 = $2 RETURNING size_bytes", [accountId, sha]);
            if ((d.rowCount ?? 0) === 0) {
                await client.query("ROLLBACK");
                res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Blob not found.", req));
                return;
            }
            const freed = Number(d.rows[0].size_bytes);
            await client.query("UPDATE quotas SET used_bytes = GREATEST(0, used_bytes - $2), updated_at = now() WHERE account_id = $1", [accountId, freed]);
            await client.query("COMMIT");
            const { FilesystemBackend } = await import("./storage.js");
            await new FilesystemBackend().remove(accountId, sha).catch(() => undefined);
            await audit("delete_blob", accountId, req, { sha, freed });
            res.json({ ok: true, freedBytes: freed });
        }
        catch (err) {
            await client.query("ROLLBACK").catch(() => undefined);
            throw err;
        }
        finally {
            client.release();
        }
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_delete_blob_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Delete failed.", req));
    }
});
// ---------- Audit log ----------
router.get("/v1/admin/audit", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const r = await db_js_1.default.query("SELECT id, action, account_id, actor_ip, detail, created_at FROM admin_audit ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
        const c = await db_js_1.default.query("SELECT count(*)::int AS n FROM admin_audit");
        res.json({ total: c.rows[0].n, limit, offset, entries: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_audit_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Audit list failed.", req));
    }
});
// ---------- Export users CSV ----------
router.get("/v1/admin/export/users", async (req, res) => {
    // Require token via Authorization header only (never via URL query param).
    const h = req.headers.authorization;
    if (!h || !h.startsWith("Bearer ")) {
        res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Authorization header required.", req));
        return;
    }
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query(`SELECT u.account_id, u.google_sub, u.trial_used, u.created_at,
              e.features, e.expires_at, q.used_bytes
       FROM users u
       LEFT JOIN entitlements e ON e.account_id = u.account_id
       LEFT JOIN quotas q ON q.account_id = u.account_id
       ORDER BY u.created_at DESC`);
        const header = "account_id,google_sub,trial_used,created_at,features,expires_at,used_bytes";
        const lines = [header].concat(r.rows.map((row) => [
            row.account_id,
            row.google_sub ?? "",
            row.trial_used,
            row.created_at,
            (row.features ?? []).join(";"),
            row.expires_at ?? "",
            row.used_bytes ?? 0,
        ]
            .map((v) => `"${String(v).replace(/"/g, '""')}"`)
            .join(",")));
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", "attachment; filename=nota-users.csv");
        res.send(lines.join("\n"));
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_export_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Export failed.", req));
    }
});
// ---------- Billing overview ----------
router.get("/v1/admin/billing/overview", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const counts = await db_js_1.default.query(`SELECT
         count(*)::int AS total,
         count(*) FILTER (WHERE status='verified')::int AS verified,
         count(*) FILTER (WHERE status='pending')::int AS pending,
         count(*) FILTER (WHERE status='refunded')::int AS refunded,
         count(*) FILTER (WHERE status='canceled')::int AS canceled,
         count(*) FILTER (WHERE status='expired')::int AS expired,
         count(*) FILTER (WHERE is_subscription AND status='verified')::int AS active_subs
       FROM purchases`);
        const byProduct = await db_js_1.default.query("SELECT product_id, count(*)::int AS n, count(*) FILTER (WHERE status='verified')::int AS verified FROM purchases GROUP BY product_id ORDER BY n DESC");
        const rtdn = await db_js_1.default.query("SELECT count(*)::int AS n FROM rtdn_events");
        const recentRtdn = await db_js_1.default.query("SELECT event_type, count(*)::int AS n FROM rtdn_events GROUP BY event_type ORDER BY n DESC");
        res.json({
            counts: counts.rows[0],
            byProduct: byProduct.rows,
            rtdnTotal: rtdn.rows[0].n,
            rtdnByType: recentRtdn.rows,
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_billing_overview_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Billing overview failed.", req));
    }
});
// ---------- Billing purchases list ----------
router.get("/v1/admin/billing/purchases", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const status = typeof req.query.status === "string" ? req.query.status : null;
    const product = typeof req.query.product === "string" ? req.query.product : null;
    const accountId = typeof req.query.accountId === "string" ? req.query.accountId : null;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const where = [];
        const params = [];
        let i = 1;
        if (status) {
            where.push(`status = $${i++}`);
            params.push(status);
        }
        if (product) {
            where.push(`product_id = $${i++}`);
            params.push(product);
        }
        if (accountId) {
            where.push(`account_id = $${i++}`);
            params.push(accountId);
        }
        const wsql = where.length ? "WHERE " + where.join(" AND ") : "";
        const c = await db_js_1.default.query(`SELECT count(*)::int AS n FROM purchases ${wsql}`, params);
        params.push(limit, offset);
        const r = await db_js_1.default.query(`SELECT id, account_id, product_id, purchase_token, status, is_subscription, expires_at, verified_at, created_at
       FROM purchases ${wsql} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
        res.json({ total: c.rows[0].n, limit, offset, purchases: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_billing_purchases_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Billing purchases list failed.", req));
    }
});
// ---------- Verify a purchase (admin) ----------
router.post("/v1/admin/purchases/verify", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({
        purchaseToken: zod_1.z.string().min(1),
        features: featuresSchema.optional(),
        days: zod_1.z.number().int().min(1).max(3650).default(30),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid verify payload.", req));
        return;
    }
    try {
        const p = await db_js_1.default.query("SELECT account_id, product_id FROM purchases WHERE purchase_token = $1", [parsed.data.purchaseToken]);
        if (p.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Purchase not found.", req));
            return;
        }
        const accountId = p.rows[0].account_id;
        const planR = await db_js_1.default.query("SELECT price_cents FROM plans WHERE code = (SELECT product_id FROM purchases WHERE purchase_token = $1)", [parsed.data.purchaseToken]);
        const amountCents = planR.rows[0] ? Number(planR.rows[0].price_cents) : 0;
        await db_js_1.default.query("UPDATE purchases SET status = 'verified', verified_at = now(), updated_at = now(), amount_cents = $2 WHERE purchase_token = $1", [parsed.data.purchaseToken, amountCents]);
        // Grant entitlement if features provided.
        if (parsed.data.features && parsed.data.features.length > 0) {
            await db_js_1.default.query(`INSERT INTO entitlements (account_id, features, expires_at, updated_at)
         VALUES ($1, $2, now() + ($3 || ' days')::interval, now())
         ON CONFLICT (account_id) DO UPDATE SET features = EXCLUDED.features, expires_at = EXCLUDED.expires_at, updated_at = now()`, [accountId, parsed.data.features, String(parsed.data.days)]);
        }
        await audit("verify_purchase", accountId, req, { token: parsed.data.purchaseToken, features: parsed.data.features });
        res.json({ ok: true, accountId, status: "verified" });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_verify_purchase_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Verify failed.", req));
    }
});
// ---------- Refund a purchase (admin) ----------
router.post("/v1/admin/purchases/refund", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ purchaseToken: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid refund payload.", req));
        return;
    }
    try {
        const p = await db_js_1.default.query("SELECT account_id FROM purchases WHERE purchase_token = $1", [parsed.data.purchaseToken]);
        if (p.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Purchase not found.", req));
            return;
        }
        const accountId = p.rows[0].account_id;
        await db_js_1.default.query("UPDATE purchases SET status = 'refunded', updated_at = now() WHERE purchase_token = $1", [parsed.data.purchaseToken]);
        await db_js_1.default.query("DELETE FROM entitlements WHERE account_id = $1", [accountId]);
        await audit("refund_purchase", accountId, req, { token: parsed.data.purchaseToken });
        res.json({ ok: true, accountId, status: "refunded" });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_refund_purchase_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Refund failed.", req));
    }
});
// ---------- RTDN events list ----------
router.get("/v1/admin/rtdn/events", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const r = await db_js_1.default.query("SELECT id, event_type, account_id, purchase_token, processed, created_at FROM rtdn_events ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
        const c = await db_js_1.default.query("SELECT count(*)::int AS n FROM rtdn_events");
        res.json({ total: c.rows[0].n, limit, offset, events: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_rtdn_events_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "RTDN events list failed.", req));
    }
});
// ---------- Plans: list all (admin) ----------
router.get("/v1/admin/plans", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query("SELECT * FROM plans ORDER BY sort_order ASC, name ASC");
        res.json({ plans: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_plans_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plans list failed.", req));
    }
});
// ---------- Plans: create ----------
router.post("/v1/admin/plans", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({
        code: zod_1.z.string().min(1).max(64).regex(/^[a-z0-9_]+$/),
        name: zod_1.z.string().min(1).max(128),
        type: zod_1.z.enum(["subscription", "storage", "feature", "trial"]),
        description: zod_1.z.string().max(512).optional(),
        priceCents: zod_1.z.number().int().min(0).max(1000000).default(0),
        currency: zod_1.z.string().length(3).default("USD"),
        billingPeriod: zod_1.z.enum(["monthly", "yearly", "lifetime", "one_time"]).optional(),
        features: zod_1.z.array(zod_1.z.string().min(1).max(64)).max(64).default([]),
        quotaBytes: zod_1.z.number().int().min(0).max(10 * 1024 * 1024 * 1024 * 1024).default(0),
        active: zod_1.z.boolean().default(true),
        sortOrder: zod_1.z.number().int().min(0).max(100000).default(0),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid plan payload.", req));
        return;
    }
    const d = parsed.data;
    try {
        const r = await db_js_1.default.query(`INSERT INTO plans (code, name, type, description, price_cents, currency, billing_period, features, quota_bytes, active, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`, [d.code, d.name, d.type, d.description ?? null, d.priceCents, d.currency, d.billingPeriod ?? null, d.features, d.quotaBytes, d.active, d.sortOrder]);
        await audit("create_plan", null, req, { code: d.code });
        res.status(201).json({ plan: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_create_plan_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plan create failed.", req));
    }
});
// ---------- Plans: update ----------
router.put("/v1/admin/plans/:code", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const codeParsed = zod_1.z.string().min(1).max(64).regex(/^[a-z0-9_]+$/).safeParse(req.params.code);
    if (!codeParsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid plan code.", req));
        return;
    }
    const schema = zod_1.z.strictObject({
        name: zod_1.z.string().min(1).max(128).optional(),
        type: zod_1.z.enum(["subscription", "storage", "feature", "trial"]).optional(),
        description: zod_1.z.string().max(512).optional(),
        priceCents: zod_1.z.number().int().min(0).max(1000000).optional(),
        currency: zod_1.z.string().length(3).optional(),
        billingPeriod: zod_1.z.enum(["monthly", "yearly", "lifetime", "one_time"]).nullable().optional(),
        features: zod_1.z.array(zod_1.z.string().min(1).max(64)).max(64).optional(),
        quotaBytes: zod_1.z.number().int().min(0).max(10 * 1024 * 1024 * 1024 * 1024).optional(),
        active: zod_1.z.boolean().optional(),
        sortOrder: zod_1.z.number().int().min(0).max(100000).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid plan payload.", req));
        return;
    }
    const d = parsed.data;
    const fields = [];
    const vals = [];
    let i = 1;
    const set = (col, val) => { fields.push(`${col} = $${i++}`); vals.push(val); };
    if (d.name !== undefined)
        set("name", d.name);
    if (d.type !== undefined)
        set("type", d.type);
    if (d.description !== undefined)
        set("description", d.description);
    if (d.priceCents !== undefined)
        set("price_cents", d.priceCents);
    if (d.currency !== undefined)
        set("currency", d.currency);
    if (d.billingPeriod !== undefined)
        set("billing_period", d.billingPeriod);
    if (d.features !== undefined)
        set("features", d.features);
    if (d.quotaBytes !== undefined)
        set("quota_bytes", d.quotaBytes);
    if (d.active !== undefined)
        set("active", d.active);
    if (d.sortOrder !== undefined)
        set("sort_order", d.sortOrder);
    if (fields.length === 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "No fields to update.", req));
        return;
    }
    fields.push("updated_at = now()");
    vals.push(codeParsed.data);
    try {
        const r = await db_js_1.default.query(`UPDATE plans SET ${fields.join(", ")} WHERE code = $${i} RETURNING *`, vals);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Plan not found.", req));
            return;
        }
        await audit("update_plan", null, req, { code: codeParsed.data, fields: Object.keys(d) });
        res.json({ plan: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_update_plan_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plan update failed.", req));
    }
});
// ---------- Plans: delete (deactivate) ----------
router.delete("/v1/admin/plans/:code", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const codeParsed = zod_1.z.string().min(1).max(64).regex(/^[a-z0-9_]+$/).safeParse(req.params.code);
    if (!codeParsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid plan code.", req));
        return;
    }
    try {
        const r = await db_js_1.default.query("UPDATE plans SET active = FALSE, updated_at = now() WHERE code = $1 RETURNING code", [codeParsed.data]);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Plan not found.", req));
            return;
        }
        await audit("deactivate_plan", null, req, { code: codeParsed.data });
        res.json({ ok: true, code: codeParsed.data });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_delete_plan_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plan delete failed.", req));
    }
});
// ---------- Users summary (free vs paid) ----------
router.get("/v1/admin/users-summary", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query(`SELECT
         count(*)::int AS total,
         count(*) FILTER (WHERE e.features IS NOT NULL AND array_length(e.features,1) > 0 AND (e.expires_at IS NULL OR e.expires_at > now()))::int AS paid,
         count(*) FILTER (WHERE NOT (e.features IS NOT NULL AND array_length(e.features,1) > 0 AND (e.expires_at IS NULL OR e.expires_at > now())))::int AS free,
         count(*) FILTER (WHERE u.trial_used = TRUE)::int AS trial_used,
         count(*) FILTER (WHERE u.created_at > now() - interval '30 days')::int AS new_users,
         count(*) FILTER (WHERE u.last_seen_at IS NOT NULL AND u.last_seen_at > now() - interval '30 days')::int AS active_users,
         count(*) FILTER (WHERE (u.last_seen_at IS NULL OR u.last_seen_at <= now() - interval '30 days') AND u.created_at <= now() - interval '30 days')::int AS inactive_users,
         count(*) FILTER (WHERE u.last_seen_at IS NULL)::int AS never_seen
       FROM users u
       LEFT JOIN entitlements e ON e.account_id = u.account_id`);
        res.json(r.rows[0]);
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_users_summary_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Users summary failed.", req));
    }
});
// ---------- Storage overview ----------
router.get("/v1/admin/storage/overview", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const totals = await db_js_1.default.query(`SELECT
         (SELECT COALESCE(SUM(used_bytes),0) FROM quotas)::bigint AS used_bytes,
         (SELECT COALESCE(SUM(size_bytes),0) FROM cloud_files)::bigint AS files_bytes,
         (SELECT count(*) FROM cloud_files)::int AS file_count,
         (SELECT count(DISTINCT account_id) FROM cloud_files)::int AS users_with_files`);
        const topUsers = await db_js_1.default.query(`SELECT q.account_id, q.used_bytes, u.trial_used,
              (SELECT count(*) FROM cloud_files c WHERE c.account_id = q.account_id)::int AS file_count
       FROM quotas q JOIN users u ON u.account_id = q.account_id
       ORDER BY q.used_bytes DESC LIMIT 20`);
        const byMime = await db_js_1.default.query("SELECT mime, count(*)::int AS n, COALESCE(SUM(size_bytes),0)::bigint AS bytes FROM cloud_files GROUP BY mime ORDER BY bytes DESC");
        let diskFree = 0, diskTotal = 0;
        try {
            const st = (0, node_fs_1.statfsSync)(storage_js_1.BLOBS_DIR);
            diskFree = st.bavail * st.bsize;
            diskTotal = st.blocks * st.bsize;
        }
        catch { }
        res.json({
            usedBytes: Number(totals.rows[0].used_bytes),
            filesBytes: Number(totals.rows[0].files_bytes),
            fileCount: totals.rows[0].file_count,
            usersWithFiles: totals.rows[0].users_with_files,
            diskFreeBytes: diskFree,
            diskTotalBytes: diskTotal,
            topUsers: topUsers.rows.map((r) => ({
                accountId: r.account_id,
                usedBytes: Number(r.used_bytes),
                fileCount: r.file_count,
                trialUsed: r.trial_used === true,
            })),
            byMime: byMime.rows.map((r) => ({ mime: r.mime, count: r.n, bytes: Number(r.bytes) })),
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_storage_overview_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Storage overview failed.", req));
    }
});
// ---------- Reconcile all users' quotas ----------
router.post("/v1/admin/storage/reconcile-all", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const users = await db_js_1.default.query("SELECT account_id FROM users");
        let reconciled = 0;
        for (const row of users.rows) {
            const accountId = row.account_id;
            await db_js_1.default.query(`INSERT INTO quotas (account_id, used_bytes) VALUES ($1, 0)
         ON CONFLICT (account_id) DO UPDATE SET used_bytes = 0, updated_at = now()`, [accountId]);
            await db_js_1.default.query(`UPDATE quotas q SET used_bytes = COALESCE(s.sum, 0), updated_at = now()
         FROM (SELECT COALESCE(SUM(size_bytes), 0)::bigint AS sum FROM cloud_files WHERE account_id = $1) s
         WHERE q.account_id = $1`, [accountId]);
            reconciled++;
        }
        await audit("reconcile_all", null, req, { reconciled });
        res.json({ ok: true, reconciled });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_reconcile_all_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Reconcile all failed.", req));
    }
});
// ---------- Revenue overview ----------
router.get("/v1/admin/revenue/overview", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const totals = await db_js_1.default.query(`SELECT
         COALESCE(SUM(amount_cents) FILTER (WHERE status='verified'),0)::bigint AS gross_cents,
         COALESCE(SUM(amount_cents) FILTER (WHERE status='refunded'),0)::bigint AS refunded_cents,
         count(*) FILTER (WHERE status='verified')::int AS verified_count,
         count(*) FILTER (WHERE status='refunded')::int AS refunded_count,
         count(*) FILTER (WHERE status='pending')::int AS pending_count,
         count(*) FILTER (WHERE status='verified' AND is_subscription=TRUE)::int AS active_subs
       FROM purchases`);
        const byProduct = await db_js_1.default.query(`SELECT product_id,
              count(*) FILTER (WHERE status='verified')::int AS verified,
              count(*) FILTER (WHERE status='refunded')::int AS refunded,
              COALESCE(SUM(amount_cents) FILTER (WHERE status='verified'),0)::bigint AS revenue_cents,
              COALESCE(SUM(amount_cents) FILTER (WHERE status='refunded'),0)::bigint AS refunded_cents
       FROM purchases GROUP BY product_id ORDER BY revenue_cents DESC`);
        const byDay = await db_js_1.default.query(`SELECT date_trunc('day', verified_at)::date AS day,
              COALESCE(SUM(amount_cents),0)::bigint AS revenue_cents,
              count(*)::int AS n
       FROM purchases WHERE status='verified' AND verified_at IS NOT NULL
         AND verified_at > now() - interval '30 days'
       GROUP BY 1 ORDER BY 1 ASC`);
        const mrr = await db_js_1.default.query(`SELECT COALESCE(SUM(
         CASE WHEN pl.billing_period = 'monthly' THEN pl.price_cents
              WHEN pl.billing_period = 'yearly' THEN pl.price_cents / 12
              ELSE 0 END
       ),0)::bigint AS mrr_cents
       FROM purchases p
       LEFT JOIN plans pl ON pl.code = p.product_id
       WHERE p.status='verified' AND p.is_subscription=TRUE`);
        const t = totals.rows[0];
        res.json({
            grossCents: Number(t.gross_cents),
            refundedCents: Number(t.refunded_cents),
            netCents: Number(t.gross_cents) - Number(t.refunded_cents),
            verifiedCount: t.verified_count,
            refundedCount: t.refunded_count,
            pendingCount: t.pending_count,
            activeSubs: t.active_subs,
            mrrCents: Number(mrr.rows[0].mrr_cents),
            byProduct: byProduct.rows.map((r) => ({
                productId: r.product_id,
                verified: r.verified,
                refunded: r.refunded,
                revenueCents: Number(r.revenue_cents),
                refundedCents: Number(r.refunded_cents),
            })),
            byDay: byDay.rows.map((r) => ({ day: r.day, revenueCents: Number(r.revenue_cents), count: r.n })),
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_revenue_overview_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Revenue overview failed.", req));
    }
});
// ---------- Subscriptions overview ----------
router.get("/v1/admin/subscriptions/overview", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const counts = await db_js_1.default.query(`SELECT
         count(*) FILTER (WHERE is_subscription)::int AS total_subs,
         count(*) FILTER (WHERE is_subscription AND status='verified' AND (expires_at IS NULL OR expires_at > now()))::int AS active,
         count(*) FILTER (WHERE is_subscription AND status='verified' AND expires_at IS NOT NULL AND expires_at <= now())::int AS expired,
         count(*) FILTER (WHERE is_subscription AND status='canceled')::int AS canceled,
         count(*) FILTER (WHERE is_subscription AND status='refunded')::int AS refunded,
         count(*) FILTER (WHERE is_subscription AND status='pending')::int AS pending,
         count(*) FILTER (WHERE NOT is_subscription)::int AS iap_total,
         count(*) FILTER (WHERE NOT is_subscription AND status='verified')::int AS iap_verified
       FROM purchases`);
        const expiring = await db_js_1.default.query(`SELECT account_id, product_id, purchase_token, expires_at
       FROM purchases
       WHERE is_subscription=TRUE AND status='verified' AND expires_at IS NOT NULL
         AND expires_at > now() AND expires_at <= now() + interval '7 days'
       ORDER BY expires_at ASC LIMIT 20`);
        const byProduct = await db_js_1.default.query(`SELECT product_id,
              count(*) FILTER (WHERE status='verified' AND (expires_at IS NULL OR expires_at > now()))::int AS active,
              count(*)::int AS total
       FROM purchases WHERE is_subscription=TRUE GROUP BY product_id ORDER BY active DESC`);
        const c = counts.rows[0];
        res.json({
            totalSubs: c.total_subs,
            active: c.active,
            expired: c.expired,
            canceled: c.canceled,
            refunded: c.refunded,
            pending: c.pending,
            iapTotal: c.iap_total,
            iapVerified: c.iap_verified,
            expiringSoon: expiring.rows,
            byProduct: byProduct.rows,
        });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_subscriptions_overview_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Subscriptions overview failed.", req));
    }
});
// ---------- Subscriptions list ----------
router.get("/v1/admin/subscriptions/list", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const status = typeof req.query.status === "string" ? req.query.status : null;
    const kind = typeof req.query.kind === "string" ? req.query.kind : "all"; // all | subscription | iap
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const where = [];
        const params = [];
        let i = 1;
        if (kind === "subscription") {
            where.push("is_subscription = TRUE");
        }
        if (kind === "iap") {
            where.push("is_subscription = FALSE");
        }
        if (status) {
            where.push(`status = $${i++}`);
            params.push(status);
        }
        const wsql = where.length ? "WHERE " + where.join(" AND ") : "";
        const c = await db_js_1.default.query(`SELECT count(*)::int AS n FROM purchases ${wsql}`, params);
        params.push(limit, offset);
        const r = await db_js_1.default.query(`SELECT id, account_id, product_id, status, is_subscription, expires_at, verified_at, created_at
       FROM purchases ${wsql} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
        res.json({ total: c.rows[0].n, limit, offset, subscriptions: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_subscriptions_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Subscriptions list failed.", req));
    }
});
// ---------- Play Console: status ----------
router.get("/v1/admin/play/status", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    res.json({
        configured: play.isConfigured(),
        packageName: play.packageName(),
        serviceAccount: play.loadServiceAccount() ? play.loadServiceAccount().client_email : null,
    });
});
// ---------- Play Console: fetch reviews ----------
router.get("/v1/admin/play/reviews", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    if (!play.isConfigured()) {
        res.status(503).json((0, middleware_js_1.errorBody)("PLAY_NOT_CONFIGURED", "Configure PLAY_PACKAGE_NAME and PLAY_SERVICE_ACCOUNT.", req));
        return;
    }
    try {
        const max = Math.min(Math.max(Number(req.query.maxResults ?? 50), 1), 100);
        const data = await play.fetchReviews(max);
        res.json(data);
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "play_reviews_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", String(err), req));
    }
});
// ---------- Play Console: verify subscription token ----------
router.post("/v1/admin/play/verify-subscription", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ subscriptionId: zod_1.z.string().min(1), purchaseToken: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    if (!play.isConfigured()) {
        res.status(503).json((0, middleware_js_1.errorBody)("PLAY_NOT_CONFIGURED", "Configure PLAY_PACKAGE_NAME and PLAY_SERVICE_ACCOUNT.", req));
        return;
    }
    try {
        const data = await play.verifySubscription(parsed.data.subscriptionId, parsed.data.purchaseToken);
        res.json(data);
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "play_verify_sub_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", String(err), req));
    }
});
// ---------- Play Console: verify product token ----------
router.post("/v1/admin/play/verify-product", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ productId: zod_1.z.string().min(1), purchaseToken: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    if (!play.isConfigured()) {
        res.status(503).json((0, middleware_js_1.errorBody)("PLAY_NOT_CONFIGURED", "Configure PLAY_PACKAGE_NAME and PLAY_SERVICE_ACCOUNT.", req));
        return;
    }
    try {
        const data = await play.verifyProduct(parsed.data.productId, parsed.data.purchaseToken);
        res.json(data);
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "play_verify_product_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", String(err), req));
    }
});
// ---------- Ban / unban user ----------
router.post("/v1/admin/users/ban", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema, banned: zod_1.z.boolean(), reason: zod_1.z.string().max(256).optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        await db_js_1.default.query("UPDATE users SET banned = $2, banned_reason = $3, banned_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE account_id = $1", [parsed.data.accountId, parsed.data.banned, parsed.data.reason ?? null]);
        await audit(parsed.data.banned ? "ban_user" : "unban_user", parsed.data.accountId, req, { reason: parsed.data.reason });
        res.json({ ok: true, accountId: parsed.data.accountId, banned: parsed.data.banned });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_ban_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Ban update failed.", req));
    }
});
// ---------- Remote config CRUD ----------
router.get("/v1/admin/config", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query("SELECT key, value, description, updated_at FROM remote_config ORDER BY key ASC");
        res.json({ config: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_config_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Config list failed.", req));
    }
});
router.put("/v1/admin/config", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ key: zod_1.z.string().min(1).max(128).regex(/^[a-z0-9_.-]+$/), value: zod_1.z.string().max(4096), description: zod_1.z.string().max(512).optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        await db_js_1.default.query(`INSERT INTO remote_config (key, value, description) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, description = COALESCE(EXCLUDED.description, remote_config.description), updated_at = now()`, [parsed.data.key, parsed.data.value, parsed.data.description ?? null]);
        await audit("set_config", null, req, { key: parsed.data.key });
        res.json({ ok: true, key: parsed.data.key });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_config_set_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Config set failed.", req));
    }
});
router.delete("/v1/admin/config/:key", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        await db_js_1.default.query("DELETE FROM remote_config WHERE key = $1", [req.params.key]);
        await audit("delete_config", null, req, { key: req.params.key });
        res.json({ ok: true });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_config_delete_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Config delete failed.", req));
    }
});
// ---------- Announcements CRUD ----------
router.get("/v1/admin/announcements", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query("SELECT * FROM announcements ORDER BY created_at DESC");
        res.json({ announcements: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_announcements_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Announcements list failed.", req));
    }
});
router.post("/v1/admin/announcements", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({
        title: zod_1.z.string().min(1).max(128),
        body: zod_1.z.string().min(1).max(2000),
        type: zod_1.z.enum(["info", "warning", "critical"]).default("info"),
        active: zod_1.z.boolean().default(true),
        startsAt: zod_1.z.string().datetime().optional(),
        endsAt: zod_1.z.string().datetime().optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    const d = parsed.data;
    try {
        const r = await db_js_1.default.query(`INSERT INTO announcements (title, body, type, active, starts_at, ends_at)
       VALUES ($1,$2,$3,$4, COALESCE($5, now()), $6) RETURNING *`, [d.title, d.body, d.type, d.active, d.startsAt ?? null, d.endsAt ?? null]);
        await audit("create_announcement", null, req, { title: d.title });
        res.status(201).json({ announcement: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_announcement_create_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Announcement create failed.", req));
    }
});
router.put("/v1/admin/announcements/:id", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    const schema = zod_1.z.strictObject({
        title: zod_1.z.string().min(1).max(128).optional(),
        body: zod_1.z.string().min(1).max(2000).optional(),
        type: zod_1.z.enum(["info", "warning", "critical"]).optional(),
        active: zod_1.z.boolean().optional(),
        endsAt: zod_1.z.string().datetime().nullable().optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    const d = parsed.data;
    const fields = [];
    const vals = [];
    let i = 1;
    const set = (col, val) => { fields.push(`${col} = $${i++}`); vals.push(val); };
    if (d.title !== undefined)
        set("title", d.title);
    if (d.body !== undefined)
        set("body", d.body);
    if (d.type !== undefined)
        set("type", d.type);
    if (d.active !== undefined)
        set("active", d.active);
    if (d.endsAt !== undefined)
        set("ends_at", d.endsAt);
    if (fields.length === 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "No fields.", req));
        return;
    }
    vals.push(id);
    try {
        const r = await db_js_1.default.query(`UPDATE announcements SET ${fields.join(", ")} WHERE id = $${i} RETURNING *`, vals);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Announcement not found.", req));
            return;
        }
        await audit("update_announcement", null, req, { id });
        res.json({ announcement: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_announcement_update_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Announcement update failed.", req));
    }
});
router.delete("/v1/admin/announcements/:id", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    try {
        await db_js_1.default.query("DELETE FROM announcements WHERE id = $1", [id]);
        await audit("delete_announcement", null, req, { id });
        res.json({ ok: true });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_announcement_delete_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Announcement delete failed.", req));
    }
});
// ---------- Create user manually ----------
router.post("/v1/admin/users/create", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ accountId: accountIdSchema, googleSub: zod_1.z.string().max(256).optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        await db_js_1.default.query("INSERT INTO users (account_id, google_sub) VALUES ($1, $2) ON CONFLICT (account_id) DO NOTHING", [parsed.data.accountId, parsed.data.googleSub ?? null]);
        await audit("create_user", parsed.data.accountId, req);
        res.status(201).json({ ok: true, accountId: parsed.data.accountId });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_create_user_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "User create failed.", req));
    }
});
// ---------- Notifications admin ----------
router.get("/v1/admin/notifications", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const r = await db_js_1.default.query("SELECT id, account_id, title, body, type, read, created_at FROM notifications ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
        const c = await db_js_1.default.query("SELECT count(*)::int AS n FROM notifications");
        res.json({ total: c.rows[0].n, limit, offset, notifications: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_notifications_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Notifications list failed.", req));
    }
});
router.post("/v1/admin/notifications", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({
        accountId: zod_1.z.union([accountIdSchema, zod_1.z.literal("*")]),
        title: zod_1.z.string().min(1).max(128),
        body: zod_1.z.string().min(1).max(2000),
        type: zod_1.z.enum(["info", "warning", "critical", "promo"]).default("info"),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    const d = parsed.data;
    try {
        if (d.accountId === "*") {
            const users = await db_js_1.default.query("SELECT account_id FROM users");
            for (const u of users.rows) {
                await db_js_1.default.query("INSERT INTO notifications (account_id, title, body, type) VALUES ($1,$2,$3,$4)", [u.account_id, d.title, d.body, d.type]);
            }
            await audit("broadcast_notification", null, req, { title: d.title, count: users.rowCount });
            res.status(201).json({ ok: true, count: users.rowCount });
        }
        else {
            await db_js_1.default.query("INSERT INTO notifications (account_id, title, body, type) VALUES ($1,$2,$3,$4)", [d.accountId, d.title, d.body, d.type]);
            await audit("send_notification", d.accountId, req, { title: d.title });
            res.status(201).json({ ok: true, count: 1 });
        }
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_notification_create_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Notification create failed.", req));
    }
});
router.delete("/v1/admin/notifications/:id", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    try {
        await db_js_1.default.query("DELETE FROM notifications WHERE id = $1", [id]);
        res.json({ ok: true });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_notification_delete_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Notification delete failed.", req));
    }
});
// ---------- Data deletion requests ----------
router.get("/v1/admin/deletion-requests", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const status = typeof req.query.status === "string" ? req.query.status : null;
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    try {
        const where = status ? "WHERE status = $1" : "";
        const params = status ? [status] : [];
        const c = await db_js_1.default.query(`SELECT count(*)::int AS n FROM data_deletion_requests ${where}`, params);
        params.push(limit, offset);
        const r = await db_js_1.default.query(`SELECT * FROM data_deletion_requests ${where} ORDER BY requested_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
        res.json({ total: c.rows[0].n, limit, offset, requests: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_deletion_requests_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Deletion requests list failed.", req));
    }
});
router.post("/v1/admin/deletion-requests/:id/process", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    const schema = zod_1.z.strictObject({ status: zod_1.z.enum(["processing", "completed", "rejected"]), notes: zod_1.z.string().max(512).optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        const r = await db_js_1.default.query("SELECT account_id FROM data_deletion_requests WHERE id = $1", [id]);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Request not found.", req));
            return;
        }
        const accountId = r.rows[0].account_id;
        await db_js_1.default.query("UPDATE data_deletion_requests SET status = $2, processed_at = now(), notes = COALESCE($3, notes) WHERE id = $1", [id, parsed.data.status, parsed.data.notes ?? null]);
        // If completed, perform full GDPR deletion.
        if (parsed.data.status === "completed") {
            await (0, gdpr_js_1.deleteAccountData)(accountId);
        }
        await audit("process_deletion_request", accountId, req, { id, status: parsed.data.status });
        res.json({ ok: true, id, status: parsed.data.status });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_deletion_process_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Process failed.", req));
    }
});
// ---------- Reports ----------
router.get("/v1/admin/reports/:type", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const type = req.params.type;
    const from = typeof req.query.from === "string" ? req.query.from : null;
    const to = typeof req.query.to === "string" ? req.query.to : null;
    const fromTs = from ? new Date(from) : new Date(Date.now() - 30 * 86400000);
    const toTs = to ? new Date(to) : new Date();
    if (isNaN(fromTs.getTime()) || isNaN(toTs.getTime())) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid date range.", req));
        return;
    }
    try {
        let data = null;
        if (type === "users") {
            const r = await db_js_1.default.query(`SELECT date_trunc('day', created_at)::date AS day, count(*)::int AS new_users
         FROM users WHERE created_at >= $1 AND created_at <= $2 GROUP BY 1 ORDER BY 1 ASC`, [fromTs, toTs]);
            const totals = await db_js_1.default.query(`SELECT count(*)::int AS total,
                count(*) FILTER (WHERE created_at >= $1 AND created_at <= $2)::int AS new_in_range,
                count(*) FILTER (WHERE last_seen_at >= $1 AND last_seen_at <= $2)::int AS active_in_range
         FROM users`, [fromTs, toTs]);
            data = { totals: totals.rows[0], byDay: r.rows };
        }
        else if (type === "revenue") {
            const r = await db_js_1.default.query(`SELECT date_trunc('day', verified_at)::date AS day,
                COALESCE(SUM(amount_cents),0)::bigint AS revenue_cents, count(*)::int AS n
         FROM purchases WHERE status='verified' AND verified_at >= $1 AND verified_at <= $2
         GROUP BY 1 ORDER BY 1 ASC`, [fromTs, toTs]);
            const totals = await db_js_1.default.query(`SELECT COALESCE(SUM(amount_cents) FILTER (WHERE status='verified'),0)::bigint AS gross_cents,
                COALESCE(SUM(amount_cents) FILTER (WHERE status='refunded'),0)::bigint AS refunded_cents,
                count(*) FILTER (WHERE status='verified')::int AS verified_count,
                count(*) FILTER (WHERE status='refunded')::int AS refunded_count
         FROM purchases WHERE created_at >= $1 AND created_at <= $2`, [fromTs, toTs]);
            data = { totals: totals.rows[0], byDay: r.rows };
        }
        else if (type === "storage") {
            const r = await db_js_1.default.query(`SELECT account_id, used_bytes FROM quotas ORDER BY used_bytes DESC LIMIT 50`);
            const totals = await db_js_1.default.query(`SELECT COALESCE(SUM(used_bytes),0)::bigint AS used_bytes, count(*)::int AS accounts FROM quotas`);
            data = { totals: totals.rows[0], topUsers: r.rows };
        }
        else if (type === "subscriptions") {
            const r = await db_js_1.default.query(`SELECT status, is_subscription, count(*)::int AS n FROM purchases GROUP BY status, is_subscription ORDER BY status`);
            data = { breakdown: r.rows };
        }
        else if (type === "audit") {
            const r = await db_js_1.default.query(`SELECT id, action, account_id, actor_ip, created_at FROM admin_audit
         WHERE created_at >= $1 AND created_at <= $2 ORDER BY created_at DESC LIMIT 500`, [fromTs, toTs]);
            data = { entries: r.rows };
        }
        else {
            res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Unknown report type.", req));
            return;
        }
        res.json({ type, from: fromTs.toISOString(), to: toTs.toISOString(), data });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_report_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Report generation failed.", req));
    }
});
// ---------- Admin auth: login ----------
router.post("/v1/admin/login", async (req, res) => {
    const schema = zod_1.z.strictObject({ username: zod_1.z.string().min(1).max(64), password: zod_1.z.string().min(1).max(256) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    const now = Date.now();
    const attempt = loginAttempts.get(parsed.data.username);
    if (attempt && attempt.lockedUntil > now) {
        res.status(429).json((0, middleware_js_1.errorBody)("RATE_LIMITED", "Too many failed attempts. Try later.", req));
        return;
    }
    try {
        const { verifyPassword, createSession } = await import("./rbac.js");
        const r = await db_js_1.default.query("SELECT id, password_hash, active FROM admin_users WHERE username = $1", [parsed.data.username]);
        if (r.rowCount === 0) {
            const a = loginAttempts.get(parsed.data.username) ?? { count: 0, lockedUntil: 0 };
            a.count += 1;
            if (a.count >= 5)
                a.lockedUntil = Date.now() + 15 * 60 * 1000;
            loginAttempts.set(parsed.data.username, a);
            res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Invalid credentials.", req));
            return;
        }
        const u = r.rows[0];
        if (!u.active) {
            res.status(403).json((0, middleware_js_1.errorBody)("FORBIDDEN", "Account disabled.", req));
            return;
        }
        const ok = await verifyPassword(parsed.data.password, u.password_hash);
        if (!ok) {
            const a = loginAttempts.get(parsed.data.username) ?? { count: 0, lockedUntil: 0 };
            a.count += 1;
            if (a.count >= 5)
                a.lockedUntil = Date.now() + 15 * 60 * 1000;
            loginAttempts.set(parsed.data.username, a);
            res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Invalid credentials.", req));
            return;
        }
        // success: reset counter
        loginAttempts.delete(parsed.data.username);
        const token = await createSession(u.id);
        res.json({ ok: true, token, expiresIn: 8 * 3600 });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_login_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Login failed.", req));
    }
});
router.post("/v1/admin/logout", async (req, res) => {
    const h = req.headers.authorization;
    const provided = h?.startsWith("Bearer ") ? h.slice(7).trim() : null;
    if (provided)
        await db_js_1.default.query("DELETE FROM admin_sessions WHERE token = $1", [provided]).catch(() => undefined);
    res.json({ ok: true });
});
// ---------- Admin users management ----------
router.get("/v1/admin/admin-users", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query("SELECT id, username, role, active, created_at, last_login_at FROM admin_users ORDER BY created_at ASC");
        res.json({ users: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_users_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Admin users list failed.", req));
    }
});
router.post("/v1/admin/admin-users", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const schema = zod_1.z.strictObject({ username: zod_1.z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.-]+$/), password: zod_1.z.string().min(8).max(256), role: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        const { hashPassword } = await import("./rbac.js");
        const hash = await hashPassword(parsed.data.password);
        const r = await db_js_1.default.query("INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, active, created_at", [parsed.data.username, hash, parsed.data.role]);
        await audit("create_admin_user", null, req, { username: parsed.data.username, role: parsed.data.role });
        res.status(201).json({ user: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_user_create_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Admin user create failed.", req));
    }
});
router.put("/v1/admin/admin-users/:id", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    const schema = zod_1.z.strictObject({ role: zod_1.z.string().min(1).optional(), active: zod_1.z.boolean().optional(), password: zod_1.z.string().min(8).max(256).optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid payload.", req));
        return;
    }
    try {
        const fields = [];
        const vals = [];
        let i = 1;
        const set = (col, val) => { fields.push(`${col} = $${i++}`); vals.push(val); };
        if (parsed.data.role !== undefined)
            set("role", parsed.data.role);
        if (parsed.data.active !== undefined)
            set("active", parsed.data.active);
        if (parsed.data.password !== undefined) {
            const { hashPassword } = await import("./rbac.js");
            set("password_hash", await hashPassword(parsed.data.password));
        }
        if (fields.length === 0) {
            res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "No fields.", req));
            return;
        }
        vals.push(id);
        const r = await db_js_1.default.query(`UPDATE admin_users SET ${fields.join(", ")} WHERE id = $${i} RETURNING id, username, role, active`, vals);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Admin user not found.", req));
            return;
        }
        await audit("update_admin_user", null, req, { id });
        res.json({ user: r.rows[0] });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_user_update_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Admin user update failed.", req));
    }
});
router.delete("/v1/admin/admin-users/:id", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid id.", req));
        return;
    }
    try {
        await db_js_1.default.query("DELETE FROM admin_users WHERE id = $1", [id]);
        await audit("delete_admin_user", null, req, { id });
        res.json({ ok: true });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_user_delete_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Admin user delete failed.", req));
    }
});
// ---------- Roles ----------
router.get("/v1/admin/roles", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    try {
        const r = await db_js_1.default.query("SELECT name, permissions, description, created_at FROM admin_roles ORDER BY name ASC");
        res.json({ roles: r.rows });
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "admin_roles_list_error", err: String(err) }));
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Roles list failed.", req));
    }
});
// ---------- Whoami ----------
router.get("/v1/admin/whoami", async (req, res) => {
    if (!(await adminAuth(req, res)))
        return;
    if (req.adminIsSuper) {
        res.json({ username: "superadmin (env token)", role: "superadmin", permissions: ["*"], isSuper: true });
        return;
    }
    res.json({ username: req.adminResolved?.username, role: req.adminResolved?.role, permissions: req.adminResolved?.permissions, isSuper: false });
});
// ---------- Dashboard HTML ----------
router.get("/admin", async (_req, res) => {
    const nonce = (await import("node:crypto")).randomBytes(16).toString("base64");
    // Inject nonce into <style> and <script> tags.
    const html = DASHBOARD_HTML
        .replace(/<style>/g, `<style nonce="${nonce}">`)
        .replace(/<script>/g, `<script nonce="${nonce}">`);
    res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`);
    res.type("html").send(html);
});
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Nota Entitlements — Admin Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e1a;
    --bg-soft: #0f1424;
    --card: #131a2b;
    --card-hover: #1a2338;
    --border: #1f2a44;
    --border-soft: #2a3655;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --accent-soft: rgba(59,130,246,0.12);
    --muted: #94a3b8;
    --muted-soft: #64748b;
    --text: #f1f5f9;
    --text-soft: #cbd5e1;
    --danger: #ef4444;
    --danger-soft: rgba(239,68,68,0.12);
    --ok: #22c55e;
    --ok-soft: rgba(34,197,94,0.12);
    --warn: #f59e0b;
    --warn-soft: rgba(245,158,11,0.12);
    --purple: #a855f7;
    --shadow: 0 4px 24px rgba(0,0,0,0.4);
    --shadow-lg: 0 8px 40px rgba(0,0,0,0.5);
    --radius: 12px;
    --radius-sm: 8px;
    --radius-lg: 16px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
  /* subtle animated background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background:
      radial-gradient(circle at 20% 10%, rgba(59,130,246,0.08) 0%, transparent 40%),
      radial-gradient(circle at 80% 90%, rgba(168,85,247,0.06) 0%, transparent 40%);
    pointer-events: none;
    z-index: 0;
  }
  header {
    position: sticky;
    top: 0;
    z-index: 50;
    padding: 16px 32px;
    background: rgba(10,14,26,0.85);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  header h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 700;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.02em;
  }
  #whoami { color: var(--muted); font-size: 13px; }
  .tokenbar { margin-left: auto; display: flex; gap: 8px; align-items: center; }
  input, button, select, textarea {
    padding: 9px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-soft);
    color: var(--text);
    font-family: inherit;
    font-size: 13px;
    transition: all 0.15s ease;
  }
  input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  input::placeholder { color: var(--muted-soft); }
  button {
    background: var(--accent);
    color: white;
    font-weight: 600;
    cursor: pointer;
    border: none;
    box-shadow: 0 2px 8px rgba(59,130,246,0.25);
  }
  button:hover { background: var(--accent-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.35); }
  button:active { transform: translateY(0); }
  button.danger { background: var(--danger); box-shadow: 0 2px 8px rgba(239,68,68,0.25); }
  button.danger:hover { background: #dc2626; box-shadow: 0 4px 12px rgba(239,68,68,0.35); }
  button.warn { background: var(--warn); color: #0a0e1a; box-shadow: 0 2px 8px rgba(245,158,11,0.25); }
  button.warn:hover { background: #d97706; }
  button.ghost { background: transparent; border: 1px solid var(--border); color: var(--text-soft); box-shadow: none; }
  button.ghost:hover { background: var(--card); border-color: var(--border-soft); color: var(--text); transform: none; }
  main {
    position: relative;
    z-index: 1;
    padding: 28px 32px;
    max-width: 1440px;
    margin: 0 auto;
    display: grid;
    gap: 24px;
  }
  .tabs {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
    padding: 6px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    width: fit-content;
  }
  .tab {
    background: transparent;
    border: none;
    color: var(--muted);
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    font-weight: 500;
    box-shadow: none;
    transition: all 0.15s ease;
  }
  .tab:hover { background: var(--bg-soft); color: var(--text); transform: none; }
  .tab.active { background: var(--accent); color: white; box-shadow: 0 2px 8px rgba(59,130,246,0.3); }
  .panel { display: none; animation: fadeIn 0.2s ease; }
  .panel.active { display: block; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    padding: 18px 20px;
    border-radius: var(--radius);
    transition: all 0.2s ease;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--purple));
    opacity: 0;
    transition: opacity 0.2s ease;
  }
  .card:hover { border-color: var(--border-soft); transform: translateY(-2px); box-shadow: var(--shadow); }
  .card:hover::before { opacity: 1; }
  .card .label {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }
  .card .value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 6px;
    color: var(--text);
    letter-spacing: -0.02em;
  }
  .card .sub { color: var(--muted-soft); font-size: 12px; margin-top: 6px; }
  h2, h3 { font-weight: 700; letter-spacing: -0.01em; }
  h2 { font-size: 22px; margin-bottom: 4px; }
  h3 { font-size: 16px; margin: 20px 0 10px; color: var(--text-soft); }
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  th, td {
    padding: 12px 14px;
    text-align: left;
    font-size: 13px;
    vertical-align: top;
    border-bottom: 1px solid var(--border);
  }
  th {
    background: var(--bg-soft);
    color: var(--muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    position: sticky;
    top: 0;
    z-index: 5;
  }
  tbody tr { transition: background 0.12s ease; }
  tbody tr:hover { background: var(--card-hover); }
  tbody tr:last-child td { border-bottom: none; }
  .rowbtns { display: flex; gap: 6px; flex-wrap: wrap; }
  .small { font-size: 12px; color: var(--muted); word-break: break-all; line-height: 1.4; }
  .modal {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.7);
    backdrop-filter: blur(4px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 20px;
  }
  .modal.open { display: flex; animation: fadeIn 0.15s ease; }
  .modal .box {
    background: var(--card);
    border: 1px solid var(--border);
    padding: 26px;
    border-radius: var(--radius-lg);
    min-width: 360px;
    max-width: 90vw;
    max-height: 90vh;
    overflow: auto;
    display: grid;
    gap: 14px;
    box-shadow: var(--shadow-lg);
  }
  .modal .box h3 { margin: 0 0 4px; font-size: 18px; color: var(--text); }
  .status {
    padding: 10px 16px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 500;
    display: none;
    animation: slideDown 0.2s ease;
  }
  .status.ok { background: var(--ok-soft); color: var(--ok); border: 1px solid rgba(34,197,94,0.3); }
  .status.err { background: var(--danger-soft); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
  @keyframes slideDown { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
  .pager { display: flex; gap: 8px; align-items: center; margin-top: 14px; }
  .detail-grid { display: grid; grid-template-columns: 150px 1fr; gap: 8px 16px; font-size: 13px; }
  .detail-grid .k { color: var(--muted); font-weight: 500; }
  .tag {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 11px;
    font-weight: 500;
    margin: 2px;
    border: 1px solid rgba(59,130,246,0.2);
  }
  .progress { height: 6px; background: var(--bg-soft); border-radius: 3px; overflow: hidden; margin-top: 6px; }
  .progress > div { height: 100%; background: linear-gradient(90deg, var(--accent), var(--purple)); border-radius: 3px; transition: width 0.3s ease; }
  .health-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
  .audit-table td { font-size: 12px; }
  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .empty { text-align: center; padding: 32px; color: var(--muted); font-size: 13px; }
  .empty::before { content: '—'; display: block; font-size: 24px; margin-bottom: 8px; opacity: 0.4; }
  a { color: var(--accent); text-decoration: none; transition: color 0.15s; }
  a:hover { color: var(--accent-hover); text-decoration: underline; }
  pre { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--border-soft); }
  @media (max-width: 768px) {
    header { padding: 12px 16px; }
    main { padding: 16px; }
    .tabs { width: 100%; }
    .tab { flex: 1; min-width: 0; font-size: 12px; padding: 7px 8px; }
    table { font-size: 12px; }
    th, td { padding: 8px 10px; }
  }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo"><div class="icon">N</div><span>Nota Admin</span></div>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-section">
        <div class="nav-section-title">Overview</div>
        <button class="nav-item active" data-tab="overview" data-onclick="switchTab('overview')"><span class="nav-icon">O</span> Dashboard</button>
        <button class="nav-item" data-tab="services" data-onclick="switchTab('health')"><span class="nav-icon">S</span> Services</button>
        <button class="nav-item" data-tab="reports" data-onclick="switchTab('reports')"><span class="nav-icon">R</span> Reports</button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Users</div>
        <button class="nav-item" data-tab="users" data-onclick="switchTab('users')"><span class="nav-icon">U</span> Users</button>
        <button class="nav-item" data-tab="adminusers" data-onclick="switchTab('adminusers')"><span class="nav-icon">A</span> Admin Users</button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Commerce</div>
        <button class="nav-item" data-tab="billing" data-onclick="switchTab('billing')"><span class="nav-icon">B</span> Billing</button>
        <button class="nav-item" data-tab="subscriptions" data-onclick="switchTab('subscriptions')"><span class="nav-icon">V</span> Subscriptions</button>
        <button class="nav-item" data-tab="plans" data-onclick="switchTab('plans')"><span class="nav-icon">P</span> Plans</button>
        <button class="nav-item" data-tab="revenue" data-onclick="switchTab('revenue')"><span class="nav-icon">$</span> Revenue</button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Infrastructure</div>
        <button class="nav-item" data-tab="storage" data-onclick="switchTab('storage')"><span class="nav-icon">D</span> Storage</button>
        <button class="nav-item" data-tab="play" data-onclick="switchTab('play')"><span class="nav-icon">G</span> Play Console</button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Management</div>
        <button class="nav-item" data-tab="control" data-onclick="switchTab('control')"><span class="nav-icon">C</span> Control</button>
        <button class="nav-item" data-tab="notifications" data-onclick="switchTab('notifications')"><span class="nav-icon">N</span> Notifications</button>
        <button class="nav-item" data-tab="deletions" data-onclick="switchTab('deletions')"><span class="nav-icon">X</span> Deletions</button>
        <button class="nav-item" data-tab="audit" data-onclick="switchTab('audit')"><span class="nav-icon">L</span> Audit Log</button>
      </div>
    </nav>
    <div class="sidebar-footer"><div id="whoami">Not logged in</div></div>
  </aside>
  <div class="main">
    <header class="topbar">
      <div><span class="topbar-title" id="pageTitle">Dashboard</span><span class="topbar-subtitle" id="pageSubtitle">Overview & metrics</span></div>
      <div class="topbar-right">
        <div class="tokenbar">
          <input id="token" placeholder="Admin token" type="password" style="width:160px;"/>
          <button class="sm" data-onclick="saveToken()">Save</button>
          <button class="sm ghost" data-onclick="loadAll()">Refresh</button>
        </div>
      </div>
    </header>
    <div class="content"><div class="content-inner">
      <div id="status" class="status"></div>
      <section id="panel-overview" class="panel active">
        <div class="page-header"><h1>Dashboard</h1><p>Overview of your Nota entitlements server</p></div>
        <div class="cards" id="overview"></div>
      </section>
      <section id="panel-users" class="panel">
        <div class="page-header"><h1>Users</h1><p>Manage and segment your user base</p></div>
        <div class="cards" id="usersSummary" style="margin-bottom:20px;"></div>
        <div class="table-toolbar">
          <input id="search" placeholder="Search accountId..."/>
          <select id="userStatus"><option value="all">All users</option><option value="free">Free</option><option value="paid">Paid</option><option value="trial">Trial used</option><option value="new">New (30d)</option><option value="active">Active (30d)</option><option value="inactive">Inactive</option></select>
          <button data-onclick="loadUsers(0)">Search</button>
          <button class="ghost" data-onclick="exportUsers()">Export CSV</button>
          <button data-onclick="createUser()">+ Create user</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>Account</th><th>Plan</th><th>Trial</th><th>Last seen</th><th>Features</th><th>Expires</th><th>Used</th><th>Actions</th></tr></thead><tbody id="users"></tbody></table></div>
        <div class="pager"><button class="ghost sm" data-onclick="prevPage()">Prev</button><span id="pageinfo"></span><button class="ghost sm" data-onclick="nextPage()">Next</button></div>
      </section>
      <section id="panel-cloud" class="panel">
        <div class="page-header"><h1>Cloud Storage</h1><p>Browse and manage user cloud files</p></div>
        <div class="table-toolbar"><input id="cloudAccount" placeholder="accountId"/><button data-onclick="loadCloudFiles()">Load files</button></div>
        <div id="cloudQuota" class="small" style="margin-bottom:12px;"></div>
        <div class="table-wrap"><table><thead><tr><th>SHA256</th><th>Size</th><th>Mime</th><th>Created</th><th>Actions</th></tr></thead><tbody id="cloudFiles"></tbody></table></div>
        <div class="pager"><button class="ghost sm" data-onclick="prevCloud()">Prev</button><span id="cloudPageinfo"></span><button class="ghost sm" data-onclick="nextCloud()">Next</button></div>
      </section>
      <section id="panel-health" class="panel">
        <div class="page-header"><h1>Services</h1><p>System health and configuration status</p></div>
        <div class="health-grid" id="health"></div>
      </section>
      <section id="panel-audit" class="panel">
        <div class="page-header"><h1>Audit Log</h1><p>Administrative action history</p></div>
        <div class="table-wrap"><table class="audit-table"><thead><tr><th>Time</th><th>Action</th><th>Account</th><th>IP</th><th>Detail</th></tr></thead><tbody id="audit"></tbody></table></div>
        <div class="pager"><button class="ghost sm" data-onclick="prevAudit()">Prev</button><span id="auditPageinfo"></span><button class="ghost sm" data-onclick="nextAudit()">Next</button></div>
      </section>
      <section id="panel-billing" class="panel">
        <div class="page-header"><h1>Billing</h1><p>Purchase and transaction management</p></div>
        <div class="cards" id="billingOverview"></div>
        <h3>Purchases</h3>
        <div class="table-toolbar">
          <select id="billingStatus"><option value="">All statuses</option><option>pending</option><option>verified</option><option>refunded</option><option>canceled</option><option>expired</option><option>rejected</option></select>
          <input id="billingProduct" placeholder="Product ID"/>
          <input id="billingAccount" placeholder="Account ID"/>
          <button data-onclick="loadBillingPurchases(0)">Filter</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Product</th><th>Status</th><th>Sub</th><th>Expires</th><th>Created</th><th>Actions</th></tr></thead><tbody id="billingPurchases"></tbody></table></div>
        <div class="pager"><button class="ghost sm" data-onclick="prevBilling()">Prev</button><span id="billingPageinfo"></span><button class="ghost sm" data-onclick="nextBilling()">Next</button></div>
        <h3>RTDN Events</h3>
        <div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Account</th><th>Token</th></tr></thead><tbody id="rtdnEvents"></tbody></table></div>
      </section>
      <section id="panel-plans" class="panel">
        <div class="page-header"><h1>Plans</h1><p>Subscription and storage plan catalog</p></div>
        <div style="margin-bottom:16px;"><button data-onclick="openPlanModal()">+ New plan</button><button class="ghost" data-onclick="loadPlans()" style="margin-left:8px;">Refresh</button></div>
        <div class="table-wrap"><table><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Price</th><th>Quota</th><th>Features</th><th>Active</th><th>Actions</th></tr></thead><tbody id="plansTable"></tbody></table></div>
      </section>
      <section id="panel-storage" class="panel">
        <div class="page-header"><h1>Storage</h1><p>Storage usage and quota management</p></div>
        <div style="margin-bottom:16px;"><button class="warn" data-onclick="reconcileAll()">Reconcile all quotas</button><button class="ghost" data-onclick="loadStorage()" style="margin-left:8px;">Refresh</button></div>
        <div class="cards" id="storageCards" style="margin-bottom:24px;"></div>
        <h3>Top users by storage</h3>
        <div class="table-wrap"><table><thead><tr><th>Account</th><th>Used</th><th>Files</th><th>Quota</th></tr></thead><tbody id="storageTopUsers"></tbody></table></div>
        <h3>By MIME type</h3>
        <div class="table-wrap"><table><thead><tr><th>MIME</th><th>Files</th><th>Bytes</th></tr></thead><tbody id="storageByMime"></tbody></table></div>
      </section>
      <section id="panel-revenue" class="panel">
        <div class="page-header"><h1>Revenue</h1><p>Financial overview and MRR tracking</p></div>
        <div class="cards" id="revenueCards"></div>
        <h3>Revenue by product</h3>
        <div class="table-wrap"><table><thead><tr><th>Product</th><th>Verified</th><th>Refunded</th><th>Revenue</th><th>Refunded amt</th></tr></thead><tbody id="revenueByProduct"></tbody></table></div>
        <h3>Daily revenue (last 30 days)</h3>
        <div id="revenueChart" style="display:flex;align-items:flex-end;gap:3px;height:120px;padding:12px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);"></div>
      </section>
      <section id="panel-subscriptions" class="panel">
        <div class="page-header"><h1>Subscriptions</h1><p>Subscription and IAP status tracking</p></div>
        <div class="cards" id="subCards"></div>
        <h3>Expiring within 7 days</h3>
        <div class="table-wrap"><table><thead><tr><th>Account</th><th>Product</th><th>Expires</th></tr></thead><tbody id="subExpiring"></tbody></table></div>
        <h3>Subscriptions / IAPs</h3>
        <div class="table-toolbar">
          <select id="subKind"><option value="all">All kinds</option><option value="subscription">Subscriptions</option><option value="iap">IAP (one-time)</option></select>
          <select id="subStatus"><option value="">All statuses</option><option>pending</option><option>verified</option><option>refunded</option><option>canceled</option><option>expired</option></select>
          <button data-onclick="loadSubscriptions(0)">Filter</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Product</th><th>Kind</th><th>Status</th><th>Expires</th><th>Verified</th></tr></thead><tbody id="subList"></tbody></table></div>
        <div class="pager"><button class="ghost sm" data-onclick="prevSub()">Prev</button><span id="subPageinfo"></span><button class="ghost sm" data-onclick="nextSub()">Next</button></div>
        <h3>By product</h3>
        <div class="table-wrap"><table><thead><tr><th>Product</th><th>Active</th><th>Total</th></tr></thead><tbody id="subByProduct"></tbody></table></div>
      </section>
      <section id="panel-play" class="panel">
        <div class="page-header"><h1>Play Console</h1><p>Google Play Developer API integration</p></div>
        <div class="cards" id="playStatus"></div>
        <h3>Verify purchase token</h3>
        <div class="table-toolbar">
          <select id="playKind"><option value="subscription">Subscription</option><option value="product">Product (IAP)</option></select>
          <input id="playId" placeholder="subscriptionId / productId"/>
          <input id="playToken" placeholder="purchaseToken"/>
          <button data-onclick="verifyPlay()">Verify</button>
        </div>
        <pre id="playResult"></pre>
        <h3>Reviews</h3>
        <div style="margin-bottom:12px;"><button data-onclick="loadPlayReviews()">Load reviews</button></div>
        <div class="table-wrap"><table><thead><tr><th>Author</th><th>Rating</th><th>Text</th><th>Modified</th></tr></thead><tbody id="playReviews"></tbody></table></div>
      </section>
      <section id="panel-control" class="panel">
        <div class="page-header"><h1>Control Center</h1><p>Remote configuration and announcements</p></div>
        <h3>Remote config</h3>
        <div class="table-toolbar">
          <input id="cfgKey" placeholder="key"/>
          <input id="cfgValue" placeholder="value"/>
          <input id="cfgDesc" placeholder="description"/>
          <button data-onclick="setConfig()">Set</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>Key</th><th>Value</th><th>Description</th><th>Updated</th><th>Actions</th></tr></thead><tbody id="cfgTable"></tbody></table></div>
        <h3>Announcements</h3>
        <div class="table-toolbar">
          <input id="annTitle" placeholder="title"/>
          <input id="annBody" placeholder="body"/>
          <select id="annType"><option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option></select>
          <button data-onclick="createAnnouncement()">Create</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>Title</th><th>Type</th><th>Active</th><th>Starts</th><th>Ends</th><th>Actions</th></tr></thead><tbody id="annTable"></tbody></table></div>
      </section>
      <section id="panel-notifications" class="panel">
        <div class="page-header"><h1>Notifications</h1><p>Send and manage in-app notifications</p></div>
        <div class="table-toolbar">
          <input id="notifAccount" placeholder="accountId or * for all"/>
          <input id="notifTitle" placeholder="title"/>
          <input id="notifBody" placeholder="body"/>
          <select id="notifType"><option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option><option value="promo">promo</option></select>
          <button data-onclick="sendNotification()">Send</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Type</th><th>Title</th><th>Read</th><th>Created</th><th>Actions</th></tr></thead><tbody id="notifTable"></tbody></table></div>
      </section>
      <section id="panel-deletions" class="panel">
        <div class="page-header"><h1>Data Deletions</h1><p>GDPR deletion requests</p></div>
        <div class="table-toolbar">
          <select id="delStatus"><option value="">All</option><option value="pending">pending</option><option value="processing">processing</option><option value="completed">completed</option><option value="rejected">rejected</option></select>
          <button data-onclick="loadDeletions(0)">Filter</button>
        </div>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Status</th><th>Reason</th><th>Requested</th><th>Processed</th><th>Actions</th></tr></thead><tbody id="delTable"></tbody></table></div>
      </section>
      <section id="panel-reports" class="panel">
        <div class="page-header"><h1>Reports</h1><p>Generate and export reports</p></div>
        <div class="table-toolbar">
          <select id="reportType"><option value="users">Users</option><option value="revenue">Revenue</option><option value="storage">Storage</option><option value="subscriptions">Subscriptions</option><option value="audit">Audit</option></select>
          <input id="reportFrom" type="date"/>
          <input id="reportTo" type="date"/>
          <button data-onclick="generateReport()">Generate</button>
          <button class="ghost" data-onclick="downloadReport()">Download JSON</button>
        </div>
        <div class="cards" id="reportSummary"></div>
        <pre id="reportPreview" style="margin-top:16px;"></pre>
      </section>
      <section id="panel-adminusers" class="panel">
        <div class="page-header"><h1>Admin Users</h1><p>Role-based access control management</p></div>
        <div style="margin-bottom:16px;">
          <button data-onclick="openCreateAdmin()">+ Create admin user</button>
          <button class="ghost" data-onclick="loadAdminUsers()" style="margin-left:8px;">Refresh</button>
        </div>
        <h3>Admin users</h3>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Active</th><th>Last login</th><th>Actions</th></tr></thead><tbody id="adminUsersTable"></tbody></table></div>
        <h3>Roles</h3>
        <div class="table-wrap"><table><thead><tr><th>Name</th><th>Permissions</th><th>Description</th></tr></thead><tbody id="rolesTable"></tbody></table></div>
      </section>
    </div>
  </div>
</div>
<!-- Login Modal -->
<div class="modal" id="loginModal">
  <div class="box">
    <h3>Admin Login</h3>
    <p class="modal-desc">Enter your credentials to access the console</p>
    <input id="loginUser" placeholder="Username"/>
    <input id="loginPass" type="password" placeholder="Password"/>
    <div style="display:flex;gap:8px;">
      <button data-onclick="doLogin()" style="flex:1;">Sign In</button>
      <button class="ghost" data-onclick="useToken()">Use token</button>
    </div>
    <div class="small" style="text-align:center;margin-top:4px;">Default: admin / admin123</div>
  </div>
</div>
<!-- Grant Modal -->
<div class="modal" id="grantModal">
  <div class="box">
    <h3>Grant / Revoke Entitlement</h3>
    <input id="gAccount" readonly placeholder="Account"/>
    <textarea id="gFeatures" rows="3" placeholder="folders, location, tags..."></textarea>
    <input id="gDays" type="number" value="30" placeholder="Days"/>
    <div style="display:flex;gap:8px;">
      <button data-onclick="doGrant()" style="flex:1;">Grant</button>
      <button class="danger" data-onclick="doRevoke()">Revoke</button>
      <button class="ghost" data-onclick="closeModal('grantModal')">Cancel</button>
    </div>
  </div>
</div>
<!-- Detail Modal -->
<div class="modal" id="detailModal">
  <div class="box">
    <h3 id="dTitle">User Detail</h3>
    <div id="dBody" class="detail-grid"></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">
      <button class="warn" data-onclick="toggleTrial()">Toggle trial</button>
      <button class="ghost" data-onclick="reconcileUser()">Reconcile</button>
      <button class="ghost" data-onclick="exportUserData()">Export (GDPR)</button>
      <button class="warn" data-onclick="toggleBan()">Ban/Unban</button>
      <button class="danger" data-onclick="deleteUser()">Delete</button>
      <button class="ghost" data-onclick="closeModal('detailModal')">Close</button>
    </div>
  </div>
</div>
<!-- Status Toast -->
<div id="status" class="status"></div>

<script>
  const API = location.origin;
  function esc(v){ return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
  let currentPage = 0, currentCloudPage = 0, currentAuditPage = 0;
  const PAGE_SIZE = 25;
  let currentDetail = null, currentCloudAccount = null;
  function tok(){ return localStorage.getItem('adminToken')||''; }
  function saveToken(){ localStorage.setItem('adminToken', document.getElementById('token').value); show('Token saved','ok'); loadAll(); }
  function show(msg,kind){ const e=document.getElementById('status'); e.textContent=msg; e.className='status '+kind; e.style.display='block'; setTimeout(()=>e.style.display='none',3000); }
  async function api(path,opts={}){
    const r = await fetch(API+path, Object.assign({headers:{'Authorization':'Bearer '+tok(),'Content-Type':'application/json'}},opts));
    if(!r.ok){ const b=await r.text(); throw new Error(r.status+' '+b); }
    return r.json();
  }
  function bytes(n){ if(n==null) return '-'; const u=['B','KB','MB','GB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return n.toFixed(1)+u[i]; }
  function switchTab(name){
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active', t.dataset.tab===name));
    document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active', p.id==='panel-'+name));
    if(name==='overview') loadOverview();
    if(name==='users') { loadUsersSummary(); loadUsers(currentPage); }
    if(name==='cloud') { if(currentCloudAccount) loadCloudFiles(currentCloudPage); }
    if(name==='health') loadHealth();
    if(name==='audit') loadAudit(currentAuditPage);
    if(name==='billing') loadBilling();
    if(name==='plans') loadPlans();
    if(name==='storage') loadStorage();
    if(name==='revenue') loadRevenue();
    if(name==='subscriptions') loadSubscriptionsTab();
    if(name==='play') loadPlay();
    if(name==='control') loadControl();
    if(name==='adminusers') loadAdminUsers();
    if(name==='notifications') loadNotifications(0);
    if(name==='deletions') loadDeletions(0);
  }
  async function loadOverview(){
    try{
      const d = await api('/v1/admin/overview');
      const pct = d.quotaBytes? Math.min(100, (d.usedBytes/d.freeQuotaBytes)*100) : 0;
      document.getElementById('overview').innerHTML = [
        ['Users',d.users,''], ['Pro accounts',d.proAccounts,''], ['Trial used',d.trialUsed,''],
        ['Storage used',bytes(d.usedBytes),'of '+bytes(d.freeQuotaBytes)+' (free base)'],
        ['Disk free',bytes(d.diskFreeBytes),'of '+bytes(d.diskTotalBytes)],
        ['Disk total',bytes(d.diskTotalBytes),'blobs: '+d.blobsDir],
      ].map(([l,v,s])=>'<div class="card"><div class="label">'+l+'</div><div class="value">'+v+'</div><div class="sub">'+s+'</div></div>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function loadUsersSummary(){
    try{
      const d = await api('/v1/admin/users-summary');
      document.getElementById('usersSummary').innerHTML = [
        ['Total users', d.total], ['Paid', d.paid], ['Free', d.free],
        ['New (30d)', d.new_users], ['Active (30d)', d.active_users],
        ['Inactive', d.inactive_users], ['Never seen', d.never_seen], ['Trial used', d.trial_used],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value">'+v+'</div></div>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function loadUsers(page){
    if(typeof page==='number') currentPage=page;
    try{
      const q = document.getElementById('search').value;
      const st = document.getElementById('userStatus').value;
      const d = await api('/v1/admin/users?search='+encodeURIComponent(q)+'&status='+encodeURIComponent(st)+'&limit='+PAGE_SIZE+'&offset='+(currentPage*PAGE_SIZE));
      const tb = document.getElementById('users');
      if(!d.users.length){ tb.innerHTML='<tr><td colspan="8" class="empty">No users</td></tr>'; }
      else tb.innerHTML = d.users.map(u=>'<tr>'+
        '<td><a href="#" data-onclick="openDetail(\''+esc(u.accountId)+'\');return false;">'+esc(u.accountId)+'</a></td>'+
        '<td>'+(u.pro?'<span style="color:var(--ok);font-weight:600;">Paid</span>':'<span style="color:var(--muted);">Free</span>')+'</td>'+
        '<td>'+(u.trialUsed?'yes':'no')+(u.trialGrant?' (grant)':'')+'</td>'+\n        '<td class="small">'+(u.lastSeenAt||'never')+'</td>'+
        '<td class="small">'+(u.features.map(f=>'<span class="tag">'+esc(f)+'</span>').join('')||'-')+'</td>'+
        '<td class="small">'+(u.expiresAt||'-')+'</td>'+
        '<td>'+bytes(u.usedBytes)+'</td>'+
        '<td class="rowbtns"><button data-onclick="openGrant(''+u.accountId+'')">Grant</button></td>'+
      '</tr>').join('');
      document.getElementById('pageinfo').textContent = 'page '+(currentPage+1)+' of '+Math.max(1,Math.ceil(d.total/PAGE_SIZE))+' ('+d.total+' total)';
    }catch(e){ show(e.message,'err'); }
  }
  function prevPage(){ if(currentPage>0) loadUsers(currentPage-1); }
  function nextPage(){ loadUsers(currentPage+1); }
  function openGrant(a){ document.getElementById('gAccount').value=a; document.getElementById('gFeatures').value='folders,location,tags,reminders,pdf,lock,favorites,pin,widget,cloud,backgrounds,media,shred'; document.getElementById('grantModal').classList.add('open'); }
  function closeModal(id){ document.getElementById(id).classList.remove('open'); }
  async function doGrant(){ try{ await api('/v1/admin/grant',{method:'POST',body:JSON.stringify({accountId:document.getElementById('gAccount').value,features:document.getElementById('gFeatures').value.split(',').map(s=>s.trim()).filter(Boolean),days:Number(document.getElementById('gDays').value)})}); show('Granted','ok'); closeModal('grantModal'); loadUsers(currentPage); loadOverview(); }catch(e){ show(e.message,'err'); } }
  async function doRevoke(){ try{ await api('/v1/admin/revoke',{method:'POST',body:JSON.stringify({accountId:document.getElementById('gAccount').value})}); show('Revoked','ok'); closeModal('grantModal'); loadUsers(currentPage); loadOverview(); }catch(e){ show(e.message,'err'); } }
  async function openDetail(a){
    try{
      const d = await api('/v1/admin/users/'+encodeURIComponent(a));
      currentDetail = d;
      document.getElementById('dTitle').textContent = 'User: '+a;
      const u = d.user;
      const e = d.entitlement || {};
      const q = d.quota || {};
      document.getElementById('dBody').innerHTML = [
        ['Account', u.account_id],
        ['Google sub', u.google_sub||'-'],
        ['Created', u.created_at],
        ['Trial used', String(u.trial_used)],
        ['Trial started', u.trial_started_at||'-'],
        ['Trial grant', JSON.stringify(d.trialGrant)],
        ['Features', (e.features||[]).join(', ')||'-'],
        ['Expires', e.expires_at||'-'],
        ['Used bytes', bytes(q.used_bytes)],
        ['Cloud files', (d.files||[]).length],
        ['Pointers', (d.pointers||[]).map(p=>p.name+'=>'+p.sha256.slice(0,12)).join(', ')||'-'],
      ].map(([k,v])=>'<div class="k">'+k+'</div><div>'+v+'</div>').join('');
      document.getElementById('detailModal').classList.add('open');
    }catch(e){ show(e.message,'err'); }
  }
  async function toggleTrial(){
    if(!currentDetail) return;
    const u = currentDetail.user;
    try{
      await api('/v1/admin/trial',{method:'POST',body:JSON.stringify({accountId:u.account_id,used:!u.trial_used})});
      show('Trial toggled','ok');
      closeModal('detailModal');
      loadUsers(currentPage); loadOverview();
    }catch(e){ show(e.message,'err'); }
  }
  async function reconcileUser(){
    if(!currentDetail) return;
    try{
      const r = await api('/v1/admin/reconcile',{method:'POST',body:JSON.stringify({accountId:currentDetail.user.account_id})});
      show('Reconciled: '+bytes(r.usedBytes),'ok');
      openDetail(currentDetail.user.account_id);
    }catch(e){ show(e.message,'err'); }
  }
  async function exportUserData(){
    if(!currentDetail) return;
    try{
      const r = await fetch(API+'/v1/account/export?accountId='+encodeURIComponent(currentDetail.user.account_id), { headers: { 'Authorization': 'Bearer '+tok() } });
      if(!r.ok){ const b=await r.text(); throw new Error(r.status+' '+b); }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'nota-data-'+currentDetail.user.account_id+'.json';
      a.click();
      URL.revokeObjectURL(url);
      show('Exported','ok');
    }catch(e){ show(e.message,'err'); }
  }
  async function deleteUser(){
    if(!currentDetail) return;
    if(!confirm('Delete account '+currentDetail.user.account_id+'? This removes all data.')) return;
    try{
      await api('/v1/admin/account?accountId='+encodeURIComponent(currentDetail.user.account_id),{method:'DELETE'});
      show('Deleted','ok');
      closeModal('detailModal');
      loadUsers(currentPage); loadOverview();
    }catch(e){ show(e.message,'err'); }
  }
  async function loadCloudFiles(page){
    if(typeof page==='number') currentCloudPage=page;
    const a = document.getElementById('cloudAccount').value.trim();
    if(!a){ show('Enter accountId','err'); return; }
    currentCloudAccount = a;
    try{
      const q = await api('/v1/cloud/quota?accountId='+encodeURIComponent(a));
      document.getElementById('cloudQuota').innerHTML = 'Quota: '+bytes(q.usedBytes)+' / '+bytes(q.quotaBytes)+' (free '+bytes(q.freeBytes)+')';
      const d = await api('/v1/admin/cloud/files?accountId='+encodeURIComponent(a)+'&limit='+PAGE_SIZE+'&offset='+(currentCloudPage*PAGE_SIZE));
      const tb = document.getElementById('cloudFiles');
      if(!d.files.length){ tb.innerHTML='<tr><td colspan="5" class="empty">No files</td></tr>'; }
      else tb.innerHTML = d.files.map(f=>'<tr>'+
        '<td class="small">'+esc(f.sha256)+'</td>'+
        '<td>'+bytes(f.size_bytes)+'</td>'+
        '<td class="small">'+f.mime+'</td>'+
        '<td class="small">'+f.created_at+'</td>'+
        '<td class="rowbtns"><button class="danger" data-onclick="deleteBlob(''+a+'',''+f.sha256+'')">Delete</button></td>'+
      '</tr>').join('');
      document.getElementById('cloudPageinfo').textContent = 'page '+(currentCloudPage+1)+' of '+Math.max(1,Math.ceil(d.total/PAGE_SIZE))+' ('+d.total+' total)';
    }catch(e){ show(e.message,'err'); }
  }
  function prevCloud(){ if(currentCloudPage>0) loadCloudFiles(currentCloudPage-1); }
  function nextCloud(){ loadCloudFiles(currentCloudPage+1); }
  async function deleteBlob(a,sha){
    if(!confirm('Delete blob '+sha.slice(0,12)+'...?')) return;
    try{
      const r = await api('/v1/admin/cloud/blob?accountId='+encodeURIComponent(a)+'&sha='+sha,{method:'DELETE'});
      show('Deleted, freed '+bytes(r.freedBytes),'ok');
      loadCloudFiles(currentCloudPage);
      loadOverview();
    }catch(e){ show(e.message,'err'); }
  }
  async function loadHealth(){
    try{
      const d = await api('/v1/admin/health');
      const indicator = (ok)=> ok ? '<span style="color:var(--ok);font-weight:700;">● UP</span>' : '<span style="color:var(--danger);font-weight:700;">● DOWN</span>';
      document.getElementById('health').innerHTML = [
        ['Service: nota-entitlements', indicator(true) + ' (pid '+d.pid+')'],
        ['Uptime', Math.floor(d.uptimeSeconds/60)+' min ('+d.uptimeSeconds+'s)'],
        ['Node.js', d.nodeVersion],
        ['Database', indicator(d.db==='up') + ' ' + d.dbVersion],
        ['Disk / Blobs', indicator(d.blobsDirExists) + ' free '+bytes(d.diskFreeBytes)+' / '+bytes(d.diskTotalBytes)],
        ['Blobs dir', d.blobsDir + (d.blobsDirExists?' (exists)':' (MISSING)')],
        ['Users', d.users], ['Cloud files', d.cloudFiles],
        ['Purchases', d.purchases], ['Plans', d.plans],
        ['Storage used', bytes(d.usedBytes)],
        ['Memory RSS', bytes(d.memoryRss)], ['Heap used', bytes(d.memoryHeapUsed)],
      ].map(([k,v])=>'<div class="card"><div class="label">'+k+'</div><div class="value" style="font-size:16px;">'+v+'</div></div>').join('');
      // config flags panel
      const cfg = d.config;
      document.getElementById('health').innerHTML += '<div class="card" style="grid-column:1/-1;"><div class="label">Configuration</div><div style="margin-top:8px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;">'+
        Object.entries(cfg).map(([k,v])=>'<div><span class="small">'+k+':</span> '+(v?'<span style="color:var(--ok);">enabled</span>':'<span style="color:var(--danger);">disabled</span>')+'</div>').join('')+
      '</div></div>';
    }catch(e){ show(e.message,'err'); }
  }
  async function loadAudit(page){
    if(typeof page==='number') currentAuditPage=page;
    try{
      const d = await api('/v1/admin/audit?limit='+PAGE_SIZE+'&offset='+(currentAuditPage*PAGE_SIZE));
      const tb = document.getElementById('audit');
      if(!d.entries.length){ tb.innerHTML='<tr><td colspan="5" class="empty">No audit entries</td></tr>'; }
      else tb.innerHTML = d.entries.map(e=>'<tr>'+
        '<td class="small">'+e.created_at+'</td>'+
        '<td>'+e.action+'</td>'+
        '<td class="small">'+esc(e.account_id||'-')+'</td>'+
        '<td class="small">'+(e.actor_ip||'-')+'</td>'+
        '<td class="small">'+(e.detail?JSON.stringify(e.detail):'-')+'</td>'+
      '</tr>').join('');
      document.getElementById('auditPageinfo').textContent = 'page '+(currentAuditPage+1)+' of '+Math.max(1,Math.ceil(d.total/PAGE_SIZE))+' ('+d.total+' total)';
    }catch(e){ show(e.message,'err'); }
  }
  function prevAudit(){ if(currentAuditPage>0) loadAudit(currentAuditPage-1); }
  function nextAudit(){ loadAudit(currentAuditPage+1); }
  async function exportUsers(){
    try{
      const r = await fetch(API+'/v1/admin/export/users', { headers: { 'Authorization': 'Bearer '+tok() } });
      if(!r.ok){ const b=await r.text(); throw new Error(r.status+' '+b); }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'nota-users.csv';
      a.click();
      URL.revokeObjectURL(url);
      show('Exported','ok');
    }catch(e){ show(e.message,'err'); }
  }

  let currentBillingPage = 0, currentRtdnPage = 0;
  async function loadBilling(){
    try{
      const d = await api('/v1/admin/billing/overview');
      const c = d.counts;
      document.getElementById('billingOverview').innerHTML = [
        ['Total purchases', c.total], ['Verified', c.verified], ['Pending', c.pending],
        ['Active subs', c.active_subs], ['Refunded', c.refunded], ['Canceled', c.canceled],
        ['Expired', c.expired], ['RTDN events', d.rtdnTotal],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value">'+v+'</div></div>').join('');
      // by product
      // rtdn by type (append small)
    }catch(e){ show(e.message,'err'); }
    loadBillingPurchases(0);
    loadRtdnEvents(0);
  }
  async function loadBillingPurchases(page){
    if(typeof page==='number') currentBillingPage=page;
    try{
      const status = document.getElementById('billingStatus').value;
      const product = document.getElementById('billingProduct').value.trim();
      const account = document.getElementById('billingAccount').value.trim();
      const d = await api('/v1/admin/billing/purchases?status='+encodeURIComponent(status)+'&product='+encodeURIComponent(product)+'&accountId='+encodeURIComponent(account)+'&limit='+PAGE_SIZE+'&offset='+(currentBillingPage*PAGE_SIZE));
      const tb = document.getElementById('billingPurchases');
      if(!d.purchases.length){ tb.innerHTML='<tr><td colspan="8" class="empty">No purchases</td></tr>'; }
      else tb.innerHTML = d.purchases.map(p=>'<tr>'+
        '<td>'+p.id+'</td>'+
        '<td class="small">'+p.account_id+'</td>'+
        '<td class="small">'+p.product_id+'</td>'+
        '<td>'+p.status+'</td>'+
        '<td>'+(p.is_subscription?'yes':'no')+'</td>'+
        '<td class="small">'+(p.expires_at||'-')+'</td>'+
        '<td class="small">'+p.created_at+'</td>'+
        '<td class="rowbtns">'+
          (p.status!=='verified'?'<button data-onclick="verifyPurchase(''+p.purchase_token+'')">Verify</button>':'')+
          (p.status==='verified'?'<button class="danger" data-onclick="refundPurchase(''+p.purchase_token+'')">Refund</button>':'')+
        '</td>'+
      '</tr>').join('');
      document.getElementById('billingPageinfo').textContent = 'page '+(currentBillingPage+1)+' of '+Math.max(1,Math.ceil(d.total/PAGE_SIZE))+' ('+d.total+' total)';
    }catch(e){ show(e.message,'err'); }
  }
  function prevBilling(){ if(currentBillingPage>0) loadBillingPurchases(currentBillingPage-1); }
  function nextBilling(){ loadBillingPurchases(currentBillingPage+1); }
  async function verifyPurchase(token){
    const features = prompt('Features to grant (comma-separated), or empty to skip:');
    const days = features? (prompt('Days (default 30):')||'30') : '30';
    try{
      await api('/v1/admin/purchases/verify',{method:'POST',body:JSON.stringify({purchaseToken:token, features: features? features.split(',').map(s=>s.trim()).filter(Boolean): undefined, days: Number(days)})});
      show('Verified','ok');
      loadBillingPurchases(currentBillingPage); loadBilling();
    }catch(e){ show(e.message,'err'); }
  }
  async function refundPurchase(token){
    if(!confirm('Refund this purchase and revoke entitlement?')) return;
    try{
      await api('/v1/admin/purchases/refund',{method:'POST',body:JSON.stringify({purchaseToken:token})});
      show('Refunded','ok');
      loadBillingPurchases(currentBillingPage); loadBilling();
    }catch(e){ show(e.message,'err'); }
  }
  async function loadRtdnEvents(page){
    if(typeof page==='number') currentRtdnPage=page;
    try{
      const d = await api('/v1/admin/rtdn/events?limit='+PAGE_SIZE+'&offset='+(currentRtdnPage*PAGE_SIZE));
      const tb = document.getElementById('rtdnEvents');
      if(!d.events.length){ tb.innerHTML='<tr><td colspan="4" class="empty">No RTDN events</td></tr>'; }
      else tb.innerHTML = d.events.map(e=>'<tr>'+
        '<td class="small">'+e.created_at+'</td>'+
        '<td>'+e.event_type+'</td>'+
        '<td class="small">'+esc(e.account_id||'-')+'</td>'+
        '<td class="small">'+(e.purchase_token?e.purchase_token.slice(0,16)+'...':'-')+'</td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }


  async function loadPlans(){
    try{
      const d = await api('/v1/admin/plans');
      const tb = document.getElementById('plansTable');
      if(!d.plans.length){ tb.innerHTML='<tr><td colspan="8" class="empty">No plans</td></tr>'; return; }
      tb.innerHTML = d.plans.map(p=>'<tr>'+
        '<td class="small">'+p.code+'</td>'+
        '<td>'+p.name+'</td>'+
        '<td>'+p.type+'</td>'+
        '<td>'+(p.price_cents/100).toFixed(2)+' '+p.currency+'</td>'+
        '<td>'+bytes(p.quota_bytes)+'</td>'+
        '<td class="small">'+(p.features||[]).join(', ')+'</td>'+
        '<td>'+(p.active?'yes':'no')+'</td>'+
        '<td class="rowbtns">'+
          '<button class="ghost" data-onclick="editPlan(''+p.code+'')">Edit</button>'+
          '<button class="danger" data-onclick="deactivatePlan(''+p.code+'')">Deactivate</button>'+
        '</td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  function openPlanModal(plan){
    const code = plan? plan.code : prompt('Plan code (lowercase, underscores):');
    if(!code) return;
    const name = prompt('Name:', plan? plan.name : code);
    if(!name) return;
    const type = prompt('Type (subscription/storage/feature/trial):', plan? plan.type : 'subscription');
    if(!type) return;
    const price = prompt('Price in cents:', plan? plan.price_cents : '0');
    const features = prompt('Features (comma):', plan? (plan.features||[]).join(',') : '');
    const quota = prompt('Quota bytes:', plan? plan.quota_bytes : '0');
    const active = confirm('Active?');
    const body = { code, name, type, priceCents: Number(price), features: features? features.split(',').map(s=>s.trim()).filter(Boolean): [], quotaBytes: Number(quota), active };
    const url = plan? '/v1/admin/plans/'+code : '/v1/admin/plans';
    const method = plan? 'PUT' : 'POST';
    api(url,{method:method,body:JSON.stringify(body)}).then(()=>{ show(plan?'Updated':'Created','ok'); loadPlans(); }).catch(e=>show(e.message,'err'));
  }
  async function editPlan(code){
    try{
      const d = await api('/v1/plans/'+code);
      openPlanModal(d.plan);
    }catch(e){ show(e.message,'err'); }
  }
  async function deactivatePlan(code){
    if(!confirm('Deactivate plan '+code+'?')) return;
    try{
      await api('/v1/admin/plans/'+code,{method:'DELETE'});
      show('Deactivated','ok');
      loadPlans();
    }catch(e){ show(e.message,'err'); }
  }


  async function loadStorage(){
    try{
      const d = await api('/v1/admin/storage/overview');
      document.getElementById('storageCards').innerHTML = [
        ['Total used', bytes(d.usedBytes)], ['Files bytes', bytes(d.filesBytes)],
        ['File count', d.fileCount], ['Users with files', d.usersWithFiles],
        ['Disk free', bytes(d.diskFreeBytes)], ['Disk total', bytes(d.diskTotalBytes)],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value" style="font-size:18px;">'+v+'</div></div>').join('');
      const tb = document.getElementById('storageTopUsers');
      if(!d.topUsers.length){ tb.innerHTML='<tr><td colspan="4" class="empty">No storage usage</td></tr>'; }
      else tb.innerHTML = d.topUsers.map(u=>'<tr>'+
        '<td class="small">'+u.accountId+'</td>'+
        '<td>'+bytes(u.usedBytes)+'</td>'+
        '<td>'+u.fileCount+'</td>'+
        '<td style="min-width:120px;"><div class="progress"><div style="width:'+Math.min(100,(u.usedBytes/104857600)*100)+'%;"></div></div></td>'+
      '</tr>').join('');
      const mb = document.getElementById('storageByMime');
      if(!d.byMime.length){ mb.innerHTML='<tr><td colspan="3" class="empty">No files</td></tr>'; }
      else mb.innerHTML = d.byMime.map(m=>'<tr><td class="small">'+m.mime+'</td><td>'+m.count+'</td><td>'+bytes(m.bytes)+'</td></tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function reconcileAll(){
    if(!confirm('Reconcile all users quotas?')) return;
    try{
      const r = await api('/v1/admin/storage/reconcile-all',{method:'POST'});
      show('Reconciled '+r.reconciled+' users','ok');
      loadStorage();
    }catch(e){ show(e.message,'err'); }
  }


  async function loadRevenue(){
    try{
      const d = await api('/v1/admin/revenue/overview');
      document.getElementById('revenueCards').innerHTML = [
        ['Gross revenue', '$'+(d.grossCents/100).toFixed(2)],
        ['Refunded', '$'+(d.refundedCents/100).toFixed(2)],
        ['Net revenue', '$'+(d.netCents/100).toFixed(2)],
        ['MRR', '$'+(d.mrrCents/100).toFixed(2)],
        ['Verified purchases', d.verifiedCount],
        ['Refunded count', d.refundedCount],
        ['Pending', d.pendingCount],
        ['Active subs', d.activeSubs],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value" style="font-size:18px;">'+v+'</div></div>').join('');
      const tb = document.getElementById('revenueByProduct');
      if(!d.byProduct.length){ tb.innerHTML='<tr><td colspan="5" class="empty">No revenue yet</td></tr>'; }
      else tb.innerHTML = d.byProduct.map(p=>'<tr>'+
        '<td class="small">'+p.productId+'</td>'+
        '<td>'+p.verified+'</td>'+
        '<td>'+p.refunded+'</td>'+
        '<td>$'+(p.revenueCents/100).toFixed(2)+'</td>'+
        '<td>$'+(p.refundedCents/100).toFixed(2)+'</td>'+
      '</tr>').join('');
      // chart
      const max = Math.max(1, ...d.byDay.map(x=>x.revenueCents));
      const chart = document.getElementById('revenueChart');
      chart.innerHTML = d.byDay.map(x=>'<div title="'+x.day+': $'+(x.revenueCents/100).toFixed(2)+'" style="flex:1;background:var(--accent);height:'+Math.max(2,(x.revenueCents/max)*100)+'%;border-radius:2px;min-width:4px;"></div>').join('');
      if(!d.byDay.length) chart.innerHTML='<div class="empty" style="align-self:center;width:100%;">No data</div>';
    }catch(e){ show(e.message,'err'); }
  }


  let currentSubPage = 0;
  async function loadSubscriptionsTab(){
    try{
      const d = await api('/v1/admin/subscriptions/overview');
      document.getElementById('subCards').innerHTML = [
        ['Total subs', d.totalSubs], ['Active', d.active], ['Expired', d.expired],
        ['Canceled', d.canceled], ['Refunded', d.refunded], ['Pending', d.pending],
        ['IAP total', d.iapTotal], ['IAP verified', d.iapVerified],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value">'+v+'</div></div>').join('');
      const et = document.getElementById('subExpiring');
      if(!d.expiringSoon.length){ et.innerHTML='<tr><td colspan="3" class="empty">None expiring soon</td></tr>'; }
      else et.innerHTML = d.expiringSoon.map(e=>'<tr><td class="small">'+e.account_id+'</td><td class="small">'+e.product_id+'</td><td class="small">'+e.expires_at+'</td></tr>').join('');
      const bp = document.getElementById('subByProduct');
      if(!d.byProduct.length){ bp.innerHTML='<tr><td colspan="3" class="empty">No data</td></tr>'; }
      else bp.innerHTML = d.byProduct.map(p=>'<tr><td class="small">'+p.product_id+'</td><td>'+p.active+'</td><td>'+p.total+'</td></tr>').join('');
    }catch(e){ show(e.message,'err'); }
    loadSubscriptions(0);
  }
  async function loadSubscriptions(page){
    if(typeof page==='number') currentSubPage=page;
    try{
      const kind = document.getElementById('subKind').value;
      const status = document.getElementById('subStatus').value;
      const d = await api('/v1/admin/subscriptions/list?kind='+encodeURIComponent(kind)+'&status='+encodeURIComponent(status)+'&limit='+PAGE_SIZE+'&offset='+(currentSubPage*PAGE_SIZE));
      const tb = document.getElementById('subList');
      if(!d.subscriptions.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No records</td></tr>'; }
      else tb.innerHTML = d.subscriptions.map(s=>'<tr>'+
        '<td>'+s.id+'</td>'+
        '<td class="small">'+s.account_id+'</td>'+
        '<td class="small">'+s.product_id+'</td>'+
        '<td>'+(s.is_subscription?'sub':'iap')+'</td>'+
        '<td>'+s.status+'</td>'+
        '<td class="small">'+(s.expires_at||'-')+'</td>'+
        '<td class="small">'+(s.verified_at||'-')+'</td>'+
      '</tr>').join('');
      document.getElementById('subPageinfo').textContent = 'page '+(currentSubPage+1)+' of '+Math.max(1,Math.ceil(d.total/PAGE_SIZE))+' ('+d.total+' total)';
    }catch(e){ show(e.message,'err'); }
  }
  function prevSub(){ if(currentSubPage>0) loadSubscriptions(currentSubPage-1); }
  function nextSub(){ loadSubscriptions(currentSubPage+1); }


  async function loadPlay(){
    try{
      const d = await api('/v1/admin/play/status');
      document.getElementById('playStatus').innerHTML = [
        ['Configured', d.configured?'yes':'no'],
        ['Package', d.packageName||'-'],
        ['Service account', d.serviceAccount||'-'],
      ].map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value" style="font-size:16px;">'+v+'</div></div>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function verifyPlay(){
    const kind = document.getElementById('playKind').value;
    const id = document.getElementById('playId').value.trim();
    const token = document.getElementById('playToken').value.trim();
    if(!id||!token){ show('Enter id and token','err'); return; }
    try{
      const url = kind==='subscription' ? '/v1/admin/play/verify-subscription' : '/v1/admin/play/verify-product';
      const body = kind==='subscription' ? {subscriptionId:id, purchaseToken:token} : {productId:id, purchaseToken:token};
      const r = await api(url,{method:'POST',body:JSON.stringify(body)});
      document.getElementById('playResult').textContent = JSON.stringify(r,null,2);
      show('Verified','ok');
    }catch(e){ document.getElementById('playResult').textContent = e.message; show(e.message,'err'); }
  }
  async function loadPlayReviews(){
    try{
      const d = await api('/v1/admin/play/reviews?maxResults=50');
      const reviews = (d.reviews||[]);
      const tb = document.getElementById('playReviews');
      if(!reviews.length){ tb.innerHTML='<tr><td colspan="4" class="empty">No reviews (or not configured)</td></tr>'; return; }
      tb.innerHTML = reviews.map(r=>{
        const c = (r.comments&&r.comments[0]&&r.comments[0].userComment) || {};
        return '<tr>'+
          '<td class="small">'+(c.reviewerLanguage||'-')+'</td>'+
          '<td>'+(c.starRating||'-')+'</td>'+
          '<td class="small">'+(c.text||'')+'</td>'+
          '<td class="small">'+(c.lastModified? new Date(c.lastModified.seconds*1000).toISOString() : '-')+'</td>'+
        '</tr>';
      }).join('');
    }catch(e){ show(e.message,'err'); }
  }


  async function loadControl(){
    await loadConfig();
    await loadAnnouncements();
  }
  async function loadConfig(){
    try{
      const d = await api('/v1/admin/config');
      const tb = document.getElementById('cfgTable');
      if(!d.config.length){ tb.innerHTML='<tr><td colspan="5" class="empty">No config</td></tr>'; return; }
      tb.innerHTML = d.config.map(c=>'<tr>'+
        '<td class="small">'+c.key+'</td>'+
        '<td class="small">'+c.value+'</td>'+
        '<td class="small">'+(c.description||'-')+'</td>'+
        '<td class="small">'+c.updated_at+'</td>'+
        '<td class="rowbtns"><button class="danger" data-onclick="deleteConfig(''+c.key+'')">Delete</button></td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function setConfig(){
    const key=document.getElementById('cfgKey').value.trim();
    const value=document.getElementById('cfgValue').value;
    const description=document.getElementById('cfgDesc').value.trim();
    if(!key){ show('Key required','err'); return; }
    try{
      await api('/v1/admin/config',{method:'PUT',body:JSON.stringify({key,value,description:description||undefined})});
      show('Set','ok');
      document.getElementById('cfgKey').value='';
      document.getElementById('cfgValue').value='';
      document.getElementById('cfgDesc').value='';
      loadConfig();
    }catch(e){ show(e.message,'err'); }
  }
  async function deleteConfig(key){
    if(!confirm('Delete config '+key+'?')) return;
    try{ await api('/v1/admin/config/'+encodeURIComponent(key),{method:'DELETE'}); show('Deleted','ok'); loadConfig(); }catch(e){ show(e.message,'err'); }
  }
  async function loadAnnouncements(){
    try{
      const d = await api('/v1/admin/announcements');
      const tb = document.getElementById('annTable');
      if(!d.announcements.length){ tb.innerHTML='<tr><td colspan="6" class="empty">No announcements</td></tr>'; return; }
      tb.innerHTML = d.announcements.map(a=>'<tr>'+
        '<td>'+a.title+'</td>'+
        '<td>'+a.type+'</td>'+
        '<td>'+(a.active?'yes':'no')+'</td>'+
        '<td class="small">'+a.starts_at+'</td>'+
        '<td class="small">'+(a.ends_at||'-')+'</td>'+
        '<td class="rowbtns">'+
          '<button class="ghost" data-onclick="toggleAnnouncement('+a.id+','+(!a.active)+')">Toggle</button>'+
          '<button class="danger" data-onclick="deleteAnnouncement('+a.id+')">Delete</button>'+
        '</td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function createAnnouncement(){
    const title=document.getElementById('annTitle').value.trim();
    const body=document.getElementById('annBody').value.trim();
    const type=document.getElementById('annType').value;
    if(!title||!body){ show('Title and body required','err'); return; }
    try{
      await api('/v1/admin/announcements',{method:'POST',body:JSON.stringify({title,body,type,active:true})});
      show('Created','ok');
      document.getElementById('annTitle').value='';
      document.getElementById('annBody').value='';
      loadAnnouncements();
    }catch(e){ show(e.message,'err'); }
  }
  async function toggleAnnouncement(id,active){
    try{ await api('/v1/admin/announcements/'+id,{method:'PUT',body:JSON.stringify({active})}); show('Updated','ok'); loadAnnouncements(); }catch(e){ show(e.message,'err'); }
  }
  async function deleteAnnouncement(id){
    if(!confirm('Delete announcement?')) return;
    try{ await api('/v1/admin/announcements/'+id,{method:'DELETE'}); show('Deleted','ok'); loadAnnouncements(); }catch(e){ show(e.message,'err'); }
  }
  async function toggleBan(){
    if(!currentDetail) return;
    const u = currentDetail.user;
    const banned = !u.banned;
    const reason = banned ? (prompt('Ban reason:')||'') : null;
    try{
      await api('/v1/admin/users/ban',{method:'POST',body:JSON.stringify({accountId:u.account_id,banned,reason})});
      show(banned?'Banned':'Unbanned','ok');
      closeModal('detailModal');
      loadUsers(currentPage); loadUsersSummary();
    }catch(e){ show(e.message,'err'); }
  }


  let currentNotifPage=0, currentDelPage=0;
  async function loadNotifications(page){
    if(typeof page==='number') currentNotifPage=page;
    try{
      const d = await api('/v1/admin/notifications?limit='+PAGE_SIZE+'&offset='+(currentNotifPage*PAGE_SIZE));
      const tb = document.getElementById('notifTable');
      if(!d.notifications.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No notifications</td></tr>'; return; }
      tb.innerHTML = d.notifications.map(n=>'<tr>'+
        '<td>'+n.id+'</td>'+
        '<td class="small">'+(n.account_id||'-')+'</td>'+
        '<td>'+n.type+'</td>'+
        '<td class="small">'+n.title+'</td>'+
        '<td>'+(n.read?'yes':'no')+'</td>'+
        '<td class="small">'+n.created_at+'</td>'+
        '<td class="rowbtns"><button class="danger" data-onclick="deleteNotification('+n.id+')">Delete</button></td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function sendNotification(){
    const account=document.getElementById('notifAccount').value.trim();
    const title=document.getElementById('notifTitle').value.trim();
    const body=document.getElementById('notifBody').value.trim();
    const type=document.getElementById('notifType').value;
    if(!account||!title||!body){ show('All fields required','err'); return; }
    try{
      const r = await api('/v1/admin/notifications',{method:'POST',body:JSON.stringify({accountId:account,title,body,type})});
      show('Sent to '+r.count+' user(s)','ok');
      document.getElementById('notifTitle').value='';
      document.getElementById('notifBody').value='';
      loadNotifications(0);
    }catch(e){ show(e.message,'err'); }
  }
  async function deleteNotification(id){
    try{ await api('/v1/admin/notifications/'+id,{method:'DELETE'}); show('Deleted','ok'); loadNotifications(currentNotifPage); }catch(e){ show(e.message,'err'); }
  }
  async function loadDeletions(page){
    if(typeof page==='number') currentDelPage=page;
    try{
      const status=document.getElementById('delStatus').value;
      const d = await api('/v1/admin/deletion-requests?status='+encodeURIComponent(status)+'&limit='+PAGE_SIZE+'&offset='+(currentDelPage*PAGE_SIZE));
      const tb = document.getElementById('delTable');
      if(!d.requests.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No requests</td></tr>'; return; }
      tb.innerHTML = d.requests.map(r=>'<tr>'+
        '<td>'+r.id+'</td>'+
        '<td class="small">'+r.account_id+'</td>'+
        '<td>'+r.status+'</td>'+
        '<td class="small">'+(r.reason||'-')+'</td>'+
        '<td class="small">'+r.requested_at+'</td>'+
        '<td class="small">'+(r.processed_at||'-')+'</td>'+
        '<td class="rowbtns">'+
          (r.status==='pending'?'<button data-onclick="processDeletion('+r.id+','processing')">Process</button>':'')+
          (r.status!=='completed'&&r.status!=='rejected'?'<button class="danger" data-onclick="processDeletion('+r.id+','completed')">Complete</button>':'')+
          (r.status!=='rejected'?'<button class="ghost" data-onclick="processDeletion('+r.id+','rejected')">Reject</button>':'')+
        '</td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  async function processDeletion(id,status){
    if(status==='completed' && !confirm('This will DELETE the account and all data. Continue?')) return;
    try{
      await api('/v1/admin/deletion-requests/'+id+'/process',{method:'POST',body:JSON.stringify({status})});
      show('Processed','ok');
      loadDeletions(currentDelPage);
    }catch(e){ show(e.message,'err'); }
  }
  async function createUser(){
    const accountId = prompt('Account ID (Firebase UID):');
    if(!accountId) return;
    const googleSub = prompt('Google sub (optional):')||undefined;
    try{
      await api('/v1/admin/users/create',{method:'POST',body:JSON.stringify({accountId,googleSub})});
      show('User created','ok');
      loadUsers(currentPage); loadUsersSummary();
    }catch(e){ show(e.message,'err'); }
  }


  let lastReport = null;
  async function generateReport(){
    try{
      const type = document.getElementById('reportType').value;
      const from = document.getElementById('reportFrom').value;
      const to = document.getElementById('reportTo').value;
      const q = (from?'&from='+from+'T00:00:00Z':'') + (to?'&to='+to+'T23:59:59Z':'');
      const d = await api('/v1/admin/reports/'+type+'?'+q.slice(1));
      lastReport = d;
      document.getElementById('reportPreview').textContent = JSON.stringify(d.data, null, 2);
      // summary cards
      const data = d.data || {};
      let cards = [];
      if(type==='users' && data.totals){ cards = [['Total users',data.totals.total],['New in range',data.totals.new_in_range],['Active in range',data.totals.active_in_range]]; }
      else if(type==='revenue' && data.totals){ cards = [['Gross', '$'+(data.totals.gross_cents/100).toFixed(2)],['Refunded', '$'+(data.totals.refunded_cents/100).toFixed(2)],['Verified', data.totals.verified_count],['Refunded count', data.totals.refunded_count]]; }
      else if(type==='storage' && data.totals){ cards = [['Used bytes', bytes(data.totals.used_bytes)],['Accounts', data.totals.accounts]]; }
      else if(type==='subscriptions' && data.breakdown){ cards = data.breakdown.map(b=>[b.status+(b.is_subscription?' (sub)':' (iap)'), b.n]); }
      else if(type==='audit' && data.entries){ cards = [['Entries', data.entries.length]]; }
      document.getElementById('reportSummary').innerHTML = cards.map(([l,v])=>'<div class="card"><div class="label">'+l+'</div><div class="value" style="font-size:18px;">'+v+'</div></div>').join('');
      show('Report generated','ok');
    }catch(e){ show(e.message,'err'); }
  }
  function downloadReport(){
    if(!lastReport){ show('Generate a report first','err'); return; }
    const blob = new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nota-report-'+lastReport.type+'-'+Date.now()+'.json';
    a.click();
    URL.revokeObjectURL(url);
  }


  async function checkAuth(){
    const t = tok();
    if(!t){ document.getElementById('loginModal').classList.add('open'); return false; }
    try{
      const w = await api('/v1/admin/whoami');
      document.getElementById('whoami').textContent = (w.username||'') + (w.role?' ['+w.role+']':'');
      return true;
    }catch(e){
      document.getElementById('loginModal').classList.add('open');
      return false;
    }
  }
  async function doLogin(){
    try{
      const r = await fetch(API+'/v1/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('loginUser').value,password:document.getElementById('loginPass').value})});
      if(!r.ok){ const b=await r.text(); throw new Error(r.status+' '+b); }
      const d = await r.json();
      localStorage.setItem('adminToken', d.token);
      document.getElementById('token').value = d.token;
      document.getElementById('loginModal').classList.remove('open');
      show('Logged in','ok');
      await checkAuth();
      loadAll();
    }catch(e){ show(e.message,'err'); }
  }
  function useToken(){
    document.getElementById('loginModal').classList.remove('open');
    const t = prompt('Paste admin token:');
    if(t){ localStorage.setItem('adminToken',t); document.getElementById('token').value=t; checkAuth().then(()=>loadAll()); }
  }
  async function loadAdminUsers(){
    try{
      const d = await api('/v1/admin/admin-users');
      const tb = document.getElementById('adminUsersTable');
      if(!d.users.length){ tb.innerHTML='<tr><td colspan="6" class="empty">No admin users</td></tr>'; }
      else tb.innerHTML = d.users.map(u=>'<tr>'+
        '<td>'+u.id+'</td>'+
        '<td>'+u.username+'</td>'+
        '<td>'+u.role+'</td>'+
        '<td>'+(u.active?'yes':'no')+'</td>'+
        '<td class="small">'+(u.last_login_at||'-')+'</td>'+
        '<td class="rowbtns">'+
          '<button class="ghost" data-onclick="editAdminUser('+u.id+',''+u.role+'','+u.active+')">Edit</button>'+
          '<button class="danger" data-onclick="deleteAdminUser('+u.id+')">Delete</button>'+
        '</td>'+
      '</tr>').join('');
      // roles
      const rd = await api('/v1/admin/roles');
      const rt = document.getElementById('rolesTable');
      rt.innerHTML = rd.roles.map(r=>'<tr>'+
        '<td>'+r.name+'</td>'+
        '<td class="small">'+(r.permissions||[]).join(', ')+'</td>'+
        '<td class="small">'+(r.description||'-')+'</td>'+
      '</tr>').join('');
    }catch(e){ show(e.message,'err'); }
  }
  function openCreateAdmin(){
    const username = prompt('Username:'); if(!username) return;
    const password = prompt('Password (min 8):'); if(!password) return;
    const role = prompt('Role (superadmin/admin/support/viewer):','admin'); if(!role) return;
    api('/v1/admin/admin-users',{method:'POST',body:JSON.stringify({username,password,role})}).then(()=>{ show('Created','ok'); loadAdminUsers(); }).catch(e=>show(e.message,'err'));
  }
  function editAdminUser(id,role,active){
    const newRole = prompt('Role:',role); if(newRole===null) return;
    const newActive = confirm('Active? (OK=yes)');
    const newPass = prompt('New password (leave empty to keep):');
    const body = { role: newRole, active: newActive };
    if(newPass) body.password = newPass;
    api('/v1/admin/admin-users/'+id,{method:'PUT',body:JSON.stringify(body)}).then(()=>{ show('Updated','ok'); loadAdminUsers(); }).catch(e=>show(e.message,'err'));
  }
  function deleteAdminUser(id){
    if(!confirm('Delete admin user?')) return;
    api('/v1/admin/admin-users/'+id,{method:'DELETE'}).then(()=>{ show('Deleted','ok'); loadAdminUsers(); }).catch(e=>show(e.message,'err'));
  }

  // CSP-friendly event delegation: no inline onclick, no eval. Parses the
  // stored handler expression (already evaluated to literals at render time)
  // and dispatches to the matching global function.
  function parseArgs(str){
    const args = [];
    let i = 0, n = str.length;
    while (i < n) {
      while (i < n && (str[i]===' '||str[i]===',')) i++;
      if (i >= n) break;
      if (str[i] === "'" || str[i] === '"') {
        const q = str[i++];
        let val = '';
        while (i < n && str[i] !== q) { val += str[i++]; }
        i++; // skip closing quote
        args.push(val);
      } else {
        // read until comma or end
        let val = '';
        while (i < n && str[i] !== ',') { val += str[i++]; }
        val = val.trim();
        if (val === 'true') args.push(true);
        else if (val === 'false') args.push(false);
        else if (val === 'null') args.push(null);
        else if (/^-?\d+(\.\d+)?$/.test(val)) args.push(Number(val));
        else args.push(val);
      }
    }
    return args;
  }
  document.addEventListener('click', function(e){
    const el = e.target && e.target.closest ? e.target.closest('[data-onclick]') : null;
    if(!el) return;
    if(el.tagName === 'A') e.preventDefault();
    const code = el.getAttribute('data-onclick');
    if(!code) return;
    // strip trailing "return false" / "return true"
    const stmt = code.split(';')[0].trim();
    const m = stmt.match(/^(\w+)\((.*)\)$/);
    if(!m) return;
    const fn = window[m[1]];
    if (typeof fn !== 'function') { console.error('unknown handler', m[1]); return; }
    try { fn.apply(null, parseArgs(m[2])); } catch(err){ console.error('handler error', err, code); }
  });
  function loadAll(){ loadOverview(); loadUsersSummary(); loadUsers(0); loadHealth(); loadAudit(0); }
  (function init(){ const t=tok(); if(t) document.getElementById('token').value=t; checkAuth().then(ok=>{ if(ok) loadAll(); else document.getElementById('loginModal').classList.add('open'); }); })();
</script>
</body>
</html>
`;
exports.default = router;
