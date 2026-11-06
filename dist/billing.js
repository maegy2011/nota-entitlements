"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const db_js_1 = __importDefault(require("./db.js"));
const middleware_js_1 = require("./middleware.js");
const auth_js_1 = require("./auth.js");
const router = (0, express_1.Router)();
const accountIdSchema = zod_1.z.string().min(1).max(128).regex(/^[A-Za-z0-9._@|-]+$/);
// ---------- Client: record a purchase token (pending verification) ----------
const recordSchema = zod_1.z.strictObject({
    accountId: accountIdSchema,
    productId: zod_1.z.string().min(1).max(128),
    purchaseToken: zod_1.z.string().min(1).max(512),
    isSubscription: zod_1.z.boolean().default(false),
    expiresAt: zod_1.z.string().datetime().optional(),
});
router.post("/purchases", auth_js_1.requireAuth, async (req, res) => {
    const parsed = recordSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid purchase payload.", req));
        return;
    }
    if ((0, auth_js_1.authSubOf)(req) !== parsed.data.accountId) {
        res.status(403).json((0, middleware_js_1.errorBody)("FORBIDDEN", "Token does not own this account.", req));
        return;
    }
    const { accountId, productId, purchaseToken, isSubscription, expiresAt } = parsed.data;
    const client = await db_js_1.default.connect();
    try {
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.current_account_id', $1, true)", [accountId]);
        const u = await client.query("SELECT 1 FROM users WHERE account_id = $1", [accountId]);
        if (u.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Account not found.", req));
            return;
        }
        // Look up plan price for historical accuracy.
        const planR = await client.query("SELECT price_cents FROM plans WHERE code = $1", [productId]);
        const amountCents = planR.rows[0] ? Number(planR.rows[0].price_cents) : 0;
        const r = await client.query(`INSERT INTO purchases (account_id, product_id, purchase_token, is_subscription, expires_at, raw_payload, amount_cents)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (purchase_token) DO NOTHING
       RETURNING id, status`, [accountId, productId, purchaseToken, isSubscription, expiresAt ?? null, req.body, amountCents]);
        await client.query("COMMIT");
        if (r.rowCount === 0) {
            res.status(200).json({ ok: true, dedupe: true });
            return;
        }
        res.status(201).json({ ok: true, id: r.rows[0].id, status: r.rows[0].status });
    }
    catch {
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Purchase record failed.", req));
    }
});
// ---------- Client: list own purchases ----------
router.get("/purchases", auth_js_1.requireAuth, async (req, res) => {
    const parsed = zod_1.z.strictObject({ accountId: accountIdSchema }).safeParse(req.query);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid accountId.", req));
        return;
    }
    if ((0, auth_js_1.authSubOf)(req) !== parsed.data.accountId) {
        res.status(403).json((0, middleware_js_1.errorBody)("FORBIDDEN", "Token does not own this account.", req));
        return;
    }
    const client = await db_js_1.default.connect();
    try {
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.current_account_id', $1, true)", [parsed.data.accountId]);
        const r = await client.query("SELECT id, product_id, status, is_subscription, expires_at, verified_at, created_at FROM purchases WHERE account_id = $1 ORDER BY created_at DESC", [parsed.data.accountId]);
        await client.query("COMMIT");
        res.json({ purchases: r.rows });
    }
    catch {
        await client.query("ROLLBACK").catch(() => undefined);
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Purchase list failed.", req));
    }
    finally {
        client.release();
    }
});
// ---------- Google RTDN webhook (skeleton) ----------
// In production: verify the Pub/Sub push (OIDC token), decode the notification,
// call Play Developer API to verify the purchase, then update state.
router.post("/google/rtdn", async (req, res) => {
    // Optional shared-secret verification (defense in depth). In production, also
    // verify the Pub/Sub OIDC token. Set RTDN_SECRET in env to enforce.
    const secret = (process.env.RTDN_SECRET ?? "").trim();
    if (secret) {
        const provided = req.headers["x-rtdn-secret"] ?? "";
        if (provided !== secret) {
            console.warn(JSON.stringify({ level: "warn", msg: "rtdn_auth_reject", ip: req.ip }));
            res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Invalid RTDN secret.", req));
            return;
        }
    }
    try {
        const body = (req.body ?? {});
        const eventType = String(body.notificationType ?? body.eventType ?? "unknown");
        const token = typeof body.purchaseToken === "string" ? body.purchaseToken : null;
        const accountId = typeof body.accountId === "string" ? body.accountId : null;
        await db_js_1.default.query("INSERT INTO rtdn_events (event_type, account_id, purchase_token, payload) VALUES ($1, $2, $3, $4)", [eventType, accountId, token, body]);
        // Best-effort: if a purchase token is known, update its status based on event type.
        if (token) {
            const map = {
                SUBSCRIPTION_RENEWED: "verified",
                SUBSCRIPTION_CANCELED: "canceled",
                SUBSCRIPTION_EXPIRED: "expired",
                SUBSCRIPTION_REVOKED: "refunded",
                ONE_TIME_PRODUCT_PURCHASED: "verified",
                REFUND: "refunded",
            };
            const newStatus = map[eventType.toUpperCase()];
            if (newStatus) {
                await db_js_1.default.query("UPDATE purchases SET status = $1, updated_at = now() WHERE purchase_token = $2", [newStatus, token]);
            }
        }
        res.status(200).json({ ok: true });
    }
    catch {
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "RTDN processing failed.", req));
    }
});
exports.default = router;
