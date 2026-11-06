"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const db_js_1 = __importDefault(require("./db.js"));
const middleware_js_1 = require("./middleware.js");
const router = (0, express_1.Router)();
const planCodeSchema = zod_1.z.string().min(1).max(64).regex(/^[a-z0-9_]+$/);
const planTypeSchema = zod_1.z.enum(["subscription", "storage", "feature", "trial"]);
const billingPeriodSchema = zod_1.z.enum(["monthly", "yearly", "lifetime", "one_time"]).optional();
const planSchema = zod_1.z.strictObject({
    code: planCodeSchema,
    name: zod_1.z.string().min(1).max(128),
    type: planTypeSchema,
    description: zod_1.z.string().max(512).optional(),
    priceCents: zod_1.z.number().int().min(0).max(1000000).default(0),
    currency: zod_1.z.string().length(3).default("USD"),
    billingPeriod: billingPeriodSchema,
    features: zod_1.z.array(zod_1.z.string().min(1).max(64)).max(64).default([]),
    quotaBytes: zod_1.z.number().int().min(0).max(10 * 1024 * 1024 * 1024 * 1024).default(0),
    active: zod_1.z.boolean().default(true),
    sortOrder: zod_1.z.number().int().min(0).max(100000).default(0),
});
// ---------- Public: list active plans ----------
router.get("/plans", async (_req, res) => {
    try {
        const r = await db_js_1.default.query("SELECT code, name, type, description, price_cents, currency, billing_period, features, quota_bytes, sort_order FROM plans WHERE active = TRUE ORDER BY sort_order ASC, name ASC");
        res.json({ plans: r.rows });
    }
    catch {
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plans list failed.", _req));
    }
});
// ---------- Public: get one plan ----------
router.get("/plans/:code", async (req, res) => {
    const parsed = planCodeSchema.safeParse(req.params.code);
    if (!parsed.success) {
        res.status(400).json((0, middleware_js_1.errorBody)("VALIDATION_ERROR", "Invalid plan code.", req));
        return;
    }
    try {
        const r = await db_js_1.default.query("SELECT * FROM plans WHERE code = $1", [parsed.data]);
        if (r.rowCount === 0) {
            res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Plan not found.", req));
            return;
        }
        res.json({ plan: r.rows[0] });
    }
    catch {
        res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Plan lookup failed.", req));
    }
});
exports.default = router;
