import { Router } from "express";
import type { Request, Response } from "express";
import { z } from "zod";
import pool from "./db.js";
import { errorBody } from "./middleware.js";
import { authSubOf, requireAuth } from "./auth.js";

const router = Router();

const planCodeSchema = z.string().min(1).max(64).regex(/^[a-z0-9_]+$/);
const planTypeSchema = z.enum(["subscription", "storage", "feature", "trial"]);
const billingPeriodSchema = z.enum(["monthly", "yearly", "lifetime", "one_time"]).optional();

const planSchema = z.strictObject({
  code: planCodeSchema,
  name: z.string().min(1).max(128),
  type: planTypeSchema,
  description: z.string().max(512).optional(),
  priceCents: z.number().int().min(0).max(1000000).default(0),
  currency: z.string().length(3).default("USD"),
  billingPeriod: billingPeriodSchema,
  features: z.array(z.string().min(1).max(64)).max(64).default([]),
  quotaBytes: z.number().int().min(0).max(10 * 1024 * 1024 * 1024 * 1024).default(0),
  active: z.boolean().default(true),
  sortOrder: z.number().int().min(0).max(100000).default(0),
});

// ---------- Public: list active plans ----------
router.get("/plans", async (_req: Request, res: Response) => {
  try {
    const r = await pool.query(
      "SELECT code, name, type, description, price_cents, currency, billing_period, features, quota_bytes, sort_order FROM plans WHERE active = TRUE ORDER BY sort_order ASC, name ASC",
    );
    res.json({ plans: r.rows });
  } catch {
    res.status(500).json(errorBody("INTERNAL_ERROR", "Plans list failed.", _req));
  }
});

// ---------- Public: get one plan ----------
router.get("/plans/:code", async (req: Request, res: Response) => {
  const parsed = planCodeSchema.safeParse(req.params.code);
  if (!parsed.success) {
    res.status(400).json(errorBody("VALIDATION_ERROR", "Invalid plan code.", req));
    return;
  }
  try {
    const r = await pool.query("SELECT * FROM plans WHERE code = $1", [parsed.data]);
    if (r.rowCount === 0) {
      res.status(404).json(errorBody("NOT_FOUND", "Plan not found.", req));
      return;
    }
    res.json({ plan: r.rows[0] });
  } catch {
    res.status(500).json(errorBody("INTERNAL_ERROR", "Plan lookup failed.", req));
  }
});

export default router;
