import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import v1 from "./routes.js";
import cloud from "./cloud.js";
import admin from "./admin.js";
import billing from "./billing.js";
import plans from "./plans.js";
import control from "./control.js";
import pool, { readinessCheck } from "./db.js";
import { accessLog, errorBody, getClientIp, requestIdMiddleware } from "./middleware.js";

const PORT = Number(process.env.PORT ?? 3111);
const HOST = process.env.HOST ?? "127.0.0.1";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", false); // we read CF-Connecting-IP ourselves; never trust XFF
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: false, // CSP set per-route (admin dashboard uses nonces)
}));
app.use(express.json({ limit: "16kb" }));
app.use(requestIdMiddleware);

// Access log with latency. No PII.
app.use((req, _res, next) => {
  const t0 = Date.now();
  _res.on("finish", () => accessLog(req, _res, Date.now() - t0));
  next();
});

// Rate limit by REAL client IP (CF-Connecting-IP -> X-Real-IP), early in pipeline.
const limiter = rateLimit({
  windowMs: 60_000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    res.status(429).json(errorBody("RATE_LIMITED", "Too many requests.", req));
  },
});
app.use("/v1/", limiter);

// Cheap liveness: no DB hit.
app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true });
});

// Per-account rate limiter (defense against shared-NAT starvation).
// Keys on accountId (body/query/params) when present, otherwise falls back to IP.
const accountLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req) => {
    const body = (req.body && typeof req.body === "object") ? req.body as Record<string, unknown> : {};
    const acct = (typeof body.accountId === "string" && body.accountId)
      || (typeof req.query?.accountId === "string" && req.query.accountId)
      || (typeof req.params?.accountId === "string" && req.params.accountId)
      || null;
    if (acct) return `acct:${acct}`;
    return getClientIp(req);
  },
  handler: (req, res) => {
    res.status(429).json(errorBody("RATE_LIMITED", "Too many requests for this account.", req));
  },
});
app.use("/v1/", accountLimiter);

app.use("/v1", v1);
app.use("/v1", cloud);
app.use("/v1", billing);
app.use("/v1", plans);
app.use("/v1", control);
app.use(admin);

// 404 envelope (no stack, no path echo).
app.use((req, res) => {
  res.status(404).json(errorBody("NOT_FOUND", "Not found.", req));
});

// 500 envelope (no stack traces to clients, ever).
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(JSON.stringify({ level: "error", requestId: req.requestId, msg: "unhandled", err: String(err) }));
  res.status(500).json(errorBody("INTERNAL_ERROR", "Unexpected error.", req));
});

const server = app.listen(PORT, HOST, async () => {
  // Readiness: DB must answer before we accept traffic. Exit -> PM2 retries.
  try {
    await readinessCheck();
    console.log(JSON.stringify({ level: "info", msg: "nota-entitlements up", host: HOST, port: PORT, firebaseConfigured: Boolean(process.env.FIREBASE_PROJECT_ID) }));
  } catch (err) {
    console.error(JSON.stringify({ level: "error", msg: "db_readiness_failed", err: String(err) }));
    process.exit(1);
  }
});

// Graceful shutdown: drain, then close pool.
function shutdown(signal: string): void {
  console.log(JSON.stringify({ level: "info", msg: "shutdown", signal }));
  server.close(() => {
    pool.end().finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
