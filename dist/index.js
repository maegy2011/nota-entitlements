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
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const routes_js_1 = __importDefault(require("./routes.js"));
const cloud_js_1 = __importDefault(require("./cloud.js"));
const admin_js_1 = __importDefault(require("./admin.js"));
const billing_js_1 = __importDefault(require("./billing.js"));
const plans_js_1 = __importDefault(require("./plans.js"));
const control_js_1 = __importDefault(require("./control.js"));
const db_js_1 = __importStar(require("./db.js"));
const middleware_js_1 = require("./middleware.js");
const PORT = Number(process.env.PORT ?? 3111);
const HOST = process.env.HOST ?? "127.0.0.1";
const app = (0, express_1.default)();
app.disable("x-powered-by");
app.set("trust proxy", false); // we read CF-Connecting-IP ourselves; never trust XFF
app.use((0, helmet_1.default)({
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    contentSecurityPolicy: false, // CSP set per-route (admin dashboard uses nonces)
}));
app.use(express_1.default.json({ limit: "16kb" }));
app.use(middleware_js_1.requestIdMiddleware);
// Access log with latency. No PII.
app.use((req, _res, next) => {
    const t0 = Date.now();
    _res.on("finish", () => (0, middleware_js_1.accessLog)(req, _res, Date.now() - t0));
    next();
});
// Rate limit by REAL client IP (CF-Connecting-IP -> X-Real-IP), early in pipeline.
const limiter = (0, express_rate_limit_1.default)({
    windowMs: 60_000,
    limit: 120,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    keyGenerator: (req) => (0, middleware_js_1.getClientIp)(req),
    handler: (req, res) => {
        res.status(429).json((0, middleware_js_1.errorBody)("RATE_LIMITED", "Too many requests.", req));
    },
});
app.use("/v1/", limiter);
// Cheap liveness: no DB hit.
app.get("/health", (_req, res) => {
    res.status(200).json({ ok: true });
});
// Per-account rate limiter (defense against shared-NAT starvation).
// Keys on accountId (body/query/params) when present, otherwise falls back to IP.
const accountLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60_000,
    limit: 60,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    keyGenerator: (req) => {
        const body = (req.body && typeof req.body === "object") ? req.body : {};
        const acct = (typeof body.accountId === "string" && body.accountId)
            || (typeof req.query?.accountId === "string" && req.query.accountId)
            || (typeof req.params?.accountId === "string" && req.params.accountId)
            || null;
        if (acct)
            return `acct:${acct}`;
        return (0, middleware_js_1.getClientIp)(req);
    },
    handler: (req, res) => {
        res.status(429).json((0, middleware_js_1.errorBody)("RATE_LIMITED", "Too many requests for this account.", req));
    },
});
app.use("/v1/", accountLimiter);
app.use("/v1", routes_js_1.default);
app.use("/v1", cloud_js_1.default);
app.use("/v1", billing_js_1.default);
app.use("/v1", plans_js_1.default);
app.use("/v1", control_js_1.default);
app.use(admin_js_1.default);
// 404 envelope (no stack, no path echo).
app.use((req, res) => {
    res.status(404).json((0, middleware_js_1.errorBody)("NOT_FOUND", "Not found.", req));
});
// 500 envelope (no stack traces to clients, ever).
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err, req, res, _next) => {
    console.error(JSON.stringify({ level: "error", requestId: req.requestId, msg: "unhandled", err: String(err) }));
    res.status(500).json((0, middleware_js_1.errorBody)("INTERNAL_ERROR", "Unexpected error.", req));
});
const server = app.listen(PORT, HOST, async () => {
    // Readiness: DB must answer before we accept traffic. Exit -> PM2 retries.
    try {
        await (0, db_js_1.readinessCheck)();
        console.log(JSON.stringify({ level: "info", msg: "nota-entitlements up", host: HOST, port: PORT, firebaseConfigured: Boolean(process.env.FIREBASE_PROJECT_ID) }));
    }
    catch (err) {
        console.error(JSON.stringify({ level: "error", msg: "db_readiness_failed", err: String(err) }));
        process.exit(1);
    }
});
// Graceful shutdown: drain, then close pool.
function shutdown(signal) {
    console.log(JSON.stringify({ level: "info", msg: "shutdown", signal }));
    server.close(() => {
        db_js_1.default.end().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
