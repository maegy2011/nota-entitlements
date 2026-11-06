"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorBody = errorBody;
exports.requestIdMiddleware = requestIdMiddleware;
exports.getClientIp = getClientIp;
exports.accessLog = accessLog;
const node_crypto_1 = require("node:crypto");
function errorBody(code, message, req) {
    return { code, message, requestId: req.requestId };
}
/** Attach a requestId to every request; echoed in logs + error bodies. */
function requestIdMiddleware(req, _res, next) {
    req.requestId = (0, node_crypto_1.randomUUID)();
    next();
}
/**
 * Real client IP behind Cloudflare Tunnel.
 * Order: CF-Connecting-IP -> X-Real-IP (set by our nginx).
 * NEVER trust X-Forwarded-For here (spoofable, and always 127.0.0.1 behind tunnel).
 */
function getClientIp(req) {
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim())
        return cf.trim().split(",")[0].trim();
    const real = req.headers["x-real-ip"];
    if (typeof real === "string" && real.trim())
        return real.trim().split(",")[0].trim();
    return req.socket.remoteAddress ?? "unknown";
}
/** Structured access log. No PII (no accountId, no tokens, no bodies). */
function accessLog(req, res, ms) {
    console.log(JSON.stringify({
        level: "info",
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ip: getClientIp(req),
        ms,
    }));
}
