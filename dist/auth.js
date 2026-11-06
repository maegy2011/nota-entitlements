"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyIdToken = verifyIdToken;
exports.bearerOf = bearerOf;
exports.requireAuth = requireAuth;
exports.authSubOf = authSubOf;
const crypto_1 = __importDefault(require("crypto"));
const https_1 = __importDefault(require("https"));
const middleware_js_1 = require("./middleware.js");
const db_js_1 = __importDefault(require("./db.js"));
// المرحلة 3 — المصادقة الموثقة: السيرفر يتحقق من توكن Firebase ID (RS256) بنفسه.
// لا كلمة مرور تُرسل أبدًا، ولا ثقة عمياء في accountId بعد اليوم: كل طلب مقيد
// يثبت ملكية الحساب عبر sub داخل توكن موقّع من جوجل. stdlib فقط — بلا اعتماديات.
// القاعدة الدائمة: 401 قبل أي تحقق آخر — الهوية أولًا.
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID ?? "";
const AUTHORIZED_PARTIES = (process.env.FIREBASE_AUTHORIZED_PARTIES ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;
const CLOCK_SKEW_S = 30;
let cache = { keys: new Map(), expiresAt: 0 };
function fetchCerts() {
    return new Promise((resolve, reject) => {
        https_1.default
            .get(CERTS_URL, { timeout: 8000 }, (res) => {
            let raw = "";
            res.on("data", (c) => (raw += c));
            res.on("end", () => {
                if (res.statusCode !== 200) {
                    reject(new Error(`certs HTTP ${res.statusCode}`));
                    return;
                }
                const maxAge = Number(/max-age=(\d+)/.exec(res.headers["cache-control"] ?? "")?.[1] ?? 3600);
                resolve({ keys: JSON.parse(raw), maxAge });
            });
        })
            .on("error", reject)
            .on("timeout", function () {
            this.destroy(new Error("certs timeout"));
        });
    });
}
async function publicKeyFor(kid) {
    if (Date.now() < cache.expiresAt) {
        const hit = cache.keys.get(kid);
        if (hit)
            return hit;
        // kid مجهول والكاش ما زال ساريًا: ربما دارت جوجل المفاتيح — أعد الجلب مرة واحدة
        // قبل الرفض، وإلا رفضنا توكنات صالحة حتى انتهاء max-age.
        try {
            const { keys, maxAge } = await fetchCerts();
            cache = { keys: new Map(Object.entries(keys)), expiresAt: Date.now() + maxAge * 1000 };
            return cache.keys.get(kid) ?? null;
        }
        catch {
            return null;
        }
    }
    const { keys, maxAge } = await fetchCerts();
    cache = { keys: new Map(Object.entries(keys)), expiresAt: Date.now() + maxAge * 1000 };
    return cache.keys.get(kid) ?? null;
}
function b64urlToBuf(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    return Buffer.from(b64 + pad, "base64");
}
// يرمي عند أي فشل — ويرجع sub (Firebase UID) عند النجاح.
async function verifyIdToken(token) {
    if (PROJECT_ID === "")
        throw new Error("FIREBASE_PROJECT_ID not configured");
    const parts = token.split(".");
    if (parts.length !== 3)
        throw new Error("malformed token");
    const header = JSON.parse(b64urlToBuf(parts[0]).toString("utf-8"));
    if (header.alg !== "RS256" || !header.kid)
        throw new Error("bad header");
    const pem = await publicKeyFor(header.kid);
    if (!pem)
        throw new Error("unknown kid");
    const ok = crypto_1.default.verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), crypto_1.default.createPublicKey(pem), b64urlToBuf(parts[2]));
    if (!ok)
        throw new Error("bad signature");
    const payload = JSON.parse(b64urlToBuf(parts[1]).toString("utf-8"));
    const now = Math.floor(Date.now() / 1000);
    if (payload.aud !== PROJECT_ID)
        throw new Error("bad audience");
    if (payload.iss !== ISSUER)
        throw new Error("bad issuer");
    if (!payload.sub)
        throw new Error("no sub");
    if (typeof payload.exp !== "number" || payload.exp <= now - CLOCK_SKEW_S)
        throw new Error("expired");
    if (typeof payload.iat === "number" && payload.iat > now + CLOCK_SKEW_S)
        throw new Error("bad iat");
    // nbf (not-before): token must not be used before this time.
    if (typeof payload.nbf === "number" && payload.nbf > now + CLOCK_SKEW_S)
        throw new Error("nbf");
    // azp (authorized party): if configured, enforce membership; otherwise lenient.
    if (payload.azp) {
        if (AUTHORIZED_PARTIES.length > 0) {
            if (!AUTHORIZED_PARTIES.includes(payload.azp))
                throw new Error("bad azp");
        }
        else if (payload.azp !== PROJECT_ID && payload.azp !== payload.aud) {
            // Lenient default: allow azp equal to aud or project id; log otherwise.
            console.warn(JSON.stringify({ level: "warn", msg: "azp_mismatch", azp: payload.azp.slice(0, 32), aud: payload.aud }));
        }
    }
    return payload.sub;
}
function bearerOf(req) {
    const h = req.headers.authorization;
    if (!h)
        return null;
    const m = /^Bearer (.+)$/.exec(h.trim());
    return m ? m[1] : null;
}
// يثبت req.authSub أو يرد 401 — يُوضع قبل أي تحقق آخر في المسارات المقيدة.
async function requireAuth(req, res, next) {
    const token = bearerOf(req);
    if (!token) {
        // بلا PII: السبب فقط (غائب) — للتمييز عن التوكن التالف في السجلات (درس 27 سبتمبر 2026)
        console.warn(JSON.stringify({ level: "warn", msg: "auth_reject", reason: "missing_bearer", firebaseConfigured: PROJECT_ID !== "", path: req.path }));
        res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Missing bearer token.", req));
        return;
    }
    try {
        const sub = await verifyIdToken(token);
        req.authSub = sub;
        // Best-effort activity tracking (fire-and-forget; never blocks the request).
        db_js_1.default.query("UPDATE users SET last_seen_at = now() WHERE google_sub = $1", [sub]).catch(() => undefined);
        next();
    }
    catch (err) {
        // سبب الرفض فقط (expired/bad_audience/...) — بلا توكن ولا هوية في السجلات أبدًا
        const detail = err instanceof Error ? err.message.slice(0, 32) : "unknown";
        console.warn(JSON.stringify({ level: "warn", msg: "auth_reject", reason: "invalid_token", detail, firebaseConfigured: PROJECT_ID !== "", path: req.path }));
        res.status(401).json((0, middleware_js_1.errorBody)("UNAUTHENTICATED", "Invalid or expired token.", req));
    }
}
function authSubOf(req) {
    return req.authSub ?? null;
}
