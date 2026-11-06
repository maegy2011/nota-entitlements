"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadServiceAccount = loadServiceAccount;
exports.packageName = packageName;
exports.isConfigured = isConfigured;
exports.fetchReviews = fetchReviews;
exports.verifySubscription = verifySubscription;
exports.verifyProduct = verifyProduct;
exports.acknowledgeSubscription = acknowledgeSubscription;
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_https_1 = __importDefault(require("node:https"));
let cachedAccount = null;
let cachedToken = null;
function loadServiceAccount() {
    if (cachedAccount)
        return cachedAccount;
    const inline = process.env.PLAY_SERVICE_ACCOUNT_JSON;
    const path = process.env.PLAY_SERVICE_ACCOUNT;
    try {
        let raw = "";
        if (inline)
            raw = inline;
        else if (path)
            raw = node_fs_1.default.readFileSync(path, "utf-8");
        else
            return null;
        const j = JSON.parse(raw);
        if (!j.client_email || !j.private_key)
            return null;
        cachedAccount = j;
        return j;
    }
    catch {
        return null;
    }
}
function packageName() {
    return (process.env.PLAY_PACKAGE_NAME ?? "").trim() || null;
}
function isConfigured() {
    return loadServiceAccount() !== null && packageName() !== null;
}
function b64url(buf) {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function signJwt(sa, scope) {
    const header = { alg: "RS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const claims = {
        iss: sa.client_email,
        scope,
        aud: "https://oauth2.googleapis.com/token",
        iat: now,
        exp: now + 3600,
    };
    const h = b64url(Buffer.from(JSON.stringify(header)));
    const c = b64url(Buffer.from(JSON.stringify(claims)));
    const input = `${h}.${c}`;
    const sign = node_crypto_1.default.createSign("RSA-SHA256");
    sign.update(input);
    const sig = sign.sign(sa.private_key);
    return `${input}.${b64url(sig)}`;
}
async function fetchAccessToken(sa, scope) {
    if (cachedToken && cachedToken.expiresAt > Date.now() + 60_000)
        return cachedToken.token;
    const jwt = await signJwt(sa, scope);
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${encodeURIComponent(jwt)}`;
    const token = await new Promise((resolve, reject) => {
        const req = node_https_1.default.request("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) } }, (res) => {
            let raw = "";
            res.on("data", (c) => (raw += c));
            res.on("end", () => {
                try {
                    const j = JSON.parse(raw);
                    if (!j.access_token)
                        reject(new Error(j.error_description || j.error || "no access_token"));
                    else {
                        cachedToken = { token: j.access_token, expiresAt: Date.now() + (j.expires_in ?? 3600) * 1000 };
                        resolve(j.access_token);
                    }
                }
                catch (e) {
                    reject(e);
                }
            });
        });
        req.on("error", reject);
        req.write(body);
        req.end();
    });
    return token;
}
async function apiGet(path, scope = "https://www.googleapis.com/auth/androidpublisher") {
    const sa = loadServiceAccount();
    if (!sa)
        throw new Error("service account not configured");
    const token = await fetchAccessToken(sa, scope);
    const pkg = packageName();
    if (!pkg)
        throw new Error("package name not configured");
    const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(pkg)}${path}`;
    return new Promise((resolve, reject) => {
        node_https_1.default.get(url, { headers: { Authorization: `Bearer ${token}` } }, (res) => {
            let raw = "";
            res.on("data", (c) => (raw += c));
            res.on("end", () => {
                try {
                    const j = JSON.parse(raw);
                    if (res.statusCode && res.statusCode >= 400)
                        reject(new Error(j?.error?.message || `HTTP ${res.statusCode}`));
                    else
                        resolve(j);
                }
                catch (e) {
                    reject(e);
                }
            });
        }).on("error", reject);
    });
}
async function apiPost(path, body, scope = "https://www.googleapis.com/auth/androidpublisher") {
    const sa = loadServiceAccount();
    if (!sa)
        throw new Error("service account not configured");
    const token = await fetchAccessToken(sa, scope);
    const pkg = packageName();
    if (!pkg)
        throw new Error("package name not configured");
    const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(pkg)}${path}`;
    const data = JSON.stringify(body ?? {});
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const req = node_https_1.default.request({ hostname: u.hostname, path: u.pathname + u.search, method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } }, (res) => {
            let raw = "";
            res.on("data", (c) => (raw += c));
            res.on("end", () => {
                try {
                    const j = raw ? JSON.parse(raw) : {};
                    if (res.statusCode && res.statusCode >= 400)
                        reject(new Error(j?.error?.message || `HTTP ${res.statusCode}`));
                    else
                        resolve(j);
                }
                catch (e) {
                    reject(e);
                }
            });
        });
        req.on("error", reject);
        req.write(data);
        req.end();
    });
}
async function fetchReviews(maxResults = 50) {
    return apiGet(`/reviews?maxResults=${maxResults}`);
}
async function verifySubscription(subscriptionId, purchaseToken) {
    return apiGet(`/purchases/subscriptions/${encodeURIComponent(subscriptionId)}/tokens/${encodeURIComponent(purchaseToken)}`);
}
async function verifyProduct(productId, purchaseToken) {
    return apiGet(`/purchases/products/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(purchaseToken)}`);
}
async function acknowledgeSubscription(subscriptionId, purchaseToken) {
    return apiPost(`/purchases/subscriptions/${encodeURIComponent(subscriptionId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`, {});
}
