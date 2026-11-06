"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashPassword = hashPassword;
exports.verifyPassword = verifyPassword;
exports.createSession = createSession;
exports.resolveSession = resolveSession;
exports.hasPermission = hasPermission;
const node_crypto_1 = __importDefault(require("node:crypto"));
const db_js_1 = __importDefault(require("./db.js"));
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
async function hashPassword(password) {
    const salt = node_crypto_1.default.randomBytes(16);
    return new Promise((resolve, reject) => {
        node_crypto_1.default.scrypt(password, salt, 64, (err, derived) => {
            if (err)
                return reject(err);
            resolve(`${salt.toString("hex")}:${derived.toString("hex")}`);
        });
    });
}
async function verifyPassword(password, hash) {
    const [saltHex, keyHex] = hash.split(":");
    if (!saltHex || !keyHex)
        return false;
    const salt = Buffer.from(saltHex, "hex");
    const key = Buffer.from(keyHex, "hex");
    return new Promise((resolve, reject) => {
        node_crypto_1.default.scrypt(password, salt, 64, (err, derived) => {
            if (err)
                return reject(err);
            resolve(node_crypto_1.default.timingSafeEqual(derived, key));
        });
    });
}
async function createSession(adminUserId) {
    const token = node_crypto_1.default.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await db_js_1.default.query("INSERT INTO admin_sessions (token, admin_user_id, expires_at) VALUES ($1, $2, $3)", [token, adminUserId, expiresAt]);
    await db_js_1.default.query("UPDATE admin_users SET last_login_at = now() WHERE id = $1", [adminUserId]);
    return token;
}
async function resolveSession(token) {
    const r = await db_js_1.default.query(`SELECT s.expires_at, u.id, u.username, u.role, u.active, r.permissions
     FROM admin_sessions s
     JOIN admin_users u ON u.id = s.admin_user_id
     JOIN admin_roles r ON r.name = u.role
     WHERE s.token = $1`, [token]);
    if (r.rowCount === 0)
        return null;
    const row = r.rows[0];
    if (!row.active)
        return null;
    if (new Date(row.expires_at).getTime() <= Date.now()) {
        await db_js_1.default.query("DELETE FROM admin_sessions WHERE token = $1", [token]);
        return null;
    }
    return { id: row.id, username: row.username, role: row.role, permissions: row.permissions ?? [] };
}
function hasPermission(resolved, perm, isSuperToken) {
    if (isSuperToken)
        return true;
    if (!resolved)
        return false;
    return resolved.permissions.includes(perm) || resolved.permissions.includes("*");
}
