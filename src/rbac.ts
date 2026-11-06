import crypto from "node:crypto";
import pool from "./db.js";

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) return reject(err);
      resolve(`${salt.toString("hex")}:${derived.toString("hex")}`);
    });
  });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const [saltHex, keyHex] = hash.split(":");
  if (!saltHex || !keyHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const key = Buffer.from(keyHex, "hex");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) return reject(err);
      resolve(crypto.timingSafeEqual(derived, key));
    });
  });
}

export async function createSession(adminUserId: number): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await pool.query("INSERT INTO admin_sessions (token, admin_user_id, expires_at) VALUES ($1, $2, $3)", [token, adminUserId, expiresAt]);
  await pool.query("UPDATE admin_users SET last_login_at = now() WHERE id = $1", [adminUserId]);
  return token;
}

export interface ResolvedAdmin {
  id: number;
  username: string;
  role: string;
  permissions: string[];
}

export async function resolveSession(token: string): Promise<ResolvedAdmin | null> {
  const r = await pool.query(
    `SELECT s.expires_at, u.id, u.username, u.role, u.active, r.permissions
     FROM admin_sessions s
     JOIN admin_users u ON u.id = s.admin_user_id
     JOIN admin_roles r ON r.name = u.role
     WHERE s.token = $1`,
    [token],
  );
  if (r.rowCount === 0) return null;
  const row = r.rows[0];
  if (!row.active) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await pool.query("DELETE FROM admin_sessions WHERE token = $1", [token]);
    return null;
  }
  return { id: row.id, username: row.username, role: row.role, permissions: row.permissions ?? [] };
}

export function hasPermission(resolved: ResolvedAdmin | null, perm: string, isSuperToken: boolean): boolean {
  if (isSuperToken) return true;
  if (!resolved) return false;
  return resolved.permissions.includes(perm) || resolved.permissions.includes("*");
}
