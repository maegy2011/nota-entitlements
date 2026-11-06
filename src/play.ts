import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
// Google Play Developer API client (service-account JWT auth). Pure module, no Express.
// Configure via env: PLAY_PACKAGE_NAME and PLAY_SERVICE_ACCOUNT (path to JSON) or
// PLAY_SERVICE_ACCOUNT_JSON (inline JSON string).

export interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id?: string;
}

let cachedAccount: ServiceAccount | null = null;
let cachedToken: { token: string; expiresAt: number } | null = null;

export function loadServiceAccount(): ServiceAccount | null {
  if (cachedAccount) return cachedAccount;
  const inline = process.env.PLAY_SERVICE_ACCOUNT_JSON;
  const path = process.env.PLAY_SERVICE_ACCOUNT;
  try {
    let raw = "";
    if (inline) raw = inline;
    else if (path) raw = fs.readFileSync(path, "utf-8");
    else return null;
    const j = JSON.parse(raw) as ServiceAccount;
    if (!j.client_email || !j.private_key) return null;
    cachedAccount = j;
    return j;
  } catch {
    return null;
  }
}

export function packageName(): string | null {
  return (process.env.PLAY_PACKAGE_NAME ?? "").trim() || null;
}

export function isConfigured(): boolean {
  return loadServiceAccount() !== null && packageName() !== null;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function signJwt(sa: ServiceAccount, scope: string): Promise<string> {
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
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(input);
  const sig = sign.sign(sa.private_key);
  return `${input}.${b64url(sig)}`;
}

async function fetchAccessToken(sa: ServiceAccount, scope: string): Promise<string> {
  if (cachedToken && cachedToken.expiresAt > Date.now() + 60_000) return cachedToken.token;
  const jwt = await signJwt(sa, scope);
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${encodeURIComponent(jwt)}`;
  const token = await new Promise<string>((resolve, reject) => {
    const req = https.request(
      "https://oauth2.googleapis.com/token",
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try {
            const j = JSON.parse(raw) as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
            if (!j.access_token) reject(new Error(j.error_description || j.error || "no access_token"));
            else {
              cachedToken = { token: j.access_token, expiresAt: Date.now() + (j.expires_in ?? 3600) * 1000 };
              resolve(j.access_token);
            }
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
  return token;
}

async function apiGet(path: string, scope = "https://www.googleapis.com/auth/androidpublisher"): Promise<unknown> {
  const sa = loadServiceAccount();
  if (!sa) throw new Error("service account not configured");
  const token = await fetchAccessToken(sa, scope);
  const pkg = packageName();
  if (!pkg) throw new Error("package name not configured");
  const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(pkg)}${path}`;
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { Authorization: `Bearer ${token}` } }, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => {
        try {
          const j = JSON.parse(raw);
          if (res.statusCode && res.statusCode >= 400) reject(new Error(j?.error?.message || `HTTP ${res.statusCode}`));
          else resolve(j);
        } catch (e) {
          reject(e);
        }
      });
    }).on("error", reject);
  });
}

async function apiPost(path: string, body: unknown, scope = "https://www.googleapis.com/auth/androidpublisher"): Promise<unknown> {
  const sa = loadServiceAccount();
  if (!sa) throw new Error("service account not configured");
  const token = await fetchAccessToken(sa, scope);
  const pkg = packageName();
  if (!pkg) throw new Error("package name not configured");
  const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(pkg)}${path}`;
  const data = JSON.stringify(body ?? {});
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      { hostname: u.hostname, path: u.pathname + u.search, method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try {
            const j = raw ? JSON.parse(raw) : {};
            if (res.statusCode && res.statusCode >= 400) reject(new Error(j?.error?.message || `HTTP ${res.statusCode}`));
            else resolve(j);
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

export async function fetchReviews(maxResults = 50): Promise<unknown> {
  return apiGet(`/reviews?maxResults=${maxResults}`);
}

export async function verifySubscription(subscriptionId: string, purchaseToken: string): Promise<unknown> {
  return apiGet(`/purchases/subscriptions/${encodeURIComponent(subscriptionId)}/tokens/${encodeURIComponent(purchaseToken)}`);
}

export async function verifyProduct(productId: string, purchaseToken: string): Promise<unknown> {
  return apiGet(`/purchases/products/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(purchaseToken)}`);
}

export async function acknowledgeSubscription(subscriptionId: string, purchaseToken: string): Promise<unknown> {
  return apiPost(`/purchases/subscriptions/${encodeURIComponent(subscriptionId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`, {});
}

