import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export type ApiError = { code: string; message: string; requestId: string };

export function errorBody(code: string, message: string, req: Request): ApiError {
  return { code, message, requestId: req.requestId };
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      requestId: string;
    }
  }
}

/** Attach a requestId to every request; echoed in logs + error bodies. */
export function requestIdMiddleware(req: Request, _res: Response, next: NextFunction): void {
  req.requestId = randomUUID();
  next();
}

/**
 * Real client IP behind Cloudflare Tunnel.
 * Order: CF-Connecting-IP -> X-Real-IP (set by our nginx).
 * NEVER trust X-Forwarded-For here (spoofable, and always 127.0.0.1 behind tunnel).
 */
export function getClientIp(req: Request): string {
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf.trim()) return cf.trim().split(",")[0].trim();
  const real = req.headers["x-real-ip"];
  if (typeof real === "string" && real.trim()) return real.trim().split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

/** Structured access log. No PII (no accountId, no tokens, no bodies). */
export function accessLog(req: Request, res: Response, ms: number): void {
  console.log(
    JSON.stringify({
      level: "info",
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ip: getClientIp(req),
      ms,
    }),
  );
}
