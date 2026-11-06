# Nota Server — Code Review Report

**Date:** 2026-11-06
**Scope:** `src/` (index, auth, routes, cloud, storage, trial, middleware, db) + migrations
**Verdict:** Comment (no critical bugs; 1 doc gap fixed, minor perf fix applied)

## Summary

Express 5 + Postgres backend for entitlements + Nota Cloud (blob store with quota metering). Strong security posture: Firebase ID token (RS256) verification via stdlib, per-account ownership checks on every route, parameterized SQL, helmet, rate limiting by real client IP, no stack traces to clients, atomic quota transactions. Two small fixes applied; one documentation gap (missing base `users` table migration) addressed.

## Applied fixes

1. **`db/migrations/000-users.sql`** (new) — base `users` table referenced by all later migrations but never defined in-repo. Now documented and re-runnable (`CREATE TABLE IF NOT EXISTS`).
2. **`src/storage.ts` `ensureDiskSpace`** — collapsed double `statfsSync(BLOBS_DIR)` into a single call (minor perf; correctness unchanged).
3. Rebuilt `dist/` via `tsc` and restarted `nota-entitlements` PM2 service; `/health` returns `{"ok":true}`.

## Findings

### Security (OWASP baseline)
| Check | Status |
|---|---|
| SQL injection | ✅ parameterized queries everywhere (`$1`, `$2`) |
| Auth | ✅ Firebase RS256 verification with cert cache, aud/iss/sub/exp checks |
| Ownership | ✅ `authSubOf(req) !== accountId` → 403 on every account-scoped route |
| Rate limiting | ✅ 120/min global, 20/min uploads, keyed by real client IP (CF-Connecting-IP) |
| Trust proxy | ✅ `trust proxy: false`; reads CF-Connecting-IP, never XFF |
| Helmet | ✅ default headers |
| Body size | ✅ `express.json({ limit: "16kb" })` for JSON; `express.raw` capped at `MAX_FILE_BYTES+1024` |
| No stack traces | ✅ 404/500 envelopes without paths or stacks |
| Secrets | ✅ `.env` not committed; `.env.example` provided |
| TEST_MODE gate | ✅ `TEST_MODE=false` in prod; `/test/simulate` returns 403 otherwise |
| Path traversal | ✅ `blobKey` uses `sha256Hex(accountId)` (hex only) + sha256 path |
| Quota atomicity | ✅ `SELECT ... FOR UPDATE` + transaction; GREATEST(0, ...) on free |

### Performance
- `ensureDiskSpace` double statfsSync (fixed).
- `quotaState`/`registered` called redundantly in some handlers — acceptable for current load.
- Chunk finalize reads up to 32MB into memory — fine for MAX_FILE_BYTES=32MB.

### Robustness
- `FilesystemBackend.put`: atomic tmp+rename, no fsync (minor durability; acceptable).
- `DELETE /v1/account`: best-effort blob removal then cascade delete; orphaned disk files possible if removal fails (minor).
- `writeChunk`: sparse-file holes possible on out-of-order offsets; final sha256 check catches incomplete (good).
- `ensureDiskSpace`: skips check when BLOBS_DIR missing (first boot) — write surfaces real error. Acceptable.

### Minor
- `trial.ts`: `TRIAL_EXPIRES_AT=2026-10-11` is in the past → trial inactive. Update env if beta trial should continue.
- `cloud.ts`: `mimeSchema` default `application/octet-stream`; client always sends octet-stream. Fine.
- `auth.ts`: `b64urlToBuf` relies on Node's lenient base64 decoder for unpadded segments (works in practice).

## Positive feedback
- Clean auth posture: 401 before any other check; sub binding enforced.
- Idempotent registration, trial start, chunked upload, account deletion.
- Quota meter is reconcilable (`/cloud/reconcile`).
- No data lock-in: downloads always allowed; quota never blocks reads.
- Structured JSON logging with requestId; no PII in access logs.

## Open items
- Add a migration runner or document the manual apply procedure (skill `nota-server-migration` exists).
- Consider requiring auth/secret header on `/test/simulate` even behind TEST_MODE (defense in depth).
- Consider fsync in `FilesystemBackend.put` for crash durability.
- Update `TRIAL_EXPIRES_AT` if beta trial should remain active.