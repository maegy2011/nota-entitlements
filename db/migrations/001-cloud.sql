-- 001-cloud.sql — Nota Cloud Phase A: quotas + file registry.
-- Blobs live on disk/R2 under <accountHash>/<sha256>; Postgres holds metadata only.
-- R2-ready: content-addressed keys never change whatever backend serves them.

CREATE TABLE IF NOT EXISTS quotas (
  account_id  TEXT PRIMARY KEY REFERENCES users(account_id) ON DELETE CASCADE,
  used_bytes  BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cloud_files (
  account_id  TEXT NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
  sha256      TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes  BIGINT NOT NULL CHECK (size_bytes > 0),
  mime        TEXT NOT NULL DEFAULT 'application/octet-stream',
  stored_r2   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, sha256)
);

CREATE INDEX IF NOT EXISTS cloud_files_account_idx ON cloud_files (account_id);
