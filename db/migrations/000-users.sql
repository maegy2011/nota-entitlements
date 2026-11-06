-- 000-users.sql — base account table (referenced by all later migrations).
-- Owned by postgres; the service connects as least-privilege role nota_svc.

CREATE TABLE IF NOT EXISTS users (
  account_id       TEXT PRIMARY KEY,
  google_sub       TEXT,
  trial_used       BOOLEAN NOT NULL DEFAULT FALSE,
  trial_started_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_google_sub_idx ON users (google_sub);