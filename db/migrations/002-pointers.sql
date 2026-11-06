-- 002-pointers.sql — named blob pointers per account (e.g. backup_latest).
-- Lets any device find the newest backup without listing blobs.

CREATE TABLE IF NOT EXISTS cloud_pointers (
  account_id  TEXT NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
  name        TEXT NOT NULL CHECK (name ~ '^[a-z_]{1,32}$'),
  sha256      TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, name)
);
