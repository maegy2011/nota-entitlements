-- 013-notifications-deletion.sql — in-app notifications + data deletion requests.
CREATE TABLE IF NOT EXISTS notifications (
  id         BIGSERIAL PRIMARY KEY,
  account_id TEXT REFERENCES users(account_id) ON DELETE CASCADE,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL,
  type       TEXT NOT NULL DEFAULT 'info' CHECK (type IN ('info','warning','critical','promo')),
  read       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_account_idx ON notifications (account_id, read, created_at DESC);

CREATE TABLE IF NOT EXISTS data_deletion_requests (
  id           BIGSERIAL PRIMARY KEY,
  account_id   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','completed','rejected')),
  reason       TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ,
  notes        TEXT
);
CREATE INDEX IF NOT EXISTS deletion_requests_status_idx ON data_deletion_requests (status, requested_at DESC);
