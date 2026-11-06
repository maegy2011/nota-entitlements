-- 006-audit.sql — admin action audit log.
CREATE TABLE IF NOT EXISTS admin_audit (
  id          BIGSERIAL PRIMARY KEY,
  action      TEXT NOT NULL,
  account_id  TEXT,
  actor_ip    TEXT,
  detail      JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_audit_created_at_idx ON admin_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_account_idx ON admin_audit (account_id);
