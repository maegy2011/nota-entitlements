-- 007-billing.sql — purchases + RTDN event log (Phase 3 billing skeleton).
DROP TABLE IF EXISTS purchases CASCADE;
CREATE TABLE purchases (
  id              BIGSERIAL PRIMARY KEY,
  account_id      TEXT NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
  product_id      TEXT NOT NULL,
  purchase_token  TEXT NOT NULL UNIQUE,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','verified','refunded','canceled','expired','rejected')),
  is_subscription BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at      TIMESTAMPTZ,
  verified_at     TIMESTAMPTZ,
  raw_payload     JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS purchases_account_idx ON purchases (account_id);
CREATE INDEX IF NOT EXISTS purchases_status_idx ON purchases (status);
CREATE INDEX IF NOT EXISTS purchases_product_idx ON purchases (product_id);
CREATE INDEX IF NOT EXISTS purchases_created_at_idx ON purchases (created_at DESC);

CREATE TABLE IF NOT EXISTS rtdn_events (
  id             BIGSERIAL PRIMARY KEY,
  event_type     TEXT NOT NULL,
  account_id     TEXT,
  purchase_token TEXT,
  payload        JSONB,
  processed      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rtdn_events_created_at_idx ON rtdn_events (created_at DESC);
