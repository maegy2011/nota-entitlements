-- 008-plans.sql — subscription/storage plan catalog.
CREATE TABLE IF NOT EXISTS plans (
  id             BIGSERIAL PRIMARY KEY,
  code           TEXT NOT NULL UNIQUE,
  name           TEXT NOT NULL,
  type           TEXT NOT NULL CHECK (type IN ('subscription','storage','feature','trial')),
  description    TEXT,
  price_cents    INTEGER NOT NULL DEFAULT 0,
  currency       TEXT NOT NULL DEFAULT 'USD',
  billing_period TEXT CHECK (billing_period IN ('monthly','yearly','lifetime','one_time')),
  features       TEXT[] NOT NULL DEFAULT '{}',
  quota_bytes    BIGINT NOT NULL DEFAULT 0,
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order     INTEGER NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS plans_type_idx ON plans (type);
CREATE INDEX IF NOT EXISTS plans_active_idx ON plans (active);
CREATE INDEX IF NOT EXISTS plans_sort_idx ON plans (sort_order);
