-- 010-revenue.sql — revenue tracking: store amount per purchase.
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS amount_cents INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS purchases_verified_at_idx ON purchases (verified_at);
