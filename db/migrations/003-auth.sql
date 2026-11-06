-- 003-auth.sql — Phase 3: bind each account to its verified Google sub.
-- Safe re-runs: IF NOT EXISTS everywhere (nota_svc has no CREATE; run as superuser).
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT;
