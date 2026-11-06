-- 004-trial.sql — Phase 6: server-side trial consumption tracking.
-- trial_used flips to true once the account activates a trial via POST /v1/trial/start.
-- Safe re-run.

ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_used BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMPTZ;
