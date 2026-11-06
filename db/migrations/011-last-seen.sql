-- 011-last-seen.sql — track last activity for active/inactive user segmentation.
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS users_last_seen_idx ON users (last_seen_at);
