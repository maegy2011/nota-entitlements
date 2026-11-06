-- 005-indexes.sql — performance indexes for admin queries and cloud listings.
CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at DESC);
CREATE INDEX IF NOT EXISTS cloud_files_created_at_idx ON cloud_files (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS entitlements_expires_at_idx ON entitlements (expires_at);
