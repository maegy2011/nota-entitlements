-- 009-plans-seed.sql — default Nota plans (idempotent).
INSERT INTO plans (code, name, type, description, price_cents, currency, billing_period, features, quota_bytes, sort_order) VALUES
  ('free', 'Free', 'subscription', 'Free tier', 0, 'USD', 'lifetime',
   '{}', 104857600, 0),
  ('pro_monthly', 'Pro Monthly', 'subscription', 'Pro subscription monthly', 399, 'USD', 'monthly',
   ARRAY['folders','location','tags','reminders','pdf','lock','favorites','pin','widget','cloud','backgrounds','media','shred'], 5368709120, 10),
  ('pro_yearly', 'Pro Yearly', 'subscription', 'Pro subscription yearly', 2999, 'USD', 'yearly',
   ARRAY['folders','location','tags','reminders','pdf','lock','favorites','pin','widget','cloud','backgrounds','media','shred'], 5368709120, 20),
  ('pro_lifetime', 'Pro Lifetime', 'subscription', 'Pro lifetime purchase', 4999, 'USD', 'lifetime',
   ARRAY['folders','location','tags','reminders','pdf','lock','favorites','pin','widget','cloud','backgrounds','media','shred'], 5368709120, 30),
  ('storage_5g', 'Storage +5GB', 'storage', 'Additional 5GB storage pack', 99, 'USD', 'one_time',
   ARRAY['storage_5g'], 5368709120, 40),
  ('storage_10g', 'Storage +10GB', 'storage', 'Additional 10GB storage pack', 149, 'USD', 'one_time',
   ARRAY['storage_10g'], 10737418240, 50),
  ('storage_5g_monthly', 'Storage 5GB Monthly', 'subscription', '5GB storage monthly', 99, 'USD', 'monthly',
   ARRAY['storage_5g'], 5368709120, 60),
  ('storage_10g_monthly', 'Storage 10GB Monthly', 'subscription', '10GB storage monthly', 149, 'USD', 'monthly',
   ARRAY['storage_10g'], 10737418240, 70)
ON CONFLICT (code) DO NOTHING;
