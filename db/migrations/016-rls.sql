-- 016-rls.sql — row-level security on user-scoped tables.
-- nota_svc must set app.current_account_id (per request) to restrict rows.
-- When unset, policies are permissive (backward compatible / admin access).
-- Set app.bypass_rls='on' to override (admin tooling).

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE quotas FORCE ROW LEVEL SECURITY;
ALTER TABLE cloud_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_files FORCE ROW LEVEL SECURITY;
ALTER TABLE cloud_pointers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_pointers FORCE ROW LEVEL SECURITY;
ALTER TABLE purchases ENABLE ROW LEVEL SECURITY;
ALTER TABLE purchases FORCE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
ALTER TABLE data_deletion_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_deletion_requests FORCE ROW LEVEL SECURITY;

DO $$
DECLARE t text; col text;
BEGIN
  FOR t IN SELECT unnest(ARRAY['users','entitlements','quotas','cloud_files','cloud_pointers','purchases','notifications','data_deletion_requests']) LOOP
    col := 'account_id';
    EXECUTE format('DROP POLICY IF EXISTS %I_account_isolation ON %I', t, t);
    EXECUTE format(
      'CREATE POLICY %I_account_isolation ON %I FOR ALL TO nota_svc USING ('
      '  current_setting(''app.bypass_rls'', true) = ''on'' '
      '  OR COALESCE(current_setting(''app.current_account_id'', true), '''') = '''' '
      '  OR %s = current_setting(''app.current_account_id'', true)'
      ') WITH CHECK ('
      '  current_setting(''app.bypass_rls'', true) = ''on'' '
      '  OR COALESCE(current_setting(''app.current_account_id'', true), '''') = '''' '
      '  OR %s = current_setting(''app.current_account_id'', true)'
      ')',
      t, t, col, col
    );
  END LOOP;
END $$;
