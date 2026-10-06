-- READ-ONLY production audit. Changes nothing. Run in the "visibility" project, then paste me the single result cell (Export > Copy as JSON).
select jsonb_pretty(jsonb_build_object(
  'tables_without_rls', (select coalesce(jsonb_agg(c.relname order by c.relname), '[]') from pg_class c join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='public' and c.relkind='r' and not c.relrowsecurity),
  'permissive_policies_using_true', (select coalesce(jsonb_agg(jsonb_build_object('table', tablename, 'policy', policyname, 'cmd', cmd, 'roles', roles)), '[]')
      from pg_policies where schemaname='public' and (qual='true' or with_check='true')),
  'anon_table_privileges', (select coalesce(jsonb_object_agg(table_name, privs), '{}') from (
      select table_name, string_agg(privilege_type, ',' order by privilege_type) privs from information_schema.role_table_grants
      where table_schema='public' and grantee='anon' group by 1) x),
  'authenticated_truncate_tables', (select coalesce(jsonb_agg(table_name order by table_name), '[]') from information_schema.role_table_grants
      where table_schema='public' and grantee='authenticated' and privilege_type='TRUNCATE'),
  'audit_log_privileges_for_app_users', (select coalesce(jsonb_agg(jsonb_build_object('who', grantee, 'priv', privilege_type)), '[]')
      from information_schema.role_table_grants where table_schema='public' and table_name='audit_log' and grantee in ('anon','authenticated')),
  'security_definer_without_search_path', (select coalesce(jsonb_agg(p.proname order by p.proname), '[]') from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where n.nspname='public' and p.prosecdef and not exists (select 1 from unnest(coalesce(p.proconfig,'{}')) c where c like 'search_path=%')),
  'functions_anon_can_run', (select coalesce(jsonb_agg(p.proname order by p.proname), '[]') from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where n.nspname='public' and has_function_privilege('anon', p.oid, 'execute')),
  'photo_bucket', (select to_jsonb(b) - 'owner' - 'owner_id' from (select id, public, file_size_limit, allowed_mime_types from storage.buckets where id='visibility-photos') b),
  'storage_policies', (select coalesce(jsonb_agg(policyname), '[]') from pg_policies where schemaname='storage' and tablename='objects'),
  'roles_count', (select coalesce(jsonb_object_agg(role, n), '{}') from (select role, count(*) n from public.profiles group by role) r),
  'accounts_not_active_drivers', (select coalesce(jsonb_agg(jsonb_build_object('email', email, 'status', driver_status)), '[]') from public.profiles where role='driver' and driver_status <> 'active')
)) as production_audit;
