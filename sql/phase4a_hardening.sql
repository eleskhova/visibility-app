-- Phase 4a: database hardening. ADDITIVE ONLY: it removes risky permissions, deletes nothing, drops no data. Safe to re-run.
-- Run AFTER phase1c_private_storage.sql. Then run phase4_escalation_test.sql (all rows must say PASS).
begin;

-- 1. No table in the public schema may be truncated, or have triggers/foreign keys added, by app users.
--    (RLS does not protect against TRUNCATE; the Supabase default grants allow it.)
do $$ declare t record; begin
  for t in select tablename from pg_tables where schemaname = 'public' loop
    execute format('revoke truncate, references, trigger on public.%I from anon, authenticated', t.tablename);
  end loop;
end $$;

-- 2. The signed-out public has no direct table access at all. The tracking page uses the track_shipment() function.
do $$ declare t record; begin
  for t in select tablename from pg_tables where schemaname = 'public' loop
    execute format('revoke all on public.%I from anon', t.tablename);
  end loop;
end $$;

-- 3. The audit log is append-only for everyone using the app: read (policy-limited) only. Triggers write to it as the owner.
revoke insert, update, delete, truncate on public.audit_log from anon, authenticated;

-- 4. Internal helper and trigger functions are not callable by the signed-out public. Signed-in users keep access
--    (the access rules call these helpers).
do $$ declare r record; begin
  for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname in (
             'audit_consent','audit_row_change','can_view_audit','check_odometer','generate_tracking_number','handle_new_user',
             'is_admin','is_admin_or_backoffice','is_staff','can_send_safety','can_operate','log_shipment_event',
             'prevent_last_admin_demotion','require_odometer_photo','sync_shipment_on_exception_resolve','guard_clock_number') loop
    execute format('revoke execute on function %s from public, anon', r.sig);
    execute format('grant execute on function %s to authenticated', r.sig);
  end loop;
end $$;

-- 5. Photo bucket: images only, size cap. (Uploads from the app are already compressed JPEGs, well under the cap.)
update storage.buckets
   set file_size_limit = 6291456,
       allowed_mime_types = array['image/jpeg','image/png','image/webp']
 where id = 'visibility-photos';

commit;
