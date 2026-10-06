-- ============================================================
-- VISIBILITY — Phase 1A: Operations Manager role, audit trail,
-- function hardening, legacy-row lockdown.
-- Run in Supabase SQL Editor on the "visibility" project.
--
-- SAFE / ADDITIVE:
--   * Does not drop any table or delete any data.
--   * Works with the CURRENT live app and with the Phase 1 app.
--   * Run BEFORE deploying the new front-end.
--   * Re-runnable (idempotent).
-- ============================================================

begin;

-- 1. New role: ops_manager (Operations Manager).
--    DB values: admin = Super Admin, backoffice = Operations Admin,
--               ops_manager = Operations Manager, driver = Driver.
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('admin', 'backoffice', 'ops_manager', 'driver'));

-- 2. Role helpers (fixed search_path = hardened security definer).
create or replace function public.is_admin()
returns boolean language sql security definer stable
set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.is_admin_or_backoffice()
returns boolean language sql security definer stable
set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('admin', 'backoffice', 'ops_manager')
  );
$$;

-- Can read the audit trail: Super Admin + Operations Manager.
create or replace function public.can_view_audit()
returns boolean language sql security definer stable
set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('admin', 'ops_manager')
  );
$$;

-- 3. Harden the other existing security-definer functions (no body change).
do $$
declare f text;
begin
  foreach f in array array[
    'public.handle_new_user()',
    'public.prevent_last_admin_demotion()',
    'public.sync_shipment_on_exception_resolve()',
    'public.log_shipment_event()',
    'public.track_shipment(text)'
  ] loop
    if to_regprocedure(f) is not null then
      execute format('alter function %s set search_path = public', f);
    end if;
  end loop;
end $$;

-- 4. Audit log (append-only; written only by triggers).
create table if not exists public.audit_log (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  user_id     uuid,
  user_email  text,
  action      text not null,
  table_name  text not null,
  record_id   text,
  old_data    jsonb,
  new_data    jsonb
);
create index if not exists audit_log_created_idx on public.audit_log (created_at desc);
create index if not exists audit_log_table_idx   on public.audit_log (table_name, created_at desc);

alter table public.audit_log enable row level security;
drop policy if exists "audit read" on public.audit_log;
create policy "audit read" on public.audit_log for select to authenticated
  using (public.can_view_audit());
-- No insert/update/delete policies: nobody can write or tamper via the API.
revoke all on public.audit_log from anon, authenticated;
grant select on public.audit_log to authenticated;

-- 5. Generic audit trigger: logs creation and changes of a watched column.
--    TG_ARGV[0] = column to watch (status / role).
create or replace function public.audit_row_change()
returns trigger language plpgsql security definer
set search_path = public as $$
declare
  col text := coalesce(tg_argv[0], 'status');
  oldv text; newv text; rid text; who text;
begin
  select email into who from public.profiles where id = auth.uid();
  rid := to_jsonb(new)->>'id';
  if tg_op = 'INSERT' then
    newv := to_jsonb(new)->>col;
    insert into public.audit_log (user_id, user_email, action, table_name, record_id, new_data)
    values (auth.uid(), who, tg_table_name || '.created', tg_table_name, rid,
            jsonb_build_object(col, newv));
  elsif tg_op = 'UPDATE' then
    oldv := to_jsonb(old)->>col;
    newv := to_jsonb(new)->>col;
    if oldv is distinct from newv then
      insert into public.audit_log (user_id, user_email, action, table_name, record_id, old_data, new_data)
      values (auth.uid(), who, tg_table_name || '.' || col || '_changed', tg_table_name, rid,
              jsonb_build_object(col, oldv), jsonb_build_object(col, newv));
    end if;
  end if;
  return new;
end;
$$;

do $$
declare t text;
begin
  foreach t in array array['shipments','exceptions','panic_alerts','vehicle_checks','fuel_logs','parcel_issues'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop trigger if exists audit_%1$s on public.%1$I', t);
      execute format(
        'create trigger audit_%1$s after insert or update on public.%1$I
           for each row execute function public.audit_row_change(%2$L)', t, 'status');
    end if;
  end loop;
end $$;

drop trigger if exists audit_profiles on public.profiles;
create trigger audit_profiles after update on public.profiles
  for each row execute function public.audit_row_change('role');

-- 6. Lock down legacy rows: drivers only read their OWN rows.
--    (Rows created before logins existed have user_id NULL; back office
--    and admins still see them.)
drop policy if exists "auth read" on public.vehicle_checks;
create policy "auth read" on public.vehicle_checks for select to authenticated
  using (public.is_admin_or_backoffice() or user_id = auth.uid());
drop policy if exists "auth read" on public.fuel_logs;
create policy "auth read" on public.fuel_logs for select to authenticated
  using (public.is_admin_or_backoffice() or user_id = auth.uid());
drop policy if exists "auth read" on public.parcel_issues;
create policy "auth read" on public.parcel_issues for select to authenticated
  using (public.is_admin_or_backoffice() or user_id = auth.uid());
drop policy if exists "auth read" on public.checkins;
create policy "auth read" on public.checkins for select to authenticated
  using (public.is_admin_or_backoffice() or user_id = auth.uid());
drop policy if exists "auth read" on public.panic_alerts;
create policy "auth read" on public.panic_alerts for select to authenticated
  using (public.is_admin_or_backoffice() or user_id = auth.uid());

commit;

-- Verify (optional):
--   select role, count(*) from profiles group by role;
--   select * from audit_log order by id desc limit 5;
