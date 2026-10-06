-- Phase 3e: clock numbers as login ID. Safe to re-run. Requires phase2a + phase3d.
-- Drivers ELSD####, admins/back office ELSA####, operations managers ELSM####. Admin assigns them.
alter table public.profiles add column if not exists clock_number text;
alter table public.profiles drop constraint if exists profiles_clock_number_check;
alter table public.profiles add constraint profiles_clock_number_check
  check (clock_number is null or clock_number ~ '^ELS[DAM][0-9]{4}$');
create unique index if not exists profiles_clock_number_uq on public.profiles (clock_number) where clock_number is not null;

-- Only an admin may change a clock number (blocks any direct profile update by a driver).
create or replace function public.guard_clock_number()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.clock_number is distinct from old.clock_number and not public.is_admin() then
    raise exception 'Only an admin can change a clock number';
  end if;
  return new;
end $$;
drop trigger if exists guard_clock_number on public.profiles;
create trigger guard_clock_number before update on public.profiles
  for each row execute function public.guard_clock_number();
drop trigger if exists audit_profiles_clock on public.profiles;
create trigger audit_profiles_clock after update on public.profiles
  for each row execute function public.audit_row_change('clock_number');

create or replace function public.staff_set_clock_number(p_user uuid, p_clock text)
returns void language plpgsql security definer set search_path = public as $$
declare t public.profiles; c text; want text;
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  select * into t from public.profiles where id = p_user;
  if t.id is null then raise exception 'User not found'; end if;
  c := nullif(upper(regexp_replace(coalesce(p_clock, ''), '\s', '', 'g')), '');
  if c is not null then
    want := case t.role when 'driver' then 'D' when 'ops_manager' then 'M' else 'A' end;
    if c !~ '^ELS[DAM][0-9]{4}$' then raise exception 'Clock number must look like ELSD0012 (ELS, a letter, 4 digits)'; end if;
    if substr(c, 4, 1) <> want then
      raise exception 'A % account must use a clock number starting ELS%', t.role, want;
    end if;
  end if;
  begin
    update public.profiles set clock_number = c where id = p_user;
  exception when unique_violation then
    raise exception 'That clock number is already in use';
  end;
end $$;

-- Pre-login lookup. Returns the sign-in email for a clock number. An unknown number gets a fake address
-- so the answer does not reveal whether a number exists. Password is still required.
create or replace function public.login_email_for_clock(p_clock text)
returns text language plpgsql security definer stable set search_path = public as $$
declare c text; e text;
begin
  c := upper(regexp_replace(coalesce(p_clock, ''), '\s', '', 'g'));
  if c !~ '^ELS[DAM][0-9]{4}$' then return 'nomatch-' || md5(c) || '@invalid.invalid'; end if;
  select email into e from public.profiles where clock_number = c;
  return coalesce(e, 'nomatch-' || md5(c) || '@invalid.invalid');
end $$;

-- my_profile now includes the clock number
drop function if exists public.my_profile();
create function public.my_profile()
returns table (id uuid, email text, full_name text, phone text, driver_status text, vehicle_type text, vehicle_reg text,
               id_masked text, avatar_path text, privacy_ack_at timestamptz, created_at timestamptz, clock_number text)
language sql security definer stable set search_path = public as $$
  select p.id, p.email, p.full_name, p.phone, p.driver_status, p.vehicle_type, p.vehicle_reg,
         case when p.id_number is null then null else repeat('•', greatest(length(p.id_number) - 4, 0)) || right(p.id_number, 4) end,
         p.avatar_path,
         (select max(c.accepted_at) from public.consent_records c where c.user_id = p.id and c.purpose = 'privacy_notice'),
         p.created_at, p.clock_number
  from public.profiles p where p.id = auth.uid();
$$;

do $$ declare f text; begin
  foreach f in array array['public.my_profile()','public.staff_set_clock_number(uuid,text)'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
  revoke all on function public.login_email_for_clock(text) from public;
  grant execute on function public.login_email_for_clock(text) to anon, authenticated;
  revoke all on function public.guard_clock_number() from public, anon, authenticated;
end $$;
