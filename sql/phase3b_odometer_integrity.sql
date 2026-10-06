-- Phase 3b: odometer integrity. REQUIRES phase3a_compliance_reports.sql first. Safe to re-run.
-- Rules enforced in the database:
--  1. Every vehicle check / fuel log must include an odometer photo taken by that user.
--  2. The last accepted km per vehicle is remembered. A new reading LOWER than it, or unreadable,
--     is kept as evidence but raises an odometer flag and puts the driver ON HOLD (cannot create
--     operational records) until staff review it. Emergency alerts and check-ins stay available.
do $$ begin
  if to_regprocedure('public.odo_parse(text)') is null then
    raise exception 'Run phase3a_compliance_reports.sql first';
  end if;
end $$;

create table if not exists public.odometer_baselines (
  reg_norm   text primary key,
  last_odo   bigint not null check (last_odo >= 0),
  updated_at timestamptz not null default now()
);
alter table public.odometer_baselines enable row level security;   -- no policies: RPC/trigger access only

create table if not exists public.odometer_flags (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users(id) on delete cascade,
  reg_norm        text,
  reading         bigint,
  previous_odo    bigint,
  reason          text not null check (reason in ('lower_than_previous','unreadable')),
  source_table    text not null,
  source_id       uuid not null,
  status          text not null default 'open' check (status in ('open','released','baseline_reset')),
  created_at      timestamptz not null default now(),
  resolved_by     uuid references auth.users(id),
  resolved_at     timestamptz,
  resolution_note text
);
create index if not exists odometer_flags_user_open on public.odometer_flags (user_id) where status = 'open';
alter table public.odometer_flags enable row level security;
drop policy if exists "staff read flags" on public.odometer_flags;
create policy "staff read flags" on public.odometer_flags for select to authenticated using (public.is_staff());
-- no insert/update/delete policies: only the trigger and staff RPCs (SECURITY DEFINER) write.

drop trigger if exists audit_odometer_flags on public.odometer_flags;
create trigger audit_odometer_flags after insert or update on public.odometer_flags
  for each row execute function public.audit_row_change('status');

-- Seed baselines from existing history (latest reading per vehicle). Staff can correct any baseline via review.
insert into public.odometer_baselines (reg_norm, last_odo)
select distinct on (reg) reg, o from (
  select public.odo_norm_reg(reg_no) reg, public.odo_parse(odo) o, created_at from public.vehicle_checks
  union all
  select public.odo_norm_reg(reg_no), public.odo_parse(odo), created_at from public.fuel_logs
) x where reg is not null and o is not null
order by reg, created_at desc
on conflict (reg_norm) do nothing;

-- Safety actions stay available while on hold; everything else needs can_operate().
create or replace function public.can_send_safety()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid()
    and (role in ('admin','backoffice','ops_manager') or (role = 'driver' and driver_status = 'active')));
$$;

create or replace function public.can_operate()
returns boolean language sql security definer stable set search_path = public as $$
  select public.can_send_safety()
     and not exists (select 1 from public.odometer_flags f where f.user_id = auth.uid() and f.status = 'open');
$$;

drop policy if exists "auth insert" on public.checkins;
create policy "auth insert" on public.checkins for insert to authenticated
  with check (user_id = auth.uid() and public.can_send_safety());
drop policy if exists "auth insert" on public.panic_alerts;
create policy "auth insert" on public.panic_alerts for insert to authenticated
  with check (user_id = auth.uid() and public.can_send_safety());

-- Rule 1: odometer photo required (BEFORE INSERT)
create or replace function public.require_odometer_photo()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if jsonb_typeof(new.photos) is distinct from 'array'
     or not exists (
       select 1 from jsonb_array_elements(new.photos) p
       where p->>'label' = 'odometer' and coalesce(p->>'url','') <> ''
         and position(new.user_id::text in (p->>'url')) > 0) then
    raise exception 'An odometer photo is required. Take a photo of the odometer right after entering the km.';
  end if;
  return new;
end $$;

-- Rule 2: compare with last accepted reading (AFTER INSERT; record is kept either way)
create or replace function public.check_odometer()
returns trigger language plpgsql security definer set search_path = public as $$
declare reg text := public.odo_norm_reg(new.reg_no); r bigint := public.odo_parse(new.odo); prev bigint; role_ text;
begin
  select role into role_ from public.profiles where id = new.user_id;
  if role_ is distinct from 'driver' or reg is null then return new; end if;
  if r is null then
    insert into public.odometer_flags (user_id, reg_norm, reading, reason, source_table, source_id)
    values (new.user_id, reg, null, 'unreadable', tg_table_name, new.id);
    return new;
  end if;
  insert into public.odometer_baselines (reg_norm, last_odo) values (reg, r) on conflict (reg_norm) do nothing;
  select last_odo into prev from public.odometer_baselines where reg_norm = reg for update;
  if r < prev then
    insert into public.odometer_flags (user_id, reg_norm, reading, previous_odo, reason, source_table, source_id)
    values (new.user_id, reg, r, prev, 'lower_than_previous', tg_table_name, new.id);
  elsif r > prev then
    update public.odometer_baselines set last_odo = r, updated_at = now() where reg_norm = reg;
  end if;
  return new;
end $$;

do $$ declare t text; begin
  foreach t in array array['vehicle_checks','fuel_logs'] loop
    execute format('drop trigger if exists odo_photo_%1$s on public.%1$I', t);
    execute format('create trigger odo_photo_%1$s before insert on public.%1$I for each row execute function public.require_odometer_photo()', t);
    execute format('drop trigger if exists odo_check_%1$s on public.%1$I', t);
    execute format('create trigger odo_check_%1$s after insert on public.%1$I for each row execute function public.check_odometer()', t);
  end loop;
end $$;

-- Driver-facing RPCs
create or replace function public.my_odometer_hold()
returns table (flag_id uuid, reg_norm text, reading bigint, previous_odo bigint, reason text, created_at timestamptz)
language sql security definer stable set search_path = public as $$
  select f.id, f.reg_norm, f.reading, f.previous_odo, f.reason, f.created_at
  from public.odometer_flags f where f.user_id = auth.uid() and f.status = 'open'
  order by f.created_at desc limit 1;
$$;

create or replace function public.vehicle_last_odometer(p_reg text)
returns bigint language sql security definer stable set search_path = public as $$
  select b.last_odo from public.odometer_baselines b
  where public.can_send_safety() and b.reg_norm = public.odo_norm_reg(p_reg);
$$;

-- Staff RPCs
create or replace function public.staff_odometer_flags(p_status text default 'open')
returns table (flag_id uuid, user_id uuid, driver_name text, email text, reg_norm text, reading bigint, previous_odo bigint,
               reason text, status text, created_at timestamptz, resolved_at timestamptz, resolution_note text, photo_url text)
language sql security definer stable set search_path = public as $$
  select f.id, f.user_id, p.full_name, p.email, f.reg_norm, f.reading, f.previous_odo, f.reason, f.status, f.created_at,
         f.resolved_at, f.resolution_note,
         case f.source_table
           when 'vehicle_checks' then (select x->>'url' from public.vehicle_checks v, jsonb_array_elements(v.photos) x where v.id = f.source_id and x->>'label' = 'odometer' limit 1)
           when 'fuel_logs'      then (select x->>'url' from public.fuel_logs v, jsonb_array_elements(v.photos) x where v.id = f.source_id and x->>'label' = 'odometer' limit 1)
         end
  from public.odometer_flags f join public.profiles p on p.id = f.user_id
  where public.is_staff() and (p_status = 'all' or f.status = p_status)
  order by f.created_at desc limit 200;
$$;

-- action: 'release' = reading was a mistake, keep the old baseline; 'reset_baseline' = the OLD baseline was wrong, use this reading.
create or replace function public.staff_resolve_odometer_flag(p_flag uuid, p_action text, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare f public.odometer_flags;
begin
  if not public.is_staff() then raise exception 'Not allowed'; end if;
  if p_action not in ('release','reset_baseline') then raise exception 'Invalid action'; end if;
  if length(trim(coalesce(p_note,''))) < 5 then raise exception 'A note explaining the decision is required'; end if;
  select * into f from public.odometer_flags where id = p_flag and status = 'open' for update;
  if not found then raise exception 'Flag not found or already resolved'; end if;
  if p_action = 'reset_baseline' then
    if f.reading is null or f.reg_norm is null then raise exception 'Unreadable reading cannot become a baseline'; end if;
    insert into public.odometer_baselines (reg_norm, last_odo) values (f.reg_norm, f.reading)
    on conflict (reg_norm) do update set last_odo = excluded.last_odo, updated_at = now();
  end if;
  update public.odometer_flags set status = case p_action when 'release' then 'released' else 'baseline_reset' end,
         resolved_by = auth.uid(), resolved_at = now(), resolution_note = left(trim(p_note), 500)
  where id = p_flag;
end $$;

do $$ declare f text; begin
  foreach f in array array['public.can_send_safety()','public.can_operate()','public.my_odometer_hold()','public.vehicle_last_odometer(text)',
    'public.staff_odometer_flags(text)','public.staff_resolve_odometer_flag(uuid,text,text)'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
