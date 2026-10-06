-- Phase 3a: compliance & km reports (read-only, staff only). Safe to re-run.
-- Adds 3 SECURITY DEFINER functions; no tables/policies changed.

-- Shared helpers (also used by Phase 3b) ------------------------------------
create or replace function public.odo_norm_reg(p text) returns text
language sql immutable set search_path = public as $$
  select nullif(upper(regexp_replace(coalesce(p,''), '[^A-Za-z0-9]', '', 'g')), '');
$$;

-- Parses what a driver typed ("84213", "84 213 km", "84,213", "84213.5") into whole km, or NULL if unusable.
create or replace function public.odo_parse(p text) returns bigint
language plpgsql immutable set search_path = public as $$
declare v text := regexp_replace(lower(coalesce(p,'')), '\s|,|km', '', 'g');
begin
  if v ~ '^[0-9]{1,7}(\.[0-9]+)?$' then return floor(v::numeric)::bigint; end if;
  return null;
end $$;

create or replace function public.staff_expiry_report(p_days int default 60)
returns table (user_id uuid, driver_name text, email text, doc_type text, doc_label text,
               expiry_date date, days_left int, doc_status text)
language sql security definer stable set search_path = public as $$
  select d.user_id, p.full_name, p.email, d.doc_type, r.label, d.expiry_date,
         (d.expiry_date - current_date)::int, d.status
  from public.driver_documents d
  join public.profiles p on p.id = d.user_id and p.role = 'driver' and p.driver_status = 'active'
  join public.document_requirements r on r.doc_type = d.doc_type
  where public.is_staff()
    and d.expiry_date is not null
    and d.status in ('submitted','under_review','approved','expired')
    and d.expiry_date <= current_date + greatest(least(coalesce(p_days,60), 365), 0)
  order by d.expiry_date asc;
$$;

create or replace function public.staff_km_summary(p_from date, p_to date)
returns table (reg_no text, readings int, drivers int, first_odo bigint, last_odo bigint, km bigint,
               backwards int, big_jumps int, invalid_readings int, last_reading timestamptz)
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.is_staff() then return; end if;
  if p_from is null or p_to is null or p_to < p_from or p_to - p_from > 92 then
    raise exception 'Date range must be 1-93 days';
  end if;
  return query
  with r as (
    select public.odo_norm_reg(v.reg_no) as reg, v.created_at as ts, v.driver as drv,
           public.odo_parse(v.odo) as o
    from public.vehicle_checks v
    where v.created_at >= p_from::timestamptz and v.created_at < (p_to + 1)::timestamptz
    union all
    select public.odo_norm_reg(f.reg_no), f.created_at, f.driver,
           public.odo_parse(f.odo)
    from public.fuel_logs f
    where f.created_at >= p_from::timestamptz and f.created_at < (p_to + 1)::timestamptz
  ), w as (
    select reg, ts, drv, o, lag(o) over (partition by reg order by ts) as prev from r where o is not null
  ), inv as (
    select reg, count(*)::int as n from r where o is null group by reg
  ), agg as (
    select reg, count(*)::int as readings, count(distinct drv)::int as drivers,
           (array_agg(o order by ts))[1] as first_odo, (array_agg(o order by ts desc))[1] as last_odo,
           count(*) filter (where prev is not null and o < prev)::int as backwards,
           count(*) filter (where prev is not null and o - prev > 1500)::int as big_jumps,
           max(ts) as last_reading
    from w group by reg
  )
  select coalesce(a.reg, i.reg), coalesce(a.readings,0), coalesce(a.drivers,0), a.first_odo, a.last_odo,
         (a.last_odo - a.first_odo), coalesce(a.backwards,0), coalesce(a.big_jumps,0), coalesce(i.n,0), a.last_reading
  from agg a full join inv i on i.reg = a.reg
  order by 1;
end $$;

create or replace function public.staff_check_compliance(p_from date, p_to date)
returns table (user_id uuid, driver_name text, email text, vehicle_checks int, days_with_check int,
               fuel_logs int, last_check timestamptz)
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.is_staff() then return; end if;
  if p_from is null or p_to is null or p_to < p_from or p_to - p_from > 92 then
    raise exception 'Date range must be 1-93 days';
  end if;
  return query
  select p.id, p.full_name, p.email,
    (select count(*)::int from public.vehicle_checks v where v.user_id = p.id
       and v.created_at >= p_from::timestamptz and v.created_at < (p_to + 1)::timestamptz),
    (select count(distinct (v.created_at at time zone 'Africa/Johannesburg')::date)::int from public.vehicle_checks v
       where v.user_id = p.id and v.created_at >= p_from::timestamptz and v.created_at < (p_to + 1)::timestamptz),
    (select count(*)::int from public.fuel_logs f where f.user_id = p.id
       and f.created_at >= p_from::timestamptz and f.created_at < (p_to + 1)::timestamptz),
    (select max(v.created_at) from public.vehicle_checks v where v.user_id = p.id)
  from public.profiles p
  where p.role = 'driver' and p.driver_status = 'active'
  order by 5 asc, 2;
end $$;

do $$ declare f text; begin
  foreach f in array array['public.odo_norm_reg(text)','public.odo_parse(text)','public.staff_expiry_report(int)','public.staff_km_summary(date,date)','public.staff_check_compliance(date,date)'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
