-- Phase 3d: driver profile + profile picture. Safe to re-run. Requires phase2a.
alter table public.profiles add column if not exists avatar_path text;

create or replace function public.my_profile()
returns table (id uuid, email text, full_name text, phone text, driver_status text, vehicle_type text, vehicle_reg text,
               id_masked text, avatar_path text, privacy_ack_at timestamptz, created_at timestamptz)
language sql security definer stable set search_path = public as $$
  select p.id, p.email, p.full_name, p.phone, p.driver_status, p.vehicle_type, p.vehicle_reg,
         case when p.id_number is null then null else repeat('•', greatest(length(p.id_number) - 4, 0)) || right(p.id_number, 4) end,
         p.avatar_path,
         (select max(c.accepted_at) from public.consent_records c where c.user_id = p.id and c.purpose = 'privacy_notice'),
         p.created_at
  from public.profiles p where p.id = auth.uid();
$$;

create or replace function public.my_documents()
returns table (doc_type text, label text, status text, expiry_date date, rejection_reason text)
language sql security definer stable set search_path = public as $$
  select d.doc_type, r.label, d.status, d.expiry_date, d.rejection_reason
  from public.driver_documents d join public.document_requirements r on r.doc_type = d.doc_type
  where d.user_id = auth.uid() order by r.sort_order;
$$;

-- The user may only point their picture at a file inside their own folder (<uid>/avatar/...).
create or replace function public.set_my_avatar(p_path text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if coalesce(p_path, '') = '' or length(p_path) > 500
     or position(auth.uid()::text || '/avatar/' in p_path) = 0 then
    raise exception 'Invalid profile picture';
  end if;
  update public.profiles set avatar_path = p_path where id = auth.uid();
end $$;

do $$ declare f text; begin
  foreach f in array array['public.my_profile()','public.my_documents()','public.set_my_avatar(text)'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
