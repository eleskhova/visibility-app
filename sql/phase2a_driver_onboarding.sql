-- ============================================================
-- VISIBILITY — Phase 2A: driver onboarding hard gate (POPIA-aware)
-- Run AFTER phase1a. Run BEFORE deploying the Phase 2 front-end.
-- Additive + re-runnable. No data is deleted.
--
-- What it enforces IN THE DATABASE (not just in the app):
--   * Every driver has a backend status (registered -> ... -> active).
--   * A driver whose status is not 'active' cannot INSERT any
--     operational record (vehicle check, fuel, parcel issue, check-in,
--     emergency alert, exception) and cannot upload operational photos.
--   * Status changes only happen through controlled functions
--     (RPCs) that validate the previous steps; drivers cannot update
--     their own status/role/documents directly.
--   * Staff (admin / ops_manager / backoffice) review documents and
--     activate, reject or suspend drivers; every change is audited.
--   * EXISTING drivers and staff are set to 'active' so nobody is
--     locked out today.
-- ============================================================
begin;

-- 1. Profile fields -------------------------------------------------
-- First run only: existing rows become 'active' (grandfathered); default for NEW sign-ups is 'registered'.
do $$ begin
  if not exists (select 1 from information_schema.columns
                 where table_schema='public' and table_name='profiles' and column_name='driver_status') then
    alter table public.profiles add column driver_status text not null default 'active';
    alter table public.profiles alter column driver_status set default 'registered';
  end if;
end $$;
alter table public.profiles drop constraint if exists profiles_driver_status_check;
alter table public.profiles add constraint profiles_driver_status_check check (driver_status in (
  'registered','privacy_acknowledged','onboarding_in_progress','documents_pending',
  'verification_pending','approved','active','suspended','rejected'));
alter table public.profiles add column if not exists full_name text;
alter table public.profiles add column if not exists phone text;
alter table public.profiles add column if not exists id_number text;
alter table public.profiles add column if not exists vehicle_type text;       -- 'car' | 'motorcycle' | 'none'
alter table public.profiles add column if not exists vehicle_reg text;
alter table public.profiles add column if not exists status_reason text;      -- rejection / suspension reason shown to driver
alter table public.profiles add column if not exists status_changed_at timestamptz;
alter table public.profiles add column if not exists onboarding_submitted_at timestamptz;
alter table public.profiles drop constraint if exists profiles_vehicle_type_check;
alter table public.profiles add constraint profiles_vehicle_type_check
  check (vehicle_type is null or vehicle_type in ('car','motorcycle','none'));

-- 2. Consent / acknowledgement records -----------------------------
create table if not exists public.consent_records (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  purpose       text not null,            -- e.g. privacy_notice, location_notice
  lawful_basis  text not null,            -- acknowledgement | consent | contract | legal_obligation | legitimate_interest
  notice_version text not null,
  accepted_at   timestamptz not null default now()
);
create index if not exists consent_records_user_idx on public.consent_records (user_id, accepted_at desc);
alter table public.consent_records enable row level security;
drop policy if exists "consent read own or staff" on public.consent_records;
create policy "consent read own or staff" on public.consent_records for select to authenticated
  using (user_id = auth.uid() or public.is_admin_or_backoffice());
revoke all on public.consent_records from anon, authenticated;
grant select on public.consent_records to authenticated;

-- 3. Required-document catalogue (dynamic requirements) -------------
create table if not exists public.document_requirements (
  doc_type    text primary key,
  label       text not null,
  instruction text not null,
  applies_to  text not null default 'all' check (applies_to in ('all','vehicle','motorcycle','car')),
  has_expiry  boolean not null default false,
  sort_order  int not null default 100,
  active      boolean not null default true
);
alter table public.document_requirements enable row level security;
drop policy if exists "requirements read" on public.document_requirements;
create policy "requirements read" on public.document_requirements for select to authenticated using (true);
revoke all on public.document_requirements from anon, authenticated;
grant select on public.document_requirements to authenticated;

insert into public.document_requirements (doc_type,label,instruction,applies_to,has_expiry,sort_order) values
 ('licence_front',  'Driver''s licence (front)', 'Take a clear photograph of the front of your driver''s licence. All four corners and the text must be visible.', 'all', true, 10),
 ('licence_back',   'Driver''s licence (back)',  'Take a clear photograph of the back of your driver''s licence.', 'all', false, 20),
 ('id_document',    'ID document',               'Photograph of your South African ID card/book or passport photo page.', 'all', false, 30),
 ('vehicle_registration', 'Vehicle / motorcycle registration or licence disc', 'Photograph of the registration document or current licence disc of the vehicle you will use.', 'vehicle', true, 40)
on conflict (doc_type) do nothing;

-- 4. Driver documents (written ONLY through submit_document / review_document)
create table if not exists public.driver_documents (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users(id) on delete cascade,
  doc_type        text not null references public.document_requirements(doc_type),
  storage_path    text not null,
  status          text not null default 'submitted'
                  check (status in ('submitted','under_review','approved','rejected','expired')),
  rejection_reason text,
  expiry_date     date,
  submitted_at    timestamptz not null default now(),
  reviewed_by     uuid references auth.users(id),
  reviewed_at     timestamptz,
  review_by_date  date,                    -- retention / review date (configurable later)
  unique (user_id, doc_type)
);
create index if not exists driver_documents_user_idx on public.driver_documents (user_id);
alter table public.driver_documents enable row level security;
drop policy if exists "docs read own or staff" on public.driver_documents;
create policy "docs read own or staff" on public.driver_documents for select to authenticated
  using (user_id = auth.uid() or public.is_admin_or_backoffice());
revoke all on public.driver_documents from anon, authenticated;
grant select on public.driver_documents to authenticated;

-- 5. Retention settings (architecture only; values to be confirmed legally)
create table if not exists public.retention_settings (
  data_type        text primary key,
  retention_months int,
  note             text
);
alter table public.retention_settings enable row level security;
drop policy if exists "retention read staff" on public.retention_settings;
create policy "retention read staff" on public.retention_settings for select to authenticated
  using (public.is_admin_or_backoffice());
revoke all on public.retention_settings from anon, authenticated;
grant select on public.retention_settings to authenticated;
insert into public.retention_settings (data_type, retention_months, note) values
 ('driver_documents', null, 'To be confirmed against Eleskhova legal/contractual requirements'),
 ('onboarding_profile', null, 'To be confirmed'),
 ('operational_records', null, 'To be confirmed'),
 ('location_data', null, 'To be confirmed')
on conflict (data_type) do nothing;

-- 6. Helpers ---------------------------------------------------------
-- Staff = admin / backoffice / ops_manager.
create or replace function public.is_staff()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role in ('admin','backoffice','ops_manager'));
$$;

-- May this user create operational records / upload operational photos?
create or replace function public.can_operate()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and (role in ('admin','backoffice','ops_manager')
           or (role = 'driver' and driver_status = 'active'))
  );
$$;

-- Documents required for a given user (dynamic: depends on vehicle assignment).
create or replace function public.required_docs_for(p_user uuid)
returns setof public.document_requirements language sql security definer stable set search_path = public as $$
  select r.* from public.document_requirements r
  join public.profiles p on p.id = p_user
  where r.active
    and (p_user = auth.uid() or public.is_staff())
    and (r.applies_to = 'all'
         or (r.applies_to = 'vehicle'    and coalesce(p.vehicle_type,'none') in ('car','motorcycle'))
         or (r.applies_to = 'motorcycle' and p.vehicle_type = 'motorcycle')
         or (r.applies_to = 'car'        and p.vehicle_type = 'car'))
  order by r.sort_order;
$$;
revoke all on function public.required_docs_for(uuid) from public, anon;
grant execute on function public.required_docs_for(uuid) to authenticated;

-- 7. Driver actions (RPC) --------------------------------------------
-- 7a. Privacy notice acknowledged (records WHAT was shown and WHEN).
create or replace function public.ack_privacy(p_version text)
returns void language plpgsql security definer set search_path = public as $$
declare me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.role <> 'driver' then raise exception 'Not a driver account'; end if;
  if p_version is null or length(p_version) > 40 then raise exception 'Invalid notice version'; end if;
  if me.driver_status in ('suspended','rejected') then raise exception 'Account is %', me.driver_status; end if;
  insert into public.consent_records (user_id, purpose, lawful_basis, notice_version)
  values (auth.uid(), 'privacy_notice', 'acknowledgement', p_version);
  if me.driver_status = 'registered' then
    update public.profiles set driver_status = 'privacy_acknowledged', status_changed_at = now() where id = auth.uid();
  end if;
end $$;

-- 7b. Personal + vehicle details.
create or replace function public.save_personal_details(
  p_full_name text, p_phone text, p_id_number text, p_vehicle_type text, p_vehicle_reg text)
returns void language plpgsql security definer set search_path = public as $$
declare me public.profiles; v_reg text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.role <> 'driver' then raise exception 'Not a driver account'; end if;
  if me.driver_status not in ('privacy_acknowledged','onboarding_in_progress','documents_pending') then
    raise exception 'Details cannot be changed in status %', me.driver_status;
  end if;
  if length(trim(coalesce(p_full_name,''))) < 3 or length(p_full_name) > 120 then raise exception 'Enter your full name'; end if;
  if regexp_replace(coalesce(p_phone,''), '[^0-9+]', '', 'g') !~ '^(\+27|0)[0-9]{9}$' then raise exception 'Enter a valid South African cell number'; end if;
  if coalesce(p_id_number,'') !~ '^[0-9]{13}$' and coalesce(p_id_number,'') !~ '^[A-Za-z0-9]{6,20}$' then raise exception 'Enter a valid ID or passport number'; end if;
  if p_vehicle_type not in ('car','motorcycle','none') then raise exception 'Select a vehicle type'; end if;
  v_reg := upper(regexp_replace(coalesce(p_vehicle_reg,''), '\s+', '', 'g'));
  if p_vehicle_type <> 'none' and (length(v_reg) < 3 or length(v_reg) > 12) then raise exception 'Enter the vehicle registration'; end if;
  update public.profiles set
    full_name = trim(p_full_name),
    phone = regexp_replace(p_phone, '[^0-9+]', '', 'g'),
    id_number = p_id_number,
    vehicle_type = p_vehicle_type,
    vehicle_reg = case when p_vehicle_type = 'none' then null else v_reg end,
    driver_status = 'onboarding_in_progress',
    status_changed_at = now()
  where id = auth.uid();
end $$;

-- 7c. Register an uploaded document (file must already exist in the driver's own folder).
create or replace function public.submit_document(p_doc_type text, p_path text, p_expiry date)
returns void language plpgsql security definer set search_path = public, storage as $$
declare me public.profiles; req public.document_requirements;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.role <> 'driver' then raise exception 'Not a driver account'; end if;
  if me.driver_status not in ('onboarding_in_progress','documents_pending') then
    raise exception 'Documents cannot be submitted in status %', me.driver_status;
  end if;
  if not exists (select 1 from public.required_docs_for(auth.uid()) r where r.doc_type = p_doc_type) then
    raise exception 'That document is not required for you';
  end if;
  select * into req from public.document_requirements where doc_type = p_doc_type;
  if (storage.foldername(p_path))[1] is distinct from auth.uid()::text
     or (storage.foldername(p_path))[2] is distinct from 'onboarding' then
    raise exception 'Invalid file location';
  end if;
  if not exists (select 1 from storage.objects where bucket_id = 'visibility-photos' and name = p_path) then
    raise exception 'File not found - upload the photo first';
  end if;
  if req.has_expiry and p_expiry is not null and p_expiry < current_date then
    raise exception 'This document has already expired';
  end if;
  insert into public.driver_documents (user_id, doc_type, storage_path, status, expiry_date, submitted_at, rejection_reason, reviewed_by, reviewed_at)
  values (auth.uid(), p_doc_type, p_path, 'submitted', p_expiry, now(), null, null, null)
  on conflict (user_id, doc_type) do update
    set storage_path = excluded.storage_path, status = 'submitted', expiry_date = excluded.expiry_date,
        submitted_at = now(), rejection_reason = null, reviewed_by = null, reviewed_at = null
    where public.driver_documents.status in ('submitted','rejected','expired');
  -- a rejected document resubmitted moves the driver back into the review queue only via submit_onboarding
end $$;

-- 7d. Final submission: every prerequisite is re-checked server-side.
create or replace function public.submit_onboarding()
returns void language plpgsql security definer set search_path = public as $$
declare me public.profiles; missing text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.role <> 'driver' then raise exception 'Not a driver account'; end if;
  if me.driver_status not in ('onboarding_in_progress','documents_pending') then
    raise exception 'Onboarding cannot be submitted in status %', me.driver_status;
  end if;
  if not exists (select 1 from public.consent_records where user_id = auth.uid() and purpose = 'privacy_notice') then
    raise exception 'Privacy notice has not been acknowledged';
  end if;
  if me.full_name is null or me.phone is null or me.id_number is null or me.vehicle_type is null then
    raise exception 'Personal details are incomplete';
  end if;
  select string_agg(r.label, ', ') into missing
  from public.required_docs_for(auth.uid()) r
  where not exists (select 1 from public.driver_documents d
                    where d.user_id = auth.uid() and d.doc_type = r.doc_type
                      and d.status in ('submitted','under_review','approved'));
  if missing is not null then raise exception 'Required documents outstanding: %', missing; end if;
  update public.profiles set driver_status = 'verification_pending', status_reason = null,
         onboarding_submitted_at = now(), status_changed_at = now() where id = auth.uid();
end $$;

-- 8. Staff actions (RPC) ----------------------------------------------
create or replace function public.review_document(p_doc_id uuid, p_decision text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare d public.driver_documents;
begin
  if not public.is_staff() then raise exception 'Not allowed'; end if;
  if p_decision not in ('approved','rejected') then raise exception 'Invalid decision'; end if;
  if p_decision = 'rejected' and length(trim(coalesce(p_reason,''))) < 3 then raise exception 'A rejection reason is required'; end if;
  select * into d from public.driver_documents where id = p_doc_id;
  if d.id is null then raise exception 'Document not found'; end if;
  update public.driver_documents set status = p_decision,
         rejection_reason = case when p_decision = 'rejected' then trim(p_reason) else null end,
         reviewed_by = auth.uid(), reviewed_at = now()
   where id = p_doc_id;
  if p_decision = 'rejected' then
    update public.profiles set driver_status = 'documents_pending', status_reason = 'A document was rejected - please resubmit.',
           status_changed_at = now()
     where id = d.user_id and role = 'driver' and driver_status in ('verification_pending','documents_pending');
  end if;
end $$;

create or replace function public.set_driver_status(p_user uuid, p_status text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare t public.profiles; missing text;
begin
  if not public.is_staff() then raise exception 'Not allowed'; end if;
  if p_status not in ('active','rejected','suspended') then raise exception 'Invalid status'; end if;
  select * into t from public.profiles where id = p_user;
  if t.id is null or t.role <> 'driver' then raise exception 'Driver not found'; end if;
  if p_status in ('rejected','suspended') and length(trim(coalesce(p_reason,''))) < 3 then raise exception 'A reason is required'; end if;
  if p_status = 'active' then
    if t.driver_status not in ('verification_pending','suspended') then
      raise exception 'Driver cannot be activated from status %', t.driver_status;
    end if;
    select string_agg(r.label, ', ') into missing
    from public.required_docs_for(p_user) r
    where not exists (select 1 from public.driver_documents d
                      where d.user_id = p_user and d.doc_type = r.doc_type and d.status = 'approved');
    if missing is not null then raise exception 'Documents not yet approved: %', missing; end if;
  end if;
  update public.profiles set driver_status = p_status,
         status_reason = case when p_status = 'active' then null else trim(p_reason) end,
         status_changed_at = now()
   where id = p_user;
end $$;

-- Staff list with the ID number masked (need-to-know: full number shown only on the detail call).
create or replace function public.staff_list_drivers()
returns table (id uuid, email text, full_name text, phone text, driver_status text, vehicle_type text, vehicle_reg text,
               id_masked text, submitted_at timestamptz, status_changed_at timestamptz, created_at timestamptz)
language sql security definer stable set search_path = public as $$
  select p.id, p.email, p.full_name, p.phone, p.driver_status, p.vehicle_type, p.vehicle_reg,
         case when p.id_number is null then null else repeat('•', greatest(length(p.id_number)-4,0)) || right(p.id_number,4) end,
         p.onboarding_submitted_at, p.status_changed_at, p.created_at
  from public.profiles p
  where p.role = 'driver' and public.is_staff()
  order by coalesce(p.onboarding_submitted_at, p.created_at) desc;
$$;

create or replace function public.staff_driver_detail(p_user uuid)
returns table (id uuid, email text, full_name text, phone text, id_number text, driver_status text,
               vehicle_type text, vehicle_reg text, status_reason text, privacy_ack_at timestamptz, privacy_version text)
language sql security definer stable set search_path = public as $$
  select p.id, p.email, p.full_name, p.phone, p.id_number, p.driver_status, p.vehicle_type, p.vehicle_reg, p.status_reason,
         (select max(c.accepted_at) from public.consent_records c where c.user_id = p.id and c.purpose = 'privacy_notice'),
         (select c.notice_version from public.consent_records c where c.user_id = p.id and c.purpose = 'privacy_notice' order by c.accepted_at desc limit 1)
  from public.profiles p
  where p.id = p_user and p.role = 'driver' and public.is_staff();
$$;

do $$
declare f text;
begin
  foreach f in array array['public.staff_driver_detail(uuid)','public.ack_privacy(text)','public.save_personal_details(text,text,text,text,text)',
    'public.submit_document(text,text,date)','public.submit_onboarding()','public.review_document(uuid,text,text)',
    'public.set_driver_status(uuid,text,text)','public.staff_list_drivers()','public.is_staff()','public.can_operate()'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;

-- 9. THE GATE: operational writes require an active driver (or staff) -------
drop policy if exists "auth insert" on public.vehicle_checks;
create policy "auth insert" on public.vehicle_checks for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());
drop policy if exists "auth insert" on public.fuel_logs;
create policy "auth insert" on public.fuel_logs for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());
drop policy if exists "auth insert" on public.parcel_issues;
create policy "auth insert" on public.parcel_issues for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());
drop policy if exists "auth insert" on public.checkins;
create policy "auth insert" on public.checkins for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());
drop policy if exists "auth insert" on public.panic_alerts;
create policy "auth insert" on public.panic_alerts for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());
drop policy if exists "insert exceptions" on public.exceptions;
create policy "insert exceptions" on public.exceptions for insert to authenticated
  with check (user_id = auth.uid() and public.can_operate());

-- Storage: onboarding uploads always allowed in own folder; operational uploads only when can_operate().
-- The old bucket-wide upload policy would let any logged-in user bypass this, so remove it.
drop policy if exists "auth upload photos" on storage.objects;
drop policy if exists "photos insert own folder" on storage.objects;
create policy "photos insert own folder" on storage.objects for insert to authenticated
  with check (
    bucket_id = 'visibility-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
    and ((storage.foldername(name))[2] = 'onboarding' or public.can_operate())
  );

-- 10. Audit status changes (profiles.driver_status, driver_documents.status) -
drop trigger if exists audit_profiles_driver_status on public.profiles;
create trigger audit_profiles_driver_status after update on public.profiles
  for each row execute function public.audit_row_change('driver_status');
drop trigger if exists audit_driver_documents on public.driver_documents;
create trigger audit_driver_documents after insert or update on public.driver_documents
  for each row execute function public.audit_row_change('status');

-- Audit consent acknowledgements too (no personal content stored).
create or replace function public.audit_consent()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.audit_log (user_id, user_email, action, table_name, record_id, new_data)
  values (new.user_id, (select email from public.profiles where id = new.user_id),
          'consent_records.' || new.purpose || '_acknowledged', 'consent_records', new.id::text,
          jsonb_build_object('notice_version', new.notice_version, 'basis', new.lawful_basis));
  return new;
end $$;
drop trigger if exists audit_consent on public.consent_records;
create trigger audit_consent after insert on public.consent_records
  for each row execute function public.audit_consent();

commit;
