-- Phase 3c: driver delivery workflow with proof of delivery + back-office updates. Safe to re-run.
-- Requires phase2a (can_operate) and phase3b (odometer hold inside can_operate; falls back gracefully if absent).
-- Drivers never write to shipments directly: only these SECURITY DEFINER RPCs, which enforce every gate.

alter table public.shipments add column if not exists assigned_to    uuid references auth.users(id);
alter table public.shipments add column if not exists assigned_at    timestamptz;
alter table public.shipments add column if not exists completed_by   uuid references auth.users(id);
alter table public.shipments add column if not exists completed_at   timestamptz;
alter table public.shipments add column if not exists pod_photo_url  text;
alter table public.shipments add column if not exists pod_recipient  text;
alter table public.shipments add column if not exists pod_note       text;
alter table public.shipments add column if not exists failure_reason text;
create index if not exists shipments_assigned_to_idx on public.shipments (assigned_to) where assigned_to is not null;
create index if not exists shipments_completed_at_idx on public.shipments (completed_at desc) where completed_at is not null;

-- ---- driver: my deliveries ---------------------------------------------------
create or replace function public.my_deliveries()
returns table (id uuid, tracking_number text, status text, recipient_name text, recipient_phone text, recipient_address text,
               recipient_suburb text, parcel_description text, sender_name text, sender_address text,
               expected_delivery_date date, completed_at timestamptz, failure_reason text)
language sql security definer stable set search_path = public as $$
  select s.id, s.tracking_number, s.status, s.recipient_name, s.recipient_phone, s.recipient_address, s.recipient_suburb,
         s.parcel_description, s.sender_name, s.sender_address, s.expected_delivery_date, s.completed_at, s.failure_reason
  from public.shipments s
  where public.can_send_safety() and s.assigned_to = auth.uid()
    and (s.status not in ('Delivered','Failed Delivery','Returned to Sender','Cancelled')
         or s.completed_at > now() - interval '2 days')
  order by (s.status in ('Delivered','Failed Delivery','Returned to Sender','Cancelled')),
           s.expected_delivery_date nulls last, s.created_at;
$$;

-- ---- driver: start (one active delivery at a time) -------------------------------
create or replace function public.driver_start_delivery(p_shipment uuid)
returns void language plpgsql security definer set search_path = public as $$
declare s public.shipments;
begin
  if not public.can_operate() then raise exception 'Your account cannot create delivery updates right now'; end if;
  select * into s from public.shipments where id = p_shipment and assigned_to = auth.uid() for update;
  if not found then raise exception 'Delivery not found'; end if;
  if s.status in ('Delivered','Failed Delivery','Returned to Sender','Cancelled') then raise exception 'This delivery is already closed'; end if;
  if s.status = 'Out for Delivery' then return; end if;
  if exists (select 1 from public.shipments o where o.assigned_to = auth.uid() and o.status = 'Out for Delivery' and o.id <> p_shipment) then
    raise exception 'Finish your current delivery (deliver it or record why it failed) before starting the next one';
  end if;
  update public.shipments set status = 'Out for Delivery' where id = p_shipment;
end $$;

-- ---- driver: confirm delivered (POD photo + recipient name mandatory) ----------------
create or replace function public.driver_complete_delivery(p_shipment uuid, p_recipient text, p_pod_path text, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare s public.shipments;
begin
  if not public.can_operate() then raise exception 'Your account cannot create delivery updates right now'; end if;
  select * into s from public.shipments where id = p_shipment and assigned_to = auth.uid() for update;
  if not found then raise exception 'Delivery not found'; end if;
  if s.status = 'Delivered' then raise exception 'This delivery is already confirmed'; end if;
  if s.status <> 'Out for Delivery' then raise exception 'Start the delivery first'; end if;
  if length(trim(coalesce(p_recipient,''))) < 2 then raise exception 'Name of the person who received the parcel is required'; end if;
  if coalesce(p_pod_path,'') = '' or position(auth.uid()::text in p_pod_path) = 0 then raise exception 'A proof-of-delivery photo is required'; end if;
  update public.shipments set status = 'Delivered', delivered_at = now(), completed_at = now(), completed_by = auth.uid(),
         pod_recipient = left(trim(p_recipient), 120), pod_photo_url = p_pod_path, pod_note = nullif(left(trim(coalesce(p_note,'')), 500), ''),
         failure_reason = null
  where id = p_shipment;
end $$;

-- ---- driver: controlled failure path ---------------------------------------------------
create or replace function public.driver_fail_delivery(p_shipment uuid, p_reason text, p_note text, p_photo text)
returns void language plpgsql security definer set search_path = public as $$
declare s public.shipments;
begin
  if not public.can_operate() then raise exception 'Your account cannot create delivery updates right now'; end if;
  if p_reason not in ('Customer unavailable','Customer refused','Incorrect address','Damaged parcel','Access problem','Other') then
    raise exception 'Choose a reason'; end if;
  if length(trim(coalesce(p_note,''))) < 5 then raise exception 'A short explanation is required'; end if;
  if p_reason = 'Damaged parcel' and (coalesce(p_photo,'') = '' or position(auth.uid()::text in p_photo) = 0) then
    raise exception 'A photo of the damaged parcel is required'; end if;
  select * into s from public.shipments where id = p_shipment and assigned_to = auth.uid() for update;
  if not found then raise exception 'Delivery not found'; end if;
  if s.status in ('Delivered','Failed Delivery','Returned to Sender','Cancelled') then raise exception 'This delivery is already closed'; end if;
  if s.status <> 'Out for Delivery' then raise exception 'Start the delivery first'; end if;
  update public.shipments set status = 'Failed Delivery', completed_at = now(), completed_by = auth.uid(),
         failure_reason = p_reason, pod_note = left(trim(p_note), 500),
         pod_photo_url = case when coalesce(p_photo,'') <> '' and position(auth.uid()::text in p_photo) > 0 then p_photo end
  where id = p_shipment;
end $$;

-- ---- staff: assign ----------------------------------------------------------------------------
create or replace function public.staff_assign_shipment(p_shipment uuid, p_driver uuid)
returns void language plpgsql security definer set search_path = public as $$
declare s public.shipments; who text;
begin
  if not public.is_staff() then raise exception 'Not allowed'; end if;
  if not exists (select 1 from public.profiles where id = p_driver and role = 'driver' and driver_status = 'active') then
    raise exception 'Driver must be an active, approved driver'; end if;
  select * into s from public.shipments where id = p_shipment for update;
  if not found then raise exception 'Shipment not found'; end if;
  if s.status in ('Delivered','Failed Delivery','Returned to Sender','Cancelled') then raise exception 'Shipment is already closed'; end if;
  if s.status = 'Out for Delivery' and s.assigned_to is distinct from p_driver then
    raise exception 'Shipment is already out for delivery with another driver'; end if;
  update public.shipments set assigned_to = p_driver, assigned_at = now() where id = p_shipment;
  select email into who from public.profiles where id = auth.uid();
  insert into public.audit_log (user_id, user_email, action, table_name, record_id, old_data, new_data)
  values (auth.uid(), who, 'shipments.assigned', 'shipments', p_shipment::text,
          jsonb_build_object('assigned_to', s.assigned_to), jsonb_build_object('assigned_to', p_driver));
end $$;

-- ---- staff: delivery updates feed ---------------------------------------------------------------
create or replace function public.staff_delivery_updates(p_since timestamptz default null)
returns table (shipment_id uuid, tracking_number text, outcome text, recipient_name text, received_by text, driver_name text,
               completed_at timestamptz, pod_photo_url text, failure_reason text, note text)
language sql security definer stable set search_path = public as $$
  select s.id, s.tracking_number, s.status, s.recipient_name, s.pod_recipient, p.full_name, s.completed_at,
         s.pod_photo_url, s.failure_reason, s.pod_note
  from public.shipments s left join public.profiles p on p.id = s.completed_by
  where public.is_staff() and s.completed_at is not null and s.completed_at > coalesce(p_since, now() - interval '7 days')
  order by s.completed_at desc limit 100;
$$;

do $$ declare f text; begin
  foreach f in array array['public.my_deliveries()','public.driver_start_delivery(uuid)','public.driver_complete_delivery(uuid,text,text,text)',
    'public.driver_fail_delivery(uuid,text,text,text)','public.staff_assign_shipment(uuid,uuid)','public.staff_delivery_updates(timestamptz)'] loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
