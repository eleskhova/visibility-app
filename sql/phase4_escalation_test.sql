-- Privilege-escalation and tamper tests. Rolls back; changes nothing. In the SQL Editor choose "Run without RLS".
-- Every row must say PASS.
begin;
grant select, insert, update, delete on all tables in schema public to authenticated; grant usage on schema public to authenticated, anon;
create temp table t9(test text, result text) on commit drop; grant all on t9 to public;
do $$
declare a uuid:=gen_random_uuid(); d1 uuid:=gen_random_uuid(); d2 uuid:=gen_random_uuid(); s1 uuid:=gen_random_uuid(); s2 uuid:=gen_random_uuid(); s3 uuid:=gen_random_uuid();
        n int; r text; v text;
begin
  insert into auth.users(id,email) values (a,'a9@x.co'),(d1,'d91@x.co'),(d2,'d92@x.co');
  insert into public.profiles(id,email,role,driver_status,full_name,id_number) values
    (a,'a9@x.co','admin','active','Adm',null),(d1,'d91@x.co','driver','active','D One','9001015009087'),(d2,'d92@x.co','driver','active','D Two','8501015009087')
    on conflict (id) do update set role=excluded.role, driver_status='active', full_name=excluded.full_name, id_number=excluded.id_number;
  insert into public.shipments(id,tracking_number,status,recipient_name,assigned_to) values
    (s1,'ESC-T1','Out for Delivery','R One',d1),(s2,'ESC-T2','Out for Delivery','R Two',d2),(s3,'ESC-T3','Delivered','R Three',d1);
  insert into public.driver_documents(user_id,doc_type,storage_path,status) values (d1,'licence_front',d1||'/onboarding/a.jpg','submitted');
  insert into public.audit_log(action,table_name,record_id) values ('seed','x','1');

  -- ===== as DRIVER 1 =====
  perform set_config('request.jwt.claims', json_build_object('sub', d1, 'role','authenticated')::text, true);
  set local role authenticated;

  select count(*) into n from public.profiles where id = d2;
  insert into t9 values ('driver cannot read another driver profile', case when n=0 then 'PASS' else 'FAIL' end);
  begin update public.profiles set role='admin' where id=d1; get diagnostics n=row_count; insert into t9 values ('driver cannot make himself admin', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot make himself admin','PASS'); end;
  begin update public.profiles set driver_status='active', status_reason=null where id=d1; get diagnostics n=row_count; insert into t9 values ('driver cannot change own status', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot change own status','PASS'); end;
  begin update public.profiles set full_name='Hacked' where id=d2; get diagnostics n=row_count; insert into t9 values ('driver cannot edit another profile', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot edit another profile','PASS'); end;
  begin update public.driver_documents set status='approved' where user_id=d1; get diagnostics n=row_count; insert into t9 values ('driver cannot approve own document', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot approve own document','PASS'); end;
  begin insert into public.driver_documents(user_id,doc_type,storage_path,status) values (d1,'prdp',d1||'/x.jpg','approved'); insert into t9 values ('driver cannot insert a pre-approved document','FAIL'); exception when others then insert into t9 values ('driver cannot insert a pre-approved document','PASS'); end;
  begin update public.shipments set status='Delivered' where id=s1; get diagnostics n=row_count; insert into t9 values ('driver cannot update shipment rows directly', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot update shipment rows directly','PASS'); end;
  begin update public.shipments set assigned_to=d1 where id=s2; get diagnostics n=row_count; insert into t9 values ('driver cannot self-assign a shipment', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot self-assign a shipment','PASS'); end;
  begin insert into public.shipments(tracking_number,status,recipient_name) values ('ESC-NEW','Created','x'); insert into t9 values ('driver cannot create shipments','FAIL'); exception when others then insert into t9 values ('driver cannot create shipments','PASS'); end;
  begin perform public.staff_assign_shipment(s2, d1); insert into t9 values ('driver cannot call assign RPC','FAIL'); exception when others then insert into t9 values ('driver cannot call assign RPC','PASS'); end;
  select count(*) into n from public.shipments where id = s2;
  insert into t9 values ('driver cannot read another driver shipment', case when n=0 then 'PASS' else 'FAIL' end);
  begin perform public.driver_complete_delivery(s2,'Someone',d1||'/pod.jpg',null); insert into t9 values ('driver cannot complete another driver delivery','FAIL'); exception when others then insert into t9 values ('driver cannot complete another driver delivery','PASS'); end;
  begin perform public.driver_complete_delivery(s1,'Someone',null,null); insert into t9 values ('delivered without photo evidence rejected','FAIL'); exception when others then insert into t9 values ('delivered without photo evidence rejected','PASS'); end;
  begin perform public.driver_complete_delivery(s1,'',d1||'/pod.jpg',null); insert into t9 values ('delivered without recipient name rejected','FAIL'); exception when others then insert into t9 values ('delivered without recipient name rejected','PASS'); end;
  begin perform public.driver_complete_delivery(s1,'Someone',d2||'/pod.jpg',null); insert into t9 values ('POD photo from another user folder rejected','FAIL'); exception when others then insert into t9 values ('POD photo from another user folder rejected','PASS'); end;
  begin perform public.driver_complete_delivery(s3,'Someone',d1||'/pod.jpg',null); insert into t9 values ('re-completing a delivered parcel rejected','FAIL'); exception when others then insert into t9 values ('re-completing a delivered parcel rejected','PASS'); end;
  begin perform public.driver_start_delivery(s3); insert into t9 values ('restarting a delivered parcel rejected','FAIL'); exception when others then insert into t9 values ('restarting a delivered parcel rejected','PASS'); end;
  begin select count(*) into n from public.staff_km_summary(current_date-5, current_date); insert into t9 values ('driver gets nothing from staff reports', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver gets nothing from staff reports','PASS'); end;
  begin select count(*) into n from public.staff_odometer_flags('open'); insert into t9 values ('driver gets nothing from odometer review', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver gets nothing from odometer review','PASS'); end;
  select count(*) into n from public.audit_log;
  insert into t9 values ('driver cannot read the audit log', case when n=0 then 'PASS' else 'FAIL' end);
  begin insert into public.checkins(driver,user_id) values ('x', d2); insert into t9 values ('driver cannot file a check-in as someone else','FAIL'); exception when others then insert into t9 values ('driver cannot file a check-in as someone else','PASS'); end;
  begin insert into public.audit_log(action,table_name) values ('forged','x'); insert into t9 values ('driver cannot write the audit log','FAIL'); exception when others then insert into t9 values ('driver cannot write the audit log','PASS'); end;
  begin delete from public.audit_log; get diagnostics n=row_count; insert into t9 values ('driver cannot delete audit rows', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('driver cannot delete audit rows','PASS'); end;
  begin perform public.staff_set_clock_number(d1,'ELSD0001'); insert into t9 values ('driver cannot set a clock number','FAIL'); exception when others then insert into t9 values ('driver cannot set a clock number','PASS'); end;
  reset role;

  -- ===== as ADMIN: audit log is immutable even for admins =====
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  set local role authenticated;
  begin update public.audit_log set action='edited'; get diagnostics n=row_count; insert into t9 values ('admin cannot edit audit rows', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('admin cannot edit audit rows','PASS'); end;
  begin delete from public.audit_log; get diagnostics n=row_count; insert into t9 values ('admin cannot delete audit rows', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t9 values ('admin cannot delete audit rows','PASS'); end;
  begin truncate public.audit_log; insert into t9 values ('admin cannot truncate audit log','FAIL'); exception when others then insert into t9 values ('admin cannot truncate audit log','PASS'); end;
  reset role;

  -- ===== suspended driver =====
  update public.profiles set driver_status='suspended' where id=d1;
  perform set_config('request.jwt.claims', json_build_object('sub', d1, 'role','authenticated')::text, true);
  set local role authenticated;
  begin perform public.driver_start_delivery(s1); insert into t9 values ('suspended driver cannot start a delivery','FAIL'); exception when others then insert into t9 values ('suspended driver cannot start a delivery','PASS'); end;
  begin insert into public.vehicle_checks(driver,reg_no,check_type,odo,user_id,photos) values ('x','CA1','AM','100',d1,'[]'); insert into t9 values ('suspended driver cannot save a vehicle check','FAIL'); exception when others then insert into t9 values ('suspended driver cannot save a vehicle check','PASS'); end;
  reset role;

  -- ===== anonymous =====
  set local role anon;
  begin perform count(*) from public.shipments; insert into t9 values ('anonymous cannot read shipments','FAIL'); exception when insufficient_privilege then insert into t9 values ('anonymous cannot read shipments','PASS'); end;
  begin perform count(*) from public.profiles; insert into t9 values ('anonymous cannot read profiles','FAIL'); exception when insufficient_privilege then insert into t9 values ('anonymous cannot read profiles','PASS'); end;
  begin perform * from public.my_profile(); insert into t9 values ('anonymous cannot call my_profile','FAIL'); exception when insufficient_privilege then insert into t9 values ('anonymous cannot call my_profile','PASS'); end;
  begin perform public.is_admin(); insert into t9 values ('anonymous cannot call internal helper functions','FAIL'); exception when insufficient_privilege then insert into t9 values ('anonymous cannot call internal helper functions','PASS'); end;
  begin perform public.track_shipment('NONE'); insert into t9 values ('anonymous tracking lookup still works','PASS'); exception when others then insert into t9 values ('anonymous tracking lookup still works','FAIL '||sqlerrm); end;
  reset role;
  select (not coalesce(public, true)) and file_size_limit is not null and allowed_mime_types is not null into v from storage.buckets where id='visibility-photos';
  insert into t9 values ('photo bucket is private with type and size limits', case when coalesce(v,'false')='true' then 'PASS' else 'FAIL' end);
end $$;
select * from t9 order by 2 desc, 1;
rollback;
