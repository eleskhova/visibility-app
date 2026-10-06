begin;
grant all on all tables in schema public to authenticated; grant usage on schema public to authenticated, anon;
create temp table t5(test text, result text) on commit drop; grant all on t5 to public;
do $$
declare a uuid:=gen_random_uuid(); d uuid:=gen_random_uuid(); d2 uuid:=gen_random_uuid(); d3 uuid:=gen_random_uuid();
  s1 uuid:=gen_random_uuid(); s2 uuid:=gen_random_uuid(); n int; r record; pod text; ph jsonb;
begin
  insert into auth.users(id,email) values (a,'a5@x.co'),(d,'d5@x.co'),(d2,'d25@x.co'),(d3,'d35@x.co');
  insert into public.profiles(id,email,role,full_name,driver_status) values (a,'a5@x.co','backoffice','Staff','active'),(d,'d5@x.co','driver','Drv One','active'),(d2,'d25@x.co','driver','Drv Two','active'),(d3,'d35@x.co','driver','Drv New','registered')
   on conflict (id) do update set role=excluded.role, driver_status=excluded.driver_status, full_name=excluded.full_name;
  insert into public.shipments(id,tracking_number,status,recipient_name,recipient_suburb) values (s1,'T-1','Collected','Mrs Dlamini','Sandton'),(s2,'T-2','Collected','Mr Naidoo','Midrand');
  pod := 'https://h/storage/'||d||'/pod/1.jpg';
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  set local role authenticated;
  begin perform public.staff_assign_shipment(s1, d3); insert into t5 values ('cannot assign to non-active driver','FAIL'); exception when others then insert into t5 values ('cannot assign to non-active driver','PASS'); end;
  perform public.staff_assign_shipment(s1, d); perform public.staff_assign_shipment(s2, d);
  insert into t5 values ('staff assigns shipments', case when (select count(*) from public.shipments where assigned_to=d)=2 then 'PASS' else 'FAIL' end);
  reset role; insert into t5 values ('assignment audited', case when (select count(*) from public.audit_log where action='shipments.assigned')=2 then 'PASS' else 'FAIL' end); set local role authenticated;
  -- driver
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  select count(*) into n from public.my_deliveries();
  insert into t5 values ('driver sees only own 2 deliveries', case when n=2 then 'PASS' else 'FAIL '||n end);
  begin perform public.driver_complete_delivery(s1,'Mrs D',pod,null); insert into t5 values ('cannot complete before starting','FAIL'); exception when others then insert into t5 values ('cannot complete before starting', case when sqlerrm like '%Start the delivery%' then 'PASS' else 'FAIL '||sqlerrm end); end;
  perform public.driver_start_delivery(s1);
  begin perform public.driver_start_delivery(s2); insert into t5 values ('cannot start next delivery while one is open','FAIL'); exception when others then insert into t5 values ('cannot start next delivery while one is open', case when sqlerrm like '%Finish your current%' then 'PASS' else 'FAIL '||sqlerrm end); end;
  begin perform public.driver_complete_delivery(s1,'Mrs D',null,null); insert into t5 values ('complete without POD photo rejected','FAIL'); exception when others then insert into t5 values ('complete without POD photo rejected','PASS'); end;
  begin perform public.driver_complete_delivery(s1,'Mrs D','https://h/storage/'||a||'/pod/x.jpg',null); insert into t5 values ('POD photo from another user path rejected','FAIL'); exception when others then insert into t5 values ('POD photo from another user path rejected','PASS'); end;
  begin perform public.driver_complete_delivery(s1,' ',pod,null); insert into t5 values ('complete without recipient name rejected','FAIL'); exception when others then insert into t5 values ('complete without recipient name rejected','PASS'); end;
  begin update public.shipments set status='Delivered' where id=s1; get diagnostics n=row_count; insert into t5 values ('driver cannot update shipments directly', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t5 values ('driver cannot update shipments directly','PASS'); end;
  perform public.driver_complete_delivery(s1,'Mrs Dlamini',pod,'Left with receptionist');
  reset role; select * into r from public.shipments where id=s1;
  insert into t5 values ('delivered: status, delivered_at, POD stored', case when r.status='Delivered' and r.delivered_at is not null and r.pod_photo_url=pod and r.pod_recipient='Mrs Dlamini' and r.completed_by=d then 'PASS' else 'FAIL' end);
  insert into t5 values ('status history logged', case when exists(select 1 from public.shipment_events where shipment_id=s1 and status='Delivered') then 'PASS' else 'FAIL' end);
  set local role authenticated;
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  begin perform public.driver_complete_delivery(s1,'Mrs Dlamini',pod,null); insert into t5 values ('cannot confirm twice','FAIL'); exception when others then insert into t5 values ('cannot confirm twice','PASS'); end;
  -- failure path
  perform public.driver_start_delivery(s2);
  begin perform public.driver_fail_delivery(s2,'Bogus','long enough note',null); insert into t5 values ('invalid failure reason rejected','FAIL'); exception when others then insert into t5 values ('invalid failure reason rejected','PASS'); end;
  begin perform public.driver_fail_delivery(s2,'Customer refused','no',null); insert into t5 values ('failure without explanation rejected','FAIL'); exception when others then insert into t5 values ('failure without explanation rejected','PASS'); end;
  begin perform public.driver_fail_delivery(s2,'Damaged parcel','box crushed',null); insert into t5 values ('damaged parcel without photo rejected','FAIL'); exception when others then insert into t5 values ('damaged parcel without photo rejected','PASS'); end;
  perform public.driver_fail_delivery(s2,'Customer refused','Customer said wrong item',null);
  reset role; select * into r from public.shipments where id=s2;
  insert into t5 values ('failed delivery recorded with reason', case when r.status='Failed Delivery' and r.failure_reason='Customer refused' and r.completed_at is not null then 'PASS' else 'FAIL' end);
  -- other driver / new driver
  set local role authenticated;
  perform set_config('request.jwt.claims', json_build_object('sub', d2, 'role','authenticated')::text, true);
  select count(*) into n from public.my_deliveries();
  insert into t5 values ('another driver sees none of them', case when n=0 then 'PASS' else 'FAIL' end);
  begin perform public.driver_start_delivery(s1); insert into t5 values ('other driver cannot act on it','FAIL'); exception when others then insert into t5 values ('other driver cannot act on it','PASS'); end;
  begin perform public.staff_assign_shipment(s1,d2); insert into t5 values ('driver cannot assign','FAIL'); exception when others then insert into t5 values ('driver cannot assign', case when sqlerrm like '%Not allowed%' then 'PASS' else 'FAIL '||sqlerrm end); end;
  select count(*) into n from public.staff_delivery_updates();
  insert into t5 values ('driver gets nothing from updates feed', case when n=0 then 'PASS' else 'FAIL' end);
  -- staff feed
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  select count(*) into n from public.staff_delivery_updates();
  insert into t5 values ('staff feed shows delivered + failed', case when n=2 and exists(select 1 from public.staff_delivery_updates() where outcome='Delivered' and driver_name='Drv One' and received_by='Mrs Dlamini') then 'PASS' else 'FAIL '||n end);
  select count(*) into n from public.staff_delivery_updates(now() + interval '1 minute');
  insert into t5 values ('feed respects since filter', case when n=0 then 'PASS' else 'FAIL' end);
  -- odometer hold blocks deliveries
  reset role;
  update public.shipments set status='Collected', completed_at=null, assigned_to=d2 where id=s1;
  insert into public.odometer_flags(user_id,reg_norm,reading,previous_odo,reason,source_table,source_id) values (d2,'ZZ',1,2,'lower_than_previous','vehicle_checks',gen_random_uuid());
  set local role authenticated;
  perform set_config('request.jwt.claims', json_build_object('sub', d2, 'role','authenticated')::text, true);
  begin perform public.driver_start_delivery(s1); insert into t5 values ('odometer-held driver cannot start delivery','FAIL'); exception when others then insert into t5 values ('odometer-held driver cannot start delivery','PASS'); end;
  reset role;
  set local role anon;
  begin perform * from public.my_deliveries(); insert into t5 values ('anon cannot execute','FAIL'); exception when insufficient_privilege then insert into t5 values ('anon cannot execute','PASS'); end;
  reset role;
end $$;
select * from t5;
rollback;
