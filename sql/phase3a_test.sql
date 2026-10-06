begin;
\i phase3a_compliance_reports.sql
create temp table t3(test text, result text) on commit drop; grant all on t3 to public;
do $$
declare a uuid:=gen_random_uuid(); d uuid:=gen_random_uuid(); d2 uuid:=gen_random_uuid(); n int; r record;
begin
  insert into auth.users(id,email) values (a,'a@x.co'),(d,'d@x.co'),(d2,'d2@x.co');
  insert into public.profiles(id,email,role,full_name,driver_status) values (a,'a@x.co','backoffice','Staff','active'),(d,'d@x.co','driver','Drv One','active'),(d2,'d2@x.co','driver','Drv Two','registered')
   on conflict (id) do update set role=excluded.role, driver_status=excluded.driver_status, full_name=excluded.full_name;
  insert into public.driver_documents(user_id,doc_type,storage_path,status,expiry_date)
   select d, doc_type, 'x/'||doc_type, 'approved', current_date + 10 from public.document_requirements where has_expiry limit 1;
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,created_at) values
   (d,'Drv One','ca 123','AM','10 000 km', now()-interval '3 days'),
   (d,'Drv One','CA123','AM','10500', now()-interval '2 days'),
   (d,'Drv One','ca123','AM','10400', now()-interval '1 day'),
   (d,'Drv One','ca123','AM','abc', now());
  insert into public.fuel_logs(user_id,driver,reg_no,garage,litres,amount,payment_method,odo,created_at) values (d,'Drv One','CA123','G','10','200','card','13000', now());
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.staff_expiry_report(30);
  insert into t3 values ('staff sees expiring doc', case when n=1 then 'PASS' else 'FAIL '||n end);
  select * into r from public.staff_km_summary(current_date-7, current_date) where reg_no is not null limit 1;
  insert into t3 values ('km normalised reg + first/last', case when r.reg_no='CA123' and r.first_odo=10000 and r.last_odo=13000 and r.km=3000 then 'PASS' else 'FAIL '||coalesce(r.reg_no,'-')||r.first_odo||'/'||r.last_odo end);
  insert into t3 values ('backwards flagged', case when r.backwards=1 then 'PASS' else 'FAIL '||r.backwards end);
  insert into t3 values ('big jump flagged', case when r.big_jumps=1 then 'PASS' else 'FAIL '||r.big_jumps end);
  insert into t3 values ('invalid reading counted', case when r.invalid_readings=1 then 'PASS' else 'FAIL '||r.invalid_readings end);
  select count(*) into n from public.staff_check_compliance(current_date-7,current_date) where user_id=d and vehicle_checks=4 and days_with_check=4;
  insert into t3 values ('compliance counts per driver', case when n=1 then 'PASS' else 'FAIL' end);
  select count(*) into n from public.staff_check_compliance(current_date-7,current_date) where user_id=d2;
  insert into t3 values ('non-active driver excluded', case when n=0 then 'PASS' else 'FAIL' end);
  begin perform * from public.staff_km_summary(current_date-200,current_date); insert into t3 values ('range cap enforced','FAIL');
  exception when others then insert into t3 values ('range cap enforced','PASS'); end;
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  select (select count(*) from public.staff_expiry_report(30))+(select count(*) from public.staff_km_summary(current_date-7,current_date))+(select count(*) from public.staff_check_compliance(current_date-7,current_date)) into n;
  insert into t3 values ('driver gets nothing from reports', case when n=0 then 'PASS' else 'FAIL '||n end);
  reset role;
  perform set_config('request.jwt.claims', '{}', true);
  set local role anon;
  begin perform * from public.staff_expiry_report(30); insert into t3 values ('anon cannot execute','FAIL');
  exception when insufficient_privilege then insert into t3 values ('anon cannot execute','PASS'); end;
  reset role;
end $$;
select * from t3;
rollback;
