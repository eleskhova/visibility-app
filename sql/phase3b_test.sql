begin;
grant all on all tables in schema public to authenticated; grant usage on schema public to authenticated, anon;
create temp table t4(test text, result text) on commit drop; grant all on t4 to public;
do $$
declare a uuid:=gen_random_uuid(); d uuid:=gen_random_uuid(); n int; fid uuid; v bigint; ok boolean;
  ph jsonb; badph jsonb := '[{"label":"front","url":"x"}]';
begin
  insert into auth.users(id,email) values (a,'a3@x.co'),(d,'d3@x.co');
  insert into public.profiles(id,email,role,full_name,driver_status) values (a,'a3@x.co','backoffice','Staff','active'),(d,'d3@x.co','driver','Drv','active')
   on conflict (id) do update set role=excluded.role, driver_status=excluded.driver_status;
  ph := jsonb_build_array(jsonb_build_object('label','odometer','url','https://h/storage/'||d||'/vehicle-checks/1.jpg'));
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  set local role authenticated;
  -- photo gate
  begin insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ 99 GP','AM','1000',true,badph); insert into t4 values ('vehicle check without odometer photo rejected','FAIL');
  exception when others then insert into t4 values ('vehicle check without odometer photo rejected', case when sqlerrm like '%odometer photo%' then 'PASS' else 'FAIL '||sqlerrm end); end;
  begin insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ 99 GP','AM','1000',true,jsonb_build_array(jsonb_build_object('label','odometer','url','https://h/storage/'||a||'/x.jpg'))); insert into t4 values ('photo from another user path rejected','FAIL');
  exception when others then insert into t4 values ('photo from another user path rejected','PASS'); end;
  begin insert into public.fuel_logs(user_id,driver,reg_no,garage,litres,amount,payment_method,odo,photos) values (d,'D','ZZ99GP','G','10','200','card','1000','[]'); insert into t4 values ('fuel log without odometer photo rejected','FAIL');
  exception when others then insert into t4 values ('fuel log without odometer photo rejected','PASS'); end;
  -- normal sequence
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ 99 GP','AM','1000',true,ph);
  insert into public.fuel_logs(user_id,driver,reg_no,garage,litres,amount,payment_method,odo,photos) values (d,'D','zz99gp','G','10','200','card','1200',ph);
  select public.vehicle_last_odometer('ZZ-99-GP') into v;
  insert into t4 values ('baseline follows increasing readings (reg normalised)', case when v=1200 then 'PASS' else 'FAIL '||coalesce(v::text,'null') end);
  select count(*) into n from public.my_odometer_hold();
  insert into t4 values ('no hold after valid readings', case when n=0 then 'PASS' else 'FAIL' end);
  -- lower reading
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ99GP','PM','900',true,ph);
  select count(*) into n from public.my_odometer_hold();
  insert into t4 values ('lower reading raises hold', case when n=1 then 'PASS' else 'FAIL' end);
  select public.vehicle_last_odometer('ZZ99GP') into v;
  insert into t4 values ('baseline NOT lowered by bad reading', case when v=1200 then 'PASS' else 'FAIL '||v end);
  begin insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ99GP','PM','1300',true,ph); insert into t4 values ('held driver cannot create vehicle check','FAIL');
  exception when others then insert into t4 values ('held driver cannot create vehicle check','PASS'); end;
  begin insert into public.fuel_logs(user_id,driver,reg_no,garage,litres,amount,payment_method,odo,photos) values (d,'D','ZZ99GP','G','10','200','card','1300',ph); insert into t4 values ('held driver cannot create fuel log','FAIL');
  exception when others then insert into t4 values ('held driver cannot create fuel log','PASS'); end;
  begin insert into public.panic_alerts(user_id,driver) values (d,'D'); insert into t4 values ('held driver CAN still send emergency alert','PASS');
  exception when others then insert into t4 values ('held driver CAN still send emergency alert','FAIL '||sqlerrm); end;
  begin update public.odometer_flags set status='released' where user_id=d; get diagnostics n = row_count; insert into t4 values ('driver cannot self-release flag', case when n=0 then 'PASS' else 'FAIL' end);
  exception when others then insert into t4 values ('driver cannot self-release flag','PASS'); end;
  begin perform public.staff_resolve_odometer_flag(gen_random_uuid(),'release','long enough note'); insert into t4 values ('driver cannot call staff resolve','FAIL');
  exception when others then insert into t4 values ('driver cannot call staff resolve', case when sqlerrm like '%Not allowed%' then 'PASS' else 'FAIL '||sqlerrm end); end;
  select count(*) into n from public.staff_odometer_flags('all');
  insert into t4 values ('driver sees nothing from staff flag list', case when n=0 then 'PASS' else 'FAIL' end);
  -- staff review
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  select flag_id into fid from public.staff_odometer_flags('open') where user_id=d limit 1;
  insert into t4 values ('staff sees the open flag with photo', case when fid is not null and (select photo_url from public.staff_odometer_flags('open') where flag_id=fid) like '%vehicle-checks%' then 'PASS' else 'FAIL' end);
  begin perform public.staff_resolve_odometer_flag(fid,'release','x'); insert into t4 values ('resolve requires a note','FAIL'); exception when others then insert into t4 values ('resolve requires a note','PASS'); end;
  perform public.staff_resolve_odometer_flag(fid,'release','Driver typo, photo shows 1,300');
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  select count(*) into n from public.my_odometer_hold();
  insert into t4 values ('release clears the hold', case when n=0 then 'PASS' else 'FAIL' end);
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ99GP','PM','1300',true,ph);
  insert into t4 values ('driver can operate again after release', 'PASS');
  -- unreadable
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ99GP','AM','abc',true,ph);
  select count(*) into n from public.my_odometer_hold();
  insert into t4 values ('unreadable km raises hold', case when n=1 then 'PASS' else 'FAIL' end);
  -- baseline reset
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  select flag_id into fid from public.staff_odometer_flags('open') where user_id=d limit 1;
  begin perform public.staff_resolve_odometer_flag(fid,'reset_baseline','cannot reset unreadable'); insert into t4 values ('unreadable cannot become baseline','FAIL'); exception when others then insert into t4 values ('unreadable cannot become baseline','PASS'); end;
  perform public.staff_resolve_odometer_flag(fid,'release','Driver confirmed mistake');
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  insert into public.vehicle_checks(user_id,driver,reg_no,check_type,odo,acknowledged,photos) values (d,'D','ZZ99GP','AM','500',true,ph);
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role','authenticated')::text, true);
  select flag_id into fid from public.staff_odometer_flags('open') where user_id=d limit 1;
  perform public.staff_resolve_odometer_flag(fid,'reset_baseline','Old reading was wrong, photo shows 500');
  select public.vehicle_last_odometer('ZZ99GP') into v;
  insert into t4 values ('reset_baseline applies the new reading', case when v=500 then 'PASS' else 'FAIL '||v end);
  begin perform public.staff_resolve_odometer_flag(fid,'release','already resolved twice'); insert into t4 values ('cannot resolve twice','FAIL'); exception when others then insert into t4 values ('cannot resolve twice','PASS'); end;
  reset role;
  select count(*) into n from public.audit_log where table_name='odometer_flags';
  insert into t4 values ('flag raise/resolve audited', case when n>=5 then 'PASS' else 'FAIL '||n end);
  set local role anon;
  begin perform * from public.my_odometer_hold(); insert into t4 values ('anon cannot execute','FAIL'); exception when insufficient_privilege then insert into t4 values ('anon cannot execute','PASS'); end;
  reset role;
end $$;
select * from t4;
rollback;
