begin;
grant all on all tables in schema public to authenticated; grant usage on schema public to authenticated, anon;
create temp table t6(test text, result text) on commit drop; grant all on t6 to public;
do $$
declare d uuid:=gen_random_uuid(); e uuid:=gen_random_uuid(); n int; r record;
begin
  insert into auth.users(id,email) values (d,'d6@x.co'),(e,'e6@x.co');
  insert into public.profiles(id,email,role,full_name,driver_status,phone,id_number) values (d,'d6@x.co','driver','Drv Six','active','0821234567','9001015009087'),(e,'e6@x.co','driver','Other','active',null,null)
   on conflict (id) do update set full_name=excluded.full_name, driver_status='active', phone=excluded.phone, id_number=excluded.id_number;
  perform set_config('request.jwt.claims', json_build_object('sub', d, 'role','authenticated')::text, true);
  set local role authenticated;
  select * into r from public.my_profile();
  insert into t6 values ('my_profile returns own row', case when r.id=d and r.full_name='Drv Six' then 'PASS' else 'FAIL' end);
  insert into t6 values ('ID number masked', case when r.id_masked like '%9087' and r.id_masked not like '9001%' then 'PASS' else 'FAIL '||r.id_masked end);
  begin perform public.set_my_avatar('https://h/storage/'||e||'/avatar/x.jpg'); insert into t6 values ('avatar in another user folder rejected','FAIL'); exception when others then insert into t6 values ('avatar in another user folder rejected','PASS'); end;
  begin perform public.set_my_avatar('https://h/storage/'||d||'/vehicle-checks/x.jpg'); insert into t6 values ('avatar outside avatar folder rejected','FAIL'); exception when others then insert into t6 values ('avatar outside avatar folder rejected','PASS'); end;
  perform public.set_my_avatar('https://h/storage/'||d||'/avatar/x.jpg');
  select * into r from public.my_profile();
  insert into t6 values ('own avatar saved', case when r.avatar_path like '%/avatar/x.jpg' then 'PASS' else 'FAIL' end);
  perform set_config('request.jwt.claims', json_build_object('sub', e, 'role','authenticated')::text, true);
  select * into r from public.my_profile();
  insert into t6 values ('other user does not see my avatar', case when r.avatar_path is null and r.id=e then 'PASS' else 'FAIL' end);
  select count(*) into n from public.my_documents();
  insert into t6 values ('my_documents only own', case when n=0 then 'PASS' else 'FAIL' end);
  begin update public.profiles set role='admin' where id=e; get diagnostics n=row_count; insert into t6 values ('driver still cannot change own role', case when n=0 then 'PASS' else 'FAIL' end); exception when others then insert into t6 values ('driver still cannot change own role','PASS'); end;
  reset role; set local role anon;
  begin perform * from public.my_profile(); insert into t6 values ('anon cannot execute','FAIL'); exception when insufficient_privilege then insert into t6 values ('anon cannot execute','PASS'); end;
  reset role;
end $$;
select * from t6;
rollback;
