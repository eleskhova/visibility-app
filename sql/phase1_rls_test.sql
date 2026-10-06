-- ============================================================
-- VISIBILITY — Phase 1 RLS / audit self-test
-- Run in the Supabase SQL Editor AFTER phase1a_audit_roles.sql.
-- It creates temporary fake users + rows, checks what each role can
-- and cannot do, shows a PASS/FAIL table, then ROLLS BACK everything.
-- Nothing is saved. Every row in the result must say PASS.
-- ============================================================
begin;

create temp table t_results (test text, expected text, actual text, result text) on commit drop;
grant all on t_results to public;

-- fake users (profiles auto-created by trigger as 'driver')
insert into auth.users (id, email, aud, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'zz.driver1@test.invalid', 'authenticated', 'authenticated'),
  ('aaaaaaaa-0000-0000-0000-000000000002', 'zz.driver2@test.invalid', 'authenticated', 'authenticated'),
  ('aaaaaaaa-0000-0000-0000-000000000003', 'zz.opsadmin@test.invalid', 'authenticated', 'authenticated'),
  ('aaaaaaaa-0000-0000-0000-000000000004', 'zz.opsmgr@test.invalid', 'authenticated', 'authenticated'),
  ('aaaaaaaa-0000-0000-0000-000000000005', 'zz.super@test.invalid', 'authenticated', 'authenticated');
update profiles set role='backoffice'  where id='aaaaaaaa-0000-0000-0000-000000000003';
update profiles set role='ops_manager' where id='aaaaaaaa-0000-0000-0000-000000000004';
update profiles set role='admin'       where id='aaaaaaaa-0000-0000-0000-000000000005';

-- seed rows owned by each driver, plus a legacy row with no owner
insert into vehicle_checks (driver, reg_no, check_type, odo, user_id) values
  ('ZZ D1','ZZ1','AM','1','aaaaaaaa-0000-0000-0000-000000000001'),
  ('ZZ D2','ZZ2','AM','1','aaaaaaaa-0000-0000-0000-000000000002'),
  ('ZZ LEGACY','ZZ3','AM','1', null);
insert into shipments (sender_name, recipient_name) values ('ZZ sender','ZZ recipient');

create or replace function pg_temp.as_user(uid text) returns void language plpgsql as $f$
begin
  perform set_config('request.jwt.claims', json_build_object('sub', uid, 'role', 'authenticated')::text, true);
  perform set_config('request.jwt.claim.sub', uid, true);
end $f$;

do $$
declare n int; ok boolean; msg text;
  d1 text := 'aaaaaaaa-0000-0000-0000-000000000001';
  d2 text := 'aaaaaaaa-0000-0000-0000-000000000002';
  oa text := 'aaaaaaaa-0000-0000-0000-000000000003';
  om text := 'aaaaaaaa-0000-0000-0000-000000000004';
  sa text := 'aaaaaaaa-0000-0000-0000-000000000005';
begin
  -- DRIVER 1: sees only own vehicle check (not driver 2, not legacy)
  perform pg_temp.as_user(d1); set local role authenticated;
  select count(*) into n from vehicle_checks where driver like 'ZZ%'; reset role;
  insert into t_results values ('driver1 sees only own vehicle checks','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  perform pg_temp.as_user(d1); set local role authenticated;
  select count(*) into n from shipments; reset role;
  insert into t_results values ('driver1 cannot read shipments','0',n::text, case when n=0 then 'PASS' else 'FAIL' end);

  perform pg_temp.as_user(d1); set local role authenticated;
  select count(*) into n from audit_log; reset role;
  insert into t_results values ('driver1 cannot read audit log','0',n::text, case when n=0 then 'PASS' else 'FAIL' end);

  perform pg_temp.as_user(d1); set local role authenticated;
  select count(*) into n from profiles; reset role;
  insert into t_results values ('driver1 sees only own profile','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  -- driver cannot escalate own role
  ok := false;
  begin
    perform pg_temp.as_user(d1); set local role authenticated;
    update profiles set role='admin' where id = d1::uuid;
    get diagnostics n = row_count; reset role;
    ok := (n = 0);
  exception when others then reset role; ok := true; end;
  insert into t_results values ('driver1 cannot make self admin','0 rows / error', case when ok then 'blocked' else 'ALLOWED' end, case when ok then 'PASS' else 'FAIL' end);

  -- driver cannot write audit log
  ok := false;
  begin
    perform pg_temp.as_user(d1); set local role authenticated;
    insert into audit_log (action, table_name) values ('hack','x'); reset role;
  exception when others then reset role; ok := true; end;
  insert into t_results values ('driver1 cannot forge audit entries','blocked', case when ok then 'blocked' else 'ALLOWED' end, case when ok then 'PASS' else 'FAIL' end);

  -- OPERATIONS ADMIN: sees all vehicle checks + shipments, NOT audit, NOT other profiles
  perform pg_temp.as_user(oa); set local role authenticated;
  select count(*) into n from vehicle_checks where driver like 'ZZ%'; reset role;
  insert into t_results values ('ops admin sees all vehicle checks (incl. legacy)','3',n::text, case when n=3 then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(oa); set local role authenticated;
  select count(*) into n from shipments where sender_name='ZZ sender'; reset role;
  insert into t_results values ('ops admin reads shipments','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(oa); set local role authenticated;
  select count(*) into n from audit_log; reset role;
  insert into t_results values ('ops admin cannot read audit log','0',n::text, case when n=0 then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(oa); set local role authenticated;
  select count(*) into n from profiles; reset role;
  insert into t_results values ('ops admin sees only own profile (no user list)','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  -- OPERATIONS MANAGER: all operations + audit log; no user list
  perform pg_temp.as_user(om); set local role authenticated;
  select count(*) into n from shipments where sender_name='ZZ sender'; reset role;
  insert into t_results values ('ops manager reads shipments','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(om); set local role authenticated;
  select count(*) into n from audit_log; reset role;
  insert into t_results values ('ops manager can read audit log','>=1',n::text, case when n>=1 then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(om); set local role authenticated;
  select count(*) into n from profiles; reset role;
  insert into t_results values ('ops manager sees only own profile','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  -- SUPER ADMIN: everything incl. all profiles + audit
  perform pg_temp.as_user(sa); set local role authenticated;
  select count(*) into n from profiles where email like 'zz.%'; reset role;
  insert into t_results values ('super admin sees all users','5',n::text, case when n=5 then 'PASS' else 'FAIL' end);

  -- AUDIT TRAIL: a status change is recorded with who/old/new
  perform pg_temp.as_user(oa); set local role authenticated;
  update shipments set status='In Transit' where sender_name='ZZ sender'; reset role;
  select count(*) into n from audit_log where table_name='shipments' and user_email='zz.opsadmin@test.invalid'
     and old_data->>'status'='Order Created' and new_data->>'status'='In Transit';
  insert into t_results values ('shipment status change is audited (who, old, new)','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  -- ROLE CHANGE is audited
  perform pg_temp.as_user(sa); set local role authenticated;
  update profiles set role='backoffice' where id = d2::uuid; reset role;
  select count(*) into n from audit_log where table_name='profiles' and new_data->>'role'='backoffice' and user_email='zz.super@test.invalid';
  insert into t_results values ('role change is audited','1',n::text, case when n=1 then 'PASS' else 'FAIL' end);

  -- storage policy shape (only checks policies exist after phase 1C)
  select count(*) into n from pg_policies where schemaname='storage' and tablename='objects' and policyname in ('photos insert own folder','photos read own or office');
  insert into t_results values ('storage policies installed (run phase1c first for PASS)','2',n::text, case when n=2 then 'PASS' else 'SKIP/FAIL' end);
end $$;

select * from t_results order by result desc, test;

rollback;
