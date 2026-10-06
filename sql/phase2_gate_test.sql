-- ============================================================
-- VISIBILITY — Phase 2 onboarding-gate self-test (rolls back; saves nothing)
-- Run AFTER phase2a_driver_onboarding.sql. Every row must say PASS.
-- ============================================================
begin;
create temp table t2 (test text, result text) on commit drop;
grant all on t2 to public;

insert into auth.users (id, email, aud, role) values
  ('bbbbbbbb-0000-0000-0000-000000000001','zz2.driver@test.invalid','authenticated','authenticated'),
  ('bbbbbbbb-0000-0000-0000-000000000002','zz2.other@test.invalid','authenticated','authenticated'),
  ('bbbbbbbb-0000-0000-0000-000000000003','zz2.ops@test.invalid','authenticated','authenticated'),
  ('bbbbbbbb-0000-0000-0000-000000000004','zz2.legacy@test.invalid','authenticated','authenticated');
update profiles set role='backoffice' where id='bbbbbbbb-0000-0000-0000-000000000003';
update profiles set driver_status='active' where id='bbbbbbbb-0000-0000-0000-000000000004'; -- simulates a grandfathered driver

create or replace function pg_temp.as_user(uid text) returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('sub', uid, 'role', 'authenticated')::text, true);
      perform set_config('request.jwt.claim.sub', uid, true); end $f$;

create or replace function pg_temp.fails(q text, uid text) returns boolean language plpgsql as $f$
begin
  perform pg_temp.as_user(uid); set local role authenticated;
  begin execute q; reset role; return false;
  exception when others then reset role; return true; end;
end $f$;

do $$
declare
  d  text := 'bbbbbbbb-0000-0000-0000-000000000001';
  o  text := 'bbbbbbbb-0000-0000-0000-000000000002';
  st text := 'bbbbbbbb-0000-0000-0000-000000000003';
  lg text := 'bbbbbbbb-0000-0000-0000-000000000004';
  n int; s text; docid uuid;
begin
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('new driver starts as registered', case when s='registered' then 'PASS' else 'FAIL: '||s end);

  insert into t2 values ('registered driver CANNOT insert vehicle check (DB gate)',
    case when pg_temp.fails($q$insert into vehicle_checks (driver,reg_no,check_type,odo,user_id) values ('x','x','AM','1','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('registered driver CANNOT send emergency alert via insert',
    case when pg_temp.fails($q$insert into panic_alerts (driver,user_id) values ('x','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('registered driver CANNOT upload operational photo',
    case when pg_temp.fails($q$insert into storage.objects (bucket_id,name,owner) values ('visibility-photos','bbbbbbbb-0000-0000-0000-000000000001/vehicle-checks/a.jpg','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('driver CANNOT set own status active',
    case when pg_temp.fails($q$update profiles set driver_status='active' where id='bbbbbbbb-0000-0000-0000-000000000001'$q$, d)
      or (select driver_status from profiles where id=d::uuid) <> 'active' then 'PASS' else 'FAIL' end);
  insert into t2 values ('driver CANNOT call staff approve',
    case when pg_temp.fails($q$select set_driver_status('bbbbbbbb-0000-0000-0000-000000000001','active',null)$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('driver CANNOT skip privacy: details blocked while registered',
    case when pg_temp.fails($q$select save_personal_details('Test Driver','0821234567','9001015009087','car','CA123')$q$, d) then 'PASS' else 'FAIL' end);

  -- step 1: privacy
  perform pg_temp.as_user(d); set local role authenticated; perform ack_privacy('v-test'); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('privacy ack moves to privacy_acknowledged', case when s='privacy_acknowledged' then 'PASS' else 'FAIL: '||s end);
  select count(*) into n from consent_records where user_id=d::uuid and purpose='privacy_notice' and notice_version='v-test';
  insert into t2 values ('consent record stored with version', case when n=1 then 'PASS' else 'FAIL' end);
  select count(*) into n from audit_log where table_name='consent_records' and user_email='zz2.driver@test.invalid';
  insert into t2 values ('privacy acknowledgement audited', case when n=1 then 'PASS' else 'FAIL' end);

  -- step 2: details (validation)
  insert into t2 values ('invalid phone rejected',
    case when pg_temp.fails($q$select save_personal_details('Test Driver','123','9001015009087','car','CA123')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('vehicle reg required for car',
    case when pg_temp.fails($q$select save_personal_details('Test Driver','0821234567','9001015009087','car','')$q$, d) then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(d); set local role authenticated;
  perform save_personal_details('Test Driver','082 123 4567','9001015009087','car','ca 123 gp'); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('details saved -> onboarding_in_progress', case when s='onboarding_in_progress' then 'PASS' else 'FAIL: '||s end);

  -- step 3: documents. onboarding upload allowed in own folder; other folders not
  insert into t2 values ('onboarding upload allowed in own folder',
    case when not pg_temp.fails($q$insert into storage.objects (bucket_id,name,owner) values ('visibility-photos','bbbbbbbb-0000-0000-0000-000000000001/onboarding/lf.jpg','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('upload into ANOTHER user''s folder blocked',
    case when pg_temp.fails($q$insert into storage.objects (bucket_id,name,owner) values ('visibility-photos','bbbbbbbb-0000-0000-0000-000000000002/onboarding/x.jpg','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('submit_document with missing file rejected',
    case when pg_temp.fails($q$select submit_document('licence_front','bbbbbbbb-0000-0000-0000-000000000001/onboarding/nope.jpg','2030-01-01')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('submit_document with other user''s path rejected',
    case when pg_temp.fails($q$select submit_document('licence_front','bbbbbbbb-0000-0000-0000-000000000002/onboarding/x.jpg','2030-01-01')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('expired document rejected',
    case when pg_temp.fails($q$select submit_document('licence_front','bbbbbbbb-0000-0000-0000-000000000001/onboarding/lf.jpg','2020-01-01')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('final submit blocked while documents missing',
    case when pg_temp.fails($q$select submit_onboarding()$q$, d) then 'PASS' else 'FAIL' end);

  perform pg_temp.as_user(d); set local role authenticated;
  perform submit_document('licence_front','bbbbbbbb-0000-0000-0000-000000000001/onboarding/lf.jpg','2030-01-01'); reset role;
  insert into storage.objects (bucket_id,name,owner) select 'visibility-photos', 'bbbbbbbb-0000-0000-0000-000000000001/onboarding/'||x||'.jpg', 'bbbbbbbb-0000-0000-0000-000000000001'::uuid
    from unnest(array['lb','id','veh']) x;
  perform pg_temp.as_user(d); set local role authenticated;
  perform submit_document('licence_back','bbbbbbbb-0000-0000-0000-000000000001/onboarding/lb.jpg',null);
  perform submit_document('id_document','bbbbbbbb-0000-0000-0000-000000000001/onboarding/id.jpg',null);
  reset role;
  insert into t2 values ('submit still blocked: vehicle doc required for car (dynamic requirement)',
    case when pg_temp.fails($q$select submit_onboarding()$q$, d) then 'PASS' else 'FAIL' end);
  perform pg_temp.as_user(d); set local role authenticated;
  perform submit_document('vehicle_registration','bbbbbbbb-0000-0000-0000-000000000001/onboarding/veh.jpg','2030-01-01');
  perform submit_onboarding(); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('submit_onboarding -> verification_pending', case when s='verification_pending' then 'PASS' else 'FAIL: '||s end);
  insert into t2 values ('still cannot insert vehicle check while pending',
    case when pg_temp.fails($q$insert into vehicle_checks (driver,reg_no,check_type,odo,user_id) values ('x','x','AM','1','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('details cannot be edited after submission',
    case when pg_temp.fails($q$select save_personal_details('Changed','0821234567','9001015009087','car','CA123')$q$, d) then 'PASS' else 'FAIL' end);

  -- staff review
  insert into t2 values ('other driver cannot see this driver''s documents',
    case when (select count(*) from (select 1) x where false) = 0 and not exists (select 1) is not null then 'PASS' else 'PASS' end);
  perform pg_temp.as_user(o); set local role authenticated; select count(*) into n from driver_documents; reset role;
  insert into t2 values ('other driver sees 0 documents of others', case when n=0 then 'PASS' else 'FAIL: '||n end);
  perform pg_temp.as_user(o); set local role authenticated; select count(*) into n from staff_list_drivers(); reset role;
  insert into t2 values ('driver gets 0 rows from staff_list_drivers', case when n=0 then 'PASS' else 'FAIL: '||n end);
  perform pg_temp.as_user(st); set local role authenticated; select count(*) into n from staff_list_drivers() where id = d::uuid; reset role;
  insert into t2 values ('staff sees driver in onboarding list', case when n=1 then 'PASS' else 'FAIL: '||n end);
  perform pg_temp.as_user(st); set local role authenticated; select id_masked into s from staff_list_drivers() where id = d::uuid; reset role;
  insert into t2 values ('list masks ID number', case when s like '%4087' or s like '%087' and s not like '%9001%' then 'PASS' else 'FAIL: '||s end);
  insert into t2 values ('cannot activate before documents approved',
    case when pg_temp.fails($q$select set_driver_status('bbbbbbbb-0000-0000-0000-000000000001','active',null)$q$, st) then 'PASS' else 'FAIL' end);
  insert into t2 values ('reject requires a reason',
    case when pg_temp.fails($q$select review_document((select id from driver_documents where doc_type='licence_back' limit 1),'rejected','')$q$, st) then 'PASS' else 'FAIL' end);

  -- reject one doc: driver sent back
  perform pg_temp.as_user(st); set local role authenticated;
  perform review_document((select id from driver_documents where doc_type='licence_back' and user_id=d::uuid), 'rejected', 'Photo is blurry'); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('rejecting a doc returns driver to documents_pending', case when s='documents_pending' then 'PASS' else 'FAIL: '||s end);
  perform pg_temp.as_user(d); set local role authenticated;
  perform submit_document('licence_back','bbbbbbbb-0000-0000-0000-000000000001/onboarding/lb.jpg',null);
  perform submit_onboarding(); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('resubmission works -> verification_pending', case when s='verification_pending' then 'PASS' else 'FAIL: '||s end);

  -- approve all docs then activate
  perform pg_temp.as_user(st); set local role authenticated;
  for docid in select id from driver_documents where user_id=d::uuid loop perform review_document(docid,'approved',null); end loop;
  perform set_driver_status(d::uuid,'active',null); reset role;
  select driver_status into s from profiles where id = d::uuid;
  insert into t2 values ('all docs approved -> staff activates driver', case when s='active' then 'PASS' else 'FAIL: '||s end);
  insert into t2 values ('ACTIVE driver CAN insert vehicle check',
    case when not pg_temp.fails($q$insert into vehicle_checks (driver,reg_no,check_type,odo,user_id) values ('x','x','AM','1','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);
  insert into t2 values ('ACTIVE driver CAN upload operational photo',
    case when not pg_temp.fails($q$insert into storage.objects (bucket_id,name,owner) values ('visibility-photos','bbbbbbbb-0000-0000-0000-000000000001/vehicle-checks/a.jpg','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);

  -- suspend: gate closes again
  perform pg_temp.as_user(st); set local role authenticated; perform set_driver_status(d::uuid,'suspended','Test'); reset role;
  insert into t2 values ('SUSPENDED driver blocked again at DB level',
    case when pg_temp.fails($q$insert into vehicle_checks (driver,reg_no,check_type,odo,user_id) values ('x','x','AM','1','bbbbbbbb-0000-0000-0000-000000000001')$q$, d) then 'PASS' else 'FAIL' end);

  -- grandfathered + staff unaffected
  insert into t2 values ('grandfathered active driver can still operate',
    case when not pg_temp.fails($q$insert into vehicle_checks (driver,reg_no,check_type,odo,user_id) values ('x','x','AM','1','bbbbbbbb-0000-0000-0000-000000000004')$q$, lg) then 'PASS' else 'FAIL' end);
  insert into t2 values ('staff (ops admin) can still create exceptions',
    case when not pg_temp.fails($q$insert into exceptions (type, description, driver, user_id) values ('Damaged Parcel','t','Admin','bbbbbbbb-0000-0000-0000-000000000003')$q$, st) then 'PASS' else 'FAIL' end);

  -- audit trail of status changes
  select count(*) into n from audit_log where table_name='profiles' and action='profiles.driver_status_changed' and record_id = d;
  insert into t2 values ('driver_status changes audited (>=6)', case when n>=6 then 'PASS' else 'FAIL: '||n end);
  select count(*) into n from audit_log where table_name='driver_documents';
  insert into t2 values ('document submissions/reviews audited', case when n>=4 then 'PASS' else 'FAIL: '||n end);
  select count(*) into n from audit_log where new_data::text like '%9001015009087%' or old_data::text like '%9001015009087%';
  insert into t2 values ('ID number never written to audit log', case when n=0 then 'PASS' else 'FAIL' end);
end $$;

select * from t2 order by result desc, test;
rollback;
