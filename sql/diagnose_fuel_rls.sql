-- READ-ONLY diagnostic. Changes nothing. Run in the "visibility" project and send me the result.
select jsonb_pretty(jsonb_build_object(
  'accounts', (select jsonb_agg(jsonb_build_object('email', email, 'role', role, 'status', driver_status)) from public.profiles),
  'open_odometer_flags', (select coalesce(jsonb_agg(jsonb_build_object('user', user_id, 'reason', reason, 'reg', reg_norm, 'reading', reading, 'previous', previous_odo)), '[]'::jsonb) from public.odometer_flags where status = 'open'),
  'fuel_logs_triggers', (select jsonb_agg(tgname) from pg_trigger where tgrelid = 'public.fuel_logs'::regclass and not tgisinternal),
  'fuel_logs_policies', (select jsonb_agg(jsonb_build_object('name', policyname, 'cmd', cmd, 'check', with_check)) from pg_policies where tablename = 'fuel_logs'),
  'user_id_default', (select column_default from information_schema.columns where table_name = 'fuel_logs' and column_name = 'user_id')
)) as diagnostic;
