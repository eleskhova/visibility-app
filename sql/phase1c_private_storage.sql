-- ============================================================
-- VISIBILITY — Phase 1C: private photo storage
-- Run ONLY AFTER the Phase 1 front-end is live (it displays photos
-- through short-lived signed links). Running this earlier would
-- break photo display in the old app.
--
-- Result:
--   * Bucket "visibility-photos" becomes PRIVATE (no public URLs).
--   * Users upload only into their own folder  <user-id>/...
--   * Users read only their own folder; back office / admin read all.
--   * Old photos (stored at bucket root, e.g. vehicle-checks/...) are
--     readable by back office / admin only.
-- Re-runnable. Does not delete any file.
-- ============================================================
begin;

update storage.buckets set public = false where id = 'visibility-photos';

drop policy if exists "auth read photos"   on storage.objects;
drop policy if exists "auth upload photos" on storage.objects;
drop policy if exists "photos insert own folder" on storage.objects;
drop policy if exists "photos read own or office" on storage.objects;

create policy "photos insert own folder" on storage.objects for insert to authenticated
  with check (
    bucket_id = 'visibility-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "photos read own or office" on storage.objects for select to authenticated
  using (
    bucket_id = 'visibility-photos'
    and (
      public.is_admin_or_backoffice()
      or (storage.foldername(name))[1] = auth.uid()::text
    )
  );

commit;

-- Verify:
--   select id, public from storage.buckets where id = 'visibility-photos';  -- public = false
