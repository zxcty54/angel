-- Run after 00_supabase_mock.sql + both migrations in a DISPOSABLE database.
-- Verifies self-service account deletion for Play Store policy compliance.
-- IMPORTANT: counts must be checked as the baseline role, because bl_profiles
-- RLS only exposes the caller's own row to authenticated sessions.
\set ON_ERROR_STOP on
BEGIN;
CREATE FUNCTION public.test_assert(ok boolean, label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN IF NOT coalesce(ok, false) THEN RAISE EXCEPTION 'FAILED: %', label; END IF; END $$;

INSERT INTO auth.users(id, phone, phone_confirmed_at) VALUES
  ('d0000000-0000-4000-8000-000000000004',NULL,NULL),
  ('d0000000-0000-4000-8000-000000000005',NULL,NULL);
INSERT INTO public.bl_locations(id,district,area_type,block_or_ulb,panchayat_name,ward_number,ward_alias,latitude,longitude) VALUES
  (9010,'Patna','urban','Delete ULB',NULL,7,'Delete Ward',25.60,85.16);

SET LOCAL ROLE authenticated;
-- Owner creates profile, post, comment and media.
SELECT set_config('request.jwt.claim.sub','d0000000-0000-4000-8000-000000000004',true);
SELECT public.bl_save_profile('Deletable neighbour',9010,'secret landmark') IS NOT NULL;
SELECT public.bl_create_post('general','Delete me','A disposable post.',9010) AS post_id \gset
SELECT public.bl_add_comment(:'post_id'::uuid,'own comment')->>'id' AS c1 \gset
INSERT INTO storage.objects(bucket_id,name,owner_id) VALUES('bl-post-media',auth.uid()::text||'/pic.jpg',auth.uid()::text);
-- A neighbour reacts and keeps their own account afterwards.
SELECT set_config('request.jwt.claim.sub','d0000000-0000-4000-8000-000000000005',true);
SELECT public.bl_save_profile('Observer neighbour',9010,'') IS NOT NULL;
SELECT public.bl_set_reaction(:'post_id'::uuid,'upvote',true);
-- Observer deletes their OWN account first: owner must survive.
SELECT public.bl_delete_my_account();
RESET ROLE;
SELECT public.test_assert((SELECT count(*)=1 FROM public.bl_profiles),'observer deletion eliminates exactly one profile');
SELECT public.test_assert((SELECT id='d0000000-0000-4000-8000-000000000004' FROM public.bl_profiles),'owner profile survived observer deletion');
-- Owner deletes their account: everything personal is wiped.
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','d0000000-0000-4000-8000-000000000004',true);
SELECT public.bl_delete_my_account();
RESET ROLE;

SELECT public.test_assert((SELECT count(*)=0 FROM public.bl_profiles),'all profiles wiped after both deletions');
SELECT public.test_assert(NOT EXISTS(SELECT 1 FROM public.bl_profiles WHERE id='d0000000-0000-4000-8000-000000000004'),'owner profile deleted');
SELECT public.test_assert((SELECT count(*)=0 FROM public.bl_posts),'posts cascaded');
SELECT public.test_assert((SELECT count(*)=0 FROM public.bl_comments),'comments cascaded');
SELECT public.test_assert((SELECT count(*)=0 FROM public.bl_post_reactions),'reactions cascaded');
SELECT public.test_assert((SELECT count(*)=0 FROM storage.objects WHERE bucket_id='bl-post-media'),'media rows removed');
SELECT public.test_assert(NOT EXISTS(SELECT 1 FROM public.bl_rate_limits WHERE user_id='d0000000-0000-4000-8000-000000000004'),'rate limit rows gone');
SELECT public.test_assert(NOT EXISTS(SELECT 1 FROM public.bl_community_moderators WHERE user_id='d0000000-0000-4000-8000-000000000004'),'moderator row gone');
ROLLBACK;
\echo 'PASS: bl_delete_my_account removes profile, content and media; other users unaffected'
