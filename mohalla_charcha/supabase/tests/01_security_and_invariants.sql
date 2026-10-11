-- Run after the migration in a DISPOSABLE local/CI PostgreSQL database.
-- This transaction rolls back fixtures and assertion helpers.
\set ON_ERROR_STOP on
BEGIN;
CREATE FUNCTION public.test_assert(ok boolean, label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN IF NOT coalesce(ok, false) THEN RAISE EXCEPTION 'FAILED: %', label; END IF; END $$;
CREATE FUNCTION public.test_raises(query text, expected text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  BEGIN EXECUTE query;
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM LIKE '%' || expected || '%' THEN RETURN; END IF;
    RAISE EXCEPTION 'Wrong exception: %, expected %', SQLERRM, expected;
  END;
  RAISE EXCEPTION 'Expected exception %, but query succeeded', expected;
END $$;

INSERT INTO auth.users(id, phone, phone_confirmed_at) VALUES
  ('a0000000-0000-4000-8000-000000000001','919999900001',now()),
  ('b0000000-0000-4000-8000-000000000001','919999900002',now()),
  ('c0000000-0000-4000-8000-000000000001','919999900003',NULL);
INSERT INTO public.bihar_locations(id,district,area_type,block_or_ulb,panchayat_name,ward_number,ward_alias,latitude,longitude) VALUES
  (9001,'Patna','urban','Test ULB',NULL,22,'Test Ward',25.5992,85.1580),
  (9002,'Patna','rural','Test Block','Danara',4,'Danara 4',25.450,84.880),
  (9003,'Patna','rural','Test Block','Mahajpura',4,'Mahajpura 4',25.451,84.881),
  (9004,'Patna','rural','Test Block','Danara',5,'Danara 5',25.452,84.882);

SELECT public.test_assert(NOT has_function_privilege('anon','public.get_feed(bigint,text,text,text,text,integer,timestamptz,uuid,integer)','EXECUTE'),'anonymous cannot invoke feed');
SELECT public.test_assert(NOT has_function_privilege('authenticated','public._profile_card(uuid)','EXECUTE'),'identity helper not exposed');
SELECT public.test_assert(NOT has_table_privilege('authenticated','public.posts','UPDATE'),'clients cannot forge counts');
SELECT public.test_assert(NOT has_table_privilege('authenticated','public.profiles','UPDATE'),'clients cannot forge reputation');
SELECT public.test_assert((SELECT count(*) = 9 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
  AND c.relname IN ('profiles','posts','bihar_locations','post_reactions','comments','post_reports','community_moderators','moderation_log','_rate_limits') AND c.relrowsecurity),'all 9 application tables have RLS');

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','c0000000-0000-4000-8000-000000000001',true);
SELECT public.test_raises($q$SELECT public.save_profile('Unverified user',9001,'')$q$,'verified_phone_required');
SELECT set_config('request.jwt.claim.sub','a0000000-0000-4000-8000-000000000001',true);
SELECT public.save_profile('Neighbour A',9001,'private landmark') IS NOT NULL;
SELECT public.test_assert((SELECT count(*)=1 FROM public.profiles),'only own profile visible');
SELECT public.create_post('civic_issue','Test civic issue','Standing water in our sample lane.',9001,
  '{"severity":"high","ditto_count":9999,"is_resolved":true}', '', '{}',25.599234,85.158932) AS issue_id \gset
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->'metadata'->>'ditto_count')::integer=0,'forged ditto count reset by server');
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->'metadata'->>'is_resolved')::boolean=false,'forged resolution reset by server');
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->>'latitude')::numeric=25.599,'latitude rounded by server');
SELECT public.test_assert(NOT (public.get_post(:'issue_id'::uuid)->'author' ? 'phone_number'),'public card excludes phone');
SELECT public.test_assert(NOT (public.get_post(:'issue_id'::uuid)->'author' ? 'locality_landmark'),'public card excludes home landmark');
SELECT public.test_raises($q$UPDATE public.posts SET upvotes_count=100$q$,'permission denied');
SELECT public.test_raises($q$INSERT INTO public.post_reactions(post_id,user_id,reaction_type) VALUES(gen_random_uuid(),auth.uid(),'upvote')$q$,'permission denied');
SELECT public.test_raises($q$SELECT public.create_post('local_review','Bad rating','This is an invalid rating.',9001,'{"business_name":"Test Shop","category":"food","rating":6}')$q$,'invalid_typed_metadata');
SELECT public.test_raises($q$SELECT public.create_post('general','Bad metadata','This must reject extra keys.',9001,'{"admin":true}')$q$,'invalid_typed_metadata');
SELECT public.test_raises($q$SELECT public.create_post('event','Bad old event','This must reject a past event.',9001,'{"venue":"Park","event_date":"2000-01-01T10:00:00Z"}')$q$,'event_date_must_be_in_future');
SELECT public.create_post('event','Test future event','Meet at the public park with neighbours.',9001,
  jsonb_build_object('venue','Park','event_date',to_jsonb(now()+interval '3 days'),'rsvp_count',99)) AS event_id \gset
SELECT public.test_assert((public.get_post(:'event_id'::uuid)->'metadata'->>'rsvp_count')::integer=0,'forged RSVP reset');
SELECT public.create_post('general','Danara ward four','This belongs only to the Danara panchayat.',9002) AS danara_id \gset
SELECT public.create_post('general','Mahajpura ward four','Same ward number, different panchayat.',9003) AS mahajpura_id \gset
SELECT public.test_assert((SELECT count(*)=1 FROM public.get_feed(9002,'ward')),'rural wards with same number do not mix');
SELECT public.test_assert((SELECT count(*)=1 FROM public.get_feed(9002,'area')),'panchayat scope excludes other panchayat');
SELECT public.test_assert((SELECT count(*)=2 FROM public.get_feed(9002,'block')),'block scope intentionally includes both panchayats');
SELECT public.test_assert((SELECT count(*)=4 FROM public.get_feed(9002,'district')),'district expansion includes both urban and rural');

INSERT INTO storage.objects(bucket_id,name,owner_id) VALUES('post-media',auth.uid()::text||'/photo.jpg',auth.uid()::text);
SELECT public.create_post('general','Test photo attachment','An owned image can be attached safely.',9001,'{}','',
  ARRAY[auth.uid()::text||'/photo.jpg']) AS media_post \gset
DELETE FROM storage.objects WHERE name=auth.uid()::text||'/photo.jpg';
SELECT public.test_assert((SELECT count(*)=1 FROM storage.objects),'attached media cannot be deleted directly');
SELECT public.test_raises($q$SELECT public.create_post('general','Sixth valid post','Rate limits apply to verified users too.',9001)$q$,'rate_limit_exceeded');

SELECT public.add_comment(:'issue_id'::uuid,'Root comment')->>'id' AS comment0 \gset
SELECT public.add_comment(:'issue_id'::uuid,'Reply level 1',:'comment0'::uuid)->>'id' AS comment1 \gset
SELECT public.add_comment(:'issue_id'::uuid,'Reply level 2',:'comment1'::uuid)->>'id' AS comment2 \gset
SELECT public.add_comment(:'issue_id'::uuid,'Reply level 3',:'comment2'::uuid)->>'id' AS comment3 \gset
SELECT public.test_raises(format('SELECT public.add_comment(%L::uuid,%L,%L::uuid)',:'issue_id','Too deep',:'comment3'),'maximum_reply_depth_is_3');
SELECT public.test_raises(format('SELECT public.add_comment(%L::uuid,%L,%L::uuid)',:'event_id','Wrong post reply',:'comment0'),'parent_comment_must_belong_to_same_post');
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->>'comments_count')::integer=4,'threaded comment counters correct');

SELECT set_config('request.jwt.claim.sub','b0000000-0000-4000-8000-000000000001',true);
SELECT public.save_profile('Neighbour B',9001,'') IS NOT NULL;
SELECT public.test_assert((SELECT count(*)=1 FROM public.profiles),'another phone remains private');
SELECT public.set_reaction(:'issue_id'::uuid,'upvote',true);
SELECT public.set_reaction(:'issue_id'::uuid,'upvote',true);
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->>'upvotes_count')::integer=1,'repeated active upvote is idempotent');
SELECT public.set_reaction(:'issue_id'::uuid,'ditto_problem',true);
SELECT public.set_reaction(:'issue_id'::uuid,'ditto_problem',true);
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->'metadata'->>'ditto_count')::integer=1,'ditto idempotent and typed');
SELECT public.set_reaction(:'event_id'::uuid,'rsvp_event',true);
SELECT public.test_assert((public.get_post(:'event_id'::uuid)->'metadata'->>'rsvp_count')::integer=1,'RSVP counter maintained');
SELECT public.test_raises(format('SELECT public.set_reaction(%L::uuid,%L,true)',:'danara_id','ditto_problem'),'reaction_does_not_match_post_type');
SELECT public.test_raises(format('SELECT public.set_issue_resolution(%L::uuid,true)',:'issue_id'),'only_author_can_resolve_civic_issue');
SELECT public.test_raises(format('SELECT public.delete_post(%L::uuid)',:'issue_id'),'only_author_can_delete_post');
SELECT public.report_post(:'issue_id'::uuid,'spam');
SELECT public.report_post(:'issue_id'::uuid,'spam');
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->>'flag_count')::integer=1,'duplicate reports do not inflate count');
SELECT public.test_raises(format('SELECT public.moderate_post(%L::uuid,true,%L)',:'issue_id','Test moderation'),'community_moderator_required');
SELECT public.test_raises($q$INSERT INTO storage.objects(bucket_id,name) VALUES('post-media','a0000000-0000-4000-8000-000000000001/forged.jpg')$q$,'row-level security');
SELECT public.test_assert((SELECT count(*)=1 FROM storage.objects),'visible post attachment readable by a neighbour');

-- Latest cursor uses timestamp AND UUID, even for equal timestamps.
SELECT public.get_feed(9001,'ward',NULL,'','latest',1) AS first_row \gset
SELECT public.test_assert((SELECT count(*)=2 FROM public.get_feed(9001,'ward',NULL,'','latest',31,
  (:'first_row'::jsonb->>'created_at')::timestamptz,(:'first_row'::jsonb->>'id')::uuid,NULL)),'stable latest cursor handles timestamp ties');
SELECT public.test_assert((SELECT count(*)=1 FROM public.get_feed(9001,'ward','event')),'unified type filter');

RESET ROLE;
INSERT INTO public.community_moderators(user_id) VALUES('b0000000-0000-4000-8000-000000000001');
SET LOCAL ROLE authenticated;
SELECT public.moderate_post(:'media_post'::uuid,true,'A community privacy review');
SELECT public.test_assert(public.get_post(:'media_post'::uuid) IS NULL,'hidden post not exposed via RPC');
SELECT public.test_assert((SELECT count(*)=0 FROM storage.objects),'hidden attachment not readable by other user');
SELECT public.moderate_post(:'media_post'::uuid,false,'Reviewed and restored');
SELECT public.set_reaction(:'issue_id'::uuid,'upvote',false);
SELECT public.set_reaction(:'issue_id'::uuid,'upvote',false);
SELECT public.test_assert((public.get_post(:'issue_id'::uuid)->>'upvotes_count')::integer=0,'removal idempotent and non-negative');
SELECT set_config('request.jwt.claim.sub','a0000000-0000-4000-8000-000000000001',true);
SELECT public.test_assert((SELECT count(*)=0 FROM public.post_reports),'other users reports remain private');
SELECT public.set_issue_resolution(:'issue_id'::uuid,true);
SELECT public.test_assert((public.community_stats(9001)->>'resolved')::integer=1,'resolved stats derived from authoritative metadata');
SELECT public.test_raises(format('SELECT public.report_post(%L::uuid,%L)',:'issue_id','spam'),'post_unavailable_or_own_post');
SELECT public.delete_post(:'event_id'::uuid);
RESET ROLE;
SELECT public.test_assert((SELECT count(*)=0 FROM public.post_reactions WHERE post_id=:'event_id'::uuid),'delete cascades reactions');
DELETE FROM public.comments WHERE id=:'comment0'::uuid;
SELECT public.test_assert((SELECT comments_count=0 FROM public.posts WHERE id=:'issue_id'::uuid),'deleting a root removes all descendant counters');
SELECT public.test_assert((SELECT count(*)=0 FROM public.comments WHERE post_id=:'issue_id'::uuid),'thread cascade consistent');

ROLLBACK;
\echo 'PASS: security, ownership, typed metadata, geo scoping, keyset cursor, media RLS, counters and moderation'
