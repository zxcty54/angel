-- Bihar Local - Mohalla Charcha / account deletion (Google Play compliance).
-- Adds ONE extra function to the bl_ namespace; touches no StockPulse object.
-- Provides self-service account deletion required by Play Store review.
BEGIN;

-- The caller's entire Bihar Local footprint is removed in one RPC:
-- 1. their media rows in the private bl-post-media bucket,
-- 2. their profile row, which cascades through posts, comments, reactions,
--    reports and moderator appointments (children are ON DELETE CASCADE),
-- 3. the anonymous auth.users row itself where permissions allow, so even
--    the guest identity is destroyed (that row never holds phone/email).
CREATE OR REPLACE FUNCTION public.bl_delete_my_account()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, storage, auth
AS $$
DECLARE
  uid uuid := public.bl_require_user();
BEGIN
  DELETE FROM storage.objects
    WHERE bucket_id = 'bl-post-media' AND name LIKE uid::text || '/%';
  DELETE FROM public.bl_profiles WHERE id = uid;
  BEGIN
    DELETE FROM auth.users WHERE id = uid;
  EXCEPTION WHEN OTHERS THEN
    -- Keep this best-effort: after the profile wipe nothing personal remains
    -- anywhere in the bl_ namespace, even if auth.users survives on some setups.
    NULL;
  END;
END $$;

REVOKE ALL ON FUNCTION public.bl_delete_my_account() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.bl_delete_my_account() FROM anon;
GRANT EXECUTE ON FUNCTION public.bl_delete_my_account() TO authenticated;

COMMENT ON FUNCTION public.bl_delete_my_account() IS 'Self-service deletion of the caller profile, all posts/comments/reactions/reports, media and (best-effort) the anonymous auth row. Required for Google Play account-deletion policy.';

COMMIT;
