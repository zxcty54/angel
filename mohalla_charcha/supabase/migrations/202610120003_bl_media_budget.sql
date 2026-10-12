-- Bihar Local - Mohalla Charcha / media storage budget.
-- Client side (v1.3.1+) compresses photos to ~0.3 MB JPEG before upload, so
-- the private bucket enforces a harder per-file cap for the free plan.
-- NOTE: no COMMENT statement here — Supabase owns storage.buckets internally
-- and COMMENT requires owner privileges ("must be owner of relation buckets").
BEGIN;

UPDATE storage.buckets
SET file_size_limit = 1500000
WHERE id = 'bl-post-media';

COMMIT;

-- Agar yeh UPDATE bhi "permission denied" de (project ke storage grants ke
-- hisaab se), to Dashboard se change kar lo: Storage → bl-post-media →
-- Edit settings → Maximum file upload size = 1.5 MB. Same result.
