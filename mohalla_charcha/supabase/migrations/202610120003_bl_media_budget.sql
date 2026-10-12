-- Bihar Local - Mohalla Charcha / media storage budget.
-- Client side (v1.3.1+) compresses photos to ~0.3 MB JPEG before upload, so
-- the private bucket can enforce a harder per-file cap for the free plan.
BEGIN;

UPDATE storage.buckets
SET file_size_limit = 1500000
WHERE id = 'bl-post-media';

COMMENT ON COLUMN storage.buckets.file_size_limit IS '1.5 MB soft guard; app compresses to ~0.3 MB JPEG/1280 px before upload (bl_ namespace only).';

COMMIT;
