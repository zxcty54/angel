-- STOCKPULSE / BIHAR LOCAL COMPATIBILITY AUDIT
-- READ ONLY: no table/data/policy/role/provider changes; no application row reads.
-- Run in Supabase SQL Editor, export the single result as JSON/CSV, share it.
-- Never share database passwords, service-role keys or JWTs.
-- This does not enable Anonymous sign-ins and cannot read that provider setting.
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '15s';

WITH public_relations AS (
  SELECT c.oid, n.nspname AS schema_name, c.relname AS name, c.relkind,
    c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS force_rls,
    c.reloptions, pg_get_userbyid(c.relowner) AS owner
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m')
), table_metadata AS (
  SELECT schema_name,name,relkind,owner,rls_enabled,force_rls,
    COALESCE(reloptions,ARRAY[]::text[]) AS options,
    has_table_privilege('anon',oid,'SELECT') AS anon_select,
    has_table_privilege('anon',oid,'INSERT') AS anon_insert,
    has_table_privilege('anon',oid,'UPDATE') AS anon_update,
    has_table_privilege('anon',oid,'DELETE') AS anon_delete,
    has_table_privilege('authenticated',oid,'SELECT') AS authenticated_select,
    has_table_privilege('authenticated',oid,'INSERT') AS authenticated_insert,
    has_table_privilege('authenticated',oid,'UPDATE') AS authenticated_update,
    has_table_privilege('authenticated',oid,'DELETE') AS authenticated_delete
  FROM public_relations
), policy_metadata AS (
  SELECT schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check
  FROM pg_policies WHERE schemaname IN ('public','storage')
), column_metadata AS (
  SELECT table_schema,table_name,column_name,data_type,udt_name,is_nullable
  FROM information_schema.columns
  WHERE table_schema='public'
), constraint_metadata AS (
  SELECT n.nspname AS schema_name,c.relname AS table_name,con.conname AS name,
    con.contype AS type,pg_get_constraintdef(con.oid) AS definition
  FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public'
), function_metadata AS (
  SELECT n.nspname AS schema_name,p.proname AS name,
    pg_get_function_identity_arguments(p.oid) AS arguments,
    pg_get_function_result(p.oid) AS result_type,
    p.prosecdef AS security_definer,p.proconfig AS settings,
    pg_get_userbyid(p.proowner) AS owner,
    has_function_privilege('anon',p.oid,'EXECUTE') AS anon_execute,
    has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated_execute
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.prokind='f'
), extension_metadata AS (
  SELECT e.extname AS name,n.nspname AS schema_name,e.extversion AS version
  FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
), storage_metadata AS (
  SELECT id,name,public,file_size_limit,allowed_mime_types FROM storage.buckets
)
SELECT jsonb_pretty(jsonb_build_object(
  'read_only',true,
  'audit_purpose','StockPulse compatibility; namespace collisions and access policies',
  'tables_views',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY name) FROM table_metadata t),'[]'::jsonb),
  'policies',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY schemaname,tablename,policyname) FROM policy_metadata t),'[]'::jsonb),
  'columns',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY table_name,column_name) FROM column_metadata t),'[]'::jsonb),
  'constraints',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY table_name,name) FROM constraint_metadata t),'[]'::jsonb),
  'functions',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY name,arguments) FROM function_metadata t),'[]'::jsonb),
  'extensions',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY name) FROM extension_metadata t),'[]'::jsonb),
  'storage_buckets',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY name) FROM storage_metadata t),'[]'::jsonb),
  'anonymous_auth_provider','Unknown from SQL metadata: review Dashboard Auth settings; do not enable before policy audit',
  'important','Anonymous users assume authenticated role. Namespacing alone does not protect another app with broad authenticated access.'
)) AS compatibility_audit;
COMMIT;
