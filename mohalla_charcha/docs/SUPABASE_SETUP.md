# Supabase setup — baad mein connect karne ke liye

Bihar Local uses its OWN namespace in the Supabase project: every table, enum,
function, trigger, index, RLS policy and storage bucket carries the `bl_`
prefix (`bl_profiles`, `bl_posts`, `bl_get_feed`, bucket `bl-post-media`, ...).
This keeps the app fully separate from StockPulse, which shares the same
project but is never read, modified or merged by anything here.

## 1. Config Dart file

`lib/config/supabase_config.dart` is the one configuration entry point. Change `defaultValue` for URL/public key if you really want, but **prefer `--dart-define`** or GitHub Repository Variables so public project configuration does not clutter source control.

| Name | Meaning | Default |
|---|---|---|
| `USE_SUPABASE` | `true` = live adapter; `false` = working local demo | false |
| `SUPABASE_URL` | `https://your-project.supabase.co` | empty |
| `SUPABASE_ANON_KEY` | Public anon JWT or new publishable key | empty |

Only public client keys belong in an APK. Telegram tokens and Android signing secrets live in **GitHub Secrets**, never Dart. The build helper rejects service-role JWTs and `sb_secret_` keys.

## 2. Apply the Bihar Local migration

1. Open the shared Supabase project and use the **SQL Editor** (or Supabase CLI).
2. Run `supabase/migrations/202610120001_bihar_local_core.sql`. It creates ONLY `bl_*` objects — 9 tables, enums, triggers, indexes, RPCs, RLS policies and the private `bl-post-media` bucket — and touches nothing else in the project.
3. This migration expects PostGIS/pg_trgm in the `extensions` schema. If those extensions are already installed in another schema, adapt the qualified types/operator classes with a deliberate migration; do not blindly relocate a live project's extension.
4. Do **not** run `supabase/tests/00_supabase_mock.sql` in real Supabase. It is a local/CI auth/storage mock, not a production migration.
5. **Shared-project warning**: Supabase anonymous sign-ins (see §4) use the PostgreSQL `authenticated` role. Every `bl_*` object this migration creates is locked down correctly, but the OTHER app's tables (StockPulse) currently allow any `authenticated` actor to insert/update/delete their own rows — which would also admit Bihar Local guest users. That is a StockPulse policy decision, deliberately left untouched here; restrict StockPulse's own policies separately if it matters.

## 3. Import locations before onboarding

Live onboarding requires an existing canonical ward. An empty location master correctly shows an empty picker rather than inventing wards.

- For a **test project only**, run `supabase/seed_demo_locations.sql` (targets `bl_locations`). Every mapping/centroid in it is illustrative.
- For real users, obtain a verified, licensed district/ULB/block/panchayat/ward dataset; keep source, retrieval date and revision in your operational records.
- Fill a CSV using `supabase/location_import_template.csv`.

```bash
python3 scripts/import_locations.py verified_locations.csv --output verified_locations.sql
# Review generated SQL, then run it as a privileged project operator in the SQL editor.
```

The helper validates hierarchy branches, names, duplicate full paths, ward range and coordinate pairs. **It cannot certify administrative accuracy.** Imports upsert alias/centroid against the canonical full path; they do not mass-retag historical posts or silently merge distinct panchayats. Normalize official alternative district spellings before import.

## 4. Guest login — no phone, no OTP

1. In the Supabase Dashboard go to **Authentication → Providers** (People section) and enable **Anonymous Sign-ins**. No credentials, no SMS provider, no DLT setup are involved.
2. On every launch `GuestAuthService.ensureSession()` restores the stored device session or silently signs in anonymously, before any profile/feed call.
3. The guest account is bound to the device install. If the user clears app data, removes the app, or signs out, the same guest identity cannot be recovered on that device — document this in your help text/privacy policy.
4. Rate limits (`bl_check_rate_limit`) apply per guest user exactly as before.

Phone verification was removed entirely: there is no `phone_number` column and no OTP flow anywhere in the app.

## 5. Permissions and API

- `bl_profiles`: authenticated users can SELECT **only their own full profile**.
- Public author cards are emitted by internal helpers via checked RPCs and **never include** the private profile landmark.
- No authenticated INSERT/UPDATE/DELETE grants on app tables. RPCs derive ownership from `auth.uid()`.
- Counts, reaction state, resolved state and moderation flags are not writable through ordinary post updates.
- `bl_get_feed` validates scope, type, search length, limits and cursor; hidden content is excluded.
- Storage object names are `<user UUID>/<random UUID>.jpg|png|webp`; create-post validates ownership/existence. The app signs object paths at read time from `bl-post-media` with 1-hour expiry; it refreshes its signing cache before expiry.
- A previously issued signed URL may remain usable until expiry after a post is hidden. Shorten TTL / use an authenticated media proxy if immediate revocation is required.
- There is no RLS resident-proof boundary: authenticated users may deliberately browse a different district through the picker. Location-first feed scope is a query/navigation invariant, not proof of geographical presence.

### Community moderation

A privileged operator appoints a trusted **community volunteer**, not a government officer:

```sql
-- Substitute a REAL bl_profiles.id that you have looked up; never use a placeholder.
INSERT INTO public.bl_community_moderators(user_id) VALUES ('REAL_PROFILE_UUID');
```

Their authenticated session can call `bl_moderate_post(post_id, hidden, reason)`; each action is audited in `bl_moderation_log`. Reports are unique and private to the reporter through client reads. Moderators need an operator-managed review interface/dashboard; the resident UI is not a moderation console. Do not auto-hide at an arbitrary flag threshold—brigading is a real risk.

## 6. Before live launch

Read `LAUNCH_CHECKLIST.md`: privacy/consent/operator contacts, guest-account loss disclosure, deletion flow, release key, verified location import, server-side image/EXIF processing, orphan storage cleanup, moderation staffing, backups and monitoring are still deployment responsibilities. No live Supabase project or provider has been connected/tested during this build.

## Local SQL tests

Use a **disposable PostgreSQL 17 + PostGIS** database named `mohalla_test`, not the live project. Create it from `template0` when your Docker image preinstalls PostGIS in the default database. On a fresh test cluster:

```bash
psql -v ON_ERROR_STOP=1 -f supabase/tests/00_supabase_mock.sql
psql -v ON_ERROR_STOP=1 -f supabase/migrations/202610120001_bihar_local_core.sql
psql -v ON_ERROR_STOP=1 -f supabase/tests/01_security_and_invariants.sql
python3 -m pip install 'psycopg[binary]==3.2.12'
python3 supabase/tests/02_concurrent_reactions.py
python3 supabase/tests/03_location_import.py
```

Use normal `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` environment variables. The CI workflow automates this and never uploads APK artifacts.
