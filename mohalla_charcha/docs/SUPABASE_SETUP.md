# Supabase setup — baad mein connect karne ke liye

## 1. Config Dart file

`lib/config/supabase_config.dart` is the one configuration entry point. Change `defaultValue` for URL/public key if you really want, but **prefer `--dart-define`** or GitHub Repository Variables so public project configuration does not clutter source control.

| Name | Meaning | Default |
|---|---|---|
| `USE_SUPABASE` | `true` = live adapter; `false` = working local demo | false |
| `SUPABASE_URL` | `https://your-project.supabase.co` | empty |
| `SUPABASE_ANON_KEY` | Public anon JWT or new publishable key | empty |

Only public client keys belong in an APK. Telegram tokens and Android signing secrets live in **GitHub Secrets**, never Dart. The build helper rejects service-role JWTs and `sb_secret_` keys.

## 2. Fresh project SQL

1. Create a fresh Supabase project; choose a region appropriate for your users.
2. Run `supabase/migrations/202610110001_core.sql` in the SQL editor, or apply it with Supabase CLI migrations.
3. This migration expects PostGIS/pg_trgm in the `extensions` schema. If those extensions are already installed in another schema, adapt the qualified types/operator classes with a deliberate migration; do not blindly relocate a live project's extension.
4. It creates all application tables, constraints, indexes, RPCs, RLS policies and the **private** `post-media` bucket (5 MB/file; JPEG/PNG/WebP only).
5. Do **not** run `supabase/tests/00_supabase_mock.sql` in real Supabase. It is a local/CI auth/storage mock, not a production migration.

The original brief schema was intentionally hardened: `location_id`, full-path uniqueness (including urban NULL panchayat), private profile access, validated JSONB, report/moderator tables, coordinate checks, counter triggers and rate limits. Existing app data would need an explicit backfill/mapping migration; none is claimed here.

## 3. Import locations before onboarding

Live onboarding requires an existing canonical ward. An empty location master correctly shows an empty picker rather than inventing wards.

- For a **test project only**, run `supabase/seed_demo_locations.sql`. Every mapping/centroid in it is illustrative.
- For real users, obtain a verified, licensed district/ULB/block/panchayat/ward dataset; keep source, retrieval date and revision in your operational records.
- Fill a CSV using `supabase/location_import_template.csv`.

```bash
python3 scripts/import_locations.py verified_locations.csv --output verified_locations.sql
# Review generated SQL, then run it as a privileged project operator in the SQL editor.
```

The helper validates hierarchy branches, names, duplicate full paths, ward range and coordinate pairs. **It cannot certify administrative accuracy.** Imports upsert alias/centroid against the canonical full path; they do not mass-retag historical posts or silently merge distinct panchayats. Normalize official alternative district spellings before import.

## 4. Phone OTP

1. Enable phone authentication and signups in Supabase Auth.
2. Configure an SMS provider with actual credentials and a reviewed India DLT/header/template setup where applicable.
3. The UI accepts Indian 10-digit mobiles, normalizes to `+91`, and expects a **6-digit** SMS OTP. Match your provider/Auth OTP settings to this length.
4. Enable provider rate limits/abuse protection and configure quotas/billing alerts. The UI resend cooldown is convenience, not a security boundary.
5. Test signup, resend, wrong/expired code, returning-user login and sign-out on physical Android devices.

No fake OTP exists in demo mode. Phone verification is **not** proof of residence. `save_profile` copies the confirmed phone from `auth.users`; a caller cannot submit someone else's number.

## 5. Permissions and API

- `profiles`: authenticated users can SELECT **only their own full profile**, including phone.
- Public author cards are emitted by internal helpers via checked RPCs and **never include phone or private profile landmark**.
- No authenticated INSERT/UPDATE/DELETE grants on app tables. RPCs derive ownership from `auth.uid()`.
- Counts, reaction state, resolved state and moderation flags are not writable through ordinary post updates.
- `get_feed` validates scope, type, search length, limits and cursor; hidden content is excluded.
- Storage object names are `<user UUID>/<random UUID>.jpg|png|webp`; create-post validates ownership/existence. The app signs object paths at read time with 1-hour expiry; it refreshes its signing cache before expiry.
- A previously issued signed URL may remain usable until expiry after a post is hidden. Shorten TTL / use an authenticated media proxy if immediate revocation is required.
- There is no RLS resident-proof boundary: authenticated users may deliberately browse a different district through the picker. Location-first feed scope is a query/navigation invariant, not proof of geographical presence.

### Community moderation

A privileged operator appoints a trusted **community volunteer**, not a government officer:

```sql
-- Substitute a REAL profiles.id that you have looked up; never use a placeholder.
INSERT INTO public.community_moderators(user_id) VALUES ('REAL_PROFILE_UUID');
```

Their authenticated session can call `moderate_post(post_id, hidden, reason)`; each action is audited. Reports are unique and private to the reporter through client reads. Moderators need an operator-managed review interface/dashboard; the resident UI is not a moderation console. Do not auto-hide at an arbitrary flag threshold—brigading is a real risk.

## 6. Before live launch

Read `LAUNCH_CHECKLIST.md`: privacy/consent/operator contacts, deletion flow, SMS testing, release key, verified location import, server-side image/EXIF processing, orphan storage cleanup, moderation staffing, backups and monitoring are still deployment responsibilities. No live Supabase project or provider has been connected/tested during this build.

## Local SQL tests

Use a **disposable PostgreSQL 17 + PostGIS** database named `mohalla_test`, not the live project. Create it from `template0` when your Docker image preinstalls PostGIS in the default database. On a fresh test cluster:

```bash
psql -v ON_ERROR_STOP=1 -f supabase/tests/00_supabase_mock.sql
psql -v ON_ERROR_STOP=1 -f supabase/migrations/202610110001_core.sql
psql -v ON_ERROR_STOP=1 -f supabase/tests/01_security_and_invariants.sql
python3 -m pip install 'psycopg[binary]==3.2.12'
python3 supabase/tests/02_concurrent_reactions.py
```

Use normal `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` environment variables. The CI workflow automates this and never uploads APK artifacts.
