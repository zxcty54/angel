# Architecture and scaling

## Boundaries

```text
Flutter screens/widgets
        ↓
AppController (query state, request generation, mutation guard, cache)
        ↓
CommunityRepository interface
        ├── DemoRepository → SharedPreferences JSON (local demo only)
        └── SupabaseRepository → checked RPCs + private Storage + Auth
                                   ↓
                             PostgreSQL / PostGIS
```

Demo mode is not a mock government workflow. Every issue stays in a P2P conversation. There are no department IDs, assigned officials, ticket numbers, escalation destinations or government webhooks.

## First-launch and branding boundary

`OnboardingService` stores device-local completion (`mohalla.welcome.v1.complete`) separately from profile/auth/demo JSON. `_AuthGate` renders `WelcomeScreen` before feed or live OTP/profile routing when incomplete. Completion is persisted before navigation; a failed write leaves the tour open. Profile replay uses a pushed tour route and does not reset completion/data. Demo home choice is an explicit profile edit, not implicit GPS or residency verification.

Logo paths live in the deterministic branding script/SVG. Flutter uses the generated local PNG; Android uses matching density/adaptive/splash resources, including API31+. No timed artificial splash delay is imposed in Flutter. Native splash is launch-time branding; the three-step tour is first-install-only.

## Unified domain model

`CommunityPost` owns common content, author, location, optional media, counts and timestamps. `PostType` selects a sealed `PostMetadata` implementation:

- `IssueMetadata`: severity, resolved, derived ditto count.
- `ReviewMetadata`: business name, category, half-star rating 1–5.
- `EventMetadata`: UTC date/time, venue, derived RSVP count.
- `GeneralMetadata`: empty metadata.

A review is a post, not a separate incompatible feed. An event RSVP is a reaction, not an independently writable JSON count. PostgreSQL validates the same type/metadata rules as Dart.

## Location identity

Urban: district + urban branch + ULB + **NULL panchayat** + ward.

Rural: district + rural branch + block + **panchayat** + ward.

Canonical master row `location_id` is the FK for posts and home profiles. `UNIQUE NULLS NOT DISTINCT` makes urban paths unique as well. Checked RPCs copy hierarchy snapshots server-side. A client cannot tag Danara Ward 4 while writing Mahajpura into a separate text field.

The picker loads/paginates one district's catalogue at a time. Only verified imported entries are selectable in live mode; absent areas show an honest empty state.

## Feed and map

- Default scope = selected home ward; browsing a different area does not change home automatically.
- `ward`: exact canonical location.
- `area`: ULB for urban, panchayat for rural.
- `block`: rural expansion across panchayats in the same block.
- `district`: deliberate expansion across both branches within that district.
- Latest feed cursor = `(created_at, id)`; no costly offset page scan.
- Most-supported cursor = `(upvotes_count, created_at, id)`. Votes are mutable, so this is **not a snapshot-stable ranking**. The controller deduplicates page IDs; refresh to re-rank.
- Search is bounded and parameterized, not concatenated into SQL commands. `%`/`_` follow SQL ILIKE wildcard semantics. Title trigram index is supplied; description/landmark OR-search may still scan the already geographically narrowed result.
- Partial indexes exclude hidden posts; ward, type, area, district, reputation/author and PostGIS indexes are included.
- The map is a bounded projection of the latest 30 matching posts, not an exhaustive viewport/vector-tile system. It only uses explicitly tagged, approximate coordinates.

## Correctness and concurrency

The controller uses monotonically increasing query generations. Slow responses for an old ward/filter are discarded; changing query clears the previous scoped feed immediately. Per-post busy guards prevent double-tap toggle races.

Server reaction API is **set desired state**, not blind toggle:

```text
set_reaction(post_id, reaction_type, active=true|false)
```

A unique `(post_id,user_id,reaction_type)` constraint plus parent-row locking makes retries idempotent. INSERT/DELETE triggers update counts/JSON metadata in the same transaction. Thread parents have a composite FK containing `post_id`, enforced depth ≤3, and transactional comment counters. Reports have one row/user/post. Reputation is server-derived support on visible posts.

## Privacy and security

- Authenticated access; private own-profile RLS; public author JSON omits phone and private landmark.
- All nine app tables have RLS. Client DML privileges are revoked; guarded security-definer RPCs qualify table names and use empty search paths.
- Default PUBLIC function execution is explicitly revoked for every app/helper function; only intended checked RPCs are granted.
- Own confirmed phone comes from Auth, never user-supplied profile JSON.
- Photo bucket is private; paths owned by posting user; temporary signed URLs; no update/overwrite policy.
- Existing signed media URLs are bearer links until expiry. Hiding a post is not immediate link revocation.
- Profile edits, posts, reactions, comments, reports and resolutions have database rate limits. Auth/provider limits are also needed for SMS.
- Human volunteer moderation, audit reasons, no flag-count auto-censorship.
- No GPS collection, no location permissions, no house-coordinate tracking. Optional pins use the selected ward centroid and are rounded server-side.
- Android disables backup and cleartext traffic. Auth persistence currently follows Supabase Flutter defaults; review hardware-backed/encrypted token storage for your threat model before production.

## What to add at greater scale

Measure real workloads before choosing partitions/shards. This delivery is not a claim of a benchmarked million-user service.

1. Verify/import canonical locations with source revisions; plan immutable IDs and boundary-change migrations.
2. Load test ward/type/district feed plans and hot-post counter contention using actual data. Add type/rank variants to broader-scope indexes if profiling warrants them.
3. Move photo resizing, EXIF stripping, malware checks and content moderation to an asynchronous trusted worker; remove orphan objects with a privileged Storage-API worker.
4. Add paginated thread loading and profile history beyond current explicit caps, plus viewport map querying/clustering.
5. Add targeted realtime refresh/push notifications with backpressure; do not broadcast every district update to every client.
6. Use a compliant, capacity-appropriate tile provider for production traffic; retain attribution and avoid offline bulk tile downloads.
7. Add idempotency keys for publish retries/offline queues; reaction retries are already idempotent, publish currently is not.
8. Add optional verified resident/community roles only after an explicit privacy model; phone verification alone is not residency verification.
9. Add telemetry with PII redaction, backups/PITR, restore drills, abuse queues and release rollback procedures.
