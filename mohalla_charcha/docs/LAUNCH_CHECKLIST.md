# Live launch checklist / honest remaining work

The local demo works and the backend schema/adapter are supplied. **This is not already a deployed, audited production service.**

## Required deployment setup

- [ ] Create/configure Supabase and apply the migration to a fresh project.
- [ ] Import a verified, licensed Bihar hierarchy dataset. Demo ward mappings must not become “official” claims.
- [ ] Configure/finance the SMS provider; review India DLT, templates and OTP abuse controls.
- [ ] Test OTP/login/session expiry/storage end-to-end against your real Supabase project.
- [ ] Add a stable release keystore and keep secure backups. Debug-signed builds are for development.
- [ ] Add Telegram secrets/destination permissions; run the delivery workflow in your repository.
- [ ] Physical-device QA: Android 7+, modern ARM64, older ARM, image picker, slow/unstable connectivity and install/update flows.

## Privacy and safety before real users

- [ ] Publish reviewed privacy/terms/consent documents and actual operator/contact details; replace generic in-app privacy guidance with your operational policy.
- [ ] Implement a verified account-deletion/export flow through a trusted server/Edge Function (never expose service-role keys in Dart).
- [ ] Review encrypted/hardware-backed auth-token storage; current live adapter uses SDK defaults.
- [ ] Trusted server-side image transcoding, EXIF stripping, malware/content checks and private-media lifecycle. Client image compression alone is not a privacy guarantee.
- [ ] Schedule a Storage-API orphan cleanup worker after failed uploads, post deletion and account deletion.
- [ ] Appoint community volunteer moderators; supply their review interface, audit process and appeal channel. Resident reports are recorded, not government tickets.
- [ ] Establish emergency/safety guidance; the app is not an emergency response service and promises no official action.
- [ ] Review reporting abuse, brigading, doxxing and scams. Do not infer verified residence from a verified phone.

## Reliability / scale

- [ ] Supabase plan, DB pooling, budget alerts, backups/PITR and restore drill.
- [ ] Production feed-query load tests and hot-post contention benchmarks.
- [ ] Persist publish idempotency keys for ambiguous network retries; add durable live offline publish queue if needed.
- [ ] Paginate replies beyond 200 and profile history beyond 100; map viewport/clustering beyond 30-feed-record projection.
- [ ] Add targeted realtime/push if needed (current live mode is refresh/pagination).
- [ ] Production map-tile provider/terms/capacity and attribution.
- [ ] PII-redacted crash/performance monitoring, rate-limit monitoring and incident runbook.
- [ ] Pin/review third-party CI actions by commit SHA for a hardened release supply chain; current workflows use major action versions with a pinned Flutter SDK and committed pub lockfile.

## Not implemented / not claimed

Government integration, official complaint routing, physical-residence verification, payments, private messaging, live push notifications, complete official boundaries, production legal sign-off, actual SMS delivery testing and actual Telegram delivery are not part of the current configured demo.
