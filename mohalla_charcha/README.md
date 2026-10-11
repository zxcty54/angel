# Mohalla Charcha 🏡

**अपना मोहल्ला, अपनी आवाज़।** Hindi-first, ward-first, people-to-people Bihar community app.

**v1.1.0:** new logo/native splash + first-install welcome tour + **one universal APK / one Telegram ZIP** + detailed [file hierarchy](docs/FILE_HIERARCHY.md).

> Working persistent demo + backend-ready Flutter/PostgreSQL/Supabase source. No government integration, official ticket routing or administrative escalation. No live Supabase/SMS deployment is claimed; see [launch gates](docs/LAUNCH_CHECKLIST.md).

## Deployment in `zxcty54/angel`

This app lives in **`mohalla_charcha/`**, preserving the repository's existing Python dashboard. Run commands from that folder. Active workflows are root `.github/workflows/mohalla-ci.yml` and `mohalla-apk-telegram.yml`; the nested workflows are standalone templates. See [actual repository layout](docs/REPOSITORY_LAYOUT.md).

## Run

Tested: **Flutter 3.35.4 / Dart 3.9.2**. App ID `in.mohallacharcha.app`; Android API24+/7+.

```bash
flutter pub get --enforce-lockfile
flutter run                     # Android, local demo by default
flutter run -d chrome           # responsive web
flutter analyze --fatal-infos
flutter test --concurrency=1
python3 -m unittest discover -s scripts/tests -v
```

No account, OTP or internet is required for the demo. Optional live tiles require internet. Images/fonts/logo are bundled.

## First install and branding

- Android launcher icon and branded native splash, including Android12+ resources.
- **Welcome is the first Flutter screen**, before demo feed or live OTP/profile onboarding.
- Three Hindi/English steps: neighbourhood, ward-first urban/rural hierarchy, P2P/privacy reminders.
- Next/back/swipe/skip; optional illustrative demo-ward choice. Language preference persists.
- Completion persists per device; normal launches bypass it. Clear app data/reinstall shows it again.
- Profile → **Welcome & app tour** replays without resetting posts/account/completion.
- Master `assets/branding/logo.svg`, in-app `logo.png`, generated native/web icons. Optional regeneration: `python3 -m pip install CairoSVG==2.8.2 && python3 scripts/generate_branding.py`.

## Features

- Cascading district → urban/rural → ULB/block → panchayat (rural) → ward.
- Home ward first; deliberate expansion to ULB/panchayat, rural block, district.
- **One post model:** civic issues, half-star local reviews, events, general conversations.
- Search, category/type filters, latest/most-supported sort, keyset paging.
- Photos, optional approximate ward-centre pin, public landmark, author resolve/reopen/delete.
- Upvotes, ditto / “मेरे यहाँ भी”, event RSVP, saved posts, copied summaries.
- Three-level replies; unique reports, volunteer moderation; no auto-hiding from flags.
- Offline illustrative map / opt-in attributed OpenStreetMap; community/events/profile.
- Persistent dummy backend + separate real Supabase OTP/onboarding/RPC/private-media adapter.
- RLS, private phone numbers, typed server validation, atomic counters, rate limits, moderator audit.

## Supabase kahan configure karna hai?

**`lib/config/supabase_config.dart`** is commented in Hinglish; `USE_SUPABASE=false` by default.

```bash
flutter run \
  --dart-define=USE_SUPABASE=true \
  --dart-define=SUPABASE_URL=https://YOUR_PROJECT.supabase.co \
  --dart-define=SUPABASE_ANON_KEY=YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY
```

Never embed a service-role/secret key. [Supabase guide](docs/SUPABASE_SETUP.md) covers the fresh-project SQL migration, master data, SMS and private storage. Local test mocks are **never for a live project**.

## One APK ZIP → Telegram with your GitHub secrets

The user reported adding **`TELEGRAM_BOT_TOKEN`** and **`TELEGRAM_CHAT_ID`** as repository secrets. They were not read in this workspace; GitHub Actions injects them into **`.github/workflows/build-apk-telegram.yml`**.

1. Put project contents at repository **root**, including hidden `.github/`, assets, `scripts/`, lockfile and Gradle wrapper.
2. Open a **same-repository non-draft PR**, or Actions → Build APK → Telegram ZIP → Run workflow → **demo**. Version tags also trigger it. Fork/draft PR delivery is skipped for secret safety.
3. Start the bot in your private destination, or give it group/channel send permission. Private chats need numeric ID—not a title/personal username.
4. Workflow tests/builds/verifies **one universal ARM32+ARM64+x86_64 APK** and sends **one ZIP** with SHA-256/install guide straight to Telegram.

**No GitHub APK artifact/release upload.** Sender refuses multiple ZIPs/APKs. Default development/debug signing is for testing; use a stable release keystore for updatable distribution.

See [Telegram/signing guide](docs/TELEGRAM_BUILD.md) and [PR guide](docs/GITHUB_PR.md).

### PR helper on your authenticated machine

The direct connector is unavailable, but the user has now authorized temporary official GitHub CLI access to publish the requested PR to `zxcty54/angel`. Bot secret names are verified; their values remain inside GitHub Actions. Do **not** paste credentials into chat.

From the extracted project folder, on your own authorized machine:

```bash
gh auth login
bash scripts/create_pull_request.sh YOUR_OWNER/YOUR_REPO
```

The helper opens a real same-repo non-draft PR using your GitHub access, does not auto-merge, and copies no APK/private config/build/cache. Then the PR workflow can use your existing bot secrets.

## Build the single APK locally

```bash
flutter build apk --release --target-platform android-arm,android-arm64,android-x64
python3 scripts/package_apks.py --version 1.1.0 --build 10001 --backend demo
```

Output is `build/app/outputs/flutter-apk/app-release.apk`; package output is one ZIP in ignored `delivery/`. Historical script name `package_apks.py` now deliberately packages **only one universal APK**, never split output.

## Data honesty / limits

- 38 district names, **12 illustrative paths—not a complete verified Bihar ward/panchayat master dataset**. People, images, incidents, counts, events, aliases and centroids are examples.
- Same-number rural wards are isolated by full district/branch/block/**panchayat**/ward identity and canonical location ID.
- No GPS/location permissions or background tracking; optional pins use rounded ward-centre coordinates. Do not post exact home details.
- Demo photos: 1.5MB combined; live max5MB each. Local browser/device data can be cleared by user/OS.
- Live map: latest30 posts; comments first200; profile latest100. Explicit caps—not unlimited paging claims.
- No push/durable live offline publish queue, payments, private messaging or government APIs. Shared text summaries are not unconfigured deep links.
- Phone verification does not verify residency. Live services/legal/operator privacy/moderation/image-processing/device/load tests remain launch gates.

## Which file does what?

**[Full file hierarchy + edit guide](docs/FILE_HIERARCHY.md)** covers every custom Dart module, branding/native resources, data/backend, tests and build/PR scripts, with startup/data/delivery diagrams.

## Documentation

- [File hierarchy](docs/FILE_HIERARCHY.md)
- [Supabase setup](docs/SUPABASE_SETUP.md)
- [Telegram build/signing](docs/TELEGRAM_BUILD.md)
- [GitHub PR](docs/GITHUB_PR.md)
- [Architecture/scaling](docs/ARCHITECTURE.md)
- [Validation report](docs/VALIDATION.md)
- [Launch checklist](docs/LAUNCH_CHECKLIST.md)
- [Asset licenses](docs/ASSETS.md)

Local build results do not imply remote delivery. The published PR/Actions run records the actual external outcome; the sender prints a Telegram message ID only after the API confirms delivery.
