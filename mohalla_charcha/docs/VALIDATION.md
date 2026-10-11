# Validation — v1.1.0

**11 October 2026. Actual local verification**, not a production audit or an assertion that GitHub/Telegram/Supabase were remotely executed.

## Updated delivery results

| Check | Observed result |
|---|---|
| SDK | Flutter3.35.4 / Dart3.9.2; framework `d693b4b9dbac2acd4477aea4555ca6dcbea44ba2` |
| Locked dependencies | `flutter pub get --enforce-lockfile` passed |
| Format/analyzer | All custom Dart/tests formatted; analyzer **No issues found** |
| Flutter tests | **60 passed**: previous47 plus13 first-launch/service/widget tests |
| Python script tests | **30 passed**: configuration, single-APK/ZIP/delivery/import/source/branding guards; fake token/mock HTTP only |
| Universal Android release | **Built successfully**, assemble186.8s; exactly `app-release.apk`, no split requirement |
| Android identity | `in.mohallacharcha.app`, **version1.1.0 / code10001**, minAPI24, target/compileAPI36 |
| Native ABIs | Actual APK contains **arm64-v8a, armeabi-v7a, x86_64** |
| APK signature | `apksigner verify --verbose --print-certs` passed; v2 signature; **Android Debug certificate** |
| APK ZIP alignment | `zipalign -c -P 16 4` passed |
| Actual package | **ONE universal APK in ONE ZIP**, approximately **25.02MiB**; APK approximately56.9MB (54.3MiB) |
| Package integrity | ZIP CRC check passed; exactly one `.apk`; streaming APK SHA-256 matches included checksum; install guide present |
| Web release | **Built successfully**,47.9s, local CanvasKit/resources/fonts; no resources CDN |
| Actual Chromium E2E | All3 welcome pages → feed → reload bypass; mobile map/profile; replay/close from Profile; fresh desktop welcome; **zero console/page errors** |
| Workflow syntax | Both workflow YAML files parsed; trusted same-repository/non-draft PR gating, manual/tag triggers; no GitHub APK artifact/release upload |
| PR/SDK helpers | Bash syntax checked; SDK revision matches local verified installation; source-copy/filter/archive unit tests passed |

The previous per-ABI outputs were superseded; the current build/package has **one universal APK**, as requested.

## Welcome/branding coverage

- Master vector/1024px PNG, density/adaptive launcher assets and Android12+ native splash resources generated and XML/asset-checked.
- First welcome appears before feed on a fresh preference state at320×720,390×844,800×600,1440×900.
- Next/back, Hindi/English, skip, completing the third step, remembered completion and returning launch.
- Profile replay/finish does not clear completion. Optional demo picker exposes rural block/panchayat/ward branching.
-320px layout tested at1.5× text scaling. General accessibility/device audits are not implied by this check.

The native splash compiled into the actual signed APK. **No physical Android/emulator splash/installation visual test was performed.** Browser screenshots show Flutter welcome/UI, not the Android system splash.

## Browser evidence (actual app, not design mockups)

- [First welcome, mobile](screenshots/welcome-mobile.png)
- [Ward/hierarchy step](screenshots/welcome-ward-mobile.png)
- [Community/privacy step](screenshots/welcome-community-mobile.png)
- [Fresh desktop welcome](screenshots/welcome-desktop.png)
- [Desktop feed](screenshots/home-desktop.png)
- [Mobile feed](screenshots/home-mobile.png)
- [Illustrative mobile map](screenshots/map-mobile.png)

Web compilation retained the optional CupertinoIcons missing-font warning. It succeeded; no missing icons were observed in these exercised welcome/feed/map/profile views. This is not a claim about every browser/platform.

## Backend results retained from the verified base

The SQL migration/backend files were unchanged by this branding/onboarding update. On the same verification date:

- Migration applied to disposable **PostgreSQL17 + PostGIS** with local auth/storage SQL mocks.
- RLS/security/invariant suite passed (rollback), including private phone fields, direct-write denial, typed metadata, canonical snapshots, media ownership, comment depth, author/moderator permissions, pagination/counters/cascades.
- Concurrency suite passed: **20 users / 8 connections**, repeated desired-state requests, exact upvote/ditto/reputation counts and exact removal.
- Seed/import integration passed in a separately created/dropped test database: seed applied twice, generated SQL three times, urbanNULL uniqueness, Unicode/apostrophes, PostGIS coordinates and different rural panchayats with the same ward number.

These are local SQL checks, **not live JWT/SMS/Storage-HTTP verification or official location certification**.

## External status — not performed

- User reported adding GitHub `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`; actual values were **not retrieved or verified**. Neither is in the app/source/local environment.
- At the initial local build there was no authenticated GitHub access or target URL. The user later supplied `zxcty54/angel` and approved temporary official CLI login; both Telegram secret names were verified present. Remote PR/run/delivery must be checked from the actual Actions outcome, not these local tests. The direct connector remains unsupported.
- `create_pull_request.sh` is a user-authorized helper. Local syntax/source-copy tests do not by themselves establish a remote PR/delivery; verify the actual PR/run URL and sender message ID.
- No live Supabase project, real phone/SMS provider/DLT, Storage HTTP integration, production release keystore or Google Play/device test.
- No complete verified Bihar ward dataset, residency verification, independent penetration/accessibility audit, production load benchmark or backup/restore drill.
- Push/durable live offline publish queue, human moderation dashboard, account-deletion workflow and server image/EXIF processing remain launch work.

The provided APK is **development/debug signed, demo-mode**. Stable release signing and [launch checklist](LAUNCH_CHECKLIST.md) must precede real-user distribution.

## Reproduce

```bash
flutter pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test
flutter analyze --fatal-infos
flutter test --concurrency=1
python3 -m unittest discover -s scripts/tests -v
flutter build apk --release --target-platform android-arm,android-arm64,android-x64
python3 scripts/package_apks.py --version 1.1.0 --build 10001 --backend demo
flutter build web --release --no-web-resources-cdn --no-wasm-dry-run --no-pub
```

Database reproduction uses the disposable harness in `.github/workflows/ci.yml`. Never run mock auth/storage/test fixtures in an actual Supabase project. See [file hierarchy](FILE_HIERARCHY.md), [Telegram guide](TELEGRAM_BUILD.md) and [PR instructions](GITHUB_PR.md).
