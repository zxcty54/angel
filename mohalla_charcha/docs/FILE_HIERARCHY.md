# Mohalla Charcha — file hierarchy aur har file ka kaam

Is guide se pata chalega **kaunsi file edit karni hai**, app ka flow kahan se shuru hota hai, aur UI/backend/build ke parts kaise connected hain. Project files GitHub repository ke **root** mein rakhein, ek extra nested folder mein nahi.

**`zxcty54/angel` deployment:** Flutter project `mohalla_charcha/` mein hai; existing Python project untouched hai. Active workflows repository-root `.github/` mein hain. [Actual layout](REPOSITORY_LAYOUT.md) dekhein. Neeche ke paths Flutter project ke relative hain.

## v1.2.0 identity / SEO files

- `branding/app_identity.json`: approved display name/version/copy; optional real `site_url`.
- `lib/config/app_identity.dart`: generated Dart identity; UI and shared summaries use it.
- `BrandWordmark` in `ui/widgets/common.dart`: responsive Bihar Local / Mohalla Charcha typography.
- `scripts/sync_identity.py`: generate/check Android strings, PWA/root metadata, static landing; optional real canonical/sitemap.
- `seo/landing.template.html`: editable readable website content and inline SVG/CSS.
- `web/discover/index.html`: generated static SEO landing, usable without Flutter/JS.
- `seo/keyword-map.csv`: relevant phrases/intents; volumes explicitly unmeasured.
- `store/listing_*.json`: truthful English/Hindi store-copy drafts.
- `docs/SEO_NAMING.md`: qualitative research, sources, decision and publication steps.
- `test/identity_test.dart`, `scripts/tests/test_seo.py`: name/layout/IDs/limits/metadata tests.

## 1. App start se home feed tak

```text
Android launcher icon
    │
    ├─ native branded splash (android/app/src/main/res/)
    │
    ▼
lib/main.dart
    ├─ Hindi date/localization setup
    ├─ device preferences
    ├─ SupabaseConfig: demo ya live?
    ├─ DemoRepository / SupabaseRepository
    └─ AppController + MohallaApp
             │
             ▼
          Auth gate
             │
             ├─ welcome not completed?
             │     └─ welcome_screen.dart
             │          1. Apna mohalla, apni awaaz
             │          2. Ward-first urban/rural hierarchy
             │          3. P2P action + privacy reminders
             │             → completion saved on this device
             │
             ├─ initialization pending? → branded loading state
             ├─ live mode, no session? → PhoneLoginScreen
             ├─ verified login, no profile? → ProfileOnboardingScreen
             └─ profile available / demo → AppShell
                    ├─ Feed
                    ├─ Map
                    ├─ Community
                    └─ Profile → replay welcome tour
```

Welcome completion key: **`mohalla.welcome.v1.complete`**. It is independent of a login/account and the demo-data bucket. Uninstall/clear app data shows welcome again. Normal launches, logout and demo reset do not force the tour again. Replaying the tour does not clear completion or reset community data.

## 2. Project tree

```text
mohalla_charcha/
├── pubspec.yaml                  # version, dependencies, bundled assets/fonts
├── pubspec.lock                  # exact, tested dependency versions + hashes
├── analysis_options.yaml         # Dart/Flutter lint configuration
├── .metadata                     # Flutter project/tool metadata
├── .gitignore                    # build output, private config, keys excluded
├── .gitattributes                # portable LF source lines / binary asset rules
├── LICENSE                       # MIT project license; fonts have their own OFL
├── README.md                     # quickest setup/run/build guide
│
├── lib/
│   ├── main.dart                 # bootstrap, MaterialApp, welcome/auth routing
│   ├── config/
│   │   └── supabase_config.dart   # SUPABASE SETTINGS GO HERE
│   ├── controllers/
│   │   └── app_controller.dart    # UI state, data operations, race guards
│   ├── models/
│   │   ├── location.dart          # complete urban/rural location identity
│   │   └── community.dart         # profile/posts/comments/metadata/feed types
│   ├── data/
│   │   ├── location_catalogue.dart # 38 district names + illustrative paths
│   │   └── demo_seed.dart         # sample people/posts/replies/images
│   ├── repositories/
│   │   ├── community_repository.dart # shared backend interface
│   │   ├── demo_repository.dart   # persistent local dummy backend
│   │   └── supabase_repository.dart # live SQL RPC / private-media adapter
│   ├── services/
│   │   ├── onboarding_service.dart # device-local first-launch completion
│   │   └── guest_auth_service.dart # no-OTP anonymous guest session (Supabase)
│   ├── theme/
│   │   └── app_theme.dart         # palette, typography, component styling
│   └── ui/
│       ├── app_shell.dart         # responsive navigation, create-post entry
│       ├── screens/
│       │   ├── welcome_screen.dart # FIRST-LAUNCH tour + Profile replay
│       │   ├── auth_screen.dart   # guest profile onboarding (no phone/OTP)
│       │   ├── feed_screen.dart   # ward-first feed/search/scopes/filters
│       │   ├── map_screen.dart    # offline illustration + opt-in OSM
│       │   ├── community_screen.dart # community stats / events
│       │   ├── create_post_screen.dart # typed post forms/photos/pin
│       │   ├── post_detail_screen.dart # full post/replies/reactions
│       │   └── profile_screen.dart # home/profile/saved/privacy/tour replay
│       └── widgets/
│           ├── common.dart        # logo/avatar/images/labels/error helpers
│           ├── location_picker.dart # cascading urban/rural ward picker
│           └── post_card.dart     # shared feed/post presentation
│
├── assets/
│   ├── branding/
│   │   ├── logo.svg               # editable master vector brand
│   │   └── logo.png               # 1024px in-app logo, loaded by BrandMark
│   ├── images/                    # neighbourhood, chai, waterlogging demos
│   └── fonts/                     # Manrope + Noto Sans Devanagari 400–800/OFL
│
├── android/
│   ├── app/build.gradle.kts        # app ID, SDK levels, release signing
│   ├── app/src/main/AndroidManifest.xml # launcher/activity/permissions
│   ├── app/src/main/kotlin/in/mohallacharcha/app/MainActivity.kt
│   ├── app/src/main/res/           # native icon/splash/theme resources
│   ├── build.gradle.kts           # Gradle repositories / project configuration
│   ├── settings.gradle.kts        # Flutter/Android/Kotlin plugin versions
│   ├── gradle.properties          # small-memory compiler/worker settings
│   ├── gradlew / gradlew.bat       # portable Gradle launcher scripts
│   └── gradle/wrapper/             # wrapper JAR + checked distribution URL/hash
│
├── web/
│   ├── index.html                 # Flutter web entry document
│   ├── flutter_bootstrap.js        # local CanvasKit/no external resources CDN
│   ├── manifest.json              # installed web app metadata
│   ├── favicon.png                # browser-tab brand
│   └── icons/                     # 192/512px web/maskable icons
│
├── supabase/
│   ├── migrations/202610120001_bihar_local_core.sql # bl_ namespaced schema + RLS + RPCs + private storage
│   ├── seed_demo_locations.sql     # OPT-IN illustrative locations, not official
│   ├── location_import_template.csv # blank 8-column master-data template
│   └── tests/
│       ├── 00_supabase_mock.sql    # LOCAL/CI mock auth/storage, never live
│       ├── 01_security_and_invariants.sql # authorization/data invariants
│       ├── 02_concurrent_reactions.py # atomic counters / duplicate requests
│       └── 03_location_import.py   # actual seed/upsert/PostGIS integration
│
├── scripts/
│   ├── configure_build.py         # safe public defines / temporary signing files
│   ├── package_apks.py            # ONE universal APK → ONE ZIP/checksum/guide
│   ├── send_telegram.py            # read repository secrets + stream ONE ZIP
│   ├── setup_flutter_ci.sh         # install/verify pinned Flutter source revision
│   ├── generate_branding.py        # master logo + Android/web icon regeneration
│   ├── import_locations.py         # validate operator CSV → reviewable SQL
│   ├── serve_preview.py            # local responsive web preview server
│   ├── source_bundle.py            # clean source ZIP / safe PR source copy
│   ├── create_pull_request.sh      # user-authenticated GitHub PR helper
│   └── tests/                     # delivery/config/import/source unit tests
│
├── test/
│   ├── onboarding_test.dart        # first launch/persistence/replay/large text
│   ├── widget_test.dart            # feed/tabs/publishing/replies/responsive UI
│   ├── controller_test.dart        # async races/persistence/location changes
│   ├── demo_repository_test.dart   # reactions/comments/saves/demo mutations
│   └── models_test.dart            # typed metadata + geographic validation
│
├── .github/workflows/
│   ├── ci.yml                     # Flutter/Python/PostgreSQL/PostGIS checks
│   └── build-apk-telegram.yml       # trusted PR/manual/tag → one APK ZIP → bot
│
└── docs/
    ├── FILE_HIERARCHY.md            # this file
    ├── SUPABASE_SETUP.md            # database/Auth/SMS/Storage/master-data setup
    ├── TELEGRAM_BUILD.md            # GitHub secrets/triggers/signing/delivery
    ├── GITHUB_PR.md                 # make a PR with your authorized GitHub access
    ├── PULL_REQUEST_BODY.md         # ready-to-use PR description
    ├── ARCHITECTURE.md              # boundaries/security/scaling decisions
    ├── LAUNCH_CHECKLIST.md          # what remains before real-user launch
    ├── VALIDATION.md                # actual tests/builds + honest limitations
    ├── ASSETS.md                    # image/font/logo licensing
    └── screenshots/                # actual browser screenshots, not mockups
```

## 3. Kaam ke hisaab se kaunsi file?

| Aap kya change karna chahte hain? | File(s) |
|---|---|
| Supabase URL / **public** key / demo/live switch | `lib/config/supabase_config.dart`; prefer `--dart-define` or GitHub Variables |
| First screen / intro text / steps / controls | `lib/ui/screens/welcome_screen.dart` |
| First-install completion / persistence | `lib/services/onboarding_service.dart` |
| Startup welcome/auth/feed decision | `_AuthGate` in `lib/main.dart` |
| Logo ka design | `PATHS` in `scripts/generate_branding.py`, then regenerate committed files |
| Flutter logo use / size | `BrandMark` in `lib/ui/widgets/common.dart` |
| Android native splash | `res/drawable/launch_background.xml`, `drawable-v21`, `values*/styles.xml` and generated splash vectors |
| Android 8+ adaptive launcher icon | `res/mipmap-anydpi-v26/ic_launcher.xml` + `mc_launcher_foreground.xml` |
| Colours/fonts/buttons | `lib/theme/app_theme.dart`, `pubspec.yaml` |
| Post business logic / feed state | `lib/controllers/app_controller.dart` |
| Demo data | `lib/data/demo_seed.dart`, `location_catalogue.dart` |
| Live data access / signed media | `lib/repositories/supabase_repository.dart` |
| Add/change post metadata | `models/community.dart`, compose/detail/card UI, SQL metadata validator; update tests together |
| Ward picker / urban vs rural | `location.dart`, `location_picker.dart`, catalogue/import/migration |
| Server permissions / counters / rate limits | actual SQL migration; never rely only on Dart UI restrictions |
| Android app ID/version/SDK/signing | `android/app/build.gradle.kts`, `pubspec.yaml`, workflow build number |
| Telegram destination/secrets | **GitHub Settings → Secrets and variables → Actions**, not Dart source |
| APK build/send trigger | `.github/workflows/build-apk-telegram.yml` |
| Single-APK ZIP rules | `scripts/package_apks.py`, `archive_to_send()` in `send_telegram.py` |
| PR banana | `docs/GITHUB_PR.md`, `scripts/create_pull_request.sh` |

## 4. Data flow

```text
Screen / widget
    → AppController (state + desired action)
        → CommunityRepository interface
            ├─ DemoRepository → SharedPreferences, local dummy state
            └─ SupabaseRepository → guarded SQL RPCs / private Storage
        ← typed Dart models
    ← notifyListeners → Provider rebuilds UI
```

`community.dart` mein **one unified post** model hai. Four post types apni sealed metadata classes use karte hain; four alag database post tables nahi hain. Full geographic identity mein rural panchayat included hai—same ward number ka matlab same location nahi hota.

## 5. One APK → Telegram flow

```text
Trusted same-repository PR / manual action / v* tag
   → check TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID (values never printed)
   → pinned SDK + locked dependencies + tests
   → optional stable release signing
   → flutter build apk --release (NO split-per-abi)
   → app-release.apk: ARM32 + ARM64 + x86_64
   → verify signature + confirm all 3 Flutter libraries
   → one ZIP: one APK + SHA256SUMS.txt + INSTALL.txt
   → streamed Telegram sendDocument
   → remove temporary secrets/ZIP
```

**No APK upload to GitHub artifacts/releases.** Fork/draft PRs do not receive delivery secrets. Repository secrets are injected by GitHub Actions at runtime; an assistant/local workspace cannot retrieve their encrypted values simply because they exist in GitHub.

## 6. Generated/private files ko commit na karein

`build/`, `.dart_tool/`, `preview/`, `.gradle/`, `delivery/`, `android/local.properties`, `android/key.properties`, `.env*`, APKs, keystores and SDK caches are not source files. `source_bundle.py` excludes them. Keep **`pubspec.lock`**, hidden **`.github/`**, Gradle wrapper and bundled asset/font license files.

Backend live launch ke liye [Supabase guide](SUPABASE_SETUP.md) aur [launch checklist](LAUNCH_CHECKLIST.md) follow karein. App **P2P-only** hai: no government APIs, official ticket queues or departmental routing.
