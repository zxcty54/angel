# Deployment in zxcty54/angel

This repository already contains a Python freight dashboard/scraper. It is **not integrated with Mohalla Charcha** and its existing files/workflow remain unchanged.

## Actual repository layout

```text
angel/
├── app.py / scraper.py / requirements.txt / macro_data.json  # existing project
├── .github/workflows/scraper.yml                             # existing, unchanged
├── .github/workflows/mohalla-ci.yml                          # app + database checks
├── .github/workflows/mohalla-apk-telegram.yml                 # ONE APK ZIP → bot
└── mohalla_charcha/                                          # complete Flutter project
    ├── pubspec.yaml / lib/ / android/ / assets/ / test/
    ├── scripts/ / supabase/ / docs/
    └── .github/workflows/                                   # standalone templates
```

All app/source-guide paths are relative to `mohalla_charcha/`. Run local commands there:

```bash
cd mohalla_charcha
flutter pub get --enforce-lockfile
flutter run
```

GitHub executes the **root** `mohalla-*` workflows. Their default working directory is `mohalla_charcha`. The nested `.github` files are standalone templates and are not separately executed by GitHub.

Actions workflow name: **Mohalla Charcha APK → Telegram ZIP**. Same-repository non-draft PRs trigger it; fork/draft delivery is skipped. Manual/tag triggers remain available. Both Telegram repository secret names were verified present; their values are unreadable through the API and never copied into source.

The app remains demo-mode/P2P-only and does not consume the existing freight data. Do not move its Flutter files into the root Python project or delete the original workflow. See [file guide](FILE_HIERARCHY.md) and [Telegram details](TELEGRAM_BUILD.md).
