# angel

This repository keeps two independent projects:

- Existing Python freight dashboard/scraper: `app.py`, `scraper.py`, `macro_data.json`, `requirements.txt`. Its original scheduled workflow is unchanged.
- **Mohalla Charcha**: Hindi-first Bihar P2P community app in [`mohalla_charcha/`](mohalla_charcha/). New logo/native splash, first-install tour, ward-first urban/rural hierarchy and **one universal APK / one Telegram ZIP**.

## Mohalla Charcha

- [Run/setup guide](mohalla_charcha/README.md)
- [File hierarchy and each file's work](mohalla_charcha/docs/FILE_HIERARCHY.md)
- [Repository layout](mohalla_charcha/docs/REPOSITORY_LAYOUT.md)
- [Telegram build/signing](mohalla_charcha/docs/TELEGRAM_BUILD.md)
- [Supabase settings](mohalla_charcha/lib/config/supabase_config.dart)

Root workflow **Mohalla Charcha APK → Telegram ZIP** uses the existing repository `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` secrets. It runs for trusted same-repository non-draft PRs, manual requests and version tags. It sends one universal APK ZIP directly to Telegram, with no GitHub APK artifact upload.

The projects do not share APIs/data. Mohalla Charcha has no government/official ticket routing. The app currently defaults to its persistent illustrative local demo; live Supabase/SMS/production signing need operator configuration.
