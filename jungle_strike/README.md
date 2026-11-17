# Jungle Strike

An independent Flutter Android action-game app (not part of Mohalla Charcha). The single-player campaign runs offline and has no Supabase, account, or backend dependency. It includes a story intro, six mission beats, stage artwork, a final Iron Vulture boss encounter, touch controls, armor, and score.

## Play locally

Install Flutter stable, then run:

```sh
cd jungle_strike
flutter create --platforms=android --org com.junglestrike .
flutter pub get
flutter run
```

Controls: left/right to move, up to jump, run button to dodge (cooldown), DOWN to toggle prone, hold FIRE to shoot, GUN to cycle PULSE / SPREAD / ROCKET, and EMOTE for a quick cheer. Three kills clear each of the first five missions; defeat the Iron Vulture in mission six. If armor runs out, tap the stage to retry from your saved checkpoint. Unlocked mission and best score save on-device with SharedPreferences; no cloud sync.

## Build and send the APK to Telegram

The workflow is `../.github/workflows/jungle-strike-apk-telegram.yml` from this app folder. It builds on pull requests that touch the game/workflow, and publishes a short-lived APK artifact on the PR run (no Telegram secrets are used for PRs). After the workflow is on the default branch, manual dispatch or a `jungle-v*` tag builds and sends the APK to Telegram. It generates Android platform files and runs formatting/analyzer/tests before building.

One-time GitHub repository setup:

1. Telegram delivery reuses the repository-level `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` Actions secrets already used by the existing Mohalla Charcha workflow. The game workflow reads those same secrets; it does not copy, print, or retrieve their values.
2. Run **Actions → Jungle Strike APK → Telegram → Run workflow**, or push a version tag to run it automatically:

```sh
git tag jungle-v1.0.0
git push origin jungle-v1.0.0
```

The bot token must stay in GitHub Actions secrets—never commit it or paste it into source/chat. The current APK uses the generated Android debug signing configuration for the release build; before a public Play Store release, configure a private production keystore and protect its credentials as repository secrets.
