# Jungle Strike

An independent Flutter Android action-game app (not part of Mohalla Charcha). The single-player campaign runs offline and has no Supabase, account, or backend dependency. It includes a story intro, six mission checkpoints, distinct stage artwork, a final Iron Vulture boss encounter, player and enemy projectiles, enemy waves, collisions, twin-stick movement/manual aim with nearest-enemy auto-lock, background drones that dive into the lane, a muscular pixel-art fighter with a rifle, boss fan-volley patterns, explosive barrels, camera shake/hit-stop, and three-choice mission upgrades.

## Play locally

Install Flutter stable, then run:

```sh
cd jungle_strike
flutter create --platforms=android --org com.junglestrike .
flutter pub get
flutter run
```

Controls: drag the on-screen joystick for continuous movement (push up to jump, down to go prone), use the run button to dodge (cooldown), hold FIRE to shoot, GUN to cycle PULSE / SPREAD / ROCKET, and EMOTE for a quick cheer. Four kills clear each of the first five missions; defeat the Iron Vulture in mission six. If armor runs out, tap the stage to retry from your saved checkpoint. Unlocked mission and best score save on-device with SharedPreferences; no cloud sync.

## Build and send the APK to Telegram

The workflow is `../.github/workflows/jungle-strike-apk-telegram.yml` from this app folder. It builds on pull requests that touch the game/workflow and sends a ZIP containing the APK, SHA-256 checksum, and install note directly to Telegram for same-repository PRs. Fork PRs build without Telegram secrets and do not send. Manual dispatch or a `jungle-v*` tag also builds and sends the ZIP. It generates Android platform files and runs formatting/analyzer/tests before building; no GitHub APK artifact is published.

One-time GitHub repository setup:

1. Telegram delivery reuses the repository-level `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` Actions secrets already used by the existing Mohalla Charcha workflow. The game workflow reads those same secrets; it does not copy, print, or retrieve their values.
2. Run **Actions → Jungle Strike APK → Telegram → Run workflow**, or push a version tag to run it automatically:

```sh
git tag jungle-v1.0.0
git push origin jungle-v1.0.0
```

The bot token must stay in GitHub Actions secrets—never commit it or paste it into source/chat. The current APK uses the generated Android debug signing configuration for the release build; before a public Play Store release, configure a private production keystore and protect its credentials as repository secrets.
