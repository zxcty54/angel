# Jungle Strike 3D

Jungle Strike is migrating from Flutter to Godot 4 as an offline, single-player third-person Android action campaign. The Godot project is under `godot/`. The older Flutter prototype remains in `lib/` as a temporary fallback only; it is no longer the APK build target.

## Godot prototype

Open `godot/project.godot` using Godot 4.4.1 or newer. The current vertical slice includes:

- 3D third-person player, shoulder camera, mouse/touch look, movement, jump, dodge with brief i-frames and hitscan firing.
- Touch joystick, look drag, fire, jump and dodge controls on mobile.
- Procedural low-poly jungle greybox, layered ridgelines, props, warm directional lighting and muzzle light.
- Six offline campaign missions, locally saved unlocked checkpoint, enemy waves, Iron Vulture boss, retry and three upgrade choices.
- Enemy hit flash and short-lived physics corpses; boss camera smoothly zooms out.

Desktop controls: WASD move, mouse look, left click or F to fire, Space to jump, Escape releases the mouse. On Android the on-screen controls are enabled automatically.

## Android APK → Telegram

`.github/workflows/jungle-strike-apk-telegram.yml` exports the Godot Android preset, packages the APK with a SHA-256 checksum/install note, and sends the ZIP directly to Telegram using the existing `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` Actions secrets. APKs are not uploaded as GitHub artifacts. Fork PRs do not receive secrets and do not send. A repository PR or manual workflow run can build; `jungle-v*` tags are available for versioned delivery.

The build currently uses the Godot Android debug signing configuration, suitable for testing only. A Play Store release needs a private production keystore stored in Actions secrets. The Godot project is an actively developed greybox, not a BGMI-equivalent art package: polished realistic character/weapon/environment assets and device profiling remain future production work.
