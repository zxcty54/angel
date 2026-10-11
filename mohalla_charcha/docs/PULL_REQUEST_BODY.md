## Changes

- New home/conversation/neighbour brand: editable SVG, high-resolution PNG, Android density/adaptive icons and web icons.
- Branded Android native launch screen, including Android 12+ resources.
- Three-step Hindi/English welcome flow before feed/authentication on the first install.
- Persistent completion, next/back/skip, optional illustrative demo-ward choice, and Profile → Welcome & app tour replay.
- Exactly **one universal APK** (ARM32 + ARM64 + x86_64) in **one ZIP** with SHA-256 and install guide.
- Direct Telegram Bot API delivery using existing `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` repository secrets; no GitHub APK artifact or release attachment.
- Non-draft same-repository PR trigger; fork PR delivery skipped. No `pull_request_target` execution.
- Detailed `docs/FILE_HIERARCHY.md` and clean-source / PR helper scripts.
- Android version 1.1.0; build code base 10000 + workflow run number, to migrate away from older ABI offsets.

## Validation

- Flutter formatting and analyzer clean; 60 unit/controller/widget tests passed locally.
- Python delivery/configuration/import tests cover one-ZIP/one-APK guards, three ABIs, checksum, size cap, secret handling and PR gating.
- See `docs/VALIDATION.md` for actual local build/browser results and untested external integrations.

## Operator notes

- Default backend remains the persistent local demo. No live Supabase/SMS credentials are bundled.
- Start the bot in a private destination, or give it send permission in the intended group/channel.
- Stable production updates require your own release keystore; without signing secrets these are development/debug-key-signed builds.
- Review trusted code before allowing secrets. Do not weaken fork gating or use `pull_request_target` to execute PR code.
- Illustrative locations are not official Bihar ward master data. No government integration/routing.
