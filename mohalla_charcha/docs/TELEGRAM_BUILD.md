# ONE APK → ONE ZIP → Telegram

Workflow: **`.github/workflows/build-apk-telegram.yml`**. Updated for the user's single-APK requirement: one universal APK containing ARM32, ARM64 and x86_64, not separate architecture downloads.

## Existing repository secrets

The user has reported adding these in GitHub. They are not present/retrievable in this local workspace; the workflow uses them **inside GitHub Actions**:

| Repository Secret | Value |
|---|---|
| `TELEGRAM_BOT_TOKEN` | BotFather bot token |
| `TELEGRAM_CHAT_ID` | Numeric private chat/group/channel destination ID |

Optional `TELEGRAM_CHAT_NAME=@public_channel` replaces numeric ID; numeric ID takes priority. `TELEGRAM_THREAD_ID` can target a numeric forum topic.

A private chat title/personal @username is not a substitute for numeric ID. **Start the bot** in your private destination, or add it to the group/channel with send permission. Do not paste tokens into chat/source/command history or publish token-bearing API URLs.

Secrets are injected only into the setup-check and send steps—not Dart, the APK, a build argument, or public logs. This session did not read or verify their actual values.

## Repository layout and PR

Place project contents at repository root: `pubspec.yaml`, `lib/`, `android/`, `assets/`, `scripts/`, `test/`, `supabase/`, hidden `.github/`, lockfile and Gradle wrapper. Never commit key properties/keystores/tokens/build output.

See [PR helper](GITHUB_PR.md) to open a same-repository PR using your own authorized GitHub CLI, or upload to a feature branch manually.

## Triggers

- **Same-repository, non-draft PR**: opened, synchronize, reopened, ready-for-review → build + Telegram send.
- **Fork/draft PR**: delivery job skipped; no bot/signing secrets given to fork code.
- **Manual**: Actions → Build APK → Telegram ZIP → Run workflow → `demo` now.
- **Version tag `v*`**: build + delivery. Repository Variable `APP_BACKEND=supabase` chooses live mode for PR/tag builds; absent variable defaults to demo.
- Ordinary branch pushes run `ci.yml`, not a separate duplicate Telegram send.

Do not use `pull_request_target` to execute changed PR code with secrets. Only allow trusted contributors write access; same-repository branches can use repository secrets. Repository/organization policy may require approval. If a newly introduced workflow does not start from the first PR, merge the reviewed workflow and run it manually from default branch.

## Build/delivery steps

1. Check secret format/configuration without network calls or value logging.
2. Java 17, Android SDK/licenses, Flutter 3.35.4 installed from official source tag with exact revision verification; enforce committed dependency lock.
3. Formatting, analyzer, Flutter tests and Python tests.
4. Temporary optional release-signing configuration; reject partial/invalid private configuration.
5. `flutter build apk --release --target-platform android-arm,android-arm64,android-x64`—**no split-per-ABI flag**.
6. Verify signature on **`build/app/outputs/flutter-apk/app-release.apk`**.
7. Package **one ZIP**, containing exactly one universal APK, `SHA256SUMS.txt`, `INSTALL.txt`. Check all three native Flutter libraries and ZIP <49 MiB. Do not silently split if oversized.
8. Sender refuses zero/multiple ZIPs or multiple APKs in the ZIP; streams the one document over HTTPS `sendDocument`.
9. Remove temporary defines/signing material/ZIP from runner.

**No GitHub APK artifact or release attachment upload.** ZIPs go directly to Telegram. Each qualifying workflow run sends one build; later PR commits can produce a newer build.

Version 1.1.0 starts local code 10001. Workflow codes are **10000 + `GITHUB_RUN_NUMBER`**, avoiding downgrade from earlier ABI-offset test builds. Keep codes monotonic if you rename/reset the workflow/repository or distribute from another pipeline.

## Signing

Without all signing secrets, a release-mode APK uses a development/debug key: testing only. Fresh GitHub runners can use different debug keys; an update can require uninstalling the old build, which deletes local data and shows welcome again.

For updatable distribution, create/back up a stable keystore:

```bash
keytool -genkeypair -v -keystore mohalla-release.jks -alias mohalla \
  -keyalg RSA -keysize 2048 -validity 10000
base64 -w 0 mohalla-release.jks
```

Add Repository Secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. Select `require_signing=true` for manual builds. Consider requiring signing/review for tag/PR distributions. App ID: `in.mohallacharcha.app`; Android 7+/API24+.

## Optional live backend

For `backend=supabase`, add Repository Variables `SUPABASE_URL` and `SUPABASE_ANON_KEY` (**public anon/publishable** only). Equivalent Secrets are fallback inputs; the helper rejects secret/service-role keys. The public key necessarily exists in a compiled client; server RLS remains mandatory.

Default demo needs none of these and sends no SMS. Live SMS/Auth/Storage integration and residency/master-data verification are separate launch tasks.

## Troubleshooting

- Missing/malformed configuration: fails before the build.
- HTTP400: verify destination/topic ID and file-size settings.
- HTTP401: verify/revoke/replace bot token.
- HTTP403: start bot/unblock it/grant destination permissions.
- HTTP429: bounded retry only after an explicit rate-limit response.
- Connection lost/invalid response: **no blind POST retry**; the document may have arrived. Check Telegram before rerunning.
- Fork/draft PR skipped: use a trusted same-repo branch or reviewed manual run; do not weaken secret security.

The APK/ZIP was verified locally. The user has since authorized publishing the PR to `zxcty54/angel`; both repository secret names are confirmed present. Actual Telegram delivery is established only by the running workflow's successful send step/message ID. In this repository choose **Mohalla Charcha APK → Telegram ZIP**; see the repository-layout guide.
