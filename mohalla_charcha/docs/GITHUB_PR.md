# GitHub PR + automatic single-APK Telegram build

## Current access boundary

The user reported adding `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` as repository secrets. Their values were **not retrieved or verified** in this workspace. GitHub Actions will inject them when the workflow runs in that repository.

The target is now `zxcty54/angel`. After the initial local-only delivery, the user authorized temporary official GitHub CLI device login. The agent can publish the requested PR using that authorization; the direct Arena GitHub connector remains unsupported. Both Telegram secret **names** were verified present through repository metadata; their values are not retrieved. Remote outcome is recorded in the PR/Actions run, not inferred from a local build. Never paste credentials into chat. See [actual repository layout](REPOSITORY_LAYOUT.md).

The source and workflow are ready. Use your own authenticated GitHub access to publish them:

## Option A — PR helper on your machine

Requirements: GitHub CLI (`gh`), Git, Python 3.10+ and write access to the target app repository. The repository needs an initial/default-branch commit (e.g. README).

Extract the updated source ZIP, open the **inner project folder**, then:

```bash
gh auth login
# Classic-token/OAuth pushes that add workflows need the workflow permission.
# If needed: gh auth refresh -s workflow
bash scripts/create_pull_request.sh YOUR_OWNER/YOUR_REPO
```

Replace the argument with your actual repository, not a placeholder. The helper:

1. Reads that repository's real default branch using your authenticated CLI.
2. Clones it to a temporary directory, creates a unique same-repository feature branch.
3. Copies clean app source, including hidden workflow files. It does not copy APKs/private config/cache, delete existing repo files, or merge a PR.
4. Commits/pushes the changes using your configured or authenticated GitHub identity.
5. Opens a non-draft PR with `docs/PULL_REQUEST_BODY.md`.
6. Cleans its temporary clone.

The helper modifies/pushes to the repository you provide; review the source/target before running it. It never needs your Telegram token locally. It has been syntax/source-filter reviewed here, **not executed against a real repository**.

A same-repository non-draft PR triggers **Build APK → Telegram ZIP**. The resulting Actions run uses the repository secrets you already added.

## Option B — GitHub web interface

1. Create a feature branch in your app repository.
2. Upload the contents of the extracted project folder at repository root. Include `.github/`, `.gitignore`, `pubspec.lock`, `scripts/`, assets and Gradle wrapper. Do not upload build output/keys.
3. Commit to the feature branch; create a non-draft PR against your default branch.
4. Open the PR's **Checks/Actions** tab. Watch **Build APK → Telegram ZIP**.
5. Start the bot in your private destination, or grant it group/channel send permissions, before delivery.

If workflow/repository settings prevent the first PR run, merge the reviewed changes and use Actions → **Build APK → Telegram ZIP** → Run workflow → `demo`.

## Security conditions

- Automatic Telegram delivery is only for **same-repository, non-draft PRs**; fork/draft PR delivery is skipped.
- Normal CI can still check fork contributions without bot/signing secrets.
- Never change this to `pull_request_target` that checks out and executes PR code with secrets.
- Only give write access to trusted contributors: code/workflows in a same-repository branch can access repository secrets.
- For public distribution, configure a stable release keystore and consider requiring signing/review on release builds.
- No GitHub APK artifact or release upload is used; **one APK / one ZIP** is sent directly to Telegram.

See [Telegram details](TELEGRAM_BUILD.md), [file hierarchy](FILE_HIERARCHY.md) and [validation report](VALIDATION.md).
