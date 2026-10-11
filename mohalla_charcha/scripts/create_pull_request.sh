#!/usr/bin/env bash
# Run on YOUR authenticated machine, not with Telegram secrets in the terminal.
# Creates a same-repository branch + non-draft PR; never auto-merges.
set -euo pipefail
repo="${1:-}"
if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo 'Usage: bash scripts/create_pull_request.sh OWNER/REPO' >&2
  exit 2
fi
command -v gh >/dev/null || { echo 'Install GitHub CLI (gh) first.' >&2; exit 1; }
command -v git >/dev/null || { echo 'Install git first.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Install Python 3.10+ first.' >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo 'Authenticate with gh auth login (repo/workflow permissions) first.' >&2; exit 1; }
source_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
base=$(gh repo view "$repo" --json defaultBranchRef --jq '.defaultBranchRef.name // empty')
if [[ -z "$base" ]]; then
  echo 'The target needs an existing default branch. Add an initial README commit first.' >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
branch="feat/welcome-single-apk-$(date -u +%Y%m%d%H%M%S)"
echo "Creating a PR in $repo against $base. Source files are copied; no existing files are deleted."
gh auth setup-git
gh repo clone "$repo" "$work/repository" -- --depth 1 --branch "$base"
git -C "$work/repository" switch -c "$branch"
# Reuse the nested app layout if present, or isolate it from a pre-existing app.
app_target="$work/repository"
if [[ -f "$work/repository/mohalla_charcha/pubspec.yaml" || -f "$work/repository/app.py" ]]; then
  app_target="$work/repository/mohalla_charcha"
fi
python3 "$source_root/scripts/source_bundle.py" --copy-to "$app_target"
if [[ "$app_target" != "$work/repository" ]]; then
  python3 - "$app_target" "$work/repository" <<'PYWRAP'
from pathlib import Path
import sys
app, repo = map(Path, sys.argv[1:])
for name, target, label in [('ci.yml','mohalla-ci.yml','Mohalla Charcha checks'),('build-apk-telegram.yml','mohalla-apk-telegram.yml','Mohalla Charcha APK → Telegram ZIP')]:
    text=(app/'.github/workflows'/name).read_text()
    text=text.replace(text.splitlines()[0], 'name: '+label, 1)
    marker='permissions:\n  contents: read\n'
    text=text.replace(marker,marker+'\ndefaults:\n  run:\n    working-directory: mohalla_charcha\n',1)
    folder=repo/'.github/workflows';folder.mkdir(parents=True,exist_ok=True)
    (folder/target).write_text(text)
PYWRAP
fi
# Respect your configured author; otherwise use your authenticated GitHub identity.
name=$(git -C "$work/repository" config user.name || true)
email=$(git -C "$work/repository" config user.email || true)
if [[ -z "$name" || -z "$email" ]]; then
  actor=$(gh api user --jq '.login')
  actor_id=$(gh api user --jq '.id')
  name="${name:-$actor}"
  email="${email:-${actor_id}+${actor}@users.noreply.github.com}"
fi
git -C "$work/repository" add --all
if git -C "$work/repository" diff --cached --quiet; then
  echo 'The target already contains these changes; no PR created.'
  exit 0
fi
git -C "$work/repository" -c user.name="$name" -c user.email="$email" commit \
  -m 'feat: branded first-launch onboarding and one universal Telegram APK'
git -C "$work/repository" push -u origin "$branch"
gh pr create --repo "$repo" --base "$base" --head "$branch" \
  --title 'Logo, first-launch onboarding, file guide and one universal APK' \
  --body-file "$source_root/docs/PULL_REQUEST_BODY.md"
echo 'PR created. The trusted same-repository PR workflow will use your repository Telegram secrets.'
echo 'Check the Actions log and Telegram. No APK artifacts are uploaded to GitHub.'
