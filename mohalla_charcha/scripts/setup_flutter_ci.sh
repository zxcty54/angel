#!/usr/bin/env bash
# Same source-based SDK installation used to verify this project locally.
# A pinned commit avoids relying on availability of old release archive URLs.
set -euo pipefail
version='3.35.4'
revision='d693b4b9dbac2acd4477aea4555ca6dcbea44ba2'
sdk="${RUNNER_TEMP:?GitHub runner temp directory is required}/mohalla-flutter"
git clone --depth 1 --branch "$version" https://github.com/flutter/flutter.git "$sdk"
actual=$(git -C "$sdk" rev-parse HEAD)
if [[ "$actual" != "$revision" ]]; then
  echo 'Flutter SDK revision mismatch. Refusing to build.' >&2
  exit 1
fi
echo "$sdk/bin" >> "${GITHUB_PATH:?GitHub Actions PATH file is required}"
"$sdk/bin/flutter" config --no-analytics
"$sdk/bin/flutter" --version
