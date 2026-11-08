#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$script_dir/../tools/socket-cli"
python3 "$script_dir/verify-socket-lock.py" "$source_dir/dependencies.lock"
if [ "${1:-}" = '--verify-only' ]; then exit 0; fi
install_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/socket-cli-poc"
mkdir -p "$install_dir"
cp "$source_dir/package.manifest" "$install_dir/package.json"
cp "$source_dir/dependencies.lock" "$install_dir/package-lock.json"
# npm verifies every downloaded package against the lockfile SRI hash.
# Tool dependency lifecycle scripts do not run.
npm ci --prefix "$install_dir" --ignore-scripts --no-audit --no-fund
"$install_dir/node_modules/.bin/socket" --version
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$install_dir/node_modules/.bin" >> "$GITHUB_PATH"
fi
echo 'Socket CLI 1.13.1 installed from the SHA-512-pinned tarball and SHA-256-pinned dependency lock.'
