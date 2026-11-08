#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$SOCKET_RESULTS_DIR"
if [ -z "${SOCKET_SECURITY_API_KEY:-}" ]; then
  echo '::error::Socket API key is unavailable.'
  exit 1
fi
# PR scans never replace the dashboard head; only an explicit develop baseline may do so.
head_flags=(--no-set-as-alerts-page)
if [ "${SOCKET_PUBLISH_BASELINE:-false}" = 'true' ]; then
  if [ "$SCAN_BRANCH" != 'develop' ] || [ "$(git rev-parse HEAD)" != "$SCAN_SHA" ]; then
    echo '::error::Baseline must scan the actual develop checkout and commit.'
    exit 1
  fi
  head_flags=(--default-branch --set-as-alerts-page)
fi
set +e
socket scan create --org "$SOCKET_ORG" --repo "$SOCKET_REPO" \
  --branch "$SCAN_BRANCH" --commit-hash "$SCAN_SHA" \
  "${head_flags[@]}" --json . \
  > "$SOCKET_RESULTS_DIR/cli-output.log" 2> "$SOCKET_RESULTS_DIR/cli-error.log"
scan_status=$?
set -e
printf '%s\n' "$scan_status" > "$SOCKET_RESULTS_DIR/cli-exit-code"
echo "Scan creation exit status: $scan_status"
exit "$scan_status"
