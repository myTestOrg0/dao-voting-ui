#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$SOCKET_RESULTS_DIR"
if [ -z "${SOCKET_SECURITY_API_KEY:-}" ]; then
  echo '::error::Socket API key is unavailable.'
  exit 1
fi
set +e
socket scan create --org "$SOCKET_ORG" --repo "$SOCKET_REPO" \
  --branch "$SCAN_BRANCH" --commit-hash "$SCAN_SHA" \
  --no-set-as-alerts-page --json . \
  > "$SOCKET_RESULTS_DIR/cli-output.log" 2> "$SOCKET_RESULTS_DIR/cli-error.log"
scan_status=$?
set -e
printf '%s\n' "$scan_status" > "$SOCKET_RESULTS_DIR/cli-exit-code"
echo "Scan creation exit status: $scan_status"
exit "$scan_status"
