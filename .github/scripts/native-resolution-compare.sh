#!/usr/bin/env bash
set -euo pipefail

results="$SOCKET_RESULTS_DIR"
base="https://api.socket.dev/v0/orgs/$SOCKET_ORG"
scripts="$GITHUB_WORKSPACE/tooling/.github/scripts"
mkdir -p "$results"

api() {
  curl --fail-with-body --silent --show-error --connect-timeout 15 --max-time 60 \
    --user "$SOCKET_SECURITY_API_KEY:" --header 'Content-Type: application/json' "$@"
}

cleanup() {
  if [ ! -f "$results/create-attempted" ] || [ -f "$results/deleted.json" ]; then
    return
  fi
  uuid=$(jq -r '.uuid // empty' "$results/created.json" 2>/dev/null || true)
  # If POST timed out, recover only this run's exact comment and selector.
  if [ -z "$uuid" ]; then
    cursor=''
    for page in {1..10}; do
      cursor_args=()
      if [ -n "$cursor" ]; then
        cursor_args=(--data-urlencode "startAfterCursor=$cursor")
      fi
      api --get --data-urlencode per_page=100 --data-urlencode direction=desc \
        "${cursor_args[@]}" \
        "$base/alerts/resolutions" > "$results/recovery.json" || return 2
      uuid=$(jq -r --slurpfile expected "$results/request.json" \
        '.items[] | select(.comment == $expected[0].comment and .vigil_selector == $expected[0].vigil_selector) | .uuid' \
        "$results/recovery.json") || return 2
      [ -n "$uuid" ] && break
      cursor=$(jq -r '.endCursor // empty' "$results/recovery.json") || return 2
      [ -z "$cursor" ] && break
    done
  fi
  if [[ ! "$uuid" =~ ^[a-zA-Z0-9-]+$ ]]; then
    echo '::error::Cannot establish the temporary resolution identity; inspect recovery.json.'
    return 2
  fi
  api "$base/alerts/resolutions/$uuid" > "$results/owned.json" || return 2
  jq -e --slurpfile expected "$results/request.json" \
    '.comment == $expected[0].comment and .vigil_selector == $expected[0].vigil_selector' \
    "$results/owned.json" > /dev/null || return 2
  api --request DELETE "$base/alerts/resolutions/$uuid" > "$results/delete-response.json" || return 2
  status=$(curl --silent --show-error --connect-timeout 15 --max-time 60 \
    --user "$SOCKET_SECURITY_API_KEY:" --output "$results/deleted-read.json" \
    --write-out '%{http_code}' "$base/alerts/resolutions/$uuid") || return 2
  test "$status" = '404' || return 2
  jq -n --arg uuid "$uuid" '{uuid:$uuid,deleted:true,read_after_delete:404}' > "$results/deleted.json"
  echo "Deleted temporary resolution $uuid; GET confirmed HTTP 404."
}

if [ "${1:-}" = cleanup ]; then
  cleanup
  exit
fi
trap 'cleanup || exit 2' EXIT

phase() {
  local name="$1"
  local folder="$results/$name"
  mkdir -p "$folder"
  socket scan create --org "$SOCKET_ORG" --repo "$SOCKET_REPO" \
    --branch "$SCAN_BRANCH" --commit-hash "$SCAN_COMMIT" \
    --no-set-as-alerts-page --json . > "$folder/cli-output.log"
  local scan_id
  scan_id=$(SOCKET_RESULTS_DIR="$folder" python3 "$scripts/wrapped_report.py" scan-id)
  api "$base/full-scans/$scan_id?include_license_details=true" > "$folder/scan-artifacts.ndjson"
  api "$base/settings/security-policy" > "$folder/security-policy.json"

  # Record native process status; a timeout is infrastructure, never a clean verdict.
  set +e
  timeout 120s socket scan report --org "$SOCKET_ORG" --report-level warn --license --json \
    "$scan_id" "$folder/cli-report.json" > "$folder/cli-report-command.log" 2>&1
  local cli_exit=$?
  SOCKET_RESULTS_DIR="$folder" SOCKET_MODE=policy SCAN_OUTCOME=success DOWNLOAD_OUTCOME=success \
    python3 "$scripts/wrapped_report.py" > "$folder/wrapper-command.log" 2>&1
  local wrapper_exit=$?
  set -e
  printf '%s\n' "$cli_exit" > "$folder/cli-exit.txt"
  printf '%s\n' "$wrapper_exit" > "$folder/wrapper-exit.txt"
  python3 "$scripts/native_resolution_compare.py" phase "$folder"
}

phase before
python3 "$scripts/native_resolution_compare.py" request "$results"
api --request POST --data-binary "@$results/request.json" \
  "$base/alerts/resolutions?dry_run=true" > "$results/dry-run.json"
jq -e --slurpfile expected "$results/request.json" \
  '.dry_run == true and .vigil_selector == $expected[0].vigil_selector' "$results/dry-run.json" > /dev/null
touch "$results/create-attempted"
api --request POST --data-binary "@$results/request.json" \
  "$base/alerts/resolutions" > "$results/created.json"
jq -e '.uuid | type == "string"' "$results/created.json" > /dev/null

phase active
cleanup
phase revoked
python3 "$scripts/native_resolution_compare.py" result "$results"
