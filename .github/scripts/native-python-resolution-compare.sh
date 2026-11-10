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


# A synthetic empty baseline makes the whole real snapshot visible as new PR findings.
mkdir -p "$RUNNER_TEMP/socket-python-empty"
printf '{"name":"socket-poc-empty-control","version":"1.0.0","private":true}\n' > "$RUNNER_TEMP/socket-python-empty/package.json"
socketcli --scm api --repo "$SOCKET_REPO" --branch "native-python-control-$GITHUB_RUN_ID" \
  --target-path "$RUNNER_TEMP/socket-python-empty" --pr-number 0 --json-file "$results/baseline.json"
baseline=$(jq -er .full_scan_id "$results/baseline.json")

phase() {
  local name="$1"
  local folder="$results/$name"
  mkdir -p "$folder"
  set +e
  timeout 240s socketcli --scm github --repo "$SOCKET_REPO" --owner "$GITHUB_REPOSITORY_OWNER" \
    --target-path . --branch "$SCAN_BRANCH" --commit-sha "$SCAN_COMMIT" --pr-number "$PR_NUMBER" \
    --base-scan-id "$baseline" --ignore-commit-files --strict-blocking --disable-ignore --disable-overview \
    --json-file "$folder/python-report.json" --summary-file "$folder/python-summary.txt" \
    --report-link-file "$folder/python-report-link.txt" > "$folder/python-command.log" 2>&1
  local code=$?
  set -e
  printf '%s\n' "$code" > "$folder/python-exit.txt"
  if [ "$code" != 0 ] && [ "$code" != 1 ]; then
    cat "$folder/python-command.log"
    return 2
  fi
  local scan_id
  scan_id=$(jq -er .full_scan_id "$folder/python-report.json")
  api "$base/full-scans/$scan_id?include_license_details=true" > "$folder/scan-artifacts.ndjson"
  api "$base/settings/security-policy" > "$folder/security-policy.json"
  GH_TOKEN="$GH_API_TOKEN" gh api --paginate "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments?per_page=100" \
    --jq '.[] | select(.user.login == "github-actions[bot]" and (.body | contains("socket-security-comment-actions"))) | {id,body,html_url}' \
    > "$folder/python-comments.ndjson"
  python3 "$scripts/native_python_resolution_compare.py" phase "$folder"
}

phase before
python3 "$scripts/native_python_resolution_compare.py" request "$results"
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
python3 "$scripts/native_python_resolution_compare.py" result "$results"
