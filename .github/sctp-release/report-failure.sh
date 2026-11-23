#!/usr/bin/env bash
# Opens (or comments on) the "release blocked" issue for an upstream tag.
#
#   report-failure.sh go1.27.4 <stage>
#
# While the issue is open, detect.sh skips that version. Close it to retry.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

tag="${1:?usage: report-failure.sh <upstream tag> <stage>}"
stage="${2:-unknown}"
title="SCTP release blocked: $tag"
run="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"

body="$OUT_DIR/issue.md"
{
  echo "The automated SCTP release for upstream \`$tag\` stopped at **$stage**."
  echo
  echo "Run: $run"
  if [[ -s "$OUT_DIR/conflicts.txt" ]]; then
    echo; echo '```'; cat "$OUT_DIR/conflicts.txt"; echo '```'
    echo
    echo "Fix it by rebasing by hand (see \`.github/sctp-release/README.md\`) and pushing the"
    echo "release branch, then close this issue so the next run retries."
  else
    echo
    echo "Logs are attached to the run as the \`sctp-release-logs\` artifact."
    echo "Close this issue once fixed so the next run retries."
  fi
} >"$body"

gh label create "$BLOCKED_LABEL" --color B60205 \
  --description "Automated SCTP release could not be cut" 2>/dev/null || true
existing=$(gh issue list --state open --label "$BLOCKED_LABEL" --search "\"$title\" in:title" \
  --json number --jq '.[0].number // empty')
if [[ -n "$existing" ]]; then
  gh issue comment "$existing" --body-file "$body"
else
  gh issue create --title "$title" --label "$BLOCKED_LABEL" --body-file "$body"
fi
