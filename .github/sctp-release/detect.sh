#!/usr/bin/env bash
# Prints "versions=<json array>" naming the upstream Go releases that still
# need an SCTP release. Run from a checkout of this repository.
#
#   INPUT_VERSION  if set, release exactly this upstream tag (manual runs)
#   GH_TOKEN       used to read open "release blocked" issues
set -euo pipefail
. "$(dirname "$0")/lib.sh"

if [[ -n "${INPUT_VERSION:-}" ]]; then
  release_line "$INPUT_VERSION" >/dev/null
  printf 'versions=["%s"]\n' "$INPUT_VERSION"
  exit 0
fi

upstream=$(git ls-remote --tags --refs "$UPSTREAM_URL" 'go1.*' |
  sed 's#.*refs/tags/##' | grep -E '^go1\.[0-9]+\.[0-9]+$' || true)
# A version counts as released only once its GitHub Release exists: a tag
# left behind by a failed publish does not stop the next run from retrying
# (which then cuts the next -sctp.K).
ours=""
if command -v gh >/dev/null && [[ -n "${GH_TOKEN:-}" ]]; then
  ours=$(gh release list --exclude-drafts --limit 1000 --json tagName --jq '.[].tagName' |
    sed "s/^${TAG_PREFIX:-}//")
else
  die "detect.sh needs gh and GH_TOKEN to list published releases"
fi
blocked=""
if command -v gh >/dev/null && [[ -n "${GH_TOKEN:-}" ]]; then
  blocked=$(gh issue list --state open --label "$BLOCKED_LABEL" --json title \
    --jq '.[].title' 2>/dev/null || true)
fi

# Newest patch release of every minor version >= MIN_MINOR.
candidates=$(echo "$upstream" | sort -V |
  awk -F. -v min="$MIN_MINOR" '$2 >= min { latest[$2] = $0 } END { for (k in latest) print latest[k] }' |
  sort -V)

todo=()
for t in $candidates; do
  if grep -qx -- "$t-sctp\.[0-9]*" <<<"$ours"; then continue; fi
  if grep -qwF -- "$t" <<<"$blocked"; then
    echo "skipping $t: an open '$BLOCKED_LABEL' issue names it" >&2
    continue
  fi
  todo+=("$t")
done

if ((${#todo[@]} == 0)); then
  echo "versions=[]"
else
  printf 'versions=[%s]\n' "$(printf '"%s",' "${todo[@]}" | sed 's/,$//')"
fi
