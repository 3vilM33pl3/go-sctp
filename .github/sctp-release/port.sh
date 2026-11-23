#!/usr/bin/env bash
# Rebases the SCTP series onto an upstream Go release tag and leaves the
# result checked out on the release branch. Run inside a full clone of this
# fork whose "origin" is the fork.
#
#   port.sh go1.27.4
#
# Source of the SCTP series:
#   - the existing release branch for that minor version (point releases), or
#   - SCTP_DEV_BRANCH when the line is new or FROM_DEV=true.
#
# Exit status 3 means the rebase conflicted; $OUT_DIR/conflicts.txt lists the
# files and the rebase is aborted.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

tag="${1:?usage: port.sh <upstream tag>}"
line=$(release_line "$tag")
rb=$(release_branch "$tag")

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
git fetch --no-tags upstream "+refs/tags/$tag:refs/tags/$tag" \
  "+refs/heads/$UPSTREAM_DEV_BRANCH:refs/remotes/upstream/$UPSTREAM_DEV_BRANCH"
git fetch --no-tags origin "+refs/heads/$SCTP_DEV_BRANCH:refs/remotes/origin/$SCTP_DEV_BRANCH"

old_rb=""
if git ls-remote --exit-code --heads origin "$rb" >/dev/null; then
  git fetch --no-tags origin "+refs/heads/$rb:refs/remotes/origin/$rb"
  old_rb=$(git rev-parse "origin/$rb")
fi

if [[ -n "$old_rb" && "${FROM_DEV:-false}" != "true" ]]; then
  src="origin/$rb"
  # The release branch sits on an earlier patch release of the same line,
  # which is an ancestor of the new tag.
  base=$(git merge-base "$src" "$tag")
else
  src="origin/$SCTP_DEV_BRANCH"
  base=$(git merge-base "$src" "upstream/$UPSTREAM_DEV_BRANCH")
fi

echo "Porting $(git rev-list --count "$base..$src") SCTP commits from $src onto $tag"
git checkout -q -B "$rb" "$src"
if ! git rebase --onto "$tag" "$base" >"$OUT_DIR/rebase.log" 2>&1; then
  {
    echo "Rebase of $src onto $tag stopped at:"
    git log -1 --format='  %h %s' REBASE_HEAD 2>/dev/null || true
    echo
    echo "Conflicting files:"
    git diff --name-only --diff-filter=U | sed 's/^/  /'
  } >"$OUT_DIR/conflicts.txt"
  git rebase --abort || true
  cat "$OUT_DIR/conflicts.txt"
  exit 3
fi

# Release toolchains ignore api/next and doc/next: cmd/api -check only reads
# api/go1.N.txt, so the SCTP API has to be listed there.
shopt -s nullglob
next=(api/next/*.txt)
if ((${#next[@]})); then
  [[ -f "api/$line.txt" ]] || die "api/$line.txt missing at $tag"
  cat "${next[@]}" >>"api/$line.txt"
  git rm -q "${next[@]}"
  git add "api/$line.txt"
fi
notes=$(git ls-files doc/next)
if [[ -n "$notes" ]]; then
  mkdir -p doc/sctp/release-notes
  for f in $notes; do
    git mv "$f" "doc/sctp/release-notes/$(echo "${f#doc/next/}" | tr / -)"
  done
fi
if ! git diff --cached --quiet; then
  git commit -q -m "api, doc: fold the SCTP API into api/$line.txt for the release branch"
fi

{
  echo "UPSTREAM_TAG=$tag"
  echo "RELEASE_BRANCH=$rb"
  echo "OLD_RELEASE_HEAD=$old_rb"
  echo "SOURCE=$src"
} >"$OUT_DIR/state.env"
echo "Release branch $rb is $(git rev-list --count "$tag..HEAD") commits on top of $tag"
