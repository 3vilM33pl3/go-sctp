#!/usr/bin/env bash
# Tags the tested release branch, pushes branch and tag, and publishes a
# GitHub Release with the distribution files from build.sh.
#
#   publish.sh go1.27.4-sctp.1
#
# Needs GH_TOKEN, and push access for "origin" that may write workflow files
# (the rebased branch carries .github/workflows changes).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
. "$OUT_DIR/state.env"

version="${1:?usage: publish.sh <release tag>}"
cd "$(git rev-parse --show-toplevel)"

git tag -a "$version" -m "SCTP release $version on $UPSTREAM_TAG"
# The lease makes the push fail if someone moved the release branch since
# port.sh read it, instead of silently overwriting their work.
git push --atomic --force-with-lease="refs/heads/$RELEASE_BRANCH:$OLD_RELEASE_HEAD" \
  origin "HEAD:refs/heads/$RELEASE_BRANCH" "refs/tags/$version"

notes="$OUT_DIR/notes.md"
{
  echo "Go $UPSTREAM_TAG with native SCTP support in package \`net\` (Linux and FreeBSD/amd64)."
  echo
  echo "## Install"
  echo
  echo '```sh'
  echo "curl -LO https://github.com/$GITHUB_REPOSITORY/releases/download/$version/$version.linux-amd64.tar.gz"
  echo "mkdir -p \$HOME/sdk && tar -C \$HOME/sdk -xzf $version.linux-amd64.tar.gz && mv \$HOME/sdk/go \$HOME/sdk/$version"
  echo "export PATH=\$HOME/sdk/$version/bin:\$PATH"
  echo "go version   # go version $version linux/amd64"
  echo '```'
  echo
  echo "Native SCTP needs the kernel module: \`sudo modprobe sctp\`."
  echo
  echo "Other platforms: replace \`linux-amd64\` with \`linux-arm64\` for 64-bit Raspberry Pi OS,"
  echo "or \`darwin-arm64\` for macOS on Apple Silicon (unpack with \`tar -xzf\` the same way)."
  echo "macOS has no kernel SCTP: there the SCTP API compiles but returns errors matching"
  echo "\`errors.ErrUnsupported\`, which is useful for writing code and cross-compiling for Linux."
  echo
  echo "## SCTP commits on top of $UPSTREAM_TAG"
  echo
  git log --reverse --format='- %s' "$UPSTREAM_TAG..HEAD"
  echo
  echo "## Tested"
  echo
  echo "- \`go test net\` SCTP tests (native Linux SCTP), with and without \`-race\`"
  echo "- \`cmd/api -check\`, cross-GOOS build and vet"
  echo "- Go/C++ interoperability matrix"
  echo
  echo "Built by [run $GITHUB_RUN_ID]($GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID) from \`$SOURCE\`."
} >"$notes"

gh release create "$version" --verify-tag --title "$version" --notes-file "$notes" \
  "$OUT_DIR"/dist/*
