# Shared helpers for the SCTP release scripts. Source, do not execute.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release.conf
. "$here/release.conf"

die() { echo "error: $*" >&2; exit 1; }

# go1.27.4 -> go1.27
release_line() {
  local t="$1"
  [[ "$t" =~ ^go1\.([0-9]+)\.[0-9]+$ ]] || die "not a Go release tag: $t"
  echo "go1.${BASH_REMATCH[1]}"
}

release_branch() { echo "${RELEASE_BRANCH_PREFIX}$(release_line "$1")"; }

# Next SCTP release tag for an upstream tag: go1.27.4 -> go1.27.4-sctp.N
next_release_tag() {
  local t="$1" n
  n=$(git ls-remote --tags --refs origin "$t-sctp.*" | sed 's#.*refs/tags/##' |
      sed -n "s/^$t-sctp\.\([0-9][0-9]*\)$/\1/p" | sort -n | tail -1)
  echo "$t-sctp.$(( ${n:-0} + 1 ))"
}

# Directory for logs and outputs shared between steps.
OUT_DIR="${SCTP_RELEASE_OUT:-${RUNNER_TEMP:-/tmp}/sctp-release}"
mkdir -p "$OUT_DIR"
