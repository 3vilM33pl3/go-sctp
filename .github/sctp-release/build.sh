#!/usr/bin/env bash
# Builds, tests and packages the checked-out release branch as a Go
# distribution named after the release tag.
#
#   build.sh go1.27.4-sctp.1
#
# Needs: a bootstrap Go on PATH (GOROOT_BOOTSTRAP defaults to its GOROOT),
# SCTP kernel support (/proc/net/sctp), cmake and g++ for the interop matrix.
# Leaves the distribution files in $OUT_DIR/dist.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

version="${1:?usage: build.sh <release tag>}"
root=$(git rev-parse --show-toplevel)
cd "$root"

[[ -e /proc/net/sctp/assocs ]] || die "SCTP kernel support is not active (try: sudo modprobe sctp)"

export GOROOT_BOOTSTRAP="${GOROOT_BOOTSTRAP:-$(go env GOROOT)}"

# The distribution reports the SCTP release as its version, for example
# "go version go1.27.4-sctp.1 linux/amd64". VERSION is restored afterwards
# so the release branch itself stays identical to what was tested.
cp VERSION "$OUT_DIR/VERSION.orig"
trap 'cp "$OUT_DIR/VERSION.orig" "$root/VERSION"' EXIT
{ echo "$version"; tail -n +2 "$OUT_DIR/VERSION.orig"; } >VERSION

step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }

step "make.bash -distpack"
(cd src && ./make.bash -distpack)
end

export GOROOT="$root" PATH="$root/bin:$PATH"
go version | grep -qF "$version" || die "built toolchain does not report $version"

step "SCTP net tests"
go test net -run 'SCTP|Sctp' -count=1 -v | tee "$OUT_DIR/sctp-tests.log"
go test net -run 'SCTP|Sctp' -count=1 -race
go test net -short -count=1
end

step "Cross-GOOS build and vet"
for t in linux/amd64 linux/arm64 linux/s390x freebsd/amd64 freebsd/arm64 darwin/arm64 \
         windows/amd64 plan9/amd64 js/wasm wasip1/wasm openbsd/amd64 netbsd/amd64; do
  GOOS="${t%/*}" GOARCH="${t#*/}" go build std
  GOOS="${t%/*}" GOARCH="${t#*/}" go vet net
done
end

step "API and dependency checks"
go test cmd/api -run Check -check
go test go/build -run TestDependencies
end

step "Go/C++ interop matrix"
INTEROP_LOG_DIR="$OUT_DIR/interop-logs" ./misc/sctp-interop/harness/run_matrix.sh
end

if [[ "${FULL_SUITE:-false}" == "true" ]]; then
  step "all.bash"
  export TMPDIR="$OUT_DIR/gotmp"; mkdir -p "$TMPDIR"
  (cd src && ./run.bash --no-rebuild)
  end
fi

step "Package"
rm -rf "$OUT_DIR/dist"; mkdir -p "$OUT_DIR/dist"
cp pkg/distpack/"$version".*.tar.gz "$OUT_DIR/dist/"
end

# Cross-compiled distributions for macOS on Apple Silicon and 64-bit
# Raspberry Pi OS. They are built here after all tests, because each
# make.bash -distpack run empties pkg/distpack. On macOS the SCTP API
# compiles but every call returns "sctp is not supported on this platform".
for t in darwin/arm64 linux/arm64; do
  step "Cross distribution $t"
  (cd src && GOOS="${t%/*}" GOARCH="${t#*/}" ./make.bash -distpack)
  cp pkg/distpack/"$version.${t%/*}-${t#*/}.tar.gz" "$OUT_DIR/dist/"
  end
done

step "Checksums"
(cd "$OUT_DIR/dist" && sha256sum ./* | sed 's# \./# #' >SHA256SUMS)
ls -l "$OUT_DIR/dist"
end
