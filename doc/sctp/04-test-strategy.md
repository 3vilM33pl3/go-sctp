# Test Strategy

## Package tests

```bash
export GOROOT=$PWD PATH=$PWD/bin:$PATH
go test net -run 'SCTP|Sctp' -count=1          # every SCTP test, including Multi and notification tests
go test net -run 'SCTP|Sctp' -count=1 -race     # the concurrency test needs -race to be meaningful
go test net -short -count=1                     # the whole package
```

Test files:

- `sctpsock_test.go`, `sctpmultisock_test.go`: portable (network parsing,
  address formatting, unsupported-error semantics).
- `sctpsock_unix_test.go` (`linux || (freebsd && amd64)`): kernel-backed
  tests shared by both platforms: dialed address types, peel-off descriptor
  flags and deadlines, concurrent state under `-race`, sockaddr byte order,
  one-to-one association options, notification delivery and decoding,
  `io.EOF`, `SCTPListener`.
- `sctpsock_linux_test.go`, `sctpsock_freebsd_test.go`: loopback and
  multihoming tests plus the kernel's raw notification numbering for the
  layout tests.

Tests skip when the kernel has no SCTP (`requireSCTP`), so they pass by
skipping on machines without the module.

## Gates every change must pass

```bash
go vet net
for t in linux/amd64 linux/s390x freebsd/amd64 freebsd/arm64 darwin/arm64 windows/amd64 \
         plan9/amd64 js/wasm wasip1/wasm openbsd/amd64 netbsd/amd64 solaris/amd64 aix/ppc64; do
  GOOS=${t%/*} GOARCH=${t#*/} go build std && GOOS=${t%/*} GOARCH=${t#*/} go vet net || echo "FAIL $t"
done
go test cmd/api -run Check -check && go test cmd/relnote -check
go test go/build -run TestDependencies      # net may not import strings et al.
(cd src && ./run.bash)                       # the full gate; see 05-ci-and-ops.md for the TMPDIR caveat
```

## FreeBSD

The backend is pure syscall, so the test binary cross-compiles:

```bash
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/sctp_freebsd.test net
scp /tmp/sctp_freebsd.test user@freebsd-host: && \
  ssh user@freebsd-host './sctp_freebsd.test -test.run "SCTP|Sctp" -test.v -test.count=1'
```

`kldload sctp` must have been run on the host.

## Interop matrix (Go ↔ C++)

```bash
./misc/sctp-interop/harness/run_matrix.sh
```

Scenarios: Go/C++ server and client in every combination, plus the Go
multihome server, failover path and C++ multihome pair. The runner reports
`interop matrix PASSED`.

## External standards conformance

See `doc/sctp/08-external-conformance-profile.md`.
