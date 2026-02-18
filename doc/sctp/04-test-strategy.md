# Test Strategy

## Unit/Package Tests

Run targeted SCTP tests in `net`:

```bash
GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP|TestParseNetworkSCTP|TestResolveSCTPAddrUnknownNetwork' -count=1 -v
```

Current tests:

- `src/net/sctpsock_test.go`
  - network parsing and address behavior
- `src/net/sctpsock_linux_test.go`
  - loopback send/recv
  - metadata path (`SCTP_RCVINFO`)
  - unknown-network behavior

## Interop Matrix (Go ↔ C++)

```bash
./misc/sctp-interop/harness/run_matrix.sh
```

Scenarios:

1. Go server `<-` Go client
2. Go server `<-` C++ client
3. C++ server `<-` Go client
4. C++ server `<-` C++ client
5. Go multihome server `<-` Go multihome client
6. Go multihome failover path `<-` Go multihome client
7. C++ multihome server `<-` C++ multihome client

## Acceptance Criteria

- Go toolchain builds (`./src/make.bash`)
- SCTP net tests pass on Linux with SCTP enabled
- Matrix runner reports `interop matrix PASSED`

## Failure Diagnostics

- For Go tests, re-run with `-v -run TestSCTPLoopbackReadWrite`
- For interop, inspect log files printed by `run_matrix.sh`

## External Standards Conformance

For external (non-project) standards-oriented validation profile, see:

- `doc/sctp/08-external-conformance-profile.md`
