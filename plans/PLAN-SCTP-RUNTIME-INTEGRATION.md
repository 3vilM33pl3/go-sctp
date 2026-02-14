# Plan: Linux SCTP as a First-Class Transport in Go Runtime

## Summary
Re-implement SCTP in the latest Go runtime on Linux so SCTP is integrated in `net` in the same style as TCP and UDP. Validate correctness and interoperability using both Go in-tree tests and a C++ SCTP client/server harness.

## Goals
- Add SCTP to Go `net` as a first-class transport (`sctp`, `sctp4`, `sctp6`).
- Preserve Go API conventions (`Resolve*Addr`, `Dial*`, `Listen*`, `Conn`-like behavior).
- Expose SCTP-specific metadata/control where needed (stream, PPID, events, init options).
- Prove interoperability against independent C++ Linux SCTP endpoints.

## Non-Goals (Initial Version)
- Full multi-platform SCTP parity beyond Linux.
- Comprehensive benchmarking against all TCP/UDP workload classes.
- Full coverage of every SCTP extension in v1.

## Public API / Interface Additions
- `type SCTPAddr struct { IP net.IP; Port int; Zone string }`
- `type SCTPConn struct`
- `type SCTPInitOptions struct`
- `type SCTPSndInfo struct`
- `type SCTPRcvInfo struct`
- `type SCTPEventMask struct`
- `ResolveSCTPAddr(network, address string) (*SCTPAddr, error)`
- `DialSCTP(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error)`
- `ListenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error)`
- `ListenSCTPInit(network string, laddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, error)` (if enabled in branch design)
- `(*SCTPConn) ReadFromSCTP(...)`
- `(*SCTPConn) WriteToSCTP(...)`
- `(*SCTPConn) SetNoDelay(...)`
- `(*SCTPConn) SetInitOptions(...)`
- `(*SCTPConn) SubscribeEvents(...)`

## Architecture and Integration Map
- Public SCTP API surface: `src/net/sctpsock.go`
- POSIX/Linux SCTP I/O path: `src/net/sctpsock_posix.go`
- Linux SCTP constants/setsockopt/cmsg handling: `src/net/sctpsock_linux.go`
- Resolver/network parsing integration: `src/net/ipsock.go`
- Dial/listen dispatch integration: `src/net/dial.go`
- Sockaddr conversion integration: `src/net/sockaddr_posix.go`
- Unsupported platforms: `src/net/sctpsock_stub.go`, `src/net/sctpsock_plan9.go`

## Protocol / Socket Model Decisions
- Linux transport: `AF_INET/AF_INET6`, `SOCK_SEQPACKET`, `IPPROTO_SCTP`.
- Data path via `sendmsg`/`recvmsg`.
- Ancillary metadata path:
  - send: `SCTP_SNDINFO`
  - receive: `SCTP_RCVINFO`
- v1 behavior emphasizes one-to-many style SCTP semantics.

## Implementation Phases

## Phase 1: Baseline and Branch Setup
- Fork latest Go runtime source in dedicated repo branch.
- Confirm Linux SCTP prerequisites:
  - kernel module (`sctp`) available
  - userspace headers/libs (`libsctp-dev` / distro equivalent)
- Build baseline toolchain (`./src/make.bash`) and run baseline `net` tests.

## Phase 2: API Surface
- Implement/verify SCTP address and connection types in `net`.
- Add network parsing support for `sctp/sctp4/sctp6`.
- Add resolver flow for SCTP addresses.

## Phase 3: Runtime I/O Path
- Wire dial/listen dispatch to SCTP socket creation.
- Implement SCTP-specific read/write wrappers with OpError semantics aligned to `net`.
- Implement Linux setsockopt wrappers for:
  - `SCTP_INITMSG`
  - `SCTP_NODELAY`
  - `SCTP_EVENT`
  - `SCTP_RECVRCVINFO`
- Implement cmsg marshaling/parsing for send/receive SCTP metadata.

## Phase 4: Compatibility / Guardrails
- Ensure unsupported platforms return deterministic `errSCTPUnsupported`.
- Keep generic `net` behavior unchanged for TCP/UDP/Unix sockets.
- Confirm no regressions in existing `net` package tests.

## Phase 5: Go Test Coverage
- Add/maintain targeted tests:
  - loopback send/receive
  - metadata path (`SCTP_RCVINFO`)
  - network parse/address behavior
  - unsupported/invalid network handling
- Canonical command:
  - `GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP|TestParseNetworkSCTP|TestResolveSCTPAddrUnknownNetwork' -count=1 -v`

## Phase 6: C++ Interop Harness
- Implement C++ SCTP client/server on Linux (`<linux/sctp.h>`, `recvmsg` control parsing).
- Implement Go SCTP client/server pair using new `net` APIs.
- Matrix runner scenarios:
  1. Go server <- C++ client
  2. C++ server <- Go client
- Validate payload + stream ID + PPID in both directions.

## Phase 7: CI / Reproducibility
- Add CI workflow for Linux SCTP-capable environment (self-hosted runner if needed).
- Persist interop logs and runtime statistics as artifacts.
- Document exact commands and prerequisites in `doc/sctp`.

## Acceptance Criteria
- Go tree builds successfully.
- SCTP-targeted Go tests pass.
- Interop matrix passes both directions with expected metadata.
- API and implementation docs are present and accurate.
- Non-SCTP networking behavior remains intact.

## Risks and Mitigations
- Linux kernel SCTP support missing:
  - Mitigation: preflight check + test skip with clear reason.
- Frozen syscall package gaps for SCTP constants:
  - Mitigation: define Linux UAPI constants/struct layouts in `net` layer.
- Behavioral mismatch between one-to-many SCTP and user TCP expectations:
  - Mitigation: explicit API docs and examples.

## Deliverables
- Runtime source changes in `go-sctp-linux/src/net/*`.
- SCTP design and implementation docs in `go-sctp-linux/doc/sctp/*`.
- Go and C++ interop harness in `go-sctp-linux/misc/sctp-interop/*`.
- Reproducible tests and benchmark artifacts in `go-sctp-linux/artifacts/*` (and/or CI artifacts).
