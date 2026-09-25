# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **fork of the Go runtime** (branch `sctp/go1.28`, tracking Go master / `go1.28-devel`) that adds first-class SCTP (Stream Control Transmission Protocol) support directly into the `net` package. SCTP sits alongside TCP/UDP as a native transport — not an external library. Linux and FreeBSD/amd64 are supported; every other platform compiles with stubs whose errors match `errors.ErrUnsupported`.

## Build Commands

This is the Go toolchain itself. There is no `go build` — you build the compiler. Go master needs a bootstrap toolchain of at least Go 1.26:

```bash
export GOROOT_BOOTSTRAP=$HOME/sdk/go1.27.1   # go install golang.org/dl/go1.27.1@latest && go1.27.1 download
cd src && ./make.bash
```

### Run SCTP tests

```bash
export GOROOT=$PWD PATH=$PWD/bin:$PATH
go test net -run 'SCTP|Sctp' -count=1 -v      # the regex must cover TestDialSCTPMulti* and TestParseSCTPNotification*
go test net -run 'SCTP|Sctp' -count=1 -race
```

Run a single test:

```bash
go test net -run 'TestSCTPLoopbackReadWrite' -count=1 -v
```

### Gates every change must pass

Any exported identifier must be registered in `api/next/99999.txt` (`#99999` is the fork's approval number) in the same commit; `go test cmd/api -run Check -check` and `go test cmd/relnote -check` enforce it. `go vet net` must pass for every GOOS (see `doc/sctp/04-test-strategy.md` for the matrix), and `net` may not import `strings` (`go test go/build -run TestDependencies`).

### Run Go/C++ interop matrix

Requires `cmake`, `g++`, `linux-libc-dev`, and SCTP kernel module loaded (`sudo modprobe sctp`):

```bash
./misc/sctp-interop/harness/run_matrix.sh
```

### Prerequisites

- Linux with SCTP kernel support (`/proc/net/sctp/assocs` must exist)
- `sudo modprobe sctp` to load the module
- For interop tests: `cmake`, `g++`, `linux-libc-dev` (or `libsctp-dev` / `lksctp-tools`)

## Architecture

### Socket model

- `DialSCTP`/`net.Dial("sctp")`: `SOCK_STREAM` + `connect(2)` (one-to-one); `DialSCTPMulti`: `SOCK_STREAM` + `connectx`, completed like `connect(2)`.
- `net.Listen("sctp")`/`ListenSCTPOneToOne`: `SOCK_STREAM` listener returning `*SCTPListener`.
- `ListenSCTP`/`OpenSCTP`/`ListenSCTPMulti*`: `SOCK_SEQPACKET` (one-to-many); `PeelOff` splits an association out.
- Per-message metadata (stream ID, PPID) flows through ancillary data (cmsg) on `sendmsg`/`recvmsg`; notifications are flagged with `SCTPMsgNotification` and decoded by `ParseSCTPNotification`.

### Key files (all in `src/net/`)

| File | Purpose |
|---|---|
| `sctpsock.go` | Portable API: `SCTPAddr`, `SCTPConn`, `SCTPListener`, option methods, dial/listen entry points |
| `sctpmultisock.go` | Multi-address endpoints (`SCTPMultiAddr`, `DialSCTPMulti`, `LocalAddrs`/`PeerAddrs`) |
| `sctpnotify.go` | Portable notification types and `ParseSCTPNotification` |
| `sctpsock_posix.go` | Kernel-backed dial/listen/accept and read/write with metadata (`linux \|\| (freebsd && amd64)`) |
| `sctpsock_unix.go` | Shared kernel plumbing: sockopts under `poll.FD.RawControl`, connectx completion, peel-off wrapping, events, assoc-id resolution, byte order (same tag) |
| `sctpsock_linux.go` / `sctpsock_freebsd.go` | Per-kernel constants, struct layouts, cmsg marshal/parse, address lists, peel-off primitive, notification tables |
| `sctpnotify_freebsd.go` / `sctpnotify_other.go` | `SCTPMsgNotification` for FreeBSD / for platforms without SCTP |
| `sctpsock_stub.go` / `sctpsock_plan9.go` | Unsupported stubs |
| `sctpsock_test.go`, `sctpmultisock_test.go` | Portable unit tests |
| `sctpsock_unix_test.go` | Kernel-backed tests shared by Linux and FreeBSD |
| `sctpsock_linux_test.go`, `sctpsock_freebsd_test.go` | Platform-specific integration tests and raw notification numbering |

### Modified upstream files

- `dial.go` — SCTP network parsing and dispatch (`dialSCTP`, `listenSCTP`, `listenSCTPOneToOne`)
- `ipsock.go` — SCTP address hints in resolver
- `sockaddr_posix.go` — `addrFunc` keys on the `sctp*` network, so both socket types map to `*SCTPAddr`
- `api/next/99999.txt`, `doc/next/6-stdlib/99-minor/net/99999.md` — API registration

### Platform build constraints

- `sctpsock_posix.go`, `sctpsock_unix.go`, `sctpsock_unix_test.go`: `//go:build linux || (freebsd && amd64)`
- `sctpsock_linux.go`: `linux`; `sctpsock_freebsd.go`: `freebsd && amd64`
- `sctpsock_stub.go`: `(!linux && !freebsd && (unix || js || wasip1 || windows)) || (freebsd && !amd64)`
- `sctpsock_plan9.go`: `plan9`
- Untagged files must not touch `netFD` fields Plan 9 lacks (`family`, `sotype`, `isConnected`) or `syscall.AF_*`; put such code behind a per-OS hook.

### Syscall approach

SCTP socket options are frozen in the `syscall` package — new constants are defined directly in the per-kernel files and issued through raw `setsockopt`/`getsockopt` inside `fd.pfd.RawControl` (`rawSockopt` in `sctpsock_unix.go`), which holds the descriptor reference. Never call `syscall.Syscall6` on `fd.pfd.Sysfd` directly. Ports in raw sockaddrs are written as bytes in network order (`rawPort`), never byte-swapped. No external C libraries.

### Test skip mechanism

Kernel-backed tests call `requireSCTP(t)` (in `sctpsock_unix_test.go`) which skips if the kernel lacks SCTP support, so tests compile and pass (via skip) on machines without SCTP. Skips for optional features are narrowed to the expected errno (`EPERM` for `SetPeerPrimaryAddr`, `ENOPROTOOPT`/`EOPNOTSUPP` for stream reset); do not skip on arbitrary errors.

## Documentation

- `doc/sctp/` — Architecture, API spec, implementation map, test strategy, CI/ops, migration notes, risks
- `plans/` — Implementation plans (runtime integration phases)
- `artifacts/` — Reproducibility outputs and benchmark artifacts

## CI

GitHub Actions workflow (`.github/workflows/sctp-linux.yml`) runs on a **self-hosted runner** with labels `[self-hosted, linux, sctp]`. It installs a bootstrap Go, builds the toolchain, runs the SCTP net tests, the cross-GOOS vet matrix, the API/relnote checks and the interop matrix, and uploads logs as artifacts; `run.bash` is available on demand. See `doc/sctp/05-ci-and-ops.md` for the `TMPDIR`/VCS caveat.
