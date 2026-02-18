# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **fork of the Go runtime** that adds first-class SCTP (Stream Control Transmission Protocol) support directly into the `net` package. SCTP sits alongside TCP/UDP as a native transport — not an external library. Linux-only for v1; other platforms compile with clean unsupported-error stubs.

## Build Commands

This is the Go toolchain itself. There is no `go build` — you build the compiler:

```bash
cd src && ./make.bash
```

### Run SCTP tests

```bash
GOROOT=$(pwd) ./bin/go test net \
  -run '^TestSCTP|TestParseNetworkSCTP|TestResolveSCTPAddrUnknownNetwork' \
  -count=1 -v
```

Run a single test:

```bash
GOROOT=$(pwd) ./bin/go test net -run 'TestSCTPLoopbackReadWrite' -count=1 -v
```

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

- Uses `SOCK_SEQPACKET` (one-to-many style, message-oriented)
- `DialSCTP` does **not** call `connect(2)` — it stores the remote address as the default destination on an unconnected socket
- Per-message metadata (stream ID, PPID) flows through ancillary data (cmsg) on `sendmsg`/`recvmsg`

### Key files (all in `src/net/`)

| File | Purpose |
|---|---|
| `sctpsock.go` | Public API: `SCTPAddr`, `SCTPConn`, `SCTPInitOptions`, `SCTPSndInfo`, `SCTPRcvInfo`, `SCTPEventMask`, `SCTPMultiAddr` |
| `sctpsock_linux.go` | Linux constants, syscall wrappers (setsockopt/getsockopt), cmsg marshal/parse |
| `sctpsock_posix.go` | POSIX socket I/O: dial, listen, read/write with metadata |
| `sctpmultisock.go` | Multi-address endpoint support (multihoming, failover) |
| `sctpsock_stub.go` | Unsupported stubs for non-Linux platforms |
| `sctpsock_test.go` | Platform-agnostic unit tests |
| `sctpsock_linux_test.go` | Linux integration tests (loopback, metadata, multihoming) |

### Modified upstream files

- `dial.go` — SCTP network parsing and dispatch (`dialSCTP`, `listenSCTP`)
- `ipsock.go` — SCTP address hints in resolver
- `sockaddr_posix.go` — SCTP sockaddr conversion

### Platform build constraints

- `sctpsock_linux.go` / `sctpsock_posix.go`: `//go:build linux`
- `sctpsock_stub.go`: `//go:build !linux && (unix || js || wasip1 || windows)`
- `sctpsock_plan9.go`: `//go:build plan9`

### Syscall approach

SCTP socket options are frozen in the `syscall` package — new constants are defined directly in `sctpsock_linux.go` and called via `syscall.Syscall6` with `SYS_SETSOCKOPT`/`SYS_GETSOCKOPT`. No external C libraries.

### Test skip mechanism

Linux tests call `requireSCTP(t)` which skips if the kernel lacks SCTP support, so tests compile and pass (via skip) on machines without SCTP.

## Documentation

- `doc/sctp/` — Architecture, API spec, implementation map, test strategy, CI/ops, migration notes, risks
- `plans/` — Implementation plans (runtime integration phases)
- `artifacts/` — Reproducibility outputs and benchmark artifacts

## CI

GitHub Actions workflow (`.github/workflows/sctp-linux.yml`) runs on a **self-hosted runner** with labels `[self-hosted, linux, sctp]`. It builds the toolchain, runs SCTP net tests, runs the interop matrix, and uploads logs as artifacts.
