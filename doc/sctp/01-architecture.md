# Linux SCTP in Go Runtime: Architecture

## Goal

Provide SCTP as a first-class transport in `net`, integrated similarly to TCP and UDP, with Linux-first behavior and C++ interoperability validation.

## Runtime Model

- Socket type: `SOCK_SEQPACKET`
- Protocol: `IPPROTO_SCTP`
- Programming model (v1): one-to-many style
- Message transport: `sendmsg/recvmsg`
- SCTP metadata path: ancillary cmsgs (`SCTP_SNDINFO`, `SCTP_RCVINFO`)

## Layering

- Public API: `src/net/sctpsock.go`
- Linux socket/data-path: `src/net/sctpsock_posix.go`, `src/net/sctpsock_linux.go`
- Non-Linux compatibility stubs: `src/net/sctpsock_stub.go`, `src/net/sctpsock_plan9.go`
- Resolver and dispatch integration:
  - `src/net/ipsock.go`
  - `src/net/dial.go`
  - `src/net/sockaddr_posix.go`

## Design Decisions

- `DialSCTP` uses an unconnected one-to-many socket and stores remote address as default destination.
- `WriteToSCTP(..., nil, ...)` on dialed sockets uses stored remote address.
- `ListenSCTP` uses `listen` path for passive one-to-many receive behavior.
- `SCTP_RECVRCVINFO` is enabled when `SetInitOptions` is applied.
- Linux-only advanced behavior is isolated from generic net API surface.
