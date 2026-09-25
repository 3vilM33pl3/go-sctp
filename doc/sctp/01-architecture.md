# SCTP in the Go Runtime: Architecture

## Goal

Provide SCTP as a first-class transport in `net`, integrated the way TCP and
UDP are, on Linux and FreeBSD, with every other GOOS compiling against
unsupported-error stubs. The tree passes Go's own gates (`./src/all.bash`,
including `cmd/api` and `cmd/relnote`).

## Socket models

| Entry point | Socket | Style | Notes |
| --- | --- | --- | --- |
| `DialSCTP`, `DialSCTPInit`, `net.Dial("sctp")` | `SOCK_STREAM` + `connect(2)` | one-to-one | Interoperates with any peer stack; `LocalAddr`/`RemoteAddr` are `*SCTPAddr`. |
| `DialSCTPMulti` | `SOCK_STREAM` + `SCTP_SOCKOPT_CONNECTX` | one-to-one, multi-homed | Waits for the association like `connect(2)`; a refused first address fails the dial. |
| `net.Listen("sctp")`, `ListenSCTPOneToOne` | `SOCK_STREAM` + `listen`/`accept` | one-to-one | Returns `*SCTPListener`; each association is its own `*SCTPConn`. |
| `ListenSCTP`, `ListenSCTPInit`, `ListenSCTPMulti*` | `SOCK_SEQPACKET` + `listen` | one-to-many | One socket carries every association; messages carry the peer address and `SCTPRcvInfo.AssocID`. `PeelOff` turns one association into its own conn. |
| `OpenSCTP` | `SOCK_SEQPACKET`, bound only | one-to-many client | Sends open new associations implicitly. |

Data moves with `sendmsg`/`recvmsg`. Per-message metadata is ancillary data:
`SCTP_SNDINFO` on send, `SCTP_RCVINFO` (and `SCTP_NXTINFO` when enabled) on
receive. Events are subscribed with `SCTP_EVENT`, one call per type; the
deprecated `SCTP_EVENTS` bitmap is never used. Notifications arrive as
messages with the platform's `MSG_NOTIFICATION` flag (`SCTPMsgNotification`)
and decode with `ParseSCTPNotification`.

## Layering

- Portable API and state: `src/net/sctpsock.go` (addresses, `SCTPConn`,
  `SCTPListener`, option methods), `src/net/sctpmultisock.go` (multi-address
  endpoints), `src/net/sctpnotify.go` (notification decoding).
- Kernel-backed implementation, `linux || (freebsd && amd64)`:
  `src/net/sctpsock_posix.go` (dial/listen/accept/read/write),
  `src/net/sctpsock_unix.go` (socket-option plumbing under `poll.FD`
  references, connectx completion, peel-off wrapping, event subscription,
  association-id resolution, network byte order helpers).
- Per-kernel ABI: `src/net/sctpsock_linux.go`, `src/net/sctpsock_freebsd.go`
  (constants, struct layouts, cmsg marshalling, address lists, peel-off
  primitive, notification type/state tables).
- Stubs: `src/net/sctpsock_stub.go` (every other unix, js, wasip1, windows,
  and FreeBSD on non-amd64), `src/net/sctpsock_plan9.go`; both return an
  error matching `errors.ErrUnsupported`.
- Integration with the generic dispatch: `src/net/dial.go`,
  `src/net/ipsock.go`, `src/net/sockaddr_posix.go` (one-line `case`
  additions; `addrFunc` keys on the network so both socket types map to
  `*SCTPAddr`).

## Design decisions

- One-to-one dials use `connect(2)` so the client interoperates cleanly with
  remote stacks and the netpoller's connect machinery; the multi-homed dial
  completes `connectx` the same way (writability plus `SO_ERROR`).
- Every raw `setsockopt`/`getsockopt` runs under `poll.FD.RawControl`, so a
  concurrent `Close` cannot recycle the descriptor.
- `SCTPConn` state shared between goroutines (`assocID`, the multihoming
  address lists) is atomic or mutex-guarded.
- Option calls on one-to-one sockets never list association ids (Linux
  rejects that with `EOPNOTSUPP`); the kernel ignores the id there.
- Peeled-off descriptors are created non-blocking and close-on-exec
  (`SCTP_SOCKOPT_PEELOFF_FLAGS` on Linux, `sctp_peeloff(2)` under `ForkLock`
  on FreeBSD).
- `SetInitOptions`, `DialSCTPInit` and `ListenSCTPInit` also enable
  `SCTP_RECVRCVINFO`; `SCTPEventMask.DataIO` means the same thing on both
  kernels.
- Notification types and association/peer-address states are normalised to
  portable constants because the kernels number them differently.
