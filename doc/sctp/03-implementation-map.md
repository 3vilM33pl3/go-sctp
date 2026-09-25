# Implementation Map

## Modified upstream files (one-line `case` additions)

- `src/net/dial.go`: `parseNetwork` and `resolveAddrList` know `sctp*`;
  `dialSingle` dispatches `*SCTPAddr` to `sd.dialSCTP`; `ListenConfig.Listen`
  to `sl.listenSCTPOneToOne`; `ListenConfig.ListenPacket` to `sl.listenSCTP`.
- `src/net/ipsock.go`: IPv4 preference, resolver network parsing and
  `internetAddrList` construct `*SCTPAddr`.
- `src/net/sockaddr_posix.go`: `addrFunc` returns `sockaddrToSCTP` for any
  fd whose network is `sctp*`, whatever the socket type.

## Added files

| File | Build constraint | Contents |
| --- | --- | --- |
| `sctpsock.go` | none | addresses, `SCTPConn`, `SCTPListener`, option methods, dial/listen entry points, unsupported-error type |
| `sctpmultisock.go` | none | `SCTPMultiAddr`, `DialSCTPMulti`, `ListenSCTPMulti*`, `LocalAddrs`/`PeerAddrs` |
| `sctpnotify.go` | none | notification types and `ParseSCTPNotification` |
| `sctpsock_posix.go` | `linux \|\| (freebsd && amd64)` | address conversion, `readFromSCTP`/`writeToSCTP`, dial/listen/open/accept internals |
| `sctpsock_unix.go` | `linux \|\| (freebsd && amd64)` | `rawSockopt` (under `poll.FD.RawControl`), `set/getSockoptBytes`, `setSCTPInitOptionsSockFD`, `completeSCTPConnectx`, `wrapPeeledSCTPFD`, `subscribeSCTPEvents`, `resolveSCTPAssocID`, `sctpOOBBufferSize`, `rawPort`/`portFromRaw` |
| `sctpsock_linux.go` | `linux` | UAPI constants, struct layouts, cmsg marshal/parse, bindx/connectx/getaddrs, `SCTP_SOCKOPT_PEELOFF_FLAGS`, notification tables, `SCTPMsgNotification` |
| `sctpsock_freebsd.go` | `freebsd && amd64` | the same for FreeBSD (`sa_len` handling, `SCTP_CONNECT_X`, `sctp_peeloff(2)`) |
| `sctpnotify_freebsd.go` | `freebsd` | `SCTPMsgNotification` for every FreeBSD arch |
| `sctpnotify_other.go` | `!linux && !freebsd` | `SCTPMsgNotification = 0` |
| `sctpsock_stub.go` | other unix, js, wasip1, windows, FreeBSD non-amd64 | unsupported stubs |
| `sctpsock_plan9.go` | `plan9` | unsupported stubs |
| `api/next/99999.txt`, `doc/next/6-stdlib/99-minor/net/99999.md` | | API registration and release note for `cmd/api`/`cmd/relnote` |

## Kernel interface details

- Socket options not in the frozen `syscall` package are defined per kernel
  and issued through raw `setsockopt`/`getsockopt` under `poll.FD.RawControl`.
- `SCTP_INITMSG` applies before `connect(2)` through `Dialer.ControlContext`
  on Linux; FreeBSD sets it on the socket and connects explicitly
  (`dialSCTPInitPlatform`).
- `SCTP_SNDINFO`/`SCTP_RCVINFO`/`SCTP_NXTINFO` cmsgs use
  `syscall.CmsgSpace`/`ParseSocketControlMessage`; the receive buffer also
  has room for the legacy `SCTP_SNDRCV` cmsg.
- Ports in raw sockaddr lists are written as bytes in network order, not
  byte-swapped, so big-endian hosts are correct.
- Notification layouts are identical on both kernels except
  `sctp_pdapi_event`; the decoder is portable and the per-kernel files only
  supply type and state mappings.
