# Implementation Map

## Modified Existing Files

- `src/net/dial.go`
  - parse network names: add `sctp/sctp4/sctp6`
  - address list hint filtering: add `*SCTPAddr`
  - dial dispatch: add `sd.dialSCTP`
  - packet listener dispatch: add `sl.listenSCTP`
- `src/net/ipsock.go`
  - IPv4 preference logic: add `*SCTPAddr`
  - resolver network parsing: add `sctp*`
  - `internetAddrList` address construction: add `SCTPAddr`
- `src/net/sockaddr_posix.go`
  - `SOCK_SEQPACKET` over INET maps to `sockaddrToSCTP`

## Added Files

- `src/net/sctpsock.go`
  - exported API, address/conn types, wrappers
- `src/net/sctpsock_posix.go` (`linux`)
  - address conversion, read/write SCTP message path, dial/listen internals
- `src/net/sctpsock_linux.go` (`linux`)
  - Linux SCTP constants, cmsg marshal/parse, `setsockopt` helpers
- `src/net/sctpsock_stub.go` (`!linux && (unix||js||wasip1||windows)`)
  - unsupported stubs
- `src/net/sctpsock_plan9.go` (`plan9`)
  - unsupported stubs

## Linux Syscall/Socket Details

- `SCTP_INITMSG` configured through `SYS_SETSOCKOPT`
- `SCTP_NODELAY` configured through `SetsockoptInt`
- `SCTP_EVENT` subscriptions set per event type
- `SCTP_SNDINFO` cmsg generated with `syscall.CmsgLen/CmsgSpace`
- `SCTP_RCVINFO` cmsg parsed with `syscall.ParseSocketControlMessage`
