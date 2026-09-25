# SCTP API Specification (Current Implementation)

The authoritative list is `api/next/99999.txt`; `go doc net.SCTPConn` shows
the documented surface. This page summarises it.

## Addresses

- `type SCTPAddr struct { IP IP; Port int; Zone string }`, with `Network`,
  `String`, `AddrPort`; `ResolveSCTPAddr`, `SCTPAddrFromAddrPort`.
- `type SCTPMultiAddr struct { Addrs []SCTPAddr }`, `ResolveSCTPMultiAddr`.

## Connections

- `DialSCTP`, `DialSCTPInit`, `DialSCTPMulti` → `*SCTPConn` (one-to-one).
- `ListenSCTP`, `ListenSCTPInit`, `ListenSCTPMulti`, `ListenSCTPMultiInit`,
  `OpenSCTP` → `*SCTPConn` (one-to-many).
- `ListenSCTPOneToOne` → `*SCTPListener` with `Accept`, `AcceptSCTP`, `Addr`,
  `Close`, `SetDeadline`, `File`, `SyscallConn`.
- `SCTPConn` implements `Conn` and `PacketConn`; `ReadFromSCTP` and
  `WriteToSCTP` carry `SCTPRcvInfo`/`SCTPSndInfo`. `ReadFromSCTP` returns
  `io.EOF` unwrapped when the peer shuts the association down and reports a
  truncated control buffer (`MSG_CTRUNC`) as an error.

## Options (all `SCTPConn` methods)

Association setup and defaults: `SetInitOptions`, `SetNoDelay`,
`SetRTOInfo`, `SetDelayedSack`, `SetDefaultPRInfo`, `SetDefaultSendInfo`,
`SetMaxBurst`, `SetMaxSeg`, `SetFragmentInterleave`, `SetAutoClose`
(one-to-many sockets only), `SetRecvRcvInfo`, `SetRecvNxtInfo`.

Authentication: `SetAuthChunks`, `SetAuthKey`, `ActivateAuthKey`,
`DeleteAuthKey`.

Multihoming: `BindAddrs`, `UnbindAddrs`, `LocalAddrs`, `PeerAddrs`,
`SetPrimaryAddr`, `SetPeerPrimaryAddr`.

Associations: `AssocIDs` (one-to-many sockets), `AssocStatus` (id 0 selects
the single association of a one-to-one socket), `PeelOff`.

Stream reconfiguration and scheduling: `EnableStreamReset`, `ResetStreams`,
`AddStreams`, `SetStreamScheduler`, `SetStreamSchedulerValue`.

## Events and notifications

- `SubscribeEvents(SCTPEventMask)`; the mask covers association, address,
  send failure (`SCTP_SEND_FAILED_EVENT`), peer error, shutdown, partial
  delivery, adaptation, authentication, sender dry, stream reset,
  association reset and stream change events, plus `DataIO` for
  `SCTP_RECVRCVINFO`.
- `SCTPMsgNotification` is the platform's `MSG_NOTIFICATION` flag;
  `ParseSCTPNotification([]byte) (*SCTPNotification, error)` decodes the
  payload with typed bodies `SCTPAssocChange`, `SCTPPeerAddrChange`,
  `SCTPRemoteError`, `SCTPSendFailed` and `SCTPStreamReset`, and portable
  `SCTPNotificationType`, `SCTPAssocState` and `SCTPPeerAddrState` values.

## Dispatch integration

- `net.Dial`/`Dialer.DialContext` accept `sctp`, `sctp4`, `sctp6` and return
  a `*SCTPConn`.
- `net.Listen`/`ListenConfig.Listen` return a `*SCTPListener`.
- `net.ListenPacket`/`ListenConfig.ListenPacket` return a one-to-many
  `*SCTPConn`.

## Platform notes

- Linux (kernel 5.1 or newer for `SCTP_EVENT`/`SCTP_SEND_FAILED_EVENT`) and
  FreeBSD 13+ on amd64 are supported.
- Every other platform compiles and returns an error matching
  `errors.ErrUnsupported`; `SCTPMsgNotification` is 0 there.
- `AssocIDs` on a one-to-one socket returns `EOPNOTSUPP` on Linux; use
  `AssocStatus(0)` instead.
