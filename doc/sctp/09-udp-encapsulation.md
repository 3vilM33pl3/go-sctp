# SCTP over UDP (RFC 6951) Fallback

## Summary

When the host has no kernel SCTP, `net` carries SCTP over UDP through a
user-space engine in `internal/sctp`. Programs need no changes: `DialSCTP`,
`ListenSCTP`, `net.Dial("sctp", ...)` and `net.ListenPacket("sctp", ...)`
switch to UDP automatically, and `(*SCTPConn).Transport()` reports which
transport is in use.

The fallback is available on Unix builds. Other platforms keep the existing
unsupported stubs.

## Transport selection

| Policy | Behaviour |
|---|---|
| `SCTPTransportDefault` | Uses GODEBUG `sctptransport`, which defaults to `SCTPNativePreferred`. |
| `SCTPNativePreferred` | Kernel SCTP. Switches to UDP only when socket creation reports no kernel support (`EPROTONOSUPPORT`, `ESOCKTNOSUPPORT`, `EAFNOSUPPORT`, `ENOPROTOOPT`, or the platform stub error). |
| `SCTPNativeOnly` | Kernel SCTP only, the pre-existing behaviour. |
| `SCTPNativePreferredWithConnectFallback` | Like `SCTPNativePreferred`, and a dial whose native association is refused or times out is retried over UDP. |
| `SCTPUDPOnly` | Always UDP. |

GODEBUG overrides for calls that do not pass a policy:

- `sctptransport=preferred` (default)
- `sctptransport=native`
- `sctptransport=udp`

Explicit configuration:

```go
c, err := net.DialSCTPConfig(ctx, "sctp", nil, raddr, net.SCTPInitOptions{},
	net.SCTPTransportConfig{
		Policy: net.SCTPUDPOnly,
		UDP:    net.SCTPUDPConfig{LocalEncapPort: 9899, RemoteEncapPort: 9899},
	})
```

Encapsulation ports default to the SCTP ports, the same as rust-sctp. Replies
follow the UDP source port the peer actually uses (RFC 6951 section 5.5).

`SCTPSndInfo.PPID`, `SCTPRcvInfo.PPID` and `SCTPNxtInfo.PPID` follow the kernel
convention on both transports, the same as rust-sctp: the field is copied to
the wire as raw memory, so callers convert with htonl/ntohl (for example
`binary.BigEndian.Uint32` of the bytes they want on the wire). On a
little-endian host, PPID `0x10032` goes on the wire as `32 00 01 00`. A
program therefore sends the same bytes whichever transport it ends up on.

## Architecture

- `src/internal/sctp`: sans-IO engine. Datagrams, application sends and timer
  ticks go in; transmits, messages and events come out. No goroutines, no
  sockets, and a caller-supplied clock, so it is tested deterministically on a
  simulated network.
  - `packet.go`: wire format, CRC32c (little-endian on the wire), chunk codecs.
  - `cookie.go`: state cookie with a SipHash-2-4 128-bit MAC.
  - `endpoint.go`: endpoint, association lookup by verification tag and by peer,
    INIT/COOKIE handshake, collision and restart handling, OOTB handling.
  - `association.go`: state machine, fragmentation, SACK and gap processing,
    congestion control, fast retransmit, T1/T2/T3/heartbeat/delayed-SACK
    timers, reassembly, graceful shutdown.
  - `pr.go`: PR-SCTP (RFC 3758) TTL and RTX policies and FORWARD TSN.
  - `reconf.go`: stream reconfiguration (RFC 6525), outgoing reset and add
    outgoing streams.
- `src/net/sctpsock_udp.go`: binds a `UDPConn`, runs one reader goroutine and
  one timer per socket, and maps the engine to the `SCTPConn` API: partial reads
  with `MSG_EOR`, notifications in the Linux layout (FreeBSD numbering on
  freebsd), rcvinfo/nxtinfo, deadlines and blocking writes.
- `src/net/sctpsock_transport.go`: public policy types and the dispatch of
  inherited `Conn` methods to the UDP transport.

A message larger than the receive window is delivered in pieces
(partial delivery): reads return its data without `MSG_EOR` until the
last piece, and no other message is delivered on that association in
between. If the sender abandons the rest of such a message (PR-SCTP), the
next read starts a new message; no partial-delivery-aborted notification is
generated. Messages queued on a one-to-many socket during implicit setup on
a stream the peer did not grant are dropped once the handshake completes.

Socket model matches the kernel path: a listener is one-to-many and creates
associations implicitly on the first send to a new peer; a dialed connection is
one-to-one. `Close` shuts associations down gracefully in the background and
aborts after a 10s linger.

## Supported over UDP

Read/Write, `ReadFromSCTP`/`WriteToSCTP` (stream, PPID, unordered, EOF, ABORT,
PR flags), deadlines, `SetReadBuffer`/`SetWriteBuffer`, `SetInitOptions`,
`SetRTOInfo`, `SetDelayedSack`, `SetDefaultSendInfo`, `SetDefaultPRInfo` (none,
TTL, RTX), `SetRecvRcvInfo`, `SetRecvNxtInfo`, `SubscribeEvents` (except
authentication), `SetNoDelay(true)`, FCFS scheduler, `AssocIDs`, `AssocStatus`,
`ResetStreams` (outgoing), `AddStreams` (outgoing), `LocalAddrs`/`PeerAddrs`.

## Not supported over UDP

These return an error that matches `errors.ErrUnsupported`:

- multihoming: `BindAddrs`, `UnbindAddrs`, `SetPrimaryAddr`,
  `SetPeerPrimaryAddr`, and multi-address dial or listen;
- SCTP-AUTH (RFC 4895): `SetAuthChunks`, `SetAuthKey`, `ActivateAuthKey`,
  `DeleteAuthKey`;
- `PeelOff`, `SyscallConn`, `File`, `SetAutoClose`, `SetFragmentInterleave`,
  `SetMaxBurst`, `SetMaxSeg`, `SetStreamSchedulerValue`, schedulers other than
  FCFS, `SetNoDelay(false)`;
- incoming stream reset, SSN/TSN reset, adding incoming streams.

The peer's incoming-reset, SSN/TSN-reset and add-incoming requests are denied.

## Security

SCTP over UDP has no encryption or authentication. The cookie MAC uses
SipHash-2-4 with a random per-endpoint key rather than HMAC, because
`crypto/internal/fips140/hmac` would pull the FIPS module (SHA-2 and SHA-3)
into every binary that imports `net` and conflicts with the package dependency
order enforced by `go/build/deps_test.go`. The cookie only needs a keyed PRF
that resists forgery for its 60s lifetime, which SipHash-128 provides.

## Testing

```bash
GOROOT=$(pwd) ./bin/go test internal/sctp -count=1 -race
GOROOT=$(pwd) ./bin/go test net -run 'TestSCTPUDP' -count=1 -v
GOROOT=$(pwd) ./bin/go test internal/sctp -run '^$' -fuzz FuzzInput -fuzztime 60s
```

The `net` tests force UDP with `SCTPUDPOnly`, so they run on hosts with and
without kernel SCTP. `misc/sctp-interop/udp` holds an interop matrix against
usrsctp and rust-sctp, both directions, which passes on Linux (rust-sctp with
64 KiB messages, its engine's limit). Linux kernel UDP encapsulation
(`net.sctp.udp_port`, `d-kernel.sh`) and FreeBSD are still to be run.
