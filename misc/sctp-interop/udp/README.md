# SCTP-over-UDP (RFC 6951) interop

Echo peers that speak one protocol: the client sends 100 messages (message
`i` on stream `i%5`, PPID `0x10000+i`, message 50 is 200 KiB), the server
echoes each on the same stream and PPID, the client checks payload, stream,
PPID and per-stream order, then shuts down gracefully and waits for
SHUTDOWN_COMPLETE.

| Peer | Source | Notes |
|---|---|---|
| Go | `goecho/` | `-transport udp` (SCTPUDPOnly) or `native`; `-lencap`/`-rencap` set encapsulation ports |
| rust-sctp | `rustecho/` | built with a rust-sctp stage1 `rustc`; `rustecho64k` uses a 64 KiB big message |
| usrsctp | `usrsctpecho/` | `usrsctp_init(udp_port)` + `SCTP_REMOTE_UDP_ENCAPS_PORT` |
| relay | `udprelay/` | UDP relay that logs every chunk and writes a pcap (for hosts where tcpdump needs root) |

```bash
RUSTC=/path/to/rust-sctp/build/x86_64-unknown-linux-gnu/stage1/bin/rustc \
USRSCTP=/path/to/usrsctp ./run_matrix.sh
```

`d-kernel.sh` tests Linux kernel UDP encapsulation. It needs
`sudo sysctl -w net.sctp.udp_port=9899 net.sctp.encap_port=9900`, which
changes SCTP for the whole host until reverted with `... =0`.

Known peer limitations (not Go bugs):

- rust-sctp's engine (vendored sctp-proto) caps messages at 64 KiB. A larger
  send fails with `ErrOutboundPacketTooLarge`; a larger incoming message is
  black-holed (fragments past 64 KiB are never SACKed and no ABORT is sent).
- rust-sctp reports `Shutdown` but no SHUTDOWN_COMP association change.
- sctp-proto drops an INIT whose last parameter is 4 bytes long; Go now puts
  Forward-TSN-Supported first for that reason.
- rust-sctp's SHUTDOWN carries its own send-side cumulative ack point
  (sctp-proto `association/mod.rs`, `ChunkShutdown { cumulative_tsn_ack:
  self.cumulative_tsn_ack_point }`) instead of the cumulative TSN it received.
  When that value is above the highest TSN Go sent, Go aborts with Protocol
  Violation (RFC 9260 section 6.2), so `b-goserver-rustclient` fails about half
  the time, depending on the random initial TSNs.

## FreeBSD

goecho reads the kernel ABI values per OS (MSG_EOR, MSG_NOTIFICATION, SCTP_EOF,
notification numbering), so it cross-compiles:

```bash
GOROOT=$PWD GOOS=freebsd GOARCH=amd64 ./bin/go build -o goecho.freebsd ./misc/sctp-interop/udp/goecho/main.go
GOROOT=$PWD GOOS=freebsd GOARCH=amd64 ./bin/go test -c -o net.test.freebsd net
```
