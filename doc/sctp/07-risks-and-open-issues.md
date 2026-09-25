# Risks and Open Issues

## Known risks

- `SCTP_EVENT` and `SCTP_SEND_FAILED_EVENT` need Linux 5.1 or newer; older
  kernels return `ENOPROTOOPT` from `SubscribeEvents`.
- Notifications interleave with data on one-to-many sockets and on any
  socket that subscribed to events; callers must check
  `SCTPMsgNotification` on every read.
- `DialSCTPMulti` follows the kernel's INIT strategy: the first address is
  tried first and the others only on timeout, so a first address that
  actively refuses fails the dial.
- `SetPeerPrimaryAddr` depends on ASCONF being enabled in the kernel.
- FreeBSD coverage runs on a remote host with a cross-compiled test binary;
  it is not part of the Linux CI job.

## Deferred scope

- Partial-delivery, adaptation and authentication notifications carry only
  their association id and raw bytes; typed bodies can follow the same
  pattern as the five decoded types.
- Deterministic multihoming failover tests (a path that times out rather
  than refuses) need a blackhole route and root privileges.
- Upstreaming: the tree now passes Go's own gates, which is the precondition
  for a proposal; the API would still need review against the proposal
  process.
