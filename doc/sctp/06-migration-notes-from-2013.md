# Migration Notes from 2013 Implementation

## What Stayed the Same

- SCTP integrated in `net` directly (not an external package)
- API follows TCP/UDP style (`Resolve*Addr`, `Dial*`, `Listen*`)
- SCTP metadata exposed through protocol-specific read/write methods

## What Changed

- Modern Go runtime/net internals (Go tip) required remapping touchpoints.
- Linux UAPI SCTP constants/structs are handled in `net` (syscall API is frozen).
- `DialSCTP` in v1 uses one-to-many socket semantics without `connect`.
- New per-event subscription API via `SCTP_EVENT` wrappers.

## Legacy-to-Current File Mapping

Legacy hotspots from old branch:

- `src/net/sctpsock.go`, `src/net/fd_sctp.go`, `src/net/dial_sctp.go`

Modern equivalents:

- `src/net/sctpsock.go`
- `src/net/sctpsock_posix.go`
- `src/net/sctpsock_linux.go`
- `src/net/dial.go`
- `src/net/ipsock.go`
