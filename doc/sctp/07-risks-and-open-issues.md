# Risks and Open Issues

## Known Risks

- `SCTP_RCVINFO` availability depends on kernel/socket option support.
- Notifications may interleave with payload reads and must be filtered by callers.
- `DialSCTP` one-to-many model differs from TCP-like connected semantics.

## Deferred Scope

- One-to-one (`SOCK_STREAM`) SCTP mode
- Multihoming failover automation tests
- Wider event typing and rich notification decoding API
- Upstreaming strategy against official `golang/go`

## Next Milestones

1. Add one-to-one SCTP path behind explicit API.
2. Add deterministic multihoming/failover integration tests.
3. Expand notification/event decoding into typed Go structs.
