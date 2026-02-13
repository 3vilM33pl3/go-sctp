# SCTP API Specification (Current Implementation)

## New Public Types

- `type SCTPAddr struct { IP net.IP; Port int; Zone string }`
- `type SCTPConn struct`
- `type SCTPInitOptions struct`
- `type SCTPSndInfo struct`
- `type SCTPRcvInfo struct`
- `type SCTPEventMask struct`

## New Public Functions

- `ResolveSCTPAddr(network, address string) (*SCTPAddr, error)`
- `DialSCTP(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error)`
- `ListenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error)`
- `ListenSCTPInit(network string, laddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, error)`
- `SCTPAddrFromAddrPort(addr netip.AddrPort) *SCTPAddr`

## New SCTPConn Methods

- `ReadFromSCTP(b []byte) (n, oobn, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error)`
- `WriteToSCTP(b []byte, addr *SCTPAddr, info *SCTPSndInfo) (int, error)`
- `SetNoDelay(bool) error`
- `SetInitOptions(SCTPInitOptions) error`
- `SubscribeEvents(SCTPEventMask) error`

## Dispatch Integration

- `net.Dial`/`DialContext` now accept: `sctp`, `sctp4`, `sctp6`
- `net.ListenPacket`/`ListenConfig.ListenPacket` now accept: `sctp`, `sctp4`, `sctp6`

## Compatibility Notes

- Linux is the only fully supported platform in v1.
- Non-Linux builds compile via stubs and return unsupported errors at runtime.
