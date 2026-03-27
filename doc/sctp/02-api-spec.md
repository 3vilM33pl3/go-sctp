# SCTP API Specification (Current Implementation)

## New Public Types

- `type SCTPAddr struct { IP net.IP; Port int; Zone string }`
- `type SCTPConn struct`
- `type SCTPInitOptions struct`
- `type SCTPSndInfo struct`
- `type SCTPRcvInfo struct`
- `type SCTPNxtInfo struct`
- `type SCTPRTOInfo struct`
- `type SCTPAssocStatus struct`
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
- `SetRTOInfo(SCTPRTOInfo) error`
- `SetDefaultSendInfo(SCTPSndInfo) error`
- `SetRecvRcvInfo(bool) error`
- `SetRecvNxtInfo(bool) error`
- `SetAutoClose(uint32) error`
- `SubscribeEvents(SCTPEventMask) error`
- `BindAddrs([]SCTPAddr) error`
- `UnbindAddrs([]SCTPAddr) error`
- `SetPrimaryAddr(*SCTPAddr) error`
- `SetPeerPrimaryAddr(*SCTPAddr) error`
- `PeelOff(assocID int32) (*SCTPConn, error)`
- `AssocIDs() ([]int32, error)`
- `AssocStatus(assocID int32) (*SCTPAssocStatus, error)`
- `EnableStreamReset(flags uint16) error`
- `ResetStreams(flags uint16, streams []uint16) error`
- `AddStreams(in, out uint16) error`

## Dispatch Integration

- `net.Dial`/`DialContext` now accept: `sctp`, `sctp4`, `sctp6`
- `net.ListenPacket`/`ListenConfig.ListenPacket` now accept: `sctp`, `sctp4`, `sctp6`

## Compatibility Notes

- Linux is the only fully supported platform in v1.
- Non-Linux builds compile via stubs and return unsupported errors at runtime.
- `SCTPRcvInfo.Next` is populated when `SetRecvNxtInfo(true)` is enabled and
  the kernel supplies `SCTP_NXTINFO` ancillary data.
- Dialed SCTP sockets use Linux `connectx` internally so association-level APIs
  such as `AssocIDs`, `AssocStatus`, peeloff, primary-address management, and
  stream reconfiguration can target a live association.
