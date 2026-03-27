// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"internal/strconv"
	"net/netip"
	"syscall"
)

// SCTPAddr represents the address of an SCTP end point.
type SCTPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

// AddrPort returns the [SCTPAddr] a as a [netip.AddrPort].
//
// If a.Port does not fit in a uint16, it's silently truncated.
//
// If a is nil, a zero value is returned.
func (a *SCTPAddr) AddrPort() netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	na, _ := netip.AddrFromSlice(a.IP)
	na = na.WithZone(a.Zone)
	return netip.AddrPortFrom(na, uint16(a.Port))
}

// Network returns the address's network name, "sctp".
func (a *SCTPAddr) Network() string { return "sctp" }

func (a *SCTPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return JoinHostPort(ip+"%"+a.Zone, strconv.Itoa(a.Port))
	}
	return JoinHostPort(ip, strconv.Itoa(a.Port))
}

func (a *SCTPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}

func (a *SCTPAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

// ResolveSCTPAddr returns an address of SCTP end point.
//
// The network must be an SCTP network name.
//
// If the host in the address parameter is not a literal IP address or
// the port is not a literal port number, ResolveSCTPAddr resolves the
// address to an address of SCTP end point.
func ResolveSCTPAddr(network, address string) (*SCTPAddr, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	case "": // a hint wildcard for Go 1.0 undocumented behavior
		network = "sctp"
	default:
		return nil, UnknownNetworkError(network)
	}
	addrs, err := DefaultResolver.internetAddrList(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return addrs.forResolve(network, address).(*SCTPAddr), nil
}

// SCTPAddrFromAddrPort returns addr as a [SCTPAddr]. If addr.IsValid() is false,
// then the returned SCTPAddr will contain a nil IP field, indicating an
// address family-agnostic unspecified address.
func SCTPAddrFromAddrPort(addr netip.AddrPort) *SCTPAddr {
	return &SCTPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}

// SCTPInitOptions configures SCTP association setup parameters.
type SCTPInitOptions struct {
	NumOStreams    uint16
	MaxInStreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

// SCTPSndInfo controls per-message SCTP metadata for sends.
type SCTPSndInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

// SCTPRcvInfo exposes SCTP metadata returned by recvmsg ancillary data.
type SCTPRcvInfo struct {
	Stream  uint16
	SSN     uint16
	Flags   uint16
	PPID    uint32
	TSN     uint32
	CumTSN  uint32
	Context uint32
	AssocID int32
	Next    *SCTPNxtInfo
}

// SCTPNxtInfo exposes SCTP next-message metadata returned by recvmsg ancillary
// data when SCTP_RECVNXTINFO is enabled.
type SCTPNxtInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Length  uint32
	AssocID int32
}

// SCTPRTOInfo configures SCTP association retransmission timeout parameters.
type SCTPRTOInfo struct {
	AssocID int32
	Initial uint32
	Max     uint32
	Min     uint32
}

// SCTPAssocStatus exposes the current status of an SCTP association.
type SCTPAssocStatus struct {
	AssocID            int32
	State              int32
	RWND               uint32
	UnackedData        uint16
	PendingData        uint16
	InStreams          uint16
	OutStreams         uint16
	FragmentationPoint uint32
	PrimaryAddr        SCTPAddr
	PrimaryState       int32
	PrimaryCWND        uint32
	PrimarySRTT        uint32
	PrimaryRTO         uint32
	PrimaryMTU         uint32
}

const (
	// SCTPUnordered requests unordered SCTP delivery for a sent message.
	SCTPUnordered = 1 << 0

	// SCTPStreamResetIncoming enables or requests incoming stream reset support.
	SCTPStreamResetIncoming = 0x01

	// SCTPStreamResetOutgoing enables or requests outgoing stream reset support.
	SCTPStreamResetOutgoing = 0x02
)

// SCTPEventMask configures SCTP event subscriptions via SCTP_EVENT.
type SCTPEventMask struct {
	DataIO          bool
	Association     bool
	Address         bool
	SendFailure     bool
	PeerError       bool
	Shutdown        bool
	PartialDelivery bool
	Adaptation      bool
	Authentication  bool
	SenderDry       bool
	StreamReset     bool
}

// SCTPConn is an implementation of the [Conn] and [PacketConn] interfaces
// for SCTP network connections.
type SCTPConn struct {
	conn
	multiLocal []SCTPAddr
	multiPeer  []SCTPAddr
	assocID    int32
}

func newSCTPConn(fd *netFD) *SCTPConn { return &SCTPConn{conn: conn{fd}} }

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return newRawConn(c.fd), nil
}

// ReadFrom implements the [PacketConn] ReadFrom method.
func (c *SCTPConn) ReadFrom(b []byte) (n int, addr Addr, err error) {
	n, _, _, saddr, _, err := c.ReadFromSCTP(b)
	if saddr == nil {
		return n, nil, err
	}
	return n, saddr, err
}

// ReadFromSCTP reads an SCTP message and returns SCTP metadata when available.
func (c *SCTPConn) ReadFromSCTP(b []byte) (n int, oobn int, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, info, err = c.readFromSCTP(b)
	if info != nil && info.AssocID != 0 && c.assocID == 0 {
		c.assocID = info.AssocID
	}
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}

// WriteTo implements the [PacketConn] WriteTo method.
func (c *SCTPConn) WriteTo(b []byte, addr Addr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	a, ok := addr.(*SCTPAddr)
	if !ok {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr, Err: syscall.EINVAL}
	}
	n, err := c.writeToSCTP(b, a, nil)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: a.opAddr(), Err: err}
	}
	return n, err
}

// WriteToSCTP writes an SCTP message using optional per-message SCTP metadata.
func (c *SCTPConn) WriteToSCTP(b []byte, addr *SCTPAddr, info *SCTPSndInfo) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeToSCTP(b, addr, info)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return n, err
}

// SetNoDelay controls SCTP_NODELAY.
func (c *SCTPConn) SetNoDelay(noDelay bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setNoDelaySCTP(c.fd, noDelay); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetInitOptions controls SCTP_INITMSG on the socket.
func (c *SCTPConn) SetInitOptions(opts SCTPInitOptions) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPInitOptions(c.fd, opts); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SubscribeEvents configures SCTP event subscriptions.
func (c *SCTPConn) SubscribeEvents(mask SCTPEventMask) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := subscribeSCTPEvents(c.fd, mask); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetRTOInfo controls SCTP_RTOINFO on the socket or association.
func (c *SCTPConn) SetRTOInfo(info SCTPRTOInfo) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPRTOInfo(c, info); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetDefaultSendInfo controls SCTP_DEFAULT_SNDINFO on the socket.
func (c *SCTPConn) SetDefaultSendInfo(info SCTPSndInfo) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPDefaultSendInfo(c, info); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetRecvRcvInfo controls SCTP_RECVRCVINFO on the socket.
func (c *SCTPConn) SetRecvRcvInfo(on bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPRecvRcvInfo(c.fd, on); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetRecvNxtInfo controls SCTP_RECVNXTINFO on the socket.
func (c *SCTPConn) SetRecvNxtInfo(on bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPRecvNxtInfo(c.fd, on); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetAutoClose controls SCTP_AUTOCLOSE on the socket.
func (c *SCTPConn) SetAutoClose(seconds uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPAutoClose(c.fd, seconds); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// BindAddrs adds local SCTP bind addresses on the socket.
func (c *SCTPConn) BindAddrs(addrs []SCTPAddr) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	addrs = c.normalizeLocalAddrs(addrs)
	if err := bindAddrsSCTP(c.fd, addrs); err != nil {
		return &OpError{Op: "bind", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	c.multiLocal = mergeUniqueSCTPAddrs(c.multiLocal, addrs)
	return nil
}

// UnbindAddrs removes local SCTP bind addresses from the socket.
func (c *SCTPConn) UnbindAddrs(addrs []SCTPAddr) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	addrs = c.normalizeLocalAddrs(addrs)
	if err := unbindAddrsSCTP(c.fd, addrs); err != nil {
		return &OpError{Op: "bind", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	c.multiLocal = subtractSCTPAddrs(c.multiLocal, addrs)
	return nil
}

// SetPrimaryAddr requests that the local SCTP stack use addr as the primary
// peer destination for the current association.
func (c *SCTPConn) SetPrimaryAddr(addr *SCTPAddr) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPPrimaryAddr(c, addr); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return nil
}

// SetPeerPrimaryAddr requests that the peer use addr as its primary destination
// for the current association.
func (c *SCTPConn) SetPeerPrimaryAddr(addr *SCTPAddr) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPPeerPrimaryAddr(c, addr); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return nil
}

// PeelOff peels an SCTP association onto a dedicated socket.
func (c *SCTPConn) PeelOff(assocID int32) (*SCTPConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	conn, err := peelOffSCTP(c, assocID)
	if err != nil {
		return nil, &OpError{Op: "peeloff", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return conn, nil
}

// AssocIDs returns the current SCTP association ids present on the socket.
func (c *SCTPConn) AssocIDs() ([]int32, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	ids, err := assocIDsSCTP(c.fd)
	if err != nil {
		return nil, &OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return ids, nil
}

// AssocStatus returns status information for an SCTP association.
func (c *SCTPConn) AssocStatus(assocID int32) (*SCTPAssocStatus, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	status, err := assocStatusSCTP(c, assocID)
	if err != nil {
		return nil, &OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return status, nil
}

// EnableStreamReset enables SCTP stream reconfiguration support on the socket.
func (c *SCTPConn) EnableStreamReset(flags uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := enableSCTPStreamReset(c, flags); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// ResetStreams requests SCTP stream reset on the current association.
func (c *SCTPConn) ResetStreams(flags uint16, streams []uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := resetSCTPStreams(c, flags, streams); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// AddStreams requests additional SCTP inbound or outbound streams.
func (c *SCTPConn) AddStreams(in, out uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := addSCTPStreams(c, in, out); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

func (c *SCTPConn) normalizeLocalAddrs(addrs []SCTPAddr) []SCTPAddr {
	if len(addrs) == 0 {
		return nil
	}
	out := copySCTPAddrs(addrs)
	la, _ := c.LocalAddr().(*SCTPAddr)
	if la == nil || la.Port == 0 {
		return out
	}
	for i := range out {
		if out[i].Port == 0 {
			out[i].Port = la.Port
		}
	}
	return out
}

// DialSCTP acts like [Dial] for SCTP networks.
func DialSCTP(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return dialSCTP(context.Background(), nil, network, laddr, raddr)
}

func dialSCTP(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	c, err := openDialSCTP(ctx, dialer, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	if assocID, err := connectAddrsSCTP(c.fd, []SCTPAddr{*raddr}); err != nil {
		c.Close()
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	} else if assocID != 0 {
		c.assocID = assocID
	}
	c.multiPeer = []SCTPAddr{*raddr}
	if la, ok := c.LocalAddr().(*SCTPAddr); ok && la != nil {
		c.multiLocal = []SCTPAddr{*la}
	}
	return c, nil
}

func openDialSCTP(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if raddr == nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: nil, Err: errMissingAddress}
	}
	sd := &sysDialer{network: network, address: raddr.String()}
	if dialer != nil {
		sd.Dialer = *dialer
	}
	c, err := sd.dialSCTP(ctx, laddr, raddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// ListenSCTP acts like [ListenPacket] for SCTP networks.
func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error) {
	return listenSCTP(context.Background(), ListenConfig{}, network, laddr)
}

func listenSCTP(ctx context.Context, lc ListenConfig, network string, laddr *SCTPAddr) (*SCTPConn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		laddr = &SCTPAddr{}
	}
	sl := &sysListener{ListenConfig: lc, network: network, address: laddr.String()}
	c, err := sl.listenSCTP(ctx, laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	if la, ok := c.LocalAddr().(*SCTPAddr); ok && la != nil {
		c.multiLocal = []SCTPAddr{*la}
	}
	return c, nil
}

// ListenSCTPInit acts like [ListenSCTP] and configures SCTP_INITMSG on the socket.
func ListenSCTPInit(network string, laddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, error) {
	c, err := listenSCTP(context.Background(), ListenConfig{}, network, laddr)
	if err != nil {
		return nil, err
	}
	if err := c.SetInitOptions(opts); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
