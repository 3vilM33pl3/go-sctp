// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"internal/strconv"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SCTPAddr represents the address of an SCTP end point.
type SCTPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

// isSCTPNetwork reports whether network names one of the SCTP networks.
func isSCTPNetwork(network string) bool {
	switch network {
	case "sctp", "sctp4", "sctp6":
		return true
	}
	return false
}

// isIPv4 reports whether a binds as an IPv4 socket. A nil or wildcard
// address counts as IPv4, matching (*TCPAddr).family; it is kept free of
// syscall constants so untagged code can compare address families on
// every GOOS.
func (a *SCTPAddr) isIPv4() bool {
	return a == nil || len(a.IP) <= IPv4len || a.IP.To4() != nil
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

// SCTPInitOptions carries the association parameters proposed in the INIT
// chunk (struct sctp_initmsg). A zero field keeps the kernel's default.
type SCTPInitOptions struct {
	NumOStreams    uint16 // outbound streams to request
	MaxInStreams   uint16 // inbound streams to accept
	MaxAttempts    uint16 // INIT retransmissions before the attempt fails
	MaxInitTimeout uint16 // upper bound on the INIT retransmission timer, in milliseconds
}

// SCTPSndInfo is the per-message send metadata (struct sctp_sndinfo).
type SCTPSndInfo struct {
	Stream  uint16 // outbound stream number
	Flags   uint16 // SCTPUnordered and the kernel's other SCTP_* send flags
	PPID    uint32 // payload protocol identifier, carried opaquely to the receiver
	Context uint32 // opaque value returned in send-failure notifications
	AssocID int32  // association, on a one-to-many socket; 0 is the socket's single or default association
}

// SCTPRcvInfo is the per-message receive metadata (struct sctp_rcvinfo),
// returned by [SCTPConn.ReadFromSCTP] when SCTP_RECVRCVINFO is enabled.
type SCTPRcvInfo struct {
	Stream  uint16       // inbound stream number
	SSN     uint16       // stream sequence number
	Flags   uint16       // SCTPUnordered if the message was delivered unordered
	PPID    uint32       // payload protocol identifier, as the sender set it
	TSN     uint32       // transmission sequence number of the first chunk
	CumTSN  uint32       // cumulative TSN acknowledged when the message was delivered
	Context uint32       // the association's SCTP_CONTEXT value
	AssocID int32        // association the message arrived on
	Next    *SCTPNxtInfo // the next queued message, when SetRecvNxtInfo is enabled
}

// SCTPNxtInfo describes the message queued after the one just read (struct
// sctp_nxtinfo), when SCTP_RECVNXTINFO is enabled.
type SCTPNxtInfo struct {
	Stream  uint16 // inbound stream number
	Flags   uint16 // SCTPUnordered and the kernel's SCTP_NEXT_* flags
	PPID    uint32 // payload protocol identifier
	Length  uint32 // length of the next message, or of the part received so far
	AssocID int32  // association the next message belongs to
}

// SCTPRTOInfo bounds the retransmission timeout (struct sctp_rtoinfo).
// Values are in milliseconds; 0 leaves a bound unchanged.
type SCTPRTOInfo struct {
	AssocID int32  // association, or 0 for the socket default
	Initial uint32 // RTO used before any round-trip measurement
	Max     uint32
	Min     uint32
}

// SCTPDelayedSackInfo configures delayed acknowledgements (struct
// sctp_sack_info).
type SCTPDelayedSackInfo struct {
	AssocID   int32  // association, or 0 for the socket default
	Delay     uint32 // SACK delay in milliseconds; 0 leaves it unchanged
	Frequency uint32 // packets received before a SACK is sent regardless of the delay; 1 disables delaying
}

// SCTPPRPolicy identifies the partial reliability policy used for SCTP_PR-SCTP.
type SCTPPRPolicy uint16

// SCTPPRInfo sets the default partial-reliability policy (struct
// sctp_default_prinfo) applied to messages sent without one.
type SCTPPRInfo struct {
	AssocID int32        // association, or 0 for the socket default
	Value   uint32       // lifetime in milliseconds for SCTPPRTTL, retransmission limit for SCTPPRRTX, priority for SCTPPRPriority
	Policy  SCTPPRPolicy // SCTPPRNone disables partial reliability
}

// SCTPAuthKey installs a shared key for SCTP AUTH (struct sctp_authkey).
// The key is installed with [SCTPConn.SetAuthKey] and selected with
// [SCTPConn.ActivateAuthKey].
type SCTPAuthKey struct {
	AssocID int32  // association, or 0 for the endpoint
	KeyID   uint16 // key identifier exchanged with the peer
	Secret  []byte // the key material
}

// SCTPScheduler identifies an SCTP stream scheduler policy.
type SCTPScheduler uint16

// SCTPAssocStatus is a snapshot of an association (SCTP_STATUS, struct
// sctp_status) taken by [SCTPConn.AssocStatus].
type SCTPAssocStatus struct {
	AssocID            int32
	State              int32    // the kernel's association state value (established, shutdown pending, ...); the numbering is platform-specific
	RWND               uint32   // the peer's current receiver window, in bytes
	UnackedData        uint16   // DATA chunks sent but not yet acknowledged
	PendingData        uint16   // DATA chunks queued for sending
	InStreams          uint16   // inbound streams negotiated
	OutStreams         uint16   // outbound streams negotiated
	FragmentationPoint uint32   // largest user-message fragment, in bytes
	PrimaryAddr        SCTPAddr // the primary path's peer address; zero until a primary path exists
	PrimaryState       int32    // the kernel's peer-address state value (active, inactive, unconfirmed)
	PrimaryCWND        uint32   // primary path congestion window, in bytes
	PrimarySRTT        uint32   // primary path smoothed round-trip time, in milliseconds
	PrimaryRTO         uint32   // primary path retransmission timeout, in milliseconds
	PrimaryMTU         uint32   // primary path MTU, in bytes
}

const (
	// SCTPUnordered requests unordered SCTP delivery for a sent message.
	SCTPUnordered = 1 << 0

	// SCTPPRNone disables partial reliability.
	SCTPPRNone SCTPPRPolicy = 0x0000

	// SCTPPRTTL enables time-based partial reliability.
	SCTPPRTTL SCTPPRPolicy = 0x0010

	// SCTPPRRTX enables retransmission-limited partial reliability.
	SCTPPRRTX SCTPPRPolicy = 0x0020

	// SCTPPRPriority enables priority-based partial reliability.
	SCTPPRPriority SCTPPRPolicy = 0x0030

	// SCTPSchedulerFCFS selects first-come, first-served stream scheduling.
	SCTPSchedulerFCFS SCTPScheduler = 0

	// SCTPSchedulerPriority selects priority-based stream scheduling.
	SCTPSchedulerPriority SCTPScheduler = 1

	// SCTPSchedulerRR selects round-robin stream scheduling.
	SCTPSchedulerRR SCTPScheduler = 2

	// SCTPSchedulerFC selects fair-capacity stream scheduling.
	SCTPSchedulerFC SCTPScheduler = 3

	// SCTPSchedulerWFQ selects weighted-fair-queueing stream scheduling.
	SCTPSchedulerWFQ SCTPScheduler = 4

	// SCTPStreamResetIncoming enables or requests incoming stream reset support.
	SCTPStreamResetIncoming = 0x01

	// SCTPStreamResetOutgoing enables or requests outgoing stream reset support.
	SCTPStreamResetOutgoing = 0x02
	// SCTPStreamResetDenied, in an [SCTPStreamReset] notification, reports that
	// the peer refused the reset.
	SCTPStreamResetDenied = 0x04
	// SCTPStreamResetFailed, in an [SCTPStreamReset] notification, reports that
	// the reset could not be performed.
	SCTPStreamResetFailed = 0x08
)

// SCTPEventMask configures SCTP event subscriptions via SCTP_EVENT.
type SCTPEventMask struct {
	// DataIO requests per-message SCTPRcvInfo ancillary data (SCTP_RECVRCVINFO)
	// on both kernels; the deprecated sctp_sndrcvinfo event is never enabled.
	DataIO bool

	Association     bool // SCTP_ASSOC_CHANGE
	Address         bool // SCTP_PEER_ADDR_CHANGE
	SendFailure     bool // SCTP_SEND_FAILED_EVENT (RFC 6458 form, carries an SCTPSndInfo)
	PeerError       bool // SCTP_REMOTE_ERROR
	Shutdown        bool // SCTP_SHUTDOWN_EVENT
	PartialDelivery bool // SCTP_PARTIAL_DELIVERY_EVENT
	Adaptation      bool // SCTP_ADAPTATION_INDICATION
	Authentication  bool // SCTP_AUTHENTICATION_EVENT
	SenderDry       bool // SCTP_SENDER_DRY_EVENT
	StreamReset     bool // SCTP_STREAM_RESET_EVENT
	AssocReset      bool // SCTP_ASSOC_RESET_EVENT
	StreamChange    bool // SCTP_STREAM_CHANGE_EVENT
}

// SCTPConn is an implementation of the [Conn] and [PacketConn] interfaces
// for SCTP network connections.
type SCTPConn struct {
	conn

	// assocID caches the association id learned from the kernel (a
	// received SCTPRcvInfo, connectx, or a peel-off). Option methods read
	// it while ReadFromSCTP may be writing it, hence atomic.
	assocID atomic.Int32

	// addrMu guards the multihoming bookkeeping below, which BindAddrs,
	// UnbindAddrs, LocalAddrs and PeerAddrs update from any goroutine.
	addrMu     sync.Mutex
	multiLocal []SCTPAddr
	multiPeer  []SCTPAddr
}

func (c *SCTPConn) setLocalAddrs(addrs []SCTPAddr) {
	c.addrMu.Lock()
	c.multiLocal = addrs
	c.addrMu.Unlock()
}

func (c *SCTPConn) setPeerAddrs(addrs []SCTPAddr) {
	c.addrMu.Lock()
	c.multiPeer = addrs
	c.addrMu.Unlock()
}

// localAddrsSnapshot returns a copy of the recorded local addresses.
func (c *SCTPConn) localAddrsSnapshot() []SCTPAddr {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	return copySCTPAddrs(c.multiLocal)
}

// peerAddrsSnapshot returns a copy of the recorded peer addresses.
func (c *SCTPConn) peerAddrsSnapshot() []SCTPAddr {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	return copySCTPAddrs(c.multiPeer)
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

// sctpUnsupportedError is returned by every SCTP operation on a platform
// without an SCTP backend. It matches [errors.ErrUnsupported].
type sctpUnsupportedError struct{}

func (sctpUnsupportedError) Error() string        { return "sctp is not supported on this platform" }
func (sctpUnsupportedError) Is(target error) bool { return target == errors.ErrUnsupported }

var errSCTPUnsupported error = sctpUnsupportedError{}

// errSCTPControlTruncated reports that the kernel had more ancillary data
// than the receive buffer could hold (MSG_CTRUNC), so no metadata is trusted.
var errSCTPControlTruncated = errors.New("truncated SCTP control message")

// ReadFromSCTP reads one SCTP message into b. It returns the payload length,
// the length of the ancillary data received, the recvmsg flags word, the
// sender's address and, when SCTP_RECVRCVINFO is enabled (see
// [SCTPEventMask.DataIO] and [SCTPConn.SetRecvRcvInfo]), the message's
// [SCTPRcvInfo]; info is nil otherwise.
//
// flags is the platform's recvmsg flags word. Compare it with syscall.MSG_EOR
// to detect the end of a partially delivered message and with
// [SCTPMsgNotification] to detect notifications, which decode with
// [ParseSCTPNotification]. When the peer has shut down the association, err
// is [io.EOF].
//
// If a message arrived but its control data could not be decoded, n and
// flags still describe the payload and err reports the problem.
func (c *SCTPConn) ReadFromSCTP(b []byte) (n int, oobn int, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, info, err = c.readFromSCTP(b)
	if info != nil && info.AssocID != 0 {
		c.assocID.CompareAndSwap(0, info.AssocID)
	}
	if err != nil && err != io.EOF {
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

// SetInitOptions sets SCTP_INITMSG, the stream counts and INIT retry limits
// proposed for associations the socket opens or accepts from now on. It also
// enables SCTP_RECVRCVINFO, so that [SCTPConn.ReadFromSCTP] returns an
// [SCTPRcvInfo] for every message; use [SCTPConn.SetRecvRcvInfo] to turn that
// off again.
func (c *SCTPConn) SetInitOptions(opts SCTPInitOptions) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPInitOptions(c.fd, opts); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SubscribeEvents selects which SCTP notifications the socket delivers.
// Notifications arrive through [SCTPConn.ReadFromSCTP] with the platform's
// MSG_NOTIFICATION flag set. Every field is applied, so a false field
// unsubscribes an event enabled by an earlier call.
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

// SetDelayedSack controls SCTP_DELAYED_SACK on the socket or association.
func (c *SCTPConn) SetDelayedSack(info SCTPDelayedSackInfo) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPDelayedSack(c, info); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetDefaultPRInfo controls SCTP_DEFAULT_PRINFO on the socket or association.
func (c *SCTPConn) SetDefaultPRInfo(info SCTPPRInfo) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPDefaultPRInfo(c, info); err != nil {
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

// SetAuthChunks controls SCTP_AUTH_CHUNK on the socket.
func (c *SCTPConn) SetAuthChunks(chunks []uint8) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPAuthChunks(c.fd, chunks); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetAuthKey configures an SCTP AUTH shared key on the socket or association.
func (c *SCTPConn) SetAuthKey(key SCTPAuthKey) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPAuthKey(c, key); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// ActivateAuthKey controls SCTP_AUTH_ACTIVE_KEY on the socket or association.
func (c *SCTPConn) ActivateAuthKey(assocID int32, keyID uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPActiveAuthKey(c, assocID, keyID); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// DeleteAuthKey removes an SCTP AUTH shared key from the socket or association.
func (c *SCTPConn) DeleteAuthKey(assocID int32, keyID uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := deleteSCTPAuthKey(c, assocID, keyID); err != nil {
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

// SetFragmentInterleave controls SCTP_FRAGMENT_INTERLEAVE on the socket.
func (c *SCTPConn) SetFragmentInterleave(level int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPFragmentInterleave(c.fd, level); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetMaxBurst controls SCTP_MAX_BURST on the socket or association.
func (c *SCTPConn) SetMaxBurst(value uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPMaxBurst(c, value); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetMaxSeg controls SCTP_MAXSEG on the socket.
func (c *SCTPConn) SetMaxSeg(value uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPMaxSeg(c.fd, value); err != nil {
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
	c.addrMu.Lock()
	c.multiLocal = mergeUniqueSCTPAddrs(c.multiLocal, addrs)
	c.addrMu.Unlock()
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
	c.addrMu.Lock()
	c.multiLocal = subtractSCTPAddrs(c.multiLocal, addrs)
	c.addrMu.Unlock()
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

// SetStreamScheduler controls SCTP_STREAM_SCHEDULER on the current association.
func (c *SCTPConn) SetStreamScheduler(policy SCTPScheduler) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPStreamScheduler(c, policy); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetStreamSchedulerValue controls SCTP_STREAM_SCHEDULER_VALUE for one stream.
func (c *SCTPConn) SetStreamSchedulerValue(stream uint16, value uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setSCTPStreamSchedulerValue(c, stream, value); err != nil {
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

// DialSCTPInit acts like [DialSCTP] but applies opts (see
// [SCTPConn.SetInitOptions], including its effect on SCTP_RECVRCVINFO) before
// the association is initiated, so the INIT chunk carries them.
func DialSCTPInit(network string, laddr, raddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, error) {
	return dialSCTPInit(context.Background(), nil, network, laddr, raddr, opts)
}

func dialSCTPInit(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, error) {
	d := &Dialer{}
	if dialer != nil {
		*d = *dialer
	}
	if c, handled, err := dialSCTPInitPlatform(ctx, d, network, laddr, raddr, opts); handled {
		return c, err
	}
	prevCtx := d.ControlContext
	prev := d.Control
	d.Control = nil
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if prevCtx != nil {
			if err := prevCtx(ctx, network, address, c); err != nil {
				return err
			}
		} else if prev != nil {
			if err := prev(network, address, c); err != nil {
				return err
			}
		}
		var innerErr error
		if err := c.Control(func(fd uintptr) {
			innerErr = setSCTPInitOptionsSockFD(int(fd), opts)
		}); err != nil {
			return err
		}
		return innerErr
	}
	return dialSCTP(ctx, d, network, laddr, raddr)
}

func dialSCTP(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
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
	c.setPeerAddrs([]SCTPAddr{*raddr})
	if la, ok := c.LocalAddr().(*SCTPAddr); ok && la != nil {
		c.setLocalAddrs([]SCTPAddr{*la})
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
	c, err := sd.openSCTP(ctx, laddr, raddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// ListenSCTP acts like [ListenPacket] for SCTP networks: it returns a
// one-to-many style socket on which every incoming association is
// multiplexed and messages carry the peer's address. For one-to-one style
// listening, where each association becomes its own connection, use
// [ListenSCTPOneToOne] or [Listen].
func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error) {
	return listenSCTP(context.Background(), ListenConfig{}, network, laddr)
}

// OpenSCTP opens an unconnected one-to-many SCTP socket bound to laddr.
func OpenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error) {
	return openSCTP(context.Background(), ListenConfig{}, network, laddr)
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
		c.setLocalAddrs([]SCTPAddr{*la})
	}
	return c, nil
}

func openSCTP(ctx context.Context, lc ListenConfig, network string, laddr *SCTPAddr) (*SCTPConn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "open", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		laddr = &SCTPAddr{}
	}
	sl := &sysListener{ListenConfig: lc, network: network, address: laddr.String()}
	c, err := sl.openSCTP(ctx, laddr)
	if err != nil {
		return nil, &OpError{Op: "open", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	if la, ok := c.LocalAddr().(*SCTPAddr); ok && la != nil {
		c.setLocalAddrs([]SCTPAddr{*la})
	}
	return c, nil
}

// ListenSCTPInit acts like [ListenSCTP] and applies opts to the socket
// before it accepts associations; see [SCTPConn.SetInitOptions].
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

// SCTPListener is a one-to-one style SCTP listener: each accepted
// association becomes its own [SCTPConn], the way a [TCPListener] hands out
// [TCPConn]s. [Listen] and [ListenConfig.Listen] return one for the SCTP
// networks. For the one-to-many style, where a single socket carries every
// association, use [ListenSCTP].
type SCTPListener struct {
	fd *netFD
	lc ListenConfig
}

func (l *SCTPListener) ok() bool { return l != nil && l.fd != nil }

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
//
// The returned RawConn only supports calling Control. Read and
// Write return an error.
func (l *SCTPListener) SyscallConn() (syscall.RawConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	return newRawListener(l.fd), nil
}

// AcceptSCTP accepts the next incoming association and returns the new
// connection.
func (l *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next association and returns a generic [Conn].
func (l *SCTPListener) Accept() (Conn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Close stops listening on the SCTP address.
// Already accepted connections are not closed.
func (l *SCTPListener) Close() error {
	if !l.ok() {
		return syscall.EINVAL
	}
	if err := l.close(); err != nil {
		return &OpError{Op: "close", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return nil
}

// Addr returns the listener's network address, a [*SCTPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *SCTPListener) Addr() Addr { return l.fd.laddr }

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (l *SCTPListener) SetDeadline(t time.Time) error {
	if !l.ok() {
		return syscall.EINVAL
	}
	return l.fd.SetDeadline(t)
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing l does not affect f, and closing f does not affect l.
//
// The returned os.File's file descriptor is different from the
// connection's. Attempting to change properties of the original
// using this duplicate may or may not have the desired effect.
func (l *SCTPListener) File() (f *os.File, err error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	f, err = l.file()
	if err != nil {
		return nil, &OpError{Op: "file", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return
}

// ListenSCTPOneToOne acts like [Listen] for SCTP networks: it returns a
// one-to-one style listener whose accepted connections are [SCTPConn]s.
//
// The network must be an SCTP network name; see func [Dial] for details.
// If the IP field of laddr is nil or an unspecified IP address,
// ListenSCTPOneToOne listens on all available unicast and anycast IP
// addresses of the local system. If the Port field of laddr is 0, a port
// number is automatically chosen.
func ListenSCTPOneToOne(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		laddr = &SCTPAddr{}
	}
	sl := &sysListener{network: network, address: laddr.String()}
	ln, err := sl.listenSCTPOneToOne(context.Background(), laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return ln, nil
}
