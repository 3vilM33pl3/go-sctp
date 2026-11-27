// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package net

import (
	"context"
	"errors"
	"internal/byteorder"
	"internal/goarch"
	"internal/sctp"
	"io"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// SCTP over UDP (RFC 6951). An sctpUDPConn owns one UDP socket and a
// user-space SCTP endpoint from internal/sctp. One goroutine reads the
// socket and one timer drives the engine's retransmission timers; every
// engine call happens under mu.

// sctpUDPLinger bounds how long a closed connection keeps running to
// finish graceful shutdowns before it aborts what is left.
const sctpUDPLinger = 10 * time.Second

// Flags reported by ReadFromSCTP, with the kernel's values.
var (
	sctpUDPMsgNotification = func() int {
		if runtime.GOOS == "freebsd" {
			return 0x2000
		}
		return 0x8000
	}()
	sctpUDPMsgEOR = syscall.MSG_EOR
)

// Send flags in SCTPSndInfo.Flags, with the kernel's values.
var sctpUDPFlagEOF, sctpUDPFlagAbort = func() (uint16, uint16) {
	if runtime.GOOS == "freebsd" {
		return 0x0100, 0x0200
	}
	return 0x0200, 0x0004 // MSG_FIN, SCTP_ABORT
}()

// Notification types (Linux numbering; FreeBSD uses the low bits).
func sctpNotifType(t uint16) uint16 {
	if runtime.GOOS == "freebsd" {
		return t
	}
	return 1<<15 | t
}

const (
	sctpNotifAssocChange  = 1
	sctpNotifShutdown     = 5
	sctpNotifSenderDry    = 9
	sctpNotifStreamReset  = 10
	sctpNotifStreamChange = 12

	sctpCommUp       = 0
	sctpCommLost     = 1
	sctpRestart      = 2
	sctpShutdownComp = 3
	sctpCantStrAssoc = 4

	sctpStreamResetIncoming = 0x0001
	sctpStreamResetOutgoing = 0x0002
	sctpStreamResetDenied   = 0x0004
)

type sctpUDPConn struct {
	net       string
	laddr     *SCTPAddr
	raddr     *SCTPAddr // dialed peer, or the default destination
	connected bool      // one-to-one connection from a dial
	encap     SCTPUDPConfig
	pc        *UDPConn
	done      chan struct{} // closed when the reader exits

	mu         sync.Mutex
	ep         *sctp.Endpoint
	assoc      *sctp.Association // the dialed association
	assocEnd   error             // why the dialed association ended
	notify     chan struct{}
	timer      *time.Timer
	closed     bool // closed by the user
	sockClosed bool
	rdl, wdl   time.Time
	notifs     [][]byte
	partial    []byte // rest of a message larger than the last read
	partialMsg sctp.Message
	mask       SCTPEventMask
	recvRcv    bool
	recvNxt    bool
	defSend    SCTPSndInfo
	defPR      SCTPPRInfo
	up         bool // the dialed association was established
}

func sctpUDPNetwork(network string, ip IP) string {
	switch network {
	case "sctp4":
		return "udp4"
	case "sctp6":
		return "udp6"
	}
	if ip != nil && !ip.IsUnspecified() {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return "udp"
}

func newSCTPUDPConn(ctx context.Context, network string, laddr *SCTPAddr, peerIP IP, cfg SCTPUDPConfig, accept bool) (*sctpUDPConn, error) {
	var lip IP
	var zone string
	port := 0
	if laddr != nil {
		lip, zone, port = laddr.IP, laddr.Zone, laddr.Port
	}
	udpNet := sctpUDPNetwork(network, lip)
	if udpNet == "udp" && peerIP != nil {
		udpNet = sctpUDPNetwork(network, peerIP)
	}
	encap := port
	if cfg.LocalEncapPort != 0 {
		encap = int(cfg.LocalEncapPort)
	}
	pc, err := ListenUDP(udpNet, &UDPAddr{IP: lip, Port: encap, Zone: zone})
	if err != nil {
		return nil, err
	}
	ua := pc.LocalAddr().(*UDPAddr)
	if port == 0 {
		if cfg.LocalEncapPort == 0 {
			port = ua.Port
		} else {
			port = 49152 + randIntn(16384)
		}
	}
	u := &sctpUDPConn{
		net:    network,
		laddr:  &SCTPAddr{IP: ua.IP, Port: port, Zone: ua.Zone},
		encap:  cfg,
		pc:     pc,
		done:   make(chan struct{}),
		notify: make(chan struct{}),
		ep: sctp.NewEndpoint(sctp.Config{
			Rand:      runtime_rand,
			LocalPort: uint16(port),
			Accept:    accept,
		}),
	}
	u.timer = time.AfterFunc(time.Hour, u.onTimer)
	u.timer.Stop()
	go u.readLoop()
	return u, nil
}

// sctpUDPDeadline returns the dial deadline from ctx and the dialer.
func sctpUDPDeadline(ctx context.Context, dialer *Dialer) time.Time {
	if dialer != nil {
		return dialer.deadline(ctx, time.Now())
	}
	d, _ := ctx.Deadline()
	return d
}

func dialSCTPUDP(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPAddr, opts *SCTPInitOptions, cfg SCTPUDPConfig) (*SCTPConn, error) {
	if dialer != nil && laddr == nil {
		if la, ok := dialer.LocalAddr.(*SCTPAddr); ok {
			laddr = la
		}
	}
	u, err := newSCTPUDPConn(ctx, network, laddr, raddr.IP, cfg, false)
	if err != nil {
		return nil, err
	}
	if opts != nil {
		u.setInit(*opts)
	}
	ra := *raddr
	u.raddr = &ra
	u.connected = true
	deadline := sctpUDPDeadline(ctx, dialer)

	u.mu.Lock()
	a, err := u.ep.Connect(time.Now(), u.udpPeer(raddr), uint16(raddr.Port))
	if err != nil {
		u.mu.Unlock()
		u.abortClose()
		return nil, err
	}
	u.assoc = a
	u.afterLocked()
	for !a.Established() && !a.Closed() {
		if err := u.waitCtxLocked(ctx, deadline); err != nil {
			u.mu.Unlock()
			u.abortClose()
			return nil, err
		}
	}
	if a.Closed() {
		err := u.assocEnd
		u.mu.Unlock()
		u.abortClose()
		if err == nil {
			err = syscall.ECONNREFUSED
		}
		return nil, err
	}
	u.mu.Unlock()
	c := &SCTPConn{udp: u, assocID: a.ID()}
	c.multiPeer = []SCTPAddr{ra}
	c.multiLocal = []SCTPAddr{*u.laddr}
	return c, nil
}

func listenSCTPUDP(ctx context.Context, lc ListenConfig, network string, laddr *SCTPAddr, opts *SCTPInitOptions, cfg SCTPUDPConfig, accept bool) (*SCTPConn, error) {
	u, err := newSCTPUDPConn(ctx, network, laddr, nil, cfg, accept)
	if err != nil {
		return nil, err
	}
	if opts != nil {
		u.setInit(*opts)
	}
	c := &SCTPConn{udp: u}
	c.multiLocal = []SCTPAddr{*u.laddr}
	return c, nil
}

func (u *sctpUDPConn) udpPeer(a *SCTPAddr) netip.AddrPort {
	ap := a.AddrPort()
	port := ap.Port()
	if u.encap.RemoteEncapPort != 0 {
		port = u.encap.RemoteEncapPort
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), port)
}

func (u *sctpUDPConn) readLoop() {
	defer close(u.done)
	buf := make([]byte, 65536)
	for {
		n, from, err := u.pc.ReadFromUDPAddrPort(buf)
		u.mu.Lock()
		if u.sockClosed {
			u.mu.Unlock()
			return
		}
		if err == nil {
			u.ep.Input(time.Now(), from, buf[:n])
			u.afterLocked()
		}
		u.mu.Unlock()
		if err != nil && errors.Is(err, ErrClosed) {
			return
		}
	}
}

func (u *sctpUDPConn) onTimer() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sockClosed {
		return
	}
	u.ep.HandleTimers(time.Now())
	u.afterLocked()
}

// afterLocked runs after every engine call: it handles events, sends
// queued packets, rearms the timer and wakes waiters.
func (u *sctpUDPConn) afterLocked() {
	for {
		ev, ok := u.ep.PollEvent()
		if !ok {
			break
		}
		u.handleEvent(ev)
	}
	for {
		t, ok := u.ep.PollTransmit()
		if !ok {
			break
		}
		if !u.sockClosed {
			// Send errors are like packet loss: SCTP retransmits.
			u.pc.WriteToUDPAddrPort(t.Data, t.To)
		}
	}
	if u.closed && u.ep.Idle() {
		u.shutdownSocketLocked()
	}
	if !u.sockClosed {
		if d := u.ep.NextDeadline(); d.IsZero() {
			u.timer.Stop()
		} else {
			u.timer.Reset(max(time.Until(d), 0))
		}
	}
	close(u.notify)
	u.notify = make(chan struct{})
}

func (u *sctpUDPConn) handleEvent(ev sctp.Event) {
	if u.assoc != nil && ev.Assoc == u.assoc.ID() {
		switch ev.Kind {
		case sctp.EventCommLost:
			switch {
			case ev.Err == sctp.ErrTimeout:
				u.assocEnd = syscall.ETIMEDOUT
			case !u.up:
				u.assocEnd = syscall.ECONNREFUSED
			default:
				u.assocEnd = syscall.ECONNRESET
			}
		case sctp.EventCantStart:
			u.assocEnd = syscall.ETIMEDOUT
		case sctp.EventShutdownComplete:
			u.assocEnd = io.EOF
		case sctp.EventCommUp:
			u.up = true
		}
	}
	if b := u.notification(ev); b != nil {
		u.notifs = append(u.notifs, b)
	}
}

// notification formats an event as the kernel's sctp_notification,
// if the user subscribed to it.
func (u *sctpUDPConn) notification(ev sctp.Event) []byte {
	put16 := byteorder.LEAppendUint16
	put32 := byteorder.LEAppendUint32
	if goarch.BigEndian {
		put16 = byteorder.BEAppendUint16
		put32 = byteorder.BEAppendUint32
	}
	head := func(typ, flags uint16, n int) []byte {
		b := make([]byte, 0, n)
		b = put16(b, sctpNotifType(typ))
		b = put16(b, flags)
		return put32(b, uint32(n))
	}
	switch ev.Kind {
	case sctp.EventCommUp, sctp.EventCommLost, sctp.EventRestart, sctp.EventShutdownComplete, sctp.EventCantStart:
		if !u.mask.Association {
			return nil
		}
		state := map[sctp.EventKind]uint16{
			sctp.EventCommUp:           sctpCommUp,
			sctp.EventCommLost:         sctpCommLost,
			sctp.EventRestart:          sctpRestart,
			sctp.EventShutdownComplete: sctpShutdownComp,
			sctp.EventCantStart:        sctpCantStrAssoc,
		}[ev.Kind]
		b := head(sctpNotifAssocChange, 0, 20)
		b = put16(b, state)
		b = put16(b, 0)
		b = put16(b, ev.OutStreams)
		b = put16(b, ev.InStreams)
		return put32(b, uint32(ev.Assoc))
	case sctp.EventShutdown:
		if !u.mask.Shutdown {
			return nil
		}
		return put32(head(sctpNotifShutdown, 0, 12), uint32(ev.Assoc))
	case sctp.EventSenderDry:
		if !u.mask.SenderDry {
			return nil
		}
		return put32(head(sctpNotifSenderDry, 0, 12), uint32(ev.Assoc))
	case sctp.EventStreamReset:
		if !u.mask.StreamReset {
			return nil
		}
		flags := uint16(sctpStreamResetOutgoing)
		if ev.Incoming {
			flags = sctpStreamResetIncoming
		}
		if ev.Failed {
			flags |= sctpStreamResetDenied
		}
		b := put32(head(sctpNotifStreamReset, flags, 12+2*len(ev.Streams)), uint32(ev.Assoc))
		for _, s := range ev.Streams {
			b = put16(b, s)
		}
		return b
	case sctp.EventStreamsAdded:
		if !u.mask.StreamReset {
			return nil
		}
		var flags uint16
		if ev.Failed {
			flags = sctpStreamResetDenied
		}
		b := put32(head(sctpNotifStreamChange, flags, 16), uint32(ev.Assoc))
		b = put16(b, ev.InStreams)
		return put16(b, ev.OutStreams)
	}
	return nil
}

func (u *sctpUDPConn) broadcastLocked() {
	close(u.notify)
	u.notify = make(chan struct{})
}

// waitCtxLocked waits for a state change, the deadline or ctx. It is
// called with mu held and returns with mu held.
func (u *sctpUDPConn) waitCtxLocked(ctx context.Context, deadline time.Time) error {
	if u.closed {
		return ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	ch := u.notify
	u.mu.Unlock()
	var tc <-chan time.Time
	var t *time.Timer
	if !deadline.IsZero() {
		t = time.NewTimer(time.Until(deadline))
		tc = t.C
	}
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}
	var err error
	select {
	case <-ch:
	case <-tc:
	case <-done:
		err = mapErr(ctx.Err())
	}
	if t != nil {
		t.Stop()
	}
	u.mu.Lock()
	return err
}

func (u *sctpUDPConn) waitLocked(read bool) error {
	dl := u.wdl
	if read {
		dl = u.rdl
	}
	return u.waitCtxLocked(nil, dl)
}

func (u *sctpUDPConn) setDeadline(t time.Time, read, write bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if read {
		u.rdl = t
	}
	if write {
		u.wdl = t
	}
	u.broadcastLocked()
}

func (u *sctpUDPConn) sctpAddr(m *sctp.Message) *SCTPAddr {
	ip := m.Peer.Addr()
	return &SCTPAddr{IP: IP(ip.AsSlice()), Port: int(m.PeerPort), Zone: ip.Zone()}
}

func (u *sctpUDPConn) rcvInfo(m *sctp.Message) *SCTPRcvInfo {
	var info *SCTPRcvInfo
	if u.recvRcv {
		info = &SCTPRcvInfo{
			Stream:  m.Stream,
			SSN:     m.SSN,
			PPID:    m.PPID,
			TSN:     m.TSN,
			CumTSN:  m.CumTSN,
			AssocID: m.Assoc,
		}
		if m.Unordered {
			info.Flags = SCTPUnordered
		}
	}
	if u.recvNxt {
		if next, ok := u.ep.PeekMessage(); ok {
			if info == nil {
				info = &SCTPRcvInfo{}
			}
			info.Next = &SCTPNxtInfo{Stream: next.Stream, PPID: next.PPID, Length: uint32(len(next.Data)), AssocID: next.Assoc}
			if next.Unordered {
				info.Next.Flags = SCTPUnordered
			}
		}
	}
	return info
}

func (u *sctpUDPConn) readFrom(b []byte) (n, oobn, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for {
		if u.closed {
			return 0, 0, 0, nil, nil, ErrClosed
		}
		if !u.rdl.IsZero() && !time.Now().Before(u.rdl) {
			return 0, 0, 0, nil, nil, os.ErrDeadlineExceeded
		}
		if len(u.notifs) > 0 {
			nb := u.notifs[0]
			u.notifs = u.notifs[1:]
			n = copy(b, nb)
			return n, 0, sctpUDPMsgNotification | sctpUDPMsgEOR, nil, nil, nil
		}
		if u.partial != nil {
			m := &u.partialMsg
			n = copy(b, u.partial)
			u.partial = u.partial[n:]
			flags = 0
			if len(u.partial) == 0 {
				u.partial = nil
				if !m.Partial {
					flags = sctpUDPMsgEOR
				}
			}
			return n, 0, flags, u.sctpAddr(m), u.rcvInfo(m), nil
		}
		if m, ok := u.ep.PollMessage(time.Now()); ok {
			if m.Aborted {
				// A partially delivered message was abandoned by
				// the sender; the next read starts a new message.
				u.afterLocked()
				continue
			}
			n = copy(b, m.Data)
			flags = 0
			if !m.Partial {
				flags = sctpUDPMsgEOR
			}
			if n < len(m.Data) {
				u.partial = m.Data[n:]
				u.partialMsg = m
				flags = 0
			}
			addr, info = u.sctpAddr(&m), u.rcvInfo(&m)
			u.afterLocked() // the window may have reopened
			return n, 0, flags, addr, info, nil
		}
		if u.assoc != nil && u.assoc.Closed() {
			if u.assocEnd == nil || u.assocEnd == io.EOF {
				return 0, 0, 0, nil, nil, io.EOF
			}
			return 0, 0, 0, nil, nil, u.assocEnd
		}
		if u.assoc != nil && u.assoc.PeerShutdown() {
			return 0, 0, 0, nil, nil, io.EOF
		}
		if err := u.waitLocked(true); err != nil {
			return 0, 0, 0, nil, nil, err
		}
	}
}

func (u *sctpUDPConn) association(id int32) *sctp.Association {
	if id == 0 {
		if u.assoc != nil {
			return u.assoc
		}
		id = u.defaultAssocID()
	}
	return u.ep.Association(id)
}

func (u *sctpUDPConn) defaultAssocID() int32 {
	if u.assoc != nil {
		return u.assoc.ID()
	}
	if ids := u.ep.Associations(); len(ids) == 1 {
		return ids[0]
	}
	return 0
}

func (u *sctpUDPConn) writeTo(b []byte, addr *SCTPAddr, info *SCTPSndInfo) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, ErrClosed
	}
	if u.connected && addr != nil {
		return 0, ErrWriteToConnected
	}
	si := u.defSend
	if info != nil {
		si = *info
	}
	now := time.Now()
	var a *sctp.Association
	switch {
	case u.connected:
		a = u.assoc
	case si.AssocID != 0:
		if a = u.ep.Association(si.AssocID); a == nil {
			return 0, syscall.EINVAL
		}
	default:
		if addr == nil {
			addr = u.raddr
		}
		if addr == nil {
			return 0, errMissingAddress
		}
		if a = u.ep.Lookup(u.udpPeer(addr), uint16(addr.Port)); a == nil {
			if si.Flags&(sctpUDPFlagAbort|sctpUDPFlagEOF) != 0 {
				return 0, syscall.EINVAL
			}
			// Implicit association setup, as sendmsg does on a
			// one-to-many socket.
			var err error
			if a, err = u.ep.Connect(now, u.udpPeer(addr), uint16(addr.Port)); err != nil {
				return 0, err
			}
		}
	}
	if si.Flags&sctpUDPFlagAbort != 0 {
		a.Abort(now)
		u.afterLocked()
		return 0, nil
	}
	if len(b) == 0 {
		if si.Flags&sctpUDPFlagEOF != 0 {
			a.Shutdown(now)
			u.afterLocked()
			return 0, nil
		}
		return 0, syscall.EINVAL
	}
	send := sctp.SendInfo{Stream: si.Stream, PPID: si.PPID, Unordered: si.Flags&SCTPUnordered != 0}
	switch u.defPR.Policy {
	case SCTPPRTTL:
		send.PRPolicy, send.PRValue = sctp.PRTTL, u.defPR.Value
	case SCTPPRRTX:
		send.PRPolicy, send.PRValue = sctp.PRRTX, u.defPR.Value
	}
	for {
		if !u.wdl.IsZero() && !now.Before(u.wdl) {
			return 0, os.ErrDeadlineExceeded
		}
		err := a.Send(now, b, send)
		switch err {
		case nil:
			if si.Flags&sctpUDPFlagEOF != 0 {
				a.Shutdown(now)
			}
			u.afterLocked()
			return len(b), nil
		case sctp.ErrWouldBlock:
			if err := u.waitLocked(false); err != nil {
				return 0, err
			}
			if u.closed {
				return 0, ErrClosed
			}
			now = time.Now()
		case sctp.ErrInvalidStream, sctp.ErrEmptyMessage:
			return 0, syscall.EINVAL
		default:
			if u.assocEnd != nil && u.assocEnd != io.EOF && a == u.assoc {
				return 0, u.assocEnd
			}
			return 0, syscall.EPIPE
		}
	}
}

func (u *sctpUDPConn) close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrClosed
	}
	u.closed = true
	u.ep.Close(time.Now())
	u.afterLocked()
	if !u.sockClosed {
		time.AfterFunc(sctpUDPLinger, func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			if !u.sockClosed {
				u.ep.Abort(time.Now())
				u.afterLocked()
				u.shutdownSocketLocked()
			}
		})
	}
	return nil
}

// abortClose tears the connection down at once, for failed dials.
func (u *sctpUDPConn) abortClose() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	u.ep.Abort(time.Now())
	u.afterLocked()
	u.shutdownSocketLocked()
}

func (u *sctpUDPConn) shutdownSocketLocked() {
	if u.sockClosed {
		return
	}
	u.sockClosed = true
	u.timer.Stop()
	u.pc.Close()
}

func (u *sctpUDPConn) setNoDelay(on bool) error {
	if on {
		return nil // the engine never delays sends
	}
	return errSCTPUDPUnsupported
}

func (u *sctpUDPConn) setInit(o SCTPInitOptions) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ep.SetInit(o.NumOStreams, o.MaxInStreams, int(o.MaxAttempts), time.Duration(o.MaxInitTimeout)*time.Millisecond)
	return nil
}

func (u *sctpUDPConn) subscribe(m SCTPEventMask) error {
	if m.Authentication {
		return errSCTPUDPUnsupported
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.mask = m
	return nil
}

func (u *sctpUDPConn) setRTO(info SCTPRTOInfo) error {
	ms := func(v uint32) time.Duration { return time.Duration(v) * time.Millisecond }
	if info.Min != 0 && info.Max != 0 && info.Min > info.Max {
		return syscall.EINVAL
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ep.SetRTO(ms(info.Initial), ms(info.Min), ms(info.Max))
	return nil
}

func (u *sctpUDPConn) setDelayedSack(info SCTPDelayedSackInfo) error {
	if info.Delay > 500 {
		return syscall.EINVAL
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ep.SetDelayedSack(time.Duration(info.Delay)*time.Millisecond, int(info.Frequency))
	return nil
}

func (u *sctpUDPConn) setDefaultPR(info SCTPPRInfo) error {
	switch info.Policy {
	case SCTPPRNone, SCTPPRTTL, SCTPPRRTX:
	default:
		return errSCTPUDPUnsupported
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.defPR = info
	return nil
}

func (u *sctpUDPConn) setDefaultSend(info SCTPSndInfo) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.defSend = info
	return nil
}

func (u *sctpUDPConn) setRecvRcvInfo(on bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.recvRcv = on
	return nil
}

func (u *sctpUDPConn) setRecvNxtInfo(on bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.recvNxt = on
	return nil
}

func (u *sctpUDPConn) setScheduler(p SCTPScheduler) error {
	if p == SCTPSchedulerFCFS {
		return nil
	}
	return errSCTPUDPUnsupported
}

func (u *sctpUDPConn) setBuffers(recv, send int) error {
	if recv < 0 || send < 0 {
		return syscall.EINVAL
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ep.SetBuffers(recv, send)
	if send > 0 {
		for _, id := range u.ep.Associations() {
			u.ep.Association(id).SetSendBuffer(send)
		}
	}
	return nil
}

func (u *sctpUDPConn) assocIDs() []int32 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ep.Associations()
}

func (u *sctpUDPConn) assocStatus(id int32) (*SCTPAssocStatus, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.association(id)
	if a == nil {
		return nil, syscall.EINVAL
	}
	st := a.Status()
	peer := netip.AddrPortFrom(a.Peer().Addr(), a.PeerPort())
	const sctpActive = 2
	return &SCTPAssocStatus{
		AssocID:            a.ID(),
		State:              int32(st.State),
		RWND:               st.Rwnd,
		UnackedData:        uint16(min(st.Unacked, 65535)),
		PendingData:        uint16(min(st.Pending, 65535)),
		InStreams:          st.InStreams,
		OutStreams:         st.OutStreams,
		FragmentationPoint: uint32(st.FragPoint),
		PrimaryAddr:        *SCTPAddrFromAddrPort(peer),
		PrimaryState:       sctpActive,
		PrimaryCWND:        uint32(st.Cwnd),
		PrimarySRTT:        uint32(st.SRTT.Milliseconds()),
		PrimaryRTO:         uint32(st.RTO.Milliseconds()),
		PrimaryMTU:         uint32(st.MTU),
	}, nil
}

func (u *sctpUDPConn) engineErr(err error) error {
	switch err {
	case nil:
		return nil
	case sctp.ErrUnsupported:
		return syscall.EOPNOTSUPP
	case sctp.ErrResetInProgress:
		return syscall.EINPROGRESS
	case sctp.ErrInvalidStream:
		return syscall.EINVAL
	case sctp.ErrClosed:
		return syscall.ENOTCONN
	}
	return err
}

func (u *sctpUDPConn) resetStreams(id int32, flags uint16, streams []uint16) error {
	if flags&SCTPStreamResetIncoming != 0 {
		return errSCTPUDPUnsupported
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.association(id)
	if a == nil {
		return syscall.EINVAL
	}
	err := a.ResetStreams(time.Now(), streams)
	u.afterLocked()
	return u.engineErr(err)
}

func (u *sctpUDPConn) addStreams(id int32, in, out uint16) error {
	if in != 0 {
		return errSCTPUDPUnsupported
	}
	if out == 0 {
		return syscall.EINVAL
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.association(id)
	if a == nil {
		return syscall.EINVAL
	}
	err := a.AddStreams(time.Now(), out)
	u.afterLocked()
	return u.engineErr(err)
}

func sctpNoKernelSupport(err error) bool {
	return errors.Is(err, errSCTPUnsupported) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.ESOCKTNOSUPPORT) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.ENOPROTOOPT)
}

func sctpConnectFailed(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}
