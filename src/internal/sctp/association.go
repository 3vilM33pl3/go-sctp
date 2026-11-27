// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"internal/byteorder"
	"net/netip"
	"time"
)

// Association states (RFC 9260 section 4). The values match the
// SCTP_* state numbering Linux reports in sctp_status.
type State int32

const (
	stateClosed           State = 1
	stateCookieWait       State = 2
	stateCookieEchoed     State = 3
	stateEstablished      State = 4
	stateShutdownPending  State = 5
	stateShutdownSent     State = 6
	stateShutdownReceived State = 7
	stateShutdownAckSent  State = 8
)

// Partial reliability policies (RFC 3758, RFC 7496).
const (
	PRNone = 0
	PRTTL  = 1 // value: lifetime in milliseconds
	PRRTX  = 2 // value: maximum number of retransmissions
)

// SendInfo carries per-message send parameters.
type SendInfo struct {
	Stream    uint16
	PPID      uint32
	Unordered bool
	PRPolicy  int
	PRValue   uint32
}

// outMsg is a user message being sent.
type outMsg struct {
	stream    uint16
	ssn       uint16
	unordered bool
	policy    int
	value     uint32
	expires   time.Time
	abandoned bool
}

// outChunk is a DATA chunk owned by the sender.
type outChunk struct {
	msg       *outMsg
	flags     uint8
	ppid      uint32
	payload   []byte
	tsn       uint32
	sentAt    time.Time
	nSent     int
	acked     bool // cumulatively or gap acknowledged
	retx      bool // marked for retransmission
	fastRetx  bool // already fast-retransmitted
	misses    int
	abandoned bool
	held      bool // queued behind a stream reset (RFC 6525 5.1.2)
}

// inFrag is a received DATA chunk awaiting reassembly.
type inFrag struct {
	tsn     uint32
	flags   uint8
	ssn     uint16
	ppid    uint32
	payload []byte
}

type inStream struct {
	nextSSN   uint16
	ordered   []inFrag // sorted by TSN
	unordered []inFrag // sorted by TSN
}

// Association is one SCTP association.
type Association struct {
	ep       *Endpoint
	id       int32
	state    State
	peer     netip.AddrPort
	peerPort uint16
	myTag    uint32
	peerTag  uint32
	mtu      int
	numOut   uint16
	numIn    uint16

	peerFwdTSN   bool
	peerReconfig bool

	// Handshake.
	t1           time.Time
	initAttempts int
	initChunk    chunk
	cookieEcho   chunk
	t1SentAt     time.Time

	// Sender.
	nextTSN     uint32
	cumAck      uint32 // highest TSN cumulatively acked by the peer
	advPeerAck  uint32 // Advanced.Peer.Ack.Point (RFC 3758)
	fwdTSNNeed  bool
	pending     []*outChunk // queued, no TSN yet
	inflight    []*outChunk // sent, sorted by TSN
	outSSN      []uint16
	buffered    int
	sndBuf      int
	peerRwnd    uint32
	cwnd        int
	ssthresh    int
	pba         int // partial bytes acked
	inFastRec   bool
	fastRecExit uint32
	t3          time.Time
	rto         time.Duration
	srtt        time.Duration
	rttvar      time.Duration
	haveRTT     bool
	errors      int
	ctrl        []chunk
	dry         bool

	// Receiver.
	peerCum       uint32 // highest TSN received in sequence
	recvd         map[uint32]struct{}
	dups          []uint32
	instreams     map[uint16]*inStream
	rcvBuf        int
	rcvHeld       int // bytes in reassembly or delivered but unread
	lastAdvRwnd   uint32
	needSack      bool
	sackNow       bool
	pktsUnacked   int
	sackTimer     time.Time
	hbTimer       time.Time
	hbSent        time.Time
	hbNonce       uint64
	hbOutstanding bool

	// Shutdown.
	t2           time.Time
	shutdownWant bool
	peerShutdown bool

	// Stream reconfiguration (RFC 6525).
	reconf
}

// ID returns the association identifier.
func (a *Association) ID() int32 { return a.id }

// Peer returns the peer's UDP address.
func (a *Association) Peer() netip.AddrPort { return a.peer }

// PeerPort returns the peer's SCTP port.
func (a *Association) PeerPort() uint16 { return a.peerPort }

// State returns the association state.
func (a *Association) State() State { return a.state }

// Established reports whether user data can flow.
func (a *Association) Established() bool {
	return a.state == stateEstablished || a.state == stateShutdownPending ||
		a.state == stateShutdownReceived || a.state == stateShutdownSent
}

// PeerShutdown reports whether the peer has started a graceful shutdown,
// after which it sends no more data.
func (a *Association) PeerShutdown() bool { return a.peerShutdown }

// Closed reports whether the association has ended.
func (a *Association) Closed() bool { return a.state == stateClosed }

// Streams returns the negotiated inbound and outbound stream counts.
func (a *Association) Streams() (in, out uint16) { return a.numIn, a.numOut }

// Buffered returns the number of user bytes not yet acknowledged.
func (a *Association) Buffered() int { return a.buffered }

// SetSendBuffer sets the send buffer size.
func (a *Association) SetSendBuffer(n int) {
	if n > 0 {
		a.sndBuf = n
	}
}

// Writable reports whether a message of n bytes can be queued now.
func (a *Association) Writable(n int) bool {
	return a.buffered == 0 || a.buffered+n <= a.sndBuf
}

// Status is a snapshot of association state.
type Status struct {
	State      State
	Rwnd       uint32
	Unacked    int
	Pending    int
	InStreams  uint16
	OutStreams uint16
	FragPoint  int
	Cwnd       int
	SRTT       time.Duration
	RTO        time.Duration
	MTU        int
	PeerUDP    netip.AddrPort
}

// Status returns a snapshot of the association.
func (a *Association) Status() Status {
	return Status{
		State:      a.state,
		Rwnd:       a.peerRwnd,
		Unacked:    len(a.inflight),
		Pending:    len(a.pending),
		InStreams:  a.numIn,
		OutStreams: a.numOut,
		FragPoint:  a.maxData(),
		Cwnd:       a.cwnd,
		SRTT:       a.srtt,
		RTO:        a.rto,
		MTU:        a.mtu,
		PeerUDP:    a.peer,
	}
}

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		d = lo
	}
	if d > hi {
		d = hi
	}
	return d
}

func (a *Association) maxData() int { return a.mtu - commonHeaderSize - dataHeaderSize }

func (a *Association) hdr() header {
	return header{a.ep.cfg.LocalPort, a.peerPort, a.peerTag}
}

func (a *Association) sendNow(chunks ...chunk) {
	a.ep.send(a.peer, a.hdr(), chunks)
}

// applyPeer records the peer's INIT or INIT ACK parameters.
func (a *Association) applyPeer(peerTag, peerTSN, arwnd uint32, numOut, numIn uint16, fwd, reconf bool) {
	a.peerTag = peerTag
	a.peerCum = peerTSN - 1
	a.peerRwnd = arwnd
	a.numOut, a.numIn = numOut, numIn
	a.outSSN = make([]uint16, numOut)
	a.peerFwdTSN, a.peerReconfig = fwd, reconf
	a.recvd = make(map[uint32]struct{})
	a.lastAdvRwnd = uint32(a.rcvBuf)
	a.reconfInit(a.nextTSN, peerTSN)
}

func (a *Association) establish(now time.Time, restart bool) {
	a.state = stateEstablished
	a.t1 = time.Time{}
	a.errors = 0
	a.hbTimer = now.Add(a.ep.cfg.HBInterval + a.rto)
	kind := EventCommUp
	if restart {
		kind = EventRestart
	}
	a.ep.emit(Event{Kind: kind, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, InStreams: a.numIn, OutStreams: a.numOut})
}

func (a *Association) sendInit(now time.Time) {
	in, extra := a.ep.localInit(a.myTag, a.nextTSN, a.numOut, a.numIn, a.rcvBuf)
	a.initChunk = in.chunk(ctInit, extra)
	a.initAttempts = 1
	a.ep.send(a.peer, header{a.ep.cfg.LocalPort, a.peerPort, 0}, []chunk{a.initChunk})
	a.t1SentAt = now
	a.t1 = now.Add(a.rto)
}

// fail ends the association after an error and reports it.
func (a *Association) fail(kind EventKind, err error) {
	a.ep.remove(a)
	a.ep.emit(Event{Kind: kind, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, Err: err})
}

// Abort sends ABORT and ends the association.
func (a *Association) Abort(now time.Time) {
	if a.state == stateClosed {
		return
	}
	if a.state != stateCookieWait {
		a.sendNow(causeChunk(ctAbort, 0, causeUserAbort, nil))
	}
	a.fail(EventCommLost, ErrClosed)
}

// Shutdown starts a graceful shutdown once queued data is acknowledged.
func (a *Association) Shutdown(now time.Time) {
	switch a.state {
	case stateCookieWait, stateCookieEchoed:
		a.Abort(now)
	case stateEstablished:
		a.state = stateShutdownPending
		a.maybeShutdown(now)
		a.transmit(now)
	}
}

// Send queues a user message.
func (a *Association) Send(now time.Time, data []byte, info SendInfo) error {
	switch a.state {
	case stateCookieWait, stateCookieEchoed, stateEstablished:
	default:
		return ErrClosed
	}
	if len(data) == 0 {
		return ErrEmptyMessage
	}
	if a.state == stateEstablished || a.state == stateCookieEchoed {
		if info.Stream >= a.numOut {
			return ErrInvalidStream
		}
	} else if info.Stream >= a.ep.cfg.NumOStreams {
		return ErrInvalidStream
	}
	if !a.Writable(len(data)) {
		return ErrWouldBlock
	}
	m := &outMsg{stream: info.Stream, unordered: info.Unordered, policy: info.PRPolicy, value: info.PRValue}
	if m.policy == PRTTL && a.peerFwdTSN {
		m.expires = now.Add(time.Duration(info.PRValue) * time.Millisecond)
	}
	if !a.peerFwdTSN && a.state == stateEstablished {
		m.policy = PRNone
	}
	max := a.maxData()
	for off := 0; off < len(data); off += max {
		end := min(off+max, len(data))
		c := &outChunk{msg: m, ppid: info.PPID, payload: append([]byte(nil), data[off:end]...), held: a.streamBlocked(info.Stream)}
		if off == 0 {
			c.flags |= dataFlagBegin
		}
		if end == len(data) {
			c.flags |= dataFlagEnd
		}
		if info.Unordered {
			c.flags |= dataFlagUnordered
		}
		a.pending = append(a.pending, c)
	}
	a.buffered += len(data)
	a.dry = false
	if a.state == stateEstablished {
		a.transmit(now)
	}
	return nil
}

// consumed reopens the receive window after the user read n bytes.
func (a *Association) consumed(now time.Time, n int) {
	a.rcvHeld -= n
	if a.rcvHeld < 0 {
		a.rcvHeld = 0
	}
	// Window update: tell the peer once the window has opened by at
	// least an MTU from a small advertised value.
	if a.Established() && int(a.rwnd())-int(a.lastAdvRwnd) >= a.mtu && int(a.lastAdvRwnd) < a.rcvBuf/2 {
		a.sackNow = true
		a.transmit(now)
	}
}

func (a *Association) rwnd() uint32 {
	if a.rcvHeld >= a.rcvBuf {
		return 0
	}
	return uint32(a.rcvBuf - a.rcvHeld)
}

// input processes the chunks of a packet that belongs to a.
func (a *Association) input(now time.Time, h header, chunks []chunk) {
	gotData := false
	for _, c := range chunks {
		if a.state == stateClosed {
			return
		}
		switch c.typ {
		case ctData:
			if a.Established() || a.state == stateCookieEchoed {
				gotData = true
				a.handleData(now, c)
			}
		case ctInitAck:
			a.handleInitAck(now, c)
		case ctCookieEcho:
			a.handleCookieEchoExisting(now, c)
		case ctCookieAck:
			if a.state == stateCookieEchoed {
				if a.initAttempts == 1 {
					a.updateRTT(now.Sub(a.t1SentAt))
				}
				a.establish(now, false)
			}
		case ctSack:
			if s, err := parseSack(c); err == nil && a.Established() {
				a.handleSack(now, s)
			}
		case ctHeartbeat:
			a.ctrl = append(a.ctrl, chunk{typ: ctHeartbeatAck, value: c.value})
		case ctHeartbeatAck:
			a.handleHeartbeatAck(now, c)
		case ctAbort:
			a.fail(EventCommLost, ErrAborted)
			return
		case ctShutdown:
			a.handleShutdown(now, c)
		case ctShutdownAck:
			if a.state == stateShutdownSent || a.state == stateShutdownAckSent {
				a.sendNow(chunk{typ: ctShutdownComplete})
				a.ep.remove(a)
				a.ep.emit(Event{Kind: EventShutdownComplete, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort})
				return
			}
		case ctShutdownComplete:
			if a.state == stateShutdownAckSent {
				a.ep.remove(a)
				a.ep.emit(Event{Kind: EventShutdownComplete, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort})
				return
			}
		case ctError:
			a.handleError(now, c)
		case ctForwardTSN:
			if f, err := parseForwardTSN(c); err == nil && a.Established() {
				gotData = true
				a.handleForwardTSN(now, f)
			}
		case ctReconfig:
			if a.Established() {
				a.handleReconfig(now, c)
			}
		default:
			// Unknown chunk: the top two bits say what to do.
			switch c.typ >> 6 {
			case 0:
				return
			case 1:
				a.ctrl = append(a.ctrl, causeChunk(ctError, 0, causeUnrecognizedChunk, append([]byte{c.typ, c.flags, 0, 0}, c.value...)[:min(4+len(c.value), 256)]))
				return
			case 3:
				a.ctrl = append(a.ctrl, causeChunk(ctError, 0, causeUnrecognizedChunk, append([]byte{c.typ, c.flags, 0, 0}, c.value...)[:min(4+len(c.value), 256)]))
			}
		}
	}
	if gotData {
		a.pktsUnacked++
		if a.pktsUnacked >= a.ep.cfg.SackFreq || a.state == stateShutdownSent {
			a.sackNow = true
		} else if a.sackTimer.IsZero() {
			a.sackTimer = now.Add(a.ep.cfg.SackDelay)
		}
		a.deliver()
	}
}

func (a *Association) handleInitAck(now time.Time, c chunk) {
	if a.state != stateCookieWait {
		return
	}
	in, err := parseInit(c)
	if err != nil || in.initTag == 0 || in.numOut == 0 || in.maxIn == 0 {
		a.fail(EventCantStart, ErrCannotStart)
		return
	}
	ck, ok := in.param(ptStateCookie)
	if !ok {
		a.sendNow(causeChunk(ctAbort, 0, causeMissingParam, []byte{0, 0, 0, 1, 0, byte(ptStateCookie)}))
		a.fail(EventCantStart, ErrCannotStart)
		return
	}
	a.applyPeer(in.initTag, in.initialTSN, in.arwnd, min(a.numOut, in.maxIn), min(a.numIn, in.numOut),
		in.supportsChunk(ctForwardTSN), in.supportsChunk(ctReconfig))
	if a.initAttempts == 1 {
		a.updateRTT(now.Sub(a.t1SentAt))
	}
	a.cookieEcho = chunk{typ: ctCookieEcho, value: append([]byte(nil), ck...)}
	a.state = stateCookieEchoed
	a.initAttempts = 1
	a.t1SentAt = now
	a.t1 = now.Add(a.rto)
	a.sendNow(a.cookieEcho)
}

// handleCookieEchoExisting handles a COOKIE ECHO whose tag matches an
// existing association: a duplicate, or an initialization collision.
func (a *Association) handleCookieEchoExisting(now time.Time, c chunk) {
	ck, ok := parseCookie(&a.ep.cookieKey, c.value)
	if !ok || ck.myTag != a.myTag {
		return
	}
	switch a.state {
	case stateCookieWait, stateCookieEchoed:
		a.applyPeer(ck.peerTag, ck.peerInitialTSN, ck.peerArwnd, ck.numOut, ck.numIn,
			ck.flags&cookieFlagPeerFwdTSN != 0, ck.flags&cookieFlagPeerReconfig != 0)
		a.establish(now, false)
	case stateEstablished, stateShutdownPending, stateShutdownReceived:
		if ck.peerTag != a.peerTag {
			return
		}
	default:
		return
	}
	a.ctrl = append(a.ctrl, chunk{typ: ctCookieAck})
}

func (a *Association) handleError(now time.Time, c chunk) {
	ps, err := parseParams(c.value)
	if err != nil {
		return
	}
	for _, p := range ps {
		if p.typ == causeStaleCookie && a.state == stateCookieEchoed {
			// Start over with a new INIT (section 5.2.6).
			a.state = stateCookieWait
			a.initAttempts++
			if a.initAttempts > a.ep.cfg.MaxInitAttempts {
				a.fail(EventCantStart, ErrCannotStart)
				return
			}
			a.ep.send(a.peer, header{a.ep.cfg.LocalPort, a.peerPort, 0}, []chunk{a.initChunk})
			a.t1 = now.Add(a.rto)
		}
	}
}

func (a *Association) updateRTT(r time.Duration) {
	if r <= 0 {
		r = time.Millisecond
	}
	if !a.haveRTT {
		a.srtt = r
		a.rttvar = r / 2
		a.haveRTT = true
	} else {
		d := a.srtt - r
		if d < 0 {
			d = -d
		}
		a.rttvar = a.rttvar*3/4 + d/4
		a.srtt = a.srtt*7/8 + r/8
	}
	a.rto = clampDur(a.srtt+4*a.rttvar, a.ep.cfg.RTOMin, a.ep.cfg.RTOMax)
}

// handleData accepts a DATA chunk into the receive buffer.
func (a *Association) handleData(now time.Time, c chunk) {
	d, err := parseData(c)
	if err != nil {
		return
	}
	if len(d.payload) == 0 {
		a.sendNow(causeChunk(ctAbort, 0, causeNoUserData, byteorder.BEAppendUint32(nil, d.tsn)))
		a.fail(EventCommLost, ErrAborted)
		return
	}
	if tsnLTE(d.tsn, a.peerCum) {
		a.dups = append(a.dups, d.tsn)
		a.sackNow = true
		return
	}
	if _, dup := a.recvd[d.tsn]; dup {
		a.dups = append(a.dups, d.tsn)
		a.sackNow = true
		return
	}
	// Drop new data beyond the window. An empty buffer always takes a
	// chunk, so a zero-window probe makes progress.
	if a.rcvHeld > 0 && a.rcvHeld+len(d.payload) > a.rcvBuf {
		a.sackNow = true
		return
	}
	if d.stream >= a.numIn {
		a.ctrl = append(a.ctrl, causeChunk(ctError, 0, causeInvalidStream,
			byteorder.BEAppendUint16(byteorder.BEAppendUint16(nil, d.stream), 0)))
		a.markReceived(d.tsn)
		return
	}
	if d.flags&dataFlagImmediate != 0 {
		a.sackNow = true
	}
	a.markReceived(d.tsn)
	if tsnGT(d.tsn, a.peerCum) {
		a.sackNow = true // a gap exists
	}
	f := inFrag{tsn: d.tsn, flags: d.flags, ssn: d.ssn, ppid: d.ppid, payload: append([]byte(nil), d.payload...)}
	if a.deferred != nil && d.flags&dataFlagUnordered == 0 && tsnGT(d.tsn, a.deferred.lastTSN) && a.streamIn(d.stream, a.deferred.streams) {
		// Sent after a stream reset we have not applied yet.
		a.deferredData = append(a.deferredData, deferredFrag{d.stream, f})
		a.rcvHeld += len(d.payload)
		return
	}
	a.addFrag(d.stream, f)
	a.rcvHeld += len(d.payload)
}

func (a *Association) addFrag(stream uint16, f inFrag) {
	s := a.instreams[stream]
	if s == nil {
		s = &inStream{}
		a.instreams[stream] = s
	}
	if f.flags&dataFlagUnordered != 0 {
		s.unordered = insertFrag(s.unordered, f)
	} else {
		if ssnLT(f.ssn, s.nextSSN) {
			a.rcvHeld -= len(f.payload) // already delivered or skipped
			return
		}
		s.ordered = insertFrag(s.ordered, f)
	}
}

func (a *Association) markReceived(tsn uint32) {
	a.recvd[tsn] = struct{}{}
	for {
		if _, ok := a.recvd[a.peerCum+1]; !ok {
			break
		}
		delete(a.recvd, a.peerCum+1)
		a.peerCum++
	}
}

func insertFrag(fs []inFrag, f inFrag) []inFrag {
	i := len(fs)
	for i > 0 && tsnGT(fs[i-1].tsn, f.tsn) {
		i--
	}
	fs = append(fs, inFrag{})
	copy(fs[i+1:], fs[i:])
	fs[i] = f
	return fs
}

// complete finds a whole message (B..E with consecutive TSNs) in fs
// starting at index i. It returns the index past its last fragment.
func complete(fs []inFrag, i int) (int, bool) {
	if fs[i].flags&dataFlagBegin == 0 {
		return 0, false
	}
	for j := i; j < len(fs); j++ {
		if j > i && (fs[j].tsn != fs[j-1].tsn+1 || fs[j].flags&dataFlagBegin != 0) {
			return 0, false
		}
		if fs[j].flags&dataFlagEnd != 0 {
			return j + 1, true
		}
	}
	return 0, false
}

func (a *Association) emitMessage(stream uint16, fs []inFrag, unordered bool) {
	n := 0
	for _, f := range fs {
		n += len(f.payload)
	}
	data := make([]byte, 0, n)
	for _, f := range fs {
		data = append(data, f.payload...)
	}
	a.ep.msgs = append(a.ep.msgs, Message{
		Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort,
		Stream: stream, SSN: fs[0].ssn, PPID: fs[0].ppid,
		TSN: fs[len(fs)-1].tsn, CumTSN: a.peerCum, Unordered: unordered, Data: data,
	})
}

// deliver moves complete messages to the endpoint's queue.
func (a *Association) deliver() {
	for id, s := range a.instreams {
		for i := 0; i < len(s.unordered); {
			if end, ok := complete(s.unordered, i); ok {
				a.emitMessage(id, s.unordered[i:end], true)
				s.unordered = append(s.unordered[:i], s.unordered[end:]...)
				continue
			}
			i++
		}
		for len(s.ordered) > 0 {
			if s.ordered[0].ssn != s.nextSSN {
				// Fragments of the next SSN may sit behind later ones.
				idx := -1
				for i := range s.ordered {
					if s.ordered[i].ssn == s.nextSSN && s.ordered[i].flags&dataFlagBegin != 0 {
						idx = i
						break
					}
				}
				if idx < 0 {
					break
				}
				end, ok := completeSSN(s.ordered, idx, s.nextSSN)
				if !ok {
					break
				}
				a.emitMessage(id, takeFrags(&s.ordered, idx, end, s.nextSSN), false)
				s.nextSSN++
				continue
			}
			end, ok := completeSSN(s.ordered, 0, s.nextSSN)
			if !ok {
				break
			}
			a.emitMessage(id, takeFrags(&s.ordered, 0, end, s.nextSSN), false)
			s.nextSSN++
		}
	}
	a.reconfOnCumAdvance()
}

// completeSSN is like complete but only considers fragments of ssn.
func completeSSN(fs []inFrag, i int, ssn uint16) (int, bool) {
	if fs[i].flags&dataFlagBegin == 0 {
		return 0, false
	}
	prev := fs[i].tsn
	if fs[i].flags&dataFlagEnd != 0 {
		return i, true
	}
	for j := i + 1; j < len(fs); j++ {
		if fs[j].ssn != ssn {
			continue
		}
		if fs[j].tsn != prev+1 {
			return 0, false
		}
		prev = fs[j].tsn
		if fs[j].flags&dataFlagEnd != 0 {
			return j, true
		}
	}
	return 0, false
}

// takeFrags removes the fragments of ssn from fs[i..last] and returns them.
func takeFrags(fs *[]inFrag, i, last int, ssn uint16) []inFrag {
	var msg, rest []inFrag
	for j, f := range *fs {
		if j >= i && j <= last && f.ssn == ssn {
			msg = append(msg, f)
		} else {
			rest = append(rest, f)
		}
	}
	*fs = rest
	return msg
}

func (a *Association) buildSack() chunk {
	s := sackChunk{cumTSN: a.peerCum, arwnd: a.rwnd()}
	if len(a.recvd) > 0 {
		tsns := make([]uint32, 0, len(a.recvd))
		for t := range a.recvd {
			tsns = append(tsns, t)
		}
		sortTSNs(tsns)
		start := tsns[0]
		prev := start
		for _, t := range tsns[1:] {
			if t != prev+1 {
				s.gaps = append(s.gaps, gapBlock{uint16(start - a.peerCum), uint16(prev - a.peerCum)})
				start = t
			}
			prev = t
		}
		s.gaps = append(s.gaps, gapBlock{uint16(start - a.peerCum), uint16(prev - a.peerCum)})
		if len(s.gaps) > 64 {
			s.gaps = s.gaps[:64]
		}
	}
	if len(a.dups) > 32 {
		a.dups = a.dups[:32]
	}
	s.dups = a.dups
	a.dups = nil
	a.lastAdvRwnd = s.arwnd
	a.needSack, a.sackNow = false, false
	a.pktsUnacked = 0
	a.sackTimer = time.Time{}
	return s.chunk()
}

func sortTSNs(t []uint32) {
	// Shell sort; gap lists are short.
	for gap := len(t) / 2; gap > 0; gap /= 2 {
		for i := gap; i < len(t); i++ {
			for j := i; j >= gap && tsnGT(t[j-gap], t[j]); j -= gap {
				t[j], t[j-gap] = t[j-gap], t[j]
			}
		}
	}
}

func (a *Association) flightSize() int {
	n := 0
	for _, c := range a.inflight {
		if !c.acked && !c.retx && !c.abandoned {
			n += len(c.payload)
		}
	}
	return n
}

// handleSack processes a SACK (section 6.2.1 and 7.2).
func (a *Association) handleSack(now time.Time, s sackChunk) {
	if tsnLT(s.cumTSN, a.cumAck) {
		return // stale
	}
	if tsnGT(s.cumTSN, a.nextTSN-1) {
		a.protocolViolation()
		return
	}
	acked := 0
	cumAdvanced := tsnGT(s.cumTSN, a.cumAck)
	var rtt time.Duration
	keep := a.inflight[:0]
	for _, c := range a.inflight {
		if tsnLTE(c.tsn, s.cumTSN) {
			if !c.acked && !c.abandoned {
				acked += len(c.payload)
				if c.nSent == 1 && !c.retx {
					rtt = now.Sub(c.sentAt)
				}
			}
			a.buffered -= len(c.payload)
			continue
		}
		keep = append(keep, c)
	}
	for i := len(keep); i < len(a.inflight); i++ {
		a.inflight[i] = nil
	}
	a.inflight = keep
	a.cumAck = s.cumTSN
	if tsnLT(a.advPeerAck, a.cumAck) {
		a.advPeerAck = a.cumAck
	}

	var highestGap uint32 = s.cumTSN
	for _, g := range s.gaps {
		lo, hi := s.cumTSN+uint32(g.start), s.cumTSN+uint32(g.end)
		if tsnGT(hi, highestGap) {
			highestGap = hi
		}
		for _, c := range a.inflight {
			if tsnLTE(lo, c.tsn) && tsnLTE(c.tsn, hi) && !c.acked {
				c.acked = true
				c.retx = false
				if !c.abandoned {
					acked += len(c.payload)
				}
				if c.nSent == 1 && rtt == 0 {
					rtt = now.Sub(c.sentAt)
				}
			}
		}
	}
	if rtt > 0 {
		a.updateRTT(rtt)
	}
	// Any SACK proves the peer is reachable, including the answers to
	// zero-window probes (RFC 9260 section 6.1).
	a.errors = 0

	// Fast retransmit (section 7.2.4).
	if len(s.gaps) > 0 {
		for _, c := range a.inflight {
			if tsnGT(c.tsn, highestGap) {
				break
			}
			if !c.acked && !c.abandoned && !c.fastRetx {
				c.misses++
				if c.misses == 3 {
					c.retx = true
					c.fastRetx = true
					if !a.inFastRec {
						a.inFastRec = true
						a.ssthresh = max(a.cwnd/2, 4*a.mtu)
						a.cwnd = a.ssthresh
						a.pba = 0
						a.fastRecExit = a.nextTSN - 1
					}
				}
			}
		}
	}
	if a.inFastRec && tsnLTE(a.fastRecExit, a.cumAck) {
		a.inFastRec = false
	}

	// Congestion window growth (section 7.2.1 and 7.2.2).
	flight := a.flightSize()
	if cumAdvanced && !a.inFastRec && acked > 0 {
		if a.cwnd <= a.ssthresh {
			if flight+acked >= a.cwnd {
				a.cwnd += min(acked, a.mtu)
			}
		} else {
			a.pba += acked
			if a.pba >= a.cwnd && flight+acked >= a.cwnd {
				a.pba -= a.cwnd
				a.cwnd += a.mtu
			}
		}
	}
	if int(s.arwnd) > flight {
		a.peerRwnd = s.arwnd - uint32(flight)
	} else {
		a.peerRwnd = 0
	}

	a.prAdvance(now)
	if len(a.inflight) == 0 {
		a.t3 = time.Time{}
	} else if cumAdvanced {
		a.t3 = now.Add(a.rto)
	}
	if len(a.inflight) == 0 && len(a.pending) == 0 && !a.dry {
		a.dry = true
		a.ep.emit(Event{Kind: EventSenderDry, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort})
	}
	a.maybeShutdown(now)
}

func (a *Association) protocolViolation() {
	a.sendNow(causeChunk(ctAbort, 0, causeProtocolViolation, nil))
	a.fail(EventCommLost, ErrAborted)
}

func (a *Association) handleHeartbeatAck(now time.Time, c chunk) {
	ps, err := parseParams(c.value)
	if err != nil || len(ps) == 0 || ps[0].typ != ptHeartbeatInfo || len(ps[0].value) < 16 {
		return
	}
	v := ps[0].value
	if byteorder.BEUint64(v) != a.hbNonce || !a.hbOutstanding {
		return
	}
	sent := time.Unix(0, int64(byteorder.BEUint64(v[8:])))
	a.hbOutstanding = false
	a.errors = 0
	if r := now.Sub(sent); r > 0 && r < a.ep.cfg.RTOMax {
		a.updateRTT(r)
	}
}

func (a *Association) handleShutdown(now time.Time, c chunk) {
	if len(c.value) < 4 {
		return
	}
	switch a.state {
	case stateEstablished, stateShutdownPending, stateShutdownReceived, stateShutdownSent:
	default:
		return
	}
	// The cumulative TSN ack acts like a SACK without gaps.
	a.handleSack(now, sackChunk{cumTSN: byteorder.BEUint32(c.value), arwnd: a.peerRwnd + uint32(a.flightSize())})
	if a.state == stateClosed {
		return
	}
	if !a.peerShutdown {
		a.peerShutdown = true
		a.ep.emit(Event{Kind: EventShutdown, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort})
	}
	if a.state == stateShutdownSent {
		a.state = stateShutdownAckSent
		a.sendNow(chunk{typ: ctShutdownAck})
		a.t2 = now.Add(a.rto)
		return
	}
	if a.state != stateShutdownAckSent {
		a.state = stateShutdownReceived
	}
	a.maybeShutdown(now)
}

// maybeShutdown advances shutdown once all outstanding data is acked.
func (a *Association) maybeShutdown(now time.Time) {
	if len(a.inflight) > 0 || len(a.pending) > 0 {
		return
	}
	switch a.state {
	case stateShutdownPending:
		a.state = stateShutdownSent
		a.sendNow(u32Chunk(ctShutdown, a.peerCum))
		a.t2 = now.Add(a.rto)
		a.t3 = time.Time{}
	case stateShutdownReceived:
		a.state = stateShutdownAckSent
		a.sendNow(chunk{typ: ctShutdownAck})
		a.t2 = now.Add(a.rto)
		a.t3 = time.Time{}
	}
}

func (a *Association) handleTimers(now time.Time) {
	due := func(t time.Time) bool { return !t.IsZero() && !now.Before(t) }
	if due(a.t1) {
		a.initAttempts++
		if a.initAttempts > a.ep.cfg.MaxInitAttempts {
			a.fail(EventCantStart, ErrCannotStart)
			return
		}
		a.rto = min(2*a.rto, a.ep.cfg.MaxInitTimeout)
		a.t1 = now.Add(a.rto)
		if a.state == stateCookieWait {
			a.ep.send(a.peer, header{a.ep.cfg.LocalPort, a.peerPort, 0}, []chunk{a.initChunk})
		} else {
			a.sendNow(a.cookieEcho)
		}
	}
	if due(a.t2) {
		a.errors++
		if a.errors > a.ep.cfg.MaxRetrans {
			a.sendNow(chunk{typ: ctAbort})
			a.fail(EventCommLost, ErrTimeout)
			return
		}
		a.rto = min(2*a.rto, a.ep.cfg.RTOMax)
		a.t2 = now.Add(a.rto)
		if a.state == stateShutdownSent {
			a.sendNow(u32Chunk(ctShutdown, a.peerCum))
		} else if a.state == stateShutdownAckSent {
			a.sendNow(chunk{typ: ctShutdownAck})
		}
	}
	if due(a.t3) {
		a.errors++
		if a.errors > a.ep.cfg.MaxRetrans {
			a.sendNow(chunk{typ: ctAbort})
			a.fail(EventCommLost, ErrTimeout)
			return
		}
		a.rto = min(2*a.rto, a.ep.cfg.RTOMax)
		a.ssthresh = max(a.cwnd/2, 4*a.mtu)
		a.cwnd = a.mtu
		a.pba = 0
		a.inFastRec = false
		for _, c := range a.inflight {
			if !c.acked && !c.abandoned {
				c.retx = true
			}
		}
		a.t3 = time.Time{}
		a.prAdvance(now)
		a.transmitRetxOnly(now)
	}
	if due(a.hbTimer) && a.Established() {
		if a.hbOutstanding {
			a.errors++
			if a.errors > a.ep.cfg.MaxRetrans {
				a.sendNow(chunk{typ: ctAbort})
				a.fail(EventCommLost, ErrTimeout)
				return
			}
		}
		a.hbNonce = a.ep.cfg.Rand()
		info := byteorder.BEAppendUint64(nil, a.hbNonce)
		info = byteorder.BEAppendUint64(info, uint64(now.UnixNano()))
		a.ctrl = append(a.ctrl, chunk{typ: ctHeartbeat, value: appendParam(nil, ptHeartbeatInfo, info)})
		a.hbOutstanding = true
		a.hbSent = now
		a.hbTimer = now.Add(a.ep.cfg.HBInterval + a.rto)
	}
	if due(a.sackTimer) {
		a.sackNow = true
	}
	if due(a.reconfTimer) {
		a.reconfRetransmit(now)
	}
	if a.state != stateClosed {
		a.transmit(now)
	}
}

// transmitRetxOnly sends one packet of chunks marked for retransmission
// after a T3 timeout (section 6.3.3: cwnd is one MTU).
func (a *Association) transmitRetxOnly(now time.Time) {
	a.transmit(now)
}

// transmit bundles control chunks, a SACK and DATA into packets.
func (a *Association) transmit(now time.Time) {
	if a.state == stateClosed || a.state == stateCookieWait {
		return
	}
	if a.state == stateCookieEchoed {
		if len(a.ctrl) > 0 {
			a.sendNow(a.ctrl...)
			a.ctrl = nil
		}
		return
	}
	if a.fwdTSNNeed && a.peerFwdTSN {
		a.ctrl = append(a.ctrl, a.buildForwardTSN())
		a.fwdTSNNeed = false
	}
	budget := a.mtu - commonHeaderSize
	var pkt []chunk
	size := 0
	flush := func() {
		if len(pkt) > 0 {
			a.sendNow(pkt...)
			pkt = nil
			size = 0
		}
	}
	add := func(c chunk) {
		n := c.length() + padLen(c.length())
		if size+n > budget {
			flush()
		}
		pkt = append(pkt, c)
		size += n
	}
	for _, c := range a.ctrl {
		add(c)
	}
	a.ctrl = nil
	if a.sackNow || (a.needSack && len(a.pending) > 0) {
		add(a.buildSack())
	}

	canData := a.state == stateEstablished || a.state == stateShutdownPending || a.state == stateShutdownReceived
	sentData := false
	if canData {
		a.prAbandon(now)
		// Retransmissions first, limited by cwnd.
		flight := a.flightSize()
		for _, c := range a.inflight {
			if !c.retx || c.abandoned {
				continue
			}
			if flight >= a.cwnd && sentData {
				break
			}
			c.retx = false
			c.nSent++
			c.sentAt = now
			c.misses = 0
			flight += len(c.payload)
			add(a.dataChunk(c))
			sentData = true
		}
		// New data, limited by cwnd and the peer's window. Chunks on
		// streams with a reset in progress wait (RFC 6525 section 5.1.2).
		burst := 0
		kept := a.pending[:0]
		stop := false
		for i, c := range a.pending {
			if stop {
				kept = append(kept, a.pending[i:]...)
				break
			}
			if c.msg.abandoned {
				a.buffered -= len(c.payload)
				continue
			}
			if c.held {
				kept = append(kept, c)
				continue
			}
			if (flight+len(c.payload) > a.cwnd || int(a.peerRwnd) < len(c.payload) || burst >= 4*a.mtu) && flight > 0 {
				kept = append(kept, c)
				stop = true
				continue
			}
			c.tsn = a.nextTSN
			a.nextTSN++
			if c.flags&dataFlagBegin != 0 && !c.msg.unordered {
				c.msg.ssn = a.outSSN[c.msg.stream]
				a.outSSN[c.msg.stream]++
			}
			c.nSent = 1
			c.sentAt = now
			a.inflight = append(a.inflight, c)
			flight += len(c.payload)
			burst += len(c.payload)
			if int(a.peerRwnd) >= len(c.payload) {
				a.peerRwnd -= uint32(len(c.payload))
			} else {
				a.peerRwnd = 0
			}
			add(a.dataChunk(c))
			sentData = true
		}
		for i := len(kept); i < len(a.pending); i++ {
			a.pending[i] = nil
		}
		a.pending = kept
	}
	flush()
	if sentData {
		if a.t3.IsZero() {
			a.t3 = now.Add(a.rto)
		}
		a.hbTimer = now.Add(a.ep.cfg.HBInterval + a.rto)
	}
	if a.pktsUnacked > 0 && a.sackTimer.IsZero() && !a.sackNow {
		a.sackTimer = now.Add(a.ep.cfg.SackDelay)
	}
	a.reconfMaybeSend(now)
}

func (a *Association) dataChunk(c *outChunk) chunk {
	d := dataChunk{flags: c.flags, tsn: c.tsn, stream: c.msg.stream, ssn: c.msg.ssn, ppid: c.ppid, payload: c.payload}
	return d.chunk()
}
