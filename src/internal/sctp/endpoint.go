// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"errors"
	"internal/byteorder"
	"net/netip"
	"time"
)

// Errors returned by the engine.
var (
	ErrClosed          = errors.New("sctp: association is closed")
	ErrWouldBlock      = errors.New("sctp: send buffer full")
	ErrInvalidStream   = errors.New("sctp: invalid stream identifier")
	ErrEmptyMessage    = errors.New("sctp: empty message")
	ErrNoAssociation   = errors.New("sctp: no such association")
	ErrAddrInUse       = errors.New("sctp: association to this peer already exists")
	ErrTimeout         = errors.New("sctp: association timed out")
	ErrAborted         = errors.New("sctp: association aborted by peer")
	ErrCannotStart     = errors.New("sctp: could not establish association")
	ErrUnsupported     = errors.New("sctp: not supported by the peer")
	ErrResetInProgress = errors.New("sctp: stream reconfiguration already in progress")
)

// Config holds endpoint and association parameters. Zero fields take the
// RFC 9260 section 16 defaults.
type Config struct {
	// Rand returns random bits for verification tags, initial TSNs and
	// the cookie key. It is required.
	Rand func() uint64

	LocalPort uint16 // SCTP port of this endpoint
	Accept    bool   // accept incoming associations

	MTU             int // largest SCTP packet (UDP payload); default 1200
	NumOStreams     uint16
	MaxInStreams    uint16
	MaxInitAttempts int
	MaxInitTimeout  time.Duration
	RTOInitial      time.Duration
	RTOMin          time.Duration
	RTOMax          time.Duration
	RecvBuffer      int // advertised receiver window
	SendBuffer      int // per-association send buffer
	SackDelay       time.Duration
	SackFreq        int
	HBInterval      time.Duration
	MaxRetrans      int
	CookieLife      time.Duration
}

func (c *Config) fill() {
	def := func(p *time.Duration, d time.Duration) {
		if *p <= 0 {
			*p = d
		}
	}
	if c.MTU <= 0 {
		c.MTU = 1200
	}
	if c.MTU < 256 {
		c.MTU = 256
	}
	if c.NumOStreams == 0 {
		c.NumOStreams = 10
	}
	if c.MaxInStreams == 0 {
		c.MaxInStreams = 65535
	}
	if c.MaxInitAttempts <= 0 {
		c.MaxInitAttempts = 8
	}
	def(&c.RTOInitial, time.Second)
	def(&c.RTOMin, time.Second)
	def(&c.RTOMax, 60*time.Second)
	def(&c.MaxInitTimeout, c.RTOMax)
	if c.RecvBuffer <= 0 {
		c.RecvBuffer = 1 << 20
	}
	if c.SendBuffer <= 0 {
		c.SendBuffer = 1 << 20
	}
	def(&c.SackDelay, 200*time.Millisecond)
	if c.SackFreq <= 0 {
		c.SackFreq = 2
	}
	def(&c.HBInterval, 30*time.Second)
	if c.MaxRetrans <= 0 {
		c.MaxRetrans = 10
	}
	def(&c.CookieLife, 60*time.Second)
}

// Transmit is a packet to send to a peer's UDP address.
type Transmit struct {
	To   netip.AddrPort
	Data []byte
}

// Message is a user message delivered by an association.
type Message struct {
	Assoc     int32
	Peer      netip.AddrPort
	PeerPort  uint16
	Stream    uint16
	SSN       uint16
	PPID      uint32
	TSN       uint32
	CumTSN    uint32
	Unordered bool
	Data      []byte

	// Partial reports that Data is a piece of a larger message and more
	// pieces follow. The engine delivers a message in pieces when it
	// would not otherwise fit in the receive window.
	Partial bool

	// Aborted marks an empty message that ends a partial delivery whose
	// remaining data the sender abandoned (PR-SCTP).
	Aborted bool
}

// EventKind identifies an association event.
type EventKind int

const (
	EventCommUp EventKind = iota
	EventCommLost
	EventRestart
	EventShutdownComplete
	EventCantStart
	EventShutdown // the peer started a graceful shutdown
	EventSenderDry
	EventStreamReset
	EventStreamsAdded
)

// Event reports an association state change.
type Event struct {
	Kind       EventKind
	Assoc      int32
	Peer       netip.AddrPort
	PeerPort   uint16
	InStreams  uint16
	OutStreams uint16
	Err        error
	Incoming   bool     // EventStreamReset: the peer reset its outgoing streams
	Streams    []uint16 // EventStreamReset: streams reset (nil = all)
	Failed     bool     // EventStreamReset / EventStreamsAdded: request denied
}

type peerKey struct {
	ip   netip.Addr
	port uint16 // peer SCTP port
}

// Endpoint is an SCTP endpoint bound to one local SCTP port. It is not
// safe for concurrent use.
type Endpoint struct {
	cfg       Config
	cookieKey [16]byte
	assocs    map[int32]*Association
	byTag     map[uint32]*Association
	byPeer    map[peerKey]*Association
	nextID    int32
	out       []Transmit
	msgs      []Message
	events    []Event
}

// NewEndpoint returns an endpoint for cfg.
func NewEndpoint(cfg Config) *Endpoint {
	cfg.fill()
	e := &Endpoint{
		cfg:    cfg,
		assocs: make(map[int32]*Association),
		byTag:  make(map[uint32]*Association),
		byPeer: make(map[peerKey]*Association),
	}
	byteorder.LEPutUint64(e.cookieKey[0:], cfg.Rand())
	byteorder.LEPutUint64(e.cookieKey[8:], cfg.Rand())
	return e
}

// Config returns the endpoint's current configuration.
func (e *Endpoint) Config() Config { return e.cfg }

// SetAccept controls whether incoming INITs start associations.
func (e *Endpoint) SetAccept(on bool) { e.cfg.Accept = on }

// SetInit sets association setup parameters for new associations.
// Zero values keep the current setting.
func (e *Endpoint) SetInit(numOut, maxIn uint16, maxAttempts int, maxInitTimeout time.Duration) {
	if numOut != 0 {
		e.cfg.NumOStreams = numOut
	}
	if maxIn != 0 {
		e.cfg.MaxInStreams = maxIn
	}
	if maxAttempts > 0 {
		e.cfg.MaxInitAttempts = maxAttempts
	}
	if maxInitTimeout > 0 {
		e.cfg.MaxInitTimeout = maxInitTimeout
	}
}

// SetRTO sets retransmission timeout bounds. Zero values keep the
// current setting. Existing associations adopt the new bounds.
func (e *Endpoint) SetRTO(initial, min, max time.Duration) {
	if initial > 0 {
		e.cfg.RTOInitial = initial
	}
	if min > 0 {
		e.cfg.RTOMin = min
	}
	if max > 0 {
		e.cfg.RTOMax = max
	}
	for _, a := range e.assocs {
		a.rto = clampDur(a.rto, e.cfg.RTOMin, e.cfg.RTOMax)
	}
}

// SetDelayedSack sets the SACK delay and frequency. Zero values keep the
// current setting.
func (e *Endpoint) SetDelayedSack(delay time.Duration, freq int) {
	if delay > 0 {
		e.cfg.SackDelay = delay
	}
	if freq > 0 {
		e.cfg.SackFreq = freq
	}
}

// SetBuffers sets the receive window and send buffer for new
// associations. Zero values keep the current setting.
func (e *Endpoint) SetBuffers(recv, send int) {
	if recv > 0 {
		e.cfg.RecvBuffer = recv
	}
	if send > 0 {
		e.cfg.SendBuffer = send
	}
}

// Association returns the association with the given ID, or nil.
func (e *Endpoint) Association(id int32) *Association { return e.assocs[id] }

// Lookup returns the association with a peer, or nil.
func (e *Endpoint) Lookup(peer netip.AddrPort, peerPort uint16) *Association {
	return e.byPeer[peerKey{peer.Addr().Unmap(), peerPort}]
}

// Associations returns the IDs of all associations, in ascending order.
func (e *Endpoint) Associations() []int32 {
	ids := make([]int32, 0, len(e.assocs))
	for id := range e.assocs {
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

// Idle reports whether the endpoint has no associations.
func (e *Endpoint) Idle() bool { return len(e.assocs) == 0 }

// PollTransmit returns the next packet to send.
func (e *Endpoint) PollTransmit() (Transmit, bool) {
	if len(e.out) == 0 {
		return Transmit{}, false
	}
	t := e.out[0]
	e.out[0] = Transmit{}
	e.out = e.out[1:]
	return t, true
}

// PendingMessage reports whether a message is ready, and its length.
func (e *Endpoint) PendingMessage() (int, bool) {
	if len(e.msgs) == 0 {
		return 0, false
	}
	return len(e.msgs[0].Data), true
}

// PeekMessage returns the next delivered message without consuming it.
func (e *Endpoint) PeekMessage() (Message, bool) {
	if len(e.msgs) == 0 {
		return Message{}, false
	}
	return e.msgs[0], true
}

// PeekMessageAt returns the i'th queued message without consuming it.
func (e *Endpoint) PeekMessageAt(i int) (Message, bool) {
	if i >= len(e.msgs) {
		return Message{}, false
	}
	return e.msgs[i], true
}

// PollMessage returns the next delivered message and reopens the
// receiver window it occupied.
func (e *Endpoint) PollMessage(now time.Time) (Message, bool) {
	if len(e.msgs) == 0 {
		return Message{}, false
	}
	m := e.msgs[0]
	e.msgs[0] = Message{}
	e.msgs = e.msgs[1:]
	if a := e.assocs[m.Assoc]; a != nil {
		a.consumed(now, len(m.Data))
	}
	return m, true
}

// PollEvent returns the next association event.
func (e *Endpoint) PollEvent() (Event, bool) {
	if len(e.events) == 0 {
		return Event{}, false
	}
	ev := e.events[0]
	e.events[0] = Event{}
	e.events = e.events[1:]
	return ev, true
}

func (e *Endpoint) emit(ev Event) { e.events = append(e.events, ev) }

func (e *Endpoint) send(to netip.AddrPort, h header, chunks []chunk) {
	e.out = append(e.out, Transmit{To: to, Data: marshalPacket(h, chunks)})
}

func (e *Endpoint) randTag() uint32 {
	for {
		t := uint32(e.cfg.Rand())
		if t != 0 && e.byTag[t] == nil {
			return t
		}
	}
}

func (e *Endpoint) newAssoc(peer netip.AddrPort, peerPort uint16) *Association {
	e.nextID++
	if e.nextID <= 0 {
		e.nextID = 1
	}
	for e.assocs[e.nextID] != nil {
		e.nextID++
	}
	a := &Association{
		ep:       e,
		id:       e.nextID,
		peer:     peer,
		peerPort: peerPort,
		myTag:    e.randTag(),
		mtu:      e.cfg.MTU,
		rto:      clampDur(e.cfg.RTOInitial, e.cfg.RTOMin, e.cfg.RTOMax),
		sndBuf:   e.cfg.SendBuffer,
		rcvBuf:   e.cfg.RecvBuffer,
	}
	a.nextTSN = uint32(e.cfg.Rand())
	a.cumAck = a.nextTSN - 1
	a.advPeerAck = a.cumAck
	a.cwnd = min(4*a.mtu, max(2*a.mtu, 4380))
	a.ssthresh = 1 << 30
	a.instreams = make(map[uint16]*inStream)
	e.assocs[a.id] = a
	e.byTag[a.myTag] = a
	e.byPeer[peerKey{peer.Addr().Unmap(), peerPort}] = a
	return a
}

func (e *Endpoint) remove(a *Association) {
	if e.assocs[a.id] != a {
		return
	}
	delete(e.assocs, a.id)
	if e.byTag[a.myTag] == a {
		delete(e.byTag, a.myTag)
	}
	k := peerKey{a.peer.Addr().Unmap(), a.peerPort}
	if e.byPeer[k] == a {
		delete(e.byPeer, k)
	}
	a.state = stateClosed
}

// Connect starts an association with a peer.
func (e *Endpoint) Connect(now time.Time, peer netip.AddrPort, peerPort uint16) (*Association, error) {
	if peerPort == 0 {
		return nil, errors.New("sctp: missing peer port")
	}
	if e.Lookup(peer, peerPort) != nil {
		return nil, ErrAddrInUse
	}
	a := e.newAssoc(peer, peerPort)
	a.state = stateCookieWait
	a.numOut = e.cfg.NumOStreams
	a.numIn = e.cfg.MaxInStreams
	a.sendInit(now)
	return a, nil
}

// Close starts a graceful shutdown of every association.
func (e *Endpoint) Close(now time.Time) {
	for _, id := range e.Associations() {
		e.assocs[id].Shutdown(now)
	}
}

// Abort aborts every association.
func (e *Endpoint) Abort(now time.Time) {
	for _, id := range e.Associations() {
		e.assocs[id].Abort(now)
	}
}

// NextDeadline returns the earliest timer deadline, or the zero time.
func (e *Endpoint) NextDeadline() time.Time {
	var d time.Time
	for _, a := range e.assocs {
		for _, t := range [...]time.Time{a.t1, a.t2, a.t3, a.hbTimer, a.sackTimer, a.reconfTimer} {
			if !t.IsZero() && (d.IsZero() || t.Before(d)) {
				d = t
			}
		}
	}
	return d
}

// HandleTimers runs the timers that have expired at now.
func (e *Endpoint) HandleTimers(now time.Time) {
	for _, id := range e.Associations() {
		if a := e.assocs[id]; a != nil {
			a.handleTimers(now)
		}
	}
}

// Input processes a datagram received from a peer's UDP address.
// Malformed packets are dropped; they never affect other associations.
func (e *Endpoint) Input(now time.Time, from netip.AddrPort, b []byte) {
	h, chunks, err := parsePacket(b)
	if err != nil || h.srcPort == 0 || h.dstPort != e.cfg.LocalPort {
		return
	}
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())

	// INIT must be alone in its packet, with a zero verification tag.
	if chunks[0].typ == ctInit {
		if h.vtag != 0 || len(chunks) != 1 {
			return
		}
		e.handleInit(now, from, h, chunks[0])
		return
	}

	var a *Association
	switch {
	case h.vtag != 0 && e.byTag[h.vtag] != nil:
		a = e.byTag[h.vtag]
		if a.peer.Addr() != from.Addr() || a.peerPort != h.srcPort {
			a = nil
		}
	case chunks[0].typ == ctAbort || chunks[0].typ == ctShutdownComplete:
		// T bit set: the tag is the peer's own.
		if c := e.byPeer[peerKey{from.Addr(), h.srcPort}]; c != nil && chunks[0].flags&flagT != 0 && h.vtag == c.peerTag {
			a = c
		}
	}

	if a == nil {
		if chunks[0].typ == ctCookieEcho {
			a = e.handleCookieEcho(now, from, h, chunks[0])
			if a == nil {
				return
			}
			chunks = chunks[1:]
		} else {
			e.outOfTheBlue(from, h, chunks)
			return
		}
	}
	if from.Port() != a.peer.Port() {
		// RFC 6951 section 5.4: follow the peer's encapsulation port.
		a.peer = from
	}
	a.input(now, h, chunks)
	if a.state != stateClosed {
		a.transmit(now)
	}
}

// outOfTheBlue answers a packet that matches no association
// (RFC 9260 section 8.4).
func (e *Endpoint) outOfTheBlue(from netip.AddrPort, h header, chunks []chunk) {
	for _, c := range chunks {
		switch c.typ {
		case ctAbort, ctShutdownComplete, ctCookieAck, ctError:
			return
		case ctShutdownAck:
			e.send(from, header{e.cfg.LocalPort, h.srcPort, h.vtag}, []chunk{{typ: ctShutdownComplete, flags: flagT}})
			return
		}
	}
	e.send(from, header{e.cfg.LocalPort, h.srcPort, h.vtag}, []chunk{{typ: ctAbort, flags: flagT}})
}

func (e *Endpoint) localInit(tag, tsn uint32, numOut, maxIn uint16, rwnd int) (initChunk, []byte) {
	in := initChunk{initTag: tag, arwnd: uint32(rwnd), numOut: numOut, maxIn: maxIn, initialTSN: tsn}
	var extra []byte
	// Forward-TSN-Supported goes first: sctp-proto (rust-sctp's and
	// webrtc-rs's engine) skips a trailing 4-byte parameter when parsing
	// INIT, miscomputes the chunk length and drops the whole packet.
	extra = appendParam(extra, ptForwardTSNSupport, nil)
	extra = appendParam(extra, ptSupportedExt, []byte{ctForwardTSN, ctReconfig})
	return in, extra
}

func (e *Endpoint) handleInit(now time.Time, from netip.AddrPort, h header, c chunk) {
	in, err := parseInit(c)
	if err != nil || in.initTag == 0 || in.numOut == 0 || in.maxIn == 0 {
		if err == nil && in.initTag != 0 {
			e.send(from, header{e.cfg.LocalPort, h.srcPort, in.initTag},
				[]chunk{causeChunk(ctAbort, 0, causeInvalidMandatory, nil)})
		}
		return
	}
	existing := e.byPeer[peerKey{from.Addr(), h.srcPort}]
	if existing == nil && !e.cfg.Accept {
		e.send(from, header{e.cfg.LocalPort, h.srcPort, in.initTag}, []chunk{{typ: ctAbort}})
		return
	}
	numOut, maxIn := e.cfg.NumOStreams, e.cfg.MaxInStreams
	ck := cookie{
		created:        now,
		peerTag:        in.initTag,
		peerInitialTSN: in.initialTSN,
		peerArwnd:      in.arwnd,
		numOut:         min(numOut, in.maxIn),
		numIn:          min(maxIn, in.numOut),
		peerPort:       h.srcPort,
		localPort:      e.cfg.LocalPort,
		peerIP:         from.Addr(),
	}
	if in.supportsChunk(ctForwardTSN) {
		ck.flags |= cookieFlagPeerFwdTSN
	}
	if in.supportsChunk(ctReconfig) {
		ck.flags |= cookieFlagPeerReconfig
	}
	var myTag, myTSN uint32
	if existing != nil && (existing.state == stateCookieWait || existing.state == stateCookieEchoed) {
		// Initialization collision (section 5.2.1): answer with the tag
		// and TSN we already announced in our own INIT.
		myTag, myTSN = existing.myTag, existing.nextTSN
	} else {
		// New association, or a peer restart (section 5.2.2): fresh values.
		myTag, myTSN = e.randTag(), uint32(e.cfg.Rand())
	}
	ck.myTag, ck.myInitialTSN = myTag, myTSN
	ack, extra := e.localInit(myTag, myTSN, numOut, maxIn, e.cfg.RecvBuffer)
	extra = appendParam(extra, ptStateCookie, ck.marshal(&e.cookieKey))
	e.send(from, header{e.cfg.LocalPort, h.srcPort, in.initTag}, []chunk{ack.chunk(ctInitAck, extra)})
}

// handleCookieEcho validates a COOKIE ECHO that matched no association
// by tag and returns the association it establishes.
func (e *Endpoint) handleCookieEcho(now time.Time, from netip.AddrPort, h header, c chunk) *Association {
	ck, ok := parseCookie(&e.cookieKey, c.value)
	if !ok || ck.myTag != h.vtag || ck.peerPort != h.srcPort || ck.localPort != e.cfg.LocalPort || ck.peerIP != from.Addr() {
		return nil
	}
	if now.Sub(ck.created) > e.cfg.CookieLife || ck.created.Sub(now) > time.Minute {
		staleness := byteorder.BEAppendUint32(nil, uint32(now.Sub(ck.created).Microseconds()))
		e.send(from, header{e.cfg.LocalPort, h.srcPort, ck.peerTag},
			[]chunk{causeChunk(ctError, 0, causeStaleCookie, staleness)})
		return nil
	}
	restart := false
	if old := e.byPeer[peerKey{from.Addr(), h.srcPort}]; old != nil {
		if old.peerTag == ck.peerTag && old.state != stateCookieWait && old.state != stateCookieEchoed {
			// A duplicate of a cookie we already accepted, under a tag we
			// have since replaced: nothing to do.
			return nil
		}
		// Peer restart: the old association is gone, and the new one is
		// reported as a restart.
		restart = old.Established()
		e.remove(old)
		if !restart {
			e.emit(Event{Kind: EventCommLost, Assoc: old.id, Peer: old.peer, PeerPort: old.peerPort, Err: ErrAborted})
		}
	}
	if !e.cfg.Accept {
		return nil
	}
	a := e.newAssoc(from, h.srcPort)
	delete(e.byTag, a.myTag)
	a.myTag = ck.myTag
	e.byTag[a.myTag] = a
	a.nextTSN = ck.myInitialTSN
	a.cumAck = a.nextTSN - 1
	a.advPeerAck = a.cumAck
	a.applyPeer(ck.peerTag, ck.peerInitialTSN, ck.peerArwnd, ck.numOut, ck.numIn,
		ck.flags&cookieFlagPeerFwdTSN != 0, ck.flags&cookieFlagPeerReconfig != 0)
	a.establish(now, restart)
	a.ctrl = append(a.ctrl, chunk{typ: ctCookieAck})
	return a
}
