// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"internal/byteorder"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

func TestSipHash128Vectors(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	// From the SipHash reference implementation (vectors_sip128).
	want := []string{
		"a3817f04ba25a8e66df67214c7550293",
		"da87c1d86b99af44347659119b22fc45",
	}
	for n, w := range want {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i)
		}
		got := siphash128(&key, msg)
		if hex.EncodeToString(got[:]) != w {
			t.Errorf("siphash128(%d bytes) = %x, want %s", n, got, w)
		}
	}
}

func TestChecksumKnownValue(t *testing.T) {
	// RFC 3720 appendix B.4: CRC32c of 32 zero bytes is 0x8a9136aa.
	// checksum treats bytes 8-11 as zero, so this covers 32 zero bytes.
	b := make([]byte, 32)
	if got := checksum(b); got != 0x8a9136aa {
		t.Fatalf("checksum = %#x, want 0x8a9136aa", got)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	d := dataChunk{flags: dataFlagBegin | dataFlagEnd, tsn: 7, stream: 3, ssn: 9, ppid: 51, payload: []byte("hello")}
	s := sackChunk{cumTSN: 100, arwnd: 5000, gaps: []gapBlock{{2, 3}, {5, 9}}, dups: []uint32{98}}
	f := forwardTSNChunk{newCumTSN: 77, streams: []streamSSN{{1, 2}, {3, 4}}}
	in := initChunk{initTag: 1, arwnd: 2, numOut: 3, maxIn: 4, initialTSN: 5}
	pkt := marshalPacket(header{5000, 6000, 0xdeadbeef}, []chunk{d.chunk(), s.chunk(), f.chunk(), in.chunk(ctInit, appendParam(nil, ptForwardTSNSupport, nil))})
	h, cs, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if h != (header{5000, 6000, 0xdeadbeef}) || len(cs) != 4 {
		t.Fatalf("header %+v, %d chunks", h, len(cs))
	}
	d2, _ := parseData(cs[0])
	if d2.tsn != 7 || d2.stream != 3 || d2.ssn != 9 || d2.ppid != 51 || string(d2.payload) != "hello" || d2.flags != d.flags {
		t.Errorf("data = %+v", d2)
	}
	s2, _ := parseSack(cs[1])
	if s2.cumTSN != 100 || s2.arwnd != 5000 || len(s2.gaps) != 2 || s2.gaps[1] != (gapBlock{5, 9}) || len(s2.dups) != 1 {
		t.Errorf("sack = %+v", s2)
	}
	f2, _ := parseForwardTSN(cs[2])
	if f2.newCumTSN != 77 || len(f2.streams) != 2 || f2.streams[1] != (streamSSN{3, 4}) {
		t.Errorf("fwd = %+v", f2)
	}
	in2, _ := parseInit(cs[3])
	if in2.initTag != 1 || in2.maxIn != 4 || !in2.supportsChunk(ctForwardTSN) {
		t.Errorf("init = %+v", in2)
	}
	pkt[len(pkt)-1] ^= 1
	if _, _, err := parsePacket(pkt); err != errBadChecksum {
		t.Errorf("corrupted packet: err = %v", err)
	}
}

func TestCookieTamper(t *testing.T) {
	key := [16]byte{1, 2, 3}
	ck := cookie{created: time.UnixMilli(123456), myTag: 1, peerTag: 2, numOut: 3, numIn: 4, peerPort: 5, localPort: 6, peerIP: netip.MustParseAddr("192.0.2.1")}
	b := ck.marshal(&key)
	got, ok := parseCookie(&key, b)
	if !ok || got.peerIP != ck.peerIP || got.myTag != 1 || !got.created.Equal(ck.created) {
		t.Fatalf("parseCookie = %+v, %v", got, ok)
	}
	for i := range b {
		b2 := bytes.Clone(b)
		b2[i] ^= 0x80
		if _, ok := parseCookie(&key, b2); ok {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
}

// sim connects two endpoints over a simulated network with a fake clock.
type sim struct {
	t      testing.TB
	now    time.Time
	rnd    *rand.Rand
	eps    map[netip.AddrPort]*Endpoint
	queue  []simPkt
	loss   float64
	dup    float64
	jitter time.Duration
	delay  time.Duration
	drop   func(from, to netip.AddrPort, data []byte) bool
	sent   int
}

type simPkt struct {
	at       time.Time
	from, to netip.AddrPort
	data     []byte
}

func newSim(t testing.TB, seed uint64) *sim {
	return &sim{
		t:     t,
		now:   time.Unix(1_700_000_000, 0),
		rnd:   rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		eps:   map[netip.AddrPort]*Endpoint{},
		delay: 10 * time.Millisecond,
	}
}

func (s *sim) endpoint(addr string, accept bool, mod func(*Config)) (*Endpoint, netip.AddrPort) {
	ap := netip.MustParseAddrPort(addr)
	cfg := Config{Rand: s.rnd.Uint64, LocalPort: 5000, Accept: accept}
	if mod != nil {
		mod(&cfg)
	}
	e := NewEndpoint(cfg)
	s.eps[ap] = e
	return e, ap
}

func (s *sim) collect() {
	for from, e := range s.eps {
		for {
			tr, ok := e.PollTransmit()
			if !ok {
				break
			}
			s.sent++
			if s.drop != nil && s.drop(from, tr.To, tr.Data) {
				continue
			}
			if s.rnd.Float64() < s.loss {
				continue
			}
			n := 1
			if s.rnd.Float64() < s.dup {
				n = 2
			}
			for range n {
				d := s.delay
				if s.jitter > 0 {
					d += time.Duration(s.rnd.Int64N(int64(s.jitter)))
				}
				s.queue = append(s.queue, simPkt{s.now.Add(d), from, tr.To, bytes.Clone(tr.Data)})
			}
		}
	}
}

// step advances to the next event. It returns false if nothing is left.
func (s *sim) step() bool {
	s.collect()
	next := time.Time{}
	for _, p := range s.queue {
		if next.IsZero() || p.at.Before(next) {
			next = p.at
		}
	}
	for _, e := range s.eps {
		if d := e.NextDeadline(); !d.IsZero() && (next.IsZero() || d.Before(next)) {
			next = d
		}
	}
	if next.IsZero() {
		return false
	}
	if next.After(s.now) {
		s.now = next
	}
	var keep []simPkt
	var due []simPkt
	for _, p := range s.queue {
		if p.at.After(s.now) {
			keep = append(keep, p)
		} else {
			due = append(due, p)
		}
	}
	s.queue = keep
	for _, p := range due {
		if e := s.eps[p.to]; e != nil {
			e.Input(s.now, p.from, p.data)
		}
	}
	for _, e := range s.eps {
		e.HandleTimers(s.now)
	}
	s.collect()
	return true
}

// runUntil steps until cond holds or the virtual time limit passes.
func (s *sim) runUntil(limit time.Duration, cond func() bool) {
	s.t.Helper()
	end := s.now.Add(limit)
	for !cond() {
		if !s.step() || s.now.After(end) {
			s.t.Fatalf("condition not met after %v of virtual time", limit)
		}
	}
}

func drainEvents(e *Endpoint) []Event {
	var evs []Event
	for {
		ev, ok := e.PollEvent()
		if !ok {
			return evs
		}
		evs = append(evs, ev)
	}
}

func hasEvent(evs []Event, k EventKind) bool {
	for _, ev := range evs {
		if ev.Kind == k {
			return true
		}
	}
	return false
}

func connectPair(t *testing.T, s *sim) (client, server *Endpoint, ca *Association, srvAddr netip.AddrPort) {
	t.Helper()
	client, _ = s.endpoint("192.0.2.1:40000", false, nil)
	server, srvAddr = s.endpoint("192.0.2.2:5000", true, nil)
	ca, err := client.Connect(s.now, srvAddr, 5000)
	if err != nil {
		t.Fatal(err)
	}
	s.runUntil(time.Minute, func() bool { return ca.Established() && !server.Idle() })
	return client, server, ca, srvAddr
}

func TestHandshakeAndEcho(t *testing.T) {
	s := newSim(t, 1)
	client, server, ca, _ := connectPair(t, s)
	if !hasEvent(drainEvents(client), EventCommUp) || !hasEvent(drainEvents(server), EventCommUp) {
		t.Fatal("missing COMM_UP")
	}
	if err := ca.Send(s.now, []byte("ping"), SendInfo{Stream: 1, PPID: 42}); err != nil {
		t.Fatal(err)
	}
	var m Message
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = server.PollMessage(s.now)
		return ok
	})
	if string(m.Data) != "ping" || m.Stream != 1 || m.PPID != 42 {
		t.Fatalf("got %+v", m)
	}
	sa := server.Association(m.Assoc)
	if err := sa.Send(s.now, []byte("pong"), SendInfo{Stream: 1, PPID: 43}); err != nil {
		t.Fatal(err)
	}
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = client.PollMessage(s.now)
		return ok
	})
	if string(m.Data) != "pong" || m.PPID != 43 {
		t.Fatalf("got %+v", m)
	}
}

func TestReject(t *testing.T) {
	s := newSim(t, 2)
	client, _ := s.endpoint("192.0.2.1:40000", false, nil)
	_, srv := s.endpoint("192.0.2.2:5000", false, nil)
	ca, _ := client.Connect(s.now, srv, 5000)
	s.runUntil(time.Minute, func() bool { return ca.Closed() })
	if !hasEvent(drainEvents(client), EventCommLost) {
		t.Fatal("no COMM_LOST after ABORT")
	}
}

func TestInitTimeout(t *testing.T) {
	s := newSim(t, 3)
	client, _ := s.endpoint("192.0.2.1:40000", false, func(c *Config) { c.MaxInitAttempts = 3 })
	ca, _ := client.Connect(s.now, netip.MustParseAddrPort("192.0.2.9:5000"), 5000)
	s.runUntil(time.Hour, func() bool { return ca.Closed() })
	if !hasEvent(drainEvents(client), EventCantStart) {
		t.Fatal("no CANT_STR_ASSOC")
	}
}

type flow struct {
	sent map[uint16][][]byte
	got  map[uint16][][]byte
}

func checkTransfer(t *testing.T, seed uint64, loss, dup float64, jitter time.Duration, n int) {
	s := newSim(t, seed)
	client, server, ca, _ := connectPair(t, s)
	s.loss, s.dup, s.jitter = loss, dup, jitter
	// At heavy loss the default limit of 10 consecutive retransmissions
	// is reached by chance (about 0.5^11 per chunk with 30% loss each
	// way), which correctly ends the association. Allow more here so
	// the test checks data integrity, not that probability.
	client.cfg.MaxRetrans, server.cfg.MaxRetrans = 40, 40
	f := flow{sent: map[uint16][][]byte{}, got: map[uint16][][]byte{}}
	var unordered [][]byte
	unorderedGot := map[string]bool{}
	queued := 0
	total := 0
	for total < n {
		for queued < n && ca.Writable(4000) {
			stream := uint16(queued % 4)
			size := 1 + s.rnd.IntN(3000)
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(queued + i)
			}
			copy(msg, fmt.Sprintf("%06d", queued))
			uo := queued%7 == 0
			if err := ca.Send(s.now, msg, SendInfo{Stream: stream, PPID: uint32(queued), Unordered: uo}); err != nil {
				t.Fatal(err)
			}
			if uo {
				unordered = append(unordered, msg)
			} else {
				f.sent[stream] = append(f.sent[stream], msg)
			}
			queued++
		}
		if !s.step() {
			sa := server.assocs
			for _, a := range sa {
				t.Logf("server assoc state=%v peerCum=%d held=%d unread=%d pd=%v recvd=%d", a.state, a.peerCum, a.rcvHeld, a.unread, a.pd, len(a.recvd))
			}
			t.Logf("client state=%v pending=%d inflight=%d cwnd=%d rwnd=%d t3=%v closed=%v cevents=%+v sevents=%+v", ca.state, len(ca.pending), len(ca.inflight), ca.cwnd, ca.peerRwnd, ca.t3, ca.Closed(), drainEvents(client), drainEvents(server))
			t.Fatal("simulation stalled")
		}
		for {
			m, ok := server.PollMessage(s.now)
			if !ok {
				break
			}
			total++
			if m.Unordered {
				unorderedGot[string(m.Data)] = true
			} else {
				f.got[m.Stream] = append(f.got[m.Stream], m.Data)
			}
		}
		if s.now.Sub(time.Unix(1_700_000_000, 0)) > 2*time.Hour {
			t.Fatalf("transfer incomplete: %d of %d messages", total, n)
		}
	}
	for st, msgs := range f.sent {
		if len(f.got[st]) != len(msgs) {
			t.Fatalf("stream %d: got %d messages, want %d", st, len(f.got[st]), len(msgs))
		}
		for i := range msgs {
			if !bytes.Equal(msgs[i], f.got[st][i]) {
				t.Fatalf("stream %d message %d differs (got prefix %q, want %q)", st, i, f.got[st][i][:6], msgs[i][:6])
			}
		}
	}
	for _, m := range unordered {
		if !unorderedGot[string(m)] {
			t.Fatalf("unordered message %q missing", m[:6])
		}
	}
	_ = client
}

func TestTransferClean(t *testing.T) { checkTransfer(t, 10, 0, 0, 0, 500) }

func TestTransferLossy(t *testing.T) {
	for seed := uint64(20); seed < 26; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			checkTransfer(t, seed, 0.1, 0.05, 30*time.Millisecond, 300)
		})
	}
}

func TestTransferHeavyLoss(t *testing.T) { checkTransfer(t, 30, 0.3, 0.1, 50*time.Millisecond, 100) }

func TestLargeMessage(t *testing.T) {
	s := newSim(t, 4)
	_, server, ca, _ := connectPair(t, s)
	s.loss = 0.05
	msg := make([]byte, 200_000)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	if err := ca.Send(s.now, msg, SendInfo{}); err != nil {
		t.Fatal(err)
	}
	var m Message
	s.runUntil(time.Hour, func() bool {
		var ok bool
		m, ok = server.PollMessage(s.now)
		return ok
	})
	if !bytes.Equal(m.Data, msg) {
		t.Fatal("large message corrupted")
	}
}

func TestGracefulShutdown(t *testing.T) {
	s := newSim(t, 5)
	client, server, ca, _ := connectPair(t, s)
	drainEvents(client)
	drainEvents(server)
	for i := range 20 {
		ca.Send(s.now, []byte(fmt.Sprint("m", i)), SendInfo{})
	}
	ca.Shutdown(s.now)
	n := 0
	s.runUntil(time.Minute, func() bool {
		for {
			if _, ok := server.PollMessage(s.now); !ok {
				break
			}
			n++
		}
		return client.Idle() && server.Idle()
	})
	for {
		if _, ok := server.PollMessage(s.now); !ok {
			break
		}
		n++
	}
	if n != 20 {
		t.Fatalf("got %d messages before shutdown, want 20", n)
	}
	if !hasEvent(drainEvents(client), EventShutdownComplete) {
		t.Error("client: no SHUTDOWN_COMP")
	}
	evs := drainEvents(server)
	if !hasEvent(evs, EventShutdown) || !hasEvent(evs, EventShutdownComplete) {
		t.Errorf("server events = %+v", evs)
	}
}

func TestAbort(t *testing.T) {
	s := newSim(t, 6)
	client, server, ca, _ := connectPair(t, s)
	ca.Abort(s.now)
	s.runUntil(time.Minute, func() bool { return server.Idle() })
	if !hasEvent(drainEvents(server), EventCommLost) {
		t.Fatal("server: no COMM_LOST")
	}
	_ = client
}

func TestPeerUnreachable(t *testing.T) {
	s := newSim(t, 7)
	client, _, ca, _ := connectPair(t, s)
	ca.Send(s.now, []byte("x"), SendInfo{})
	s.loss = 1
	ca.Send(s.now, []byte("y"), SendInfo{})
	s.runUntil(24*time.Hour, func() bool { return ca.Closed() })
	evs := drainEvents(client)
	if !hasEvent(evs, EventCommLost) {
		t.Fatalf("events = %+v", evs)
	}
}

func TestInitCollision(t *testing.T) {
	s := newSim(t, 8)
	a, aAddr := s.endpoint("192.0.2.1:5000", true, nil)
	b, bAddr := s.endpoint("192.0.2.2:5000", true, nil)
	aa, _ := a.Connect(s.now, bAddr, 5000)
	ba, _ := b.Connect(s.now, aAddr, 5000)
	s.runUntil(time.Minute, func() bool {
		return aa.Established() && ba.Established() && len(a.assocs) == 1 && len(b.assocs) == 1
	})
	aa.Send(s.now, []byte("from a"), SendInfo{})
	var m Message
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = b.PollMessage(s.now)
		return ok
	})
	if string(m.Data) != "from a" {
		t.Fatalf("got %q", m.Data)
	}
}

func TestPeerRestart(t *testing.T) {
	s := newSim(t, 9)
	_, server, _, srvAddr := connectPair(t, s)
	drainEvents(server)
	// The client host restarts: a new endpoint at the same address.
	client2, _ := s.endpoint("192.0.2.1:40000", false, nil)
	ca2, _ := client2.Connect(s.now, srvAddr, 5000)
	s.runUntil(time.Minute, func() bool { return ca2.Established() })
	evs := drainEvents(server)
	if !hasEvent(evs, EventRestart) {
		t.Fatalf("server events = %+v", evs)
	}
	if len(server.assocs) != 1 {
		t.Fatalf("server has %d associations", len(server.assocs))
	}
}

func TestPRTTLAbandon(t *testing.T) {
	s := newSim(t, 11)
	_, server, ca, _ := connectPair(t, s)
	if !ca.peerFwdTSN {
		t.Fatal("peer did not negotiate FORWARD TSN")
	}
	// Drop every DATA packet carrying the first message.
	s.drop = func(from, to netip.AddrPort, data []byte) bool {
		return bytes.Contains(data, []byte("doomed"))
	}
	ca.Send(s.now, []byte("doomed"), SendInfo{Stream: 0, PRPolicy: PRTTL, PRValue: 500})
	ca.Send(s.now, []byte("survivor"), SendInfo{Stream: 0})
	var m Message
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = server.PollMessage(s.now)
		return ok
	})
	if string(m.Data) != "survivor" {
		t.Fatalf("got %q", m.Data)
	}
	s.runUntil(time.Minute, func() bool { return ca.Buffered() == 0 })
}

func TestPRRTXAbandon(t *testing.T) {
	s := newSim(t, 12)
	_, server, ca, _ := connectPair(t, s)
	s.drop = func(from, to netip.AddrPort, data []byte) bool {
		return bytes.Contains(data, []byte("doomed"))
	}
	ca.Send(s.now, []byte("doomed"), SendInfo{Stream: 2, PRPolicy: PRRTX, PRValue: 1})
	ca.Send(s.now, []byte("after"), SendInfo{Stream: 2})
	var m Message
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = server.PollMessage(s.now)
		return ok
	})
	if string(m.Data) != "after" {
		t.Fatalf("got %q", m.Data)
	}
}

func TestStreamReset(t *testing.T) {
	s := newSim(t, 13)
	client, server, ca, _ := connectPair(t, s)
	drainEvents(client)
	drainEvents(server)
	for i := range 3 {
		ca.Send(s.now, []byte(fmt.Sprint("before", i)), SendInfo{Stream: 1})
	}
	if err := ca.ResetStreams(s.now, []uint16{1}); err != nil {
		t.Fatal(err)
	}
	if err := ca.Send(s.now, []byte("blocked"), SendInfo{Stream: 1}); err != nil {
		t.Fatal(err)
	}
	ca.Send(s.now, []byte("after"), SendInfo{Stream: 1})
	var got []Message
	s.runUntil(time.Minute, func() bool {
		for {
			m, ok := server.PollMessage(s.now)
			if !ok {
				break
			}
			got = append(got, m)
		}
		return len(got) == 5
	})
	want := []string{"before0", "before1", "before2", "blocked", "after"}
	wantSSN := []uint16{0, 1, 2, 0, 1}
	for i, m := range got {
		if string(m.Data) != want[i] || m.SSN != wantSSN[i] {
			t.Fatalf("message %d = %q SSN %d, want %q SSN %d", i, m.Data, m.SSN, want[i], wantSSN[i])
		}
	}
	evs := drainEvents(server)
	if !hasEvent(evs, EventStreamReset) {
		t.Fatalf("server events = %+v", evs)
	}
	if !hasEvent(drainEvents(client), EventStreamReset) {
		t.Fatal("client: no stream reset event")
	}
}

func TestAddStreams(t *testing.T) {
	s := newSim(t, 14)
	_, server, ca, _ := connectPair(t, s)
	_, out := ca.Streams()
	if err := ca.AddStreams(s.now, 5); err != nil {
		t.Fatal(err)
	}
	s.runUntil(time.Minute, func() bool { _, o := ca.Streams(); return o == out+5 })
	if err := ca.Send(s.now, []byte("new stream"), SendInfo{Stream: out + 4}); err != nil {
		t.Fatal(err)
	}
	var m Message
	s.runUntil(time.Minute, func() bool {
		var ok bool
		m, ok = server.PollMessage(s.now)
		return ok
	})
	if m.Stream != out+4 {
		t.Fatalf("got stream %d", m.Stream)
	}
}

func TestOutOfTheBlueAbort(t *testing.T) {
	s := newSim(t, 15)
	e, _ := s.endpoint("192.0.2.2:5000", true, nil)
	pkt := marshalPacket(header{6000, 5000, 1234}, []chunk{u32Chunk(ctSack, 1)})
	e.Input(s.now, netip.MustParseAddrPort("192.0.2.3:6000"), pkt)
	tr, ok := e.PollTransmit()
	if !ok {
		t.Fatal("no response to OOTB packet")
	}
	h, cs, err := parsePacket(tr.Data)
	if err != nil || cs[0].typ != ctAbort || cs[0].flags&flagT == 0 || h.vtag != 1234 {
		t.Fatalf("response %+v %+v %v", h, cs, err)
	}
}

func TestReceiveWindow(t *testing.T) {
	s := newSim(t, 16)
	client, _ := s.endpoint("192.0.2.1:40000", false, nil)
	server, srv := s.endpoint("192.0.2.2:5000", true, func(c *Config) { c.RecvBuffer = 8000 })
	ca, _ := client.Connect(s.now, srv, 5000)
	s.runUntil(time.Minute, func() bool { return ca.Established() })
	for i := range 50 {
		ca.Send(s.now, bytes.Repeat([]byte{byte(i)}, 1000), SendInfo{})
	}
	// Without reading, the server must hold at most its window.
	for range 2000 {
		s.step()
	}
	held := 0
	for _, m := range server.msgs {
		held += len(m.Data)
	}
	if held > 8000+1172 {
		t.Fatalf("server holds %d bytes with an 8000-byte window", held)
	}
	got := 0
	s.runUntil(time.Hour, func() bool {
		for {
			m, ok := server.PollMessage(s.now)
			if !ok {
				break
			}
			if m.Data[0] != byte(got) {
				t.Fatalf("message %d out of order", got)
			}
			got++
		}
		return got == 50
	})
}

func FuzzInput(f *testing.F) {
	f.Add(marshalPacket(header{6000, 5000, 0}, []chunk{(&initChunk{initTag: 1, numOut: 1, maxIn: 1}).chunk(ctInit, nil)}))
	f.Add(marshalPacket(header{6000, 5000, 7}, []chunk{u32Chunk(ctShutdown, 1), {typ: ctData, value: make([]byte, 20)}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		e := NewEndpoint(Config{Rand: func() uint64 { return 42 }, LocalPort: 5000, Accept: true})
		now := time.Unix(1_700_000_000, 0)
		from := netip.MustParseAddrPort("192.0.2.1:6000")
		e.Input(now, from, b)
		// Also feed it with a valid checksum so parsing goes deeper.
		if len(b) >= 12 {
			fixed := bytes.Clone(b)
			fixed[2], fixed[3] = 0x13, 0x88
			if h, cs, err := parsePacket(fixed); err == nil {
				e.Input(now, from, marshalPacket(h, cs))
			} else if _, cs, err := parsePacketNoCRC(fixed); err == nil {
				e.Input(now, from, marshalPacket(header{6000, 5000, 0}, cs))
			}
		}
		e.HandleTimers(now.Add(time.Hour))
	})
}

func parsePacketNoCRC(b []byte) (header, []chunk, error) {
	c := bytes.Clone(b)
	copy(c[8:12], []byte{0, 0, 0, 0})
	sum := checksum(c)
	c[8], c[9], c[10], c[11] = byte(sum), byte(sum>>8), byte(sum>>16), byte(sum>>24)
	return parsePacket(c)
}

// readPieces reads one message, joining partially delivered pieces.
func readPieces(t *testing.T, s *sim, e *Endpoint, pieces *int) Message {
	t.Helper()
	var whole Message
	started := false
	s.runUntil(time.Hour, func() bool {
		for {
			m, ok := e.PollMessage(s.now)
			if !ok {
				return false
			}
			if m.Aborted {
				t.Fatal("unexpected aborted partial delivery")
			}
			if !started {
				whole, started = m, true
				whole.Data = bytes.Clone(m.Data)
			} else {
				if m.Stream != whole.Stream || m.Unordered != whole.Unordered {
					t.Fatalf("piece from stream %d interleaved into message on stream %d", m.Stream, whole.Stream)
				}
				whole.Data = append(whole.Data, m.Data...)
			}
			*pieces++
			if !m.Partial {
				whole.Partial = false
				return true
			}
		}
	})
	return whole
}

func TestPartialDelivery(t *testing.T) {
	for _, unordered := range []bool{false, true} {
		s := newSim(t, 17)
		s.loss = 0.05
		client, _ := s.endpoint("192.0.2.1:40000", false, nil)
		server, srv := s.endpoint("192.0.2.2:5000", true, func(c *Config) { c.RecvBuffer = 8000 })
		ca, _ := client.Connect(s.now, srv, 5000)
		s.runUntil(time.Minute, func() bool { return ca.Established() })
		big := make([]byte, 50_000)
		for i := range big {
			big[i] = byte(i * 13)
		}
		if err := ca.Send(s.now, big, SendInfo{Stream: 2, Unordered: unordered}); err != nil {
			t.Fatal(err)
		}
		if err := ca.Send(s.now, []byte("after"), SendInfo{Stream: 3}); err != nil {
			t.Fatal(err)
		}
		pieces := 0
		m := readPieces(t, s, server, &pieces)
		if !bytes.Equal(m.Data, big) || m.Stream != 2 {
			t.Fatalf("unordered=%v: message larger than the window corrupted (%d bytes, stream %d)", unordered, len(m.Data), m.Stream)
		}
		if pieces < 2 {
			t.Fatalf("unordered=%v: delivered in %d piece(s), want partial delivery", unordered, pieces)
		}
		pieces = 0
		if m := readPieces(t, s, server, &pieces); string(m.Data) != "after" || pieces != 1 {
			t.Fatalf("unordered=%v: next message = %q in %d pieces", unordered, m.Data, pieces)
		}
	}
}

func TestQueuedStreamBeyondNegotiated(t *testing.T) {
	s := newSim(t, 18)
	client, _ := s.endpoint("192.0.2.1:40000", false, nil)
	_, srv := s.endpoint("192.0.2.2:5000", true, func(c *Config) { c.MaxInStreams = 1 })
	ca, err := client.Connect(s.now, srv, 5000)
	if err != nil {
		t.Fatal(err)
	}
	// Queued during setup on a stream the peer will not grant.
	if err := ca.Send(s.now, []byte("dropped"), SendInfo{Stream: 9}); err != nil {
		t.Fatal(err)
	}
	if err := ca.Send(s.now, []byte("kept"), SendInfo{Stream: 0}); err != nil {
		t.Fatal(err)
	}
	s.runUntil(time.Minute, func() bool { return ca.Established() })
	if ca.numOut != 1 {
		t.Fatalf("numOut = %d, want 1", ca.numOut)
	}
	s.runUntil(time.Minute, func() bool { return ca.Buffered() == 0 })
}

func TestWindowExceptionBounded(t *testing.T) {
	s := newSim(t, 19)
	client, _ := s.endpoint("192.0.2.1:40000", false, nil)
	server, srv := s.endpoint("192.0.2.2:5000", true, func(c *Config) { c.RecvBuffer = 8000 })
	ca, _ := client.Connect(s.now, srv, 5000)
	s.runUntil(time.Minute, func() bool { return ca.Established() && len(server.assocs) == 1 })
	var sa *Association
	for _, a := range server.assocs {
		sa = a
	}
	// Consecutive TSNs on stream 0 whose SSNs skip the expected 0, so
	// none can be delivered: the window must still hold.
	for i := range 100 {
		d := dataChunk{flags: dataFlagBegin | dataFlagEnd, tsn: sa.peerCum + 1, stream: 0, ssn: uint16(5 + i), payload: make([]byte, 1000)}
		sa.handleData(s.now, d.chunk())
	}
	if sa.rcvHeld > 8000+1200 {
		t.Fatalf("held %d bytes of undeliverable data with an 8000-byte window", sa.rcvHeld)
	}
}

func TestPRTTLExpiresAfterPrefixAcked(t *testing.T) {
	s := newSim(t, 20)
	s.delay = 100 * time.Millisecond
	_, server, ca, _ := connectPair(t, s)
	// The first flight is acked well after the 20ms lifetime, while
	// most fragments are still queued.
	big := make([]byte, 100_000)
	ca.Send(s.now, big, SendInfo{Stream: 0, PRPolicy: PRTTL, PRValue: 20})
	ca.Send(s.now, []byte("after"), SendInfo{Stream: 0})
	var got []string
	s.runUntil(time.Minute, func() bool {
		for {
			m, ok := server.PollMessage(s.now)
			if !ok {
				break
			}
			got = append(got, string(m.Data[:min(len(m.Data), 5)]))
			if string(m.Data) == "after" {
				return true
			}
		}
		return false
	})
	if len(got) != 1 {
		t.Fatalf("delivered %q, want only the message after the abandoned one", got)
	}
	s.runUntil(time.Minute, func() bool { return ca.Buffered() == 0 && len(ca.inflight) == 0 })
}

func TestNoHeartbeatSpinInShutdownAckSent(t *testing.T) {
	s := newSim(t, 21)
	_, server, _, _ := connectPair(t, s)
	// Put the server in SHUTDOWN-ACK-SENT, as when SHUTDOWN COMPLETE is
	// lost, and let the heartbeat deadline pass.
	var sa *Association
	for _, a := range server.assocs {
		sa = a
	}
	sa.state = stateShutdownAckSent
	sa.hbTimer = s.now.Add(time.Second)
	sa.t2 = s.now.Add(time.Hour)
	later := s.now.Add(2 * time.Second)
	server.HandleTimers(later)
	if d := server.NextDeadline(); !d.IsZero() && !d.After(later) {
		t.Fatalf("NextDeadline = %v, still due at %v", d, later)
	}
}

// sctp-proto (used by rust-sctp and webrtc-rs) drops an INIT whose last
// parameter is header-only (4 bytes), so INIT and INIT ACK must not end
// with Forward-TSN-Supported.
func TestInitLastParamNotHeaderOnly(t *testing.T) {
	e := NewEndpoint(Config{Rand: func() uint64 { return 42 }, LocalPort: 5000, Accept: true})
	_, extra := e.localInit(1, 1, 10, 10, 65536)
	var last uint16
	for p := extra; len(p) >= 4; {
		l := int(byteorder.BEUint16(p[2:]))
		last = uint16(l)
		p = p[min(len(p), l+padLen(l-4)):]
	}
	if last <= 4 {
		t.Fatalf("INIT parameters end with a %d-byte parameter: % x", last, extra)
	}
}
