// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"internal/byteorder"
	"time"
)

// Stream reconfiguration (RFC 6525): outgoing SSN reset and adding
// outgoing streams, in both directions.

// Reconfiguration response results (RFC 6525 section 4.4).
const (
	reconfSuccessNothing   = 0
	reconfSuccessPerformed = 1
	reconfDenied           = 2
	reconfBadSeq           = 5
	reconfInProgress       = 6
)

const (
	reqNone = iota
	reqReset
	reqAdd
)

type deferredReset struct {
	reqSN   uint32
	lastTSN uint32
	streams []uint16
}

type reconf struct {
	reconfTimer time.Time

	myReqSN   uint32 // next request sequence number we send
	peerReqSN uint32 // next request sequence number we expect

	// Our request: queued (want*) and then outstanding (req*).
	wantKind    int
	wantStreams []uint16
	wantAdd     uint16
	reqKind     int
	reqSN       uint32
	reqStreams  []uint16
	reqAdd      uint16
	reqChunk    chunk

	// The peer's last request, for retransmissions.
	lastPeerResult uint32
	deferred       *deferredReset
	deferredData   []deferredFrag
}

type deferredFrag struct {
	stream uint16
	f      inFrag
}

func (a *Association) reconfInit(myTSN, peerTSN uint32) {
	// The first request sequence number equals the initial TSN.
	a.myReqSN = myTSN
	a.peerReqSN = peerTSN
}

// streamBlocked reports whether data on stream must wait for an
// outgoing reset to complete.
func (a *Association) streamBlocked(stream uint16) bool {
	in := func(ss []uint16) bool {
		if len(ss) == 0 {
			return true // all streams
		}
		for _, s := range ss {
			if s == stream {
				return true
			}
		}
		return false
	}
	return (a.reqKind == reqReset && in(a.reqStreams)) || (a.wantKind == reqReset && in(a.wantStreams))
}

// ResetStreams requests a reset of outgoing streams (nil means all).
// The request goes out once data already queued on those streams has
// been sent; messages queued afterwards are held until the peer
// answers, and then start again from SSN 0.
func (a *Association) ResetStreams(now time.Time, streams []uint16) error {
	if !a.Established() {
		return ErrClosed
	}
	if !a.peerReconfig {
		return ErrUnsupported
	}
	if a.wantKind != reqNone || a.reqKind != reqNone {
		return ErrResetInProgress
	}
	for _, s := range streams {
		if s >= a.numOut {
			return ErrInvalidStream
		}
	}
	a.wantKind = reqReset
	a.wantStreams = append([]uint16(nil), streams...)
	a.transmit(now)
	return nil
}

// AddStreams asks the peer to accept n more outgoing streams.
func (a *Association) AddStreams(now time.Time, n uint16) error {
	if !a.Established() {
		return ErrClosed
	}
	if !a.peerReconfig {
		return ErrUnsupported
	}
	if a.wantKind != reqNone || a.reqKind != reqNone {
		return ErrResetInProgress
	}
	if n == 0 || int(a.numOut)+int(n) > 65535 {
		return ErrInvalidStream
	}
	a.wantKind = reqAdd
	a.wantAdd = n
	a.transmit(now)
	return nil
}

// StreamResetPending reports whether a stream reconfiguration request is
// queued or outstanding.
func (a *Association) StreamResetPending() bool {
	return a.wantKind != reqNone || a.reqKind != reqNone
}

func (a *Association) reconfMaybeSend(now time.Time) {
	if a.wantKind == reqNone || a.reqKind != reqNone || !a.Established() {
		return
	}
	var p []byte
	switch a.wantKind {
	case reqReset:
		// Wait until data queued on these streams is on the wire.
		for _, c := range a.pending {
			if !c.held && a.streamIn(c.msg.stream, a.wantStreams) && !c.msg.abandoned {
				return
			}
		}
		v := byteorder.BEAppendUint32(nil, a.myReqSN)
		v = byteorder.BEAppendUint32(v, a.peerReqSN-1) // response SN: unused
		v = byteorder.BEAppendUint32(v, a.nextTSN-1)   // sender's last assigned TSN
		for _, s := range a.wantStreams {
			v = byteorder.BEAppendUint16(v, s)
		}
		p = appendParam(nil, ptOutSSNReset, v)
		a.reqStreams = a.wantStreams
	case reqAdd:
		v := byteorder.BEAppendUint32(nil, a.myReqSN)
		v = byteorder.BEAppendUint16(v, a.wantAdd)
		v = byteorder.BEAppendUint16(v, 0)
		p = appendParam(nil, ptAddOutStreams, v)
		a.reqAdd = a.wantAdd
	}
	a.reqKind = a.wantKind
	a.reqSN = a.myReqSN
	a.myReqSN++
	a.wantKind, a.wantStreams, a.wantAdd = reqNone, nil, 0
	a.reqChunk = chunk{typ: ctReconfig, value: p}
	a.sendNow(a.reqChunk)
	a.reconfTimer = now.Add(a.rto)
}

func (a *Association) streamIn(s uint16, ss []uint16) bool {
	if len(ss) == 0 {
		return true
	}
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func (a *Association) reconfRetransmit(now time.Time) {
	if a.reqKind == reqNone {
		a.reconfTimer = time.Time{}
		return
	}
	a.errors++
	if a.errors > a.ep.cfg.MaxRetrans {
		a.sendNow(chunk{typ: ctAbort})
		a.fail(EventCommLost, ErrTimeout)
		return
	}
	a.rto = min(2*a.rto, a.ep.cfg.RTOMax)
	a.reconfTimer = now.Add(a.rto)
	a.ctrl = append(a.ctrl, a.reqChunk)
}

func respParam(sn, result uint32) []byte {
	v := byteorder.BEAppendUint32(nil, sn)
	v = byteorder.BEAppendUint32(v, result)
	return appendParam(nil, ptReconfigResponse, v)
}

func (a *Association) handleReconfig(now time.Time, c chunk) {
	ps, err := parseParams(c.value)
	if err != nil {
		return
	}
	var resp []byte
	for _, p := range ps {
		v := p.value
		switch p.typ {
		case ptOutSSNReset:
			if len(v) < 12 || (len(v)-12)%2 != 0 {
				continue
			}
			sn := byteorder.BEUint32(v)
			lastTSN := byteorder.BEUint32(v[8:])
			var streams []uint16
			for q := v[12:]; len(q) >= 2; q = q[2:] {
				streams = append(streams, byteorder.BEUint16(q))
			}
			resp = append(resp, a.peerOutReset(sn, lastTSN, streams)...)
		case ptInSSNReset:
			if len(v) >= 4 {
				resp = append(resp, a.peerSimpleRequest(byteorder.BEUint32(v), reconfDenied)...)
			}
		case ptSSNTSNReset, ptAddInStreams:
			if len(v) >= 4 {
				resp = append(resp, a.peerSimpleRequest(byteorder.BEUint32(v), reconfDenied)...)
			}
		case ptAddOutStreams:
			if len(v) < 8 {
				continue
			}
			sn := byteorder.BEUint32(v)
			n := byteorder.BEUint16(v[4:])
			result := uint32(reconfDenied)
			if sn == a.peerReqSN && int(a.numIn)+int(n) <= int(a.ep.cfg.MaxInStreams) {
				a.numIn += n
				result = reconfSuccessPerformed
				a.ep.emit(Event{Kind: EventStreamsAdded, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, InStreams: a.numIn, OutStreams: a.numOut, Incoming: true})
			}
			resp = append(resp, a.peerSimpleRequest(sn, result)...)
		case ptReconfigResponse:
			if len(v) >= 8 {
				a.handleReconfResponse(now, byteorder.BEUint32(v), byteorder.BEUint32(v[4:]))
			}
		}
	}
	if len(resp) > 0 {
		a.ctrl = append(a.ctrl, chunk{typ: ctReconfig, value: resp})
	}
}

// peerSimpleRequest answers a request that completes immediately.
func (a *Association) peerSimpleRequest(sn, result uint32) []byte {
	switch {
	case sn == a.peerReqSN:
		a.peerReqSN++
		a.lastPeerResult = result
		return respParam(sn, result)
	case sn == a.peerReqSN-1:
		return respParam(sn, a.lastPeerResult)
	}
	return respParam(sn, reconfBadSeq)
}

func (a *Association) peerOutReset(sn, lastTSN uint32, streams []uint16) []byte {
	switch {
	case sn == a.peerReqSN:
	case sn == a.peerReqSN-1:
		if a.deferred != nil && a.deferred.reqSN == sn {
			return respParam(sn, reconfInProgress)
		}
		return respParam(sn, a.lastPeerResult)
	default:
		return respParam(sn, reconfBadSeq)
	}
	for _, s := range streams {
		if s >= a.numIn {
			a.peerReqSN++
			a.lastPeerResult = reconfDenied
			return respParam(sn, reconfDenied)
		}
	}
	a.peerReqSN++
	a.deferred = &deferredReset{reqSN: sn, lastTSN: lastTSN, streams: streams}
	if tsnLTE(lastTSN, a.peerCum) {
		return a.applyDeferredReset()
	}
	return respParam(sn, reconfInProgress)
}

// reconfOnCumAdvance applies a deferred incoming reset once every TSN up
// to the sender's last TSN has arrived and been delivered.
func (a *Association) reconfOnCumAdvance() {
	if a.deferred == nil || !tsnLTE(a.deferred.lastTSN, a.peerCum) {
		return
	}
	if r := a.applyDeferredReset(); r != nil {
		a.ctrl = append(a.ctrl, chunk{typ: ctReconfig, value: r})
	}
	a.deliver()
}

func (a *Association) applyDeferredReset() []byte {
	d := a.deferred
	a.deferred = nil
	if len(d.streams) == 0 {
		for _, s := range a.instreams {
			s.nextSSN = 0
		}
	} else {
		for _, id := range d.streams {
			if s := a.instreams[id]; s != nil {
				s.nextSSN = 0
			}
		}
	}
	held := a.deferredData
	a.deferredData = nil
	for _, df := range held {
		a.addFrag(df.stream, df.f)
	}
	a.lastPeerResult = reconfSuccessPerformed
	a.ep.emit(Event{Kind: EventStreamReset, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, Incoming: true, Streams: d.streams})
	return respParam(d.reqSN, reconfSuccessPerformed)
}

func (a *Association) handleReconfResponse(now time.Time, sn, result uint32) {
	if a.reqKind == reqNone || sn != a.reqSN {
		return
	}
	if result == reconfInProgress {
		// The peer is waiting for data; retry after a timeout.
		a.reconfTimer = now.Add(a.rto)
		return
	}
	ok := result == reconfSuccessPerformed || result == reconfSuccessNothing
	switch a.reqKind {
	case reqReset:
		if ok {
			if len(a.reqStreams) == 0 {
				for i := range a.outSSN {
					a.outSSN[i] = 0
				}
			} else {
				for _, s := range a.reqStreams {
					a.outSSN[s] = 0
				}
			}
		}
		a.ep.emit(Event{Kind: EventStreamReset, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, Streams: a.reqStreams, Failed: !ok})
	case reqAdd:
		if ok {
			a.numOut += a.reqAdd
			a.outSSN = append(a.outSSN, make([]uint16, a.reqAdd)...)
		}
		a.ep.emit(Event{Kind: EventStreamsAdded, Assoc: a.id, Peer: a.peer, PeerPort: a.peerPort, InStreams: a.numIn, OutStreams: a.numOut, Failed: !ok})
	}
	a.errors = 0
	a.reqKind, a.reqStreams, a.reqAdd = reqNone, nil, 0
	a.reconfTimer = time.Time{}
	for _, c := range a.pending {
		c.held = false
	}
	a.transmit(now)
}
