// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import "time"

// Partial reliability (RFC 3758).

// prAbandon abandons messages whose lifetime or retransmission budget is
// spent. Only peers that announced FORWARD TSN support get abandonment.
func (a *Association) prAbandon(now time.Time) {
	if !a.peerFwdTSN {
		return
	}
	expired := func(c *outChunk) bool {
		m := c.msg
		switch m.policy {
		case PRTTL:
			return !m.expires.IsZero() && !now.Before(m.expires)
		case PRRTX:
			return c.retx && c.nSent > int(m.value)
		}
		return false
	}
	changed := false
	for _, c := range a.inflight {
		if !c.abandoned && !c.acked && !c.msg.abandoned && expired(c) {
			c.msg.abandoned = true
			changed = true
		}
	}
	for _, c := range a.pending {
		if !c.msg.abandoned && c.msg.policy == PRTTL && expired(c) {
			c.msg.abandoned = true
			changed = true
		}
	}
	if !changed {
		return
	}
	for _, c := range a.inflight {
		if c.msg.abandoned && !c.abandoned {
			c.abandoned = true
			c.retx = false
		}
	}
	a.prAdvance(now)
}

// prAdvance moves Advanced.Peer.Ack.Point over abandoned chunks and asks
// for a FORWARD TSN when it passes the cumulative ack (RFC 3758 3.5).
func (a *Association) prAdvance(now time.Time) {
	if !a.peerFwdTSN {
		return
	}
	if tsnLT(a.advPeerAck, a.cumAck) {
		a.advPeerAck = a.cumAck
	}
	for _, c := range a.inflight {
		if c.tsn != a.advPeerAck+1 {
			if tsnLTE(c.tsn, a.advPeerAck) {
				continue
			}
			break
		}
		if !c.abandoned && !c.acked {
			break
		}
		a.advPeerAck = c.tsn
	}
	if tsnGT(a.advPeerAck, a.cumAck) {
		a.fwdTSNNeed = true
		if a.t3.IsZero() {
			a.t3 = now.Add(a.rto)
		}
	}
}

func (a *Association) buildForwardTSN() chunk {
	f := forwardTSNChunk{newCumTSN: a.advPeerAck}
	last := map[uint16]uint16{}
	for _, c := range a.inflight {
		if tsnGT(c.tsn, a.advPeerAck) {
			break
		}
		if c.abandoned && !c.msg.unordered {
			if s, ok := last[c.msg.stream]; !ok || ssnLT(s, c.msg.ssn) {
				last[c.msg.stream] = c.msg.ssn
			}
		}
	}
	for s, ssn := range last {
		f.streams = append(f.streams, streamSSN{s, ssn})
	}
	return f.chunk()
}

// handleForwardTSN skips abandoned TSNs and messages on the receiver.
func (a *Association) handleForwardTSN(now time.Time, f forwardTSNChunk) {
	a.sackNow = true
	if tsnLTE(f.newCumTSN, a.peerCum) {
		return
	}
	if tsnGT(f.newCumTSN, a.peerCum+1<<30) {
		return // implausible jump
	}
	for t := range a.recvd {
		if tsnLTE(t, f.newCumTSN) {
			delete(a.recvd, t)
		}
	}
	a.peerCum = f.newCumTSN
	for {
		if _, ok := a.recvd[a.peerCum+1]; !ok {
			break
		}
		delete(a.recvd, a.peerCum+1)
		a.peerCum++
	}
	for _, s := range a.instreams {
		keep := s.unordered[:0]
		for _, fr := range s.unordered {
			if tsnLTE(fr.tsn, f.newCumTSN) && !wholeAt(s.unordered, fr) {
				a.rcvHeld -= len(fr.payload)
				continue
			}
			keep = append(keep, fr)
		}
		s.unordered = keep
	}
	for _, p := range f.streams {
		s := a.instreams[p.stream]
		if s == nil {
			s = &inStream{}
			a.instreams[p.stream] = s
		}
		// Deliver complete messages up to the skipped SSN and drop the
		// fragments of abandoned ones.
		for !ssnLT(p.ssn, s.nextSSN) {
			ssn := s.nextSSN
			idx := -1
			for i := range s.ordered {
				if s.ordered[i].ssn == ssn && s.ordered[i].flags&dataFlagBegin != 0 {
					idx = i
					break
				}
			}
			if idx >= 0 {
				if end, ok := completeSSN(s.ordered, idx, ssn); ok {
					a.emitMessage(p.stream, takeFrags(&s.ordered, idx, end, ssn), false)
					s.nextSSN++
					continue
				}
			}
			keep := s.ordered[:0]
			for _, fr := range s.ordered {
				if fr.ssn == ssn {
					a.rcvHeld -= len(fr.payload)
					continue
				}
				keep = append(keep, fr)
			}
			s.ordered = keep
			s.nextSSN++
		}
	}
	if a.rcvHeld < 0 {
		a.rcvHeld = 0
	}
}

// wholeAt reports whether fr belongs to a complete unordered message in
// fs, which must still be delivered even if FORWARD TSN covers it.
func wholeAt(fs []inFrag, fr inFrag) bool {
	for i := range fs {
		if end, ok := complete(fs, i); ok {
			if tsnLTE(fs[i].tsn, fr.tsn) && tsnLTE(fr.tsn, fs[end-1].tsn) {
				return true
			}
		}
	}
	return false
}
