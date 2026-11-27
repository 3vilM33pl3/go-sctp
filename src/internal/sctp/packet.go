// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sctp is a user-space SCTP engine (RFC 9260) used by package net
// to carry SCTP over UDP (RFC 6951) when the host has no kernel SCTP.
//
// The engine does no I/O of its own: callers feed it received datagrams,
// user sends and the current time, and drain packets to transmit, messages
// to deliver and events. Package net owns the UDP socket, goroutines and
// deadlines.
package sctp

import (
	"errors"
	"hash/crc32"
	"internal/byteorder"
)

// Chunk types (RFC 9260 section 3.2, RFC 3758, RFC 6525).
const (
	ctData             uint8 = 0
	ctInit             uint8 = 1
	ctInitAck          uint8 = 2
	ctSack             uint8 = 3
	ctHeartbeat        uint8 = 4
	ctHeartbeatAck     uint8 = 5
	ctAbort            uint8 = 6
	ctShutdown         uint8 = 7
	ctShutdownAck      uint8 = 8
	ctError            uint8 = 9
	ctCookieEcho       uint8 = 10
	ctCookieAck        uint8 = 11
	ctShutdownComplete uint8 = 14
	ctReconfig         uint8 = 130
	ctForwardTSN       uint8 = 192
)

// DATA chunk flags.
const (
	dataFlagEnd       uint8 = 1 << 0
	dataFlagBegin     uint8 = 1 << 1
	dataFlagUnordered uint8 = 1 << 2
	dataFlagImmediate uint8 = 1 << 3
)

// flagT is the T bit of ABORT and SHUTDOWN COMPLETE: the verification tag
// was reflected from the received packet.
const flagT uint8 = 1

// Parameter types.
const (
	ptHeartbeatInfo      uint16 = 1
	ptIPv4               uint16 = 5
	ptIPv6               uint16 = 6
	ptStateCookie        uint16 = 7
	ptUnrecognized       uint16 = 8
	ptCookiePreservative uint16 = 9
	ptHostName           uint16 = 11
	ptSupportedAddrTypes uint16 = 12
	ptOutSSNReset        uint16 = 13
	ptInSSNReset         uint16 = 14
	ptSSNTSNReset        uint16 = 15
	ptReconfigResponse   uint16 = 16
	ptAddOutStreams      uint16 = 17
	ptAddInStreams       uint16 = 18
	ptECNCapable         uint16 = 0x8000
	ptSupportedExt       uint16 = 0x8008
	ptForwardTSNSupport  uint16 = 0xc000
)

// Error cause codes.
const (
	causeInvalidStream     uint16 = 1
	causeMissingParam      uint16 = 2
	causeStaleCookie       uint16 = 3
	causeOutOfResource     uint16 = 4
	causeUnrecognizedChunk uint16 = 6
	causeInvalidMandatory  uint16 = 7
	causeUnrecognizedParam uint16 = 8
	causeNoUserData        uint16 = 9
	causeCookieShutdown    uint16 = 10
	causeRestartNewAddrs   uint16 = 11
	causeUserAbort         uint16 = 12
	causeProtocolViolation uint16 = 13
)

const (
	commonHeaderSize = 12
	chunkHeaderSize  = 4
	dataHeaderSize   = 16 // chunk header + TSN, stream, SSN, PPID
)

var (
	errShortPacket = errors.New("sctp: packet too short")
	errBadChecksum = errors.New("sctp: bad checksum")
	errBadChunk    = errors.New("sctp: malformed chunk")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// header is the SCTP common header.
type header struct {
	srcPort, dstPort uint16
	vtag             uint32
}

// chunk is a raw chunk: its type, flags and value (without padding).
type chunk struct {
	typ   uint8
	flags uint8
	value []byte
}

func (c chunk) length() int { return chunkHeaderSize + len(c.value) }

func padLen(n int) int { return (4 - n&3) & 3 }

// checksum returns the CRC32c of an SCTP packet, computed with the
// checksum field taken as zero.
func checksum(b []byte) uint32 {
	var zero [4]byte
	crc := crc32.Update(0, castagnoli, b[:8])
	crc = crc32.Update(crc, castagnoli, zero[:])
	return crc32.Update(crc, castagnoli, b[12:])
}

// parsePacket validates the checksum and splits a packet into chunks.
// The returned chunks alias b.
func parsePacket(b []byte) (header, []chunk, error) {
	var h header
	if len(b) < commonHeaderSize+chunkHeaderSize {
		return h, nil, errShortPacket
	}
	// The CRC32c is stored in the byte order the RFC's reference code
	// produces, which is little-endian on the wire.
	if byteorder.LEUint32(b[8:12]) != checksum(b) {
		return h, nil, errBadChecksum
	}
	h.srcPort = byteorder.BEUint16(b[0:])
	h.dstPort = byteorder.BEUint16(b[2:])
	h.vtag = byteorder.BEUint32(b[4:])
	var chunks []chunk
	rest := b[commonHeaderSize:]
	for len(rest) > 0 {
		if len(rest) < chunkHeaderSize {
			return h, nil, errBadChunk
		}
		n := int(byteorder.BEUint16(rest[2:]))
		if n < chunkHeaderSize || n > len(rest) {
			return h, nil, errBadChunk
		}
		chunks = append(chunks, chunk{typ: rest[0], flags: rest[1], value: rest[chunkHeaderSize:n]})
		n += padLen(n)
		if n > len(rest) {
			n = len(rest) // tolerate a missing pad on the last chunk
		}
		rest = rest[n:]
	}
	if len(chunks) == 0 {
		return h, nil, errBadChunk
	}
	return h, chunks, nil
}

// appendChunk appends a chunk with padding to b.
func appendChunk(b []byte, c chunk) []byte {
	b = append(b, c.typ, c.flags)
	b = byteorder.BEAppendUint16(b, uint16(c.length()))
	b = append(b, c.value...)
	for range padLen(len(c.value)) {
		b = append(b, 0)
	}
	return b
}

// marshalPacket builds a packet with a valid checksum.
func marshalPacket(h header, chunks []chunk) []byte {
	n := commonHeaderSize
	for _, c := range chunks {
		n += c.length() + padLen(c.length())
	}
	b := make([]byte, commonHeaderSize, n)
	byteorder.BEPutUint16(b[0:], h.srcPort)
	byteorder.BEPutUint16(b[2:], h.dstPort)
	byteorder.BEPutUint32(b[4:], h.vtag)
	for _, c := range chunks {
		b = appendChunk(b, c)
	}
	byteorder.LEPutUint32(b[8:], checksum(b))
	return b
}

// param is a type-length-value parameter or error cause.
type param struct {
	typ   uint16
	value []byte
}

// parseParams parses a sequence of padded TLVs.
func parseParams(b []byte) ([]param, error) {
	var ps []param
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errBadChunk
		}
		n := int(byteorder.BEUint16(b[2:]))
		if n < 4 || n > len(b) {
			return nil, errBadChunk
		}
		ps = append(ps, param{typ: byteorder.BEUint16(b), value: b[4:n]})
		n += padLen(n)
		if n > len(b) {
			n = len(b)
		}
		b = b[n:]
	}
	return ps, nil
}

func appendParam(b []byte, typ uint16, value []byte) []byte {
	b = byteorder.BEAppendUint16(b, typ)
	b = byteorder.BEAppendUint16(b, uint16(4+len(value)))
	b = append(b, value...)
	for range padLen(len(value)) {
		b = append(b, 0)
	}
	return b
}

// dataChunk is a decoded DATA chunk.
type dataChunk struct {
	flags   uint8
	tsn     uint32
	stream  uint16
	ssn     uint16
	ppid    uint32
	payload []byte
}

func parseData(c chunk) (dataChunk, error) {
	if len(c.value) < 12 {
		return dataChunk{}, errBadChunk
	}
	return dataChunk{
		flags:   c.flags,
		tsn:     byteorder.BEUint32(c.value),
		stream:  byteorder.BEUint16(c.value[4:]),
		ssn:     byteorder.BEUint16(c.value[6:]),
		ppid:    byteorder.BEUint32(c.value[8:]),
		payload: c.value[12:],
	}, nil
}

func (d *dataChunk) chunk() chunk {
	v := make([]byte, 12, 12+len(d.payload))
	byteorder.BEPutUint32(v, d.tsn)
	byteorder.BEPutUint16(v[4:], d.stream)
	byteorder.BEPutUint16(v[6:], d.ssn)
	byteorder.BEPutUint32(v[8:], d.ppid)
	return chunk{typ: ctData, flags: d.flags, value: append(v, d.payload...)}
}

// initChunk is a decoded INIT or INIT ACK chunk.
type initChunk struct {
	initTag    uint32
	arwnd      uint32
	numOut     uint16
	maxIn      uint16
	initialTSN uint32
	params     []param
}

func parseInit(c chunk) (initChunk, error) {
	if len(c.value) < 16 {
		return initChunk{}, errBadChunk
	}
	ps, err := parseParams(c.value[16:])
	if err != nil {
		return initChunk{}, err
	}
	return initChunk{
		initTag:    byteorder.BEUint32(c.value),
		arwnd:      byteorder.BEUint32(c.value[4:]),
		numOut:     byteorder.BEUint16(c.value[8:]),
		maxIn:      byteorder.BEUint16(c.value[10:]),
		initialTSN: byteorder.BEUint32(c.value[12:]),
		params:     ps,
	}, nil
}

func (in *initChunk) chunk(typ uint8, extra []byte) chunk {
	v := make([]byte, 16, 16+len(extra))
	byteorder.BEPutUint32(v, in.initTag)
	byteorder.BEPutUint32(v[4:], in.arwnd)
	byteorder.BEPutUint16(v[8:], in.numOut)
	byteorder.BEPutUint16(v[10:], in.maxIn)
	byteorder.BEPutUint32(v[12:], in.initialTSN)
	return chunk{typ: typ, value: append(v, extra...)}
}

func (in *initChunk) param(typ uint16) ([]byte, bool) {
	for _, p := range in.params {
		if p.typ == typ {
			return p.value, true
		}
	}
	return nil, false
}

// supportsChunk reports whether the peer listed chunk type t in a
// Supported Extensions parameter, or (for FORWARD TSN) sent the
// Forward-TSN-Supported parameter.
func (in *initChunk) supportsChunk(t uint8) bool {
	if t == ctForwardTSN {
		if _, ok := in.param(ptForwardTSNSupport); ok {
			return true
		}
	}
	if v, ok := in.param(ptSupportedExt); ok {
		for _, x := range v {
			if x == t {
				return true
			}
		}
	}
	return false
}

// gapBlock is a SACK gap ack block, as offsets from the cumulative TSN.
type gapBlock struct{ start, end uint16 }

type sackChunk struct {
	cumTSN uint32
	arwnd  uint32
	gaps   []gapBlock
	dups   []uint32
}

func parseSack(c chunk) (sackChunk, error) {
	v := c.value
	if len(v) < 12 {
		return sackChunk{}, errBadChunk
	}
	s := sackChunk{cumTSN: byteorder.BEUint32(v), arwnd: byteorder.BEUint32(v[4:])}
	ng := int(byteorder.BEUint16(v[8:]))
	nd := int(byteorder.BEUint16(v[10:]))
	if len(v) < 12+4*ng+4*nd {
		return sackChunk{}, errBadChunk
	}
	p := v[12:]
	for range ng {
		s.gaps = append(s.gaps, gapBlock{byteorder.BEUint16(p), byteorder.BEUint16(p[2:])})
		p = p[4:]
	}
	for range nd {
		s.dups = append(s.dups, byteorder.BEUint32(p))
		p = p[4:]
	}
	return s, nil
}

func (s *sackChunk) chunk() chunk {
	v := make([]byte, 0, 12+4*len(s.gaps)+4*len(s.dups))
	v = byteorder.BEAppendUint32(v, s.cumTSN)
	v = byteorder.BEAppendUint32(v, s.arwnd)
	v = byteorder.BEAppendUint16(v, uint16(len(s.gaps)))
	v = byteorder.BEAppendUint16(v, uint16(len(s.dups)))
	for _, g := range s.gaps {
		v = byteorder.BEAppendUint16(v, g.start)
		v = byteorder.BEAppendUint16(v, g.end)
	}
	for _, d := range s.dups {
		v = byteorder.BEAppendUint32(v, d)
	}
	return chunk{typ: ctSack, value: v}
}

// streamSSN is a stream/SSN pair carried in FORWARD TSN.
type streamSSN struct{ stream, ssn uint16 }

type forwardTSNChunk struct {
	newCumTSN uint32
	streams   []streamSSN
}

func parseForwardTSN(c chunk) (forwardTSNChunk, error) {
	v := c.value
	if len(v) < 4 || (len(v)-4)%4 != 0 {
		return forwardTSNChunk{}, errBadChunk
	}
	f := forwardTSNChunk{newCumTSN: byteorder.BEUint32(v)}
	for p := v[4:]; len(p) >= 4; p = p[4:] {
		f.streams = append(f.streams, streamSSN{byteorder.BEUint16(p), byteorder.BEUint16(p[2:])})
	}
	return f, nil
}

func (f *forwardTSNChunk) chunk() chunk {
	v := byteorder.BEAppendUint32(nil, f.newCumTSN)
	for _, s := range f.streams {
		v = byteorder.BEAppendUint16(v, s.stream)
		v = byteorder.BEAppendUint16(v, s.ssn)
	}
	return chunk{typ: ctForwardTSN, value: v}
}

func u32Chunk(typ uint8, x uint32) chunk {
	return chunk{typ: typ, value: byteorder.BEAppendUint32(nil, x)}
}

// causeChunk builds an ABORT or ERROR chunk carrying one cause.
func causeChunk(typ, flags uint8, cause uint16, info []byte) chunk {
	return chunk{typ: typ, flags: flags, value: appendParam(nil, cause, info)}
}

// TSN and SSN serial arithmetic (RFC 1982).
func tsnLT(a, b uint32) bool  { return int32(a-b) < 0 }
func tsnLTE(a, b uint32) bool { return int32(a-b) <= 0 }
func tsnGT(a, b uint32) bool  { return int32(a-b) > 0 }
func ssnLT(a, b uint16) bool  { return int16(a-b) < 0 }
