// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"internal/byteorder"
	"math/bits"
	"net/netip"
	"time"
)

// The State Cookie carries everything needed to build the association
// when the COOKIE ECHO arrives, so a listener keeps no state for
// half-open associations (RFC 9260 section 5.1.3).
//
// The cookie is authenticated with SipHash-2-4 (128-bit output) under a
// random per-endpoint key. SipHash is a keyed PRF built for short inputs;
// using it keeps package net free of the crypto packages, which the
// standard library's dependency rules keep out of net.

const (
	cookieVersion = 1
	cookieBody    = 56
	cookieMACLen  = 16
	cookieLen     = cookieBody + cookieMACLen
)

const (
	cookieFlagPeerFwdTSN   = 1 << 0
	cookieFlagPeerReconfig = 1 << 1
)

type cookie struct {
	flags          uint8
	created        time.Time
	myTag          uint32
	peerTag        uint32
	myInitialTSN   uint32
	peerInitialTSN uint32
	peerArwnd      uint32
	numOut         uint16
	numIn          uint16
	peerPort       uint16
	localPort      uint16
	peerIP         netip.Addr
}

func (c *cookie) marshal(key *[16]byte) []byte {
	b := make([]byte, cookieBody, cookieLen)
	b[0] = cookieVersion
	b[1] = c.flags
	byteorder.BEPutUint64(b[4:], uint64(c.created.UnixMilli()))
	byteorder.BEPutUint32(b[12:], c.myTag)
	byteorder.BEPutUint32(b[16:], c.peerTag)
	byteorder.BEPutUint32(b[20:], c.myInitialTSN)
	byteorder.BEPutUint32(b[24:], c.peerInitialTSN)
	byteorder.BEPutUint32(b[28:], c.peerArwnd)
	byteorder.BEPutUint16(b[32:], c.numOut)
	byteorder.BEPutUint16(b[34:], c.numIn)
	byteorder.BEPutUint16(b[36:], c.peerPort)
	byteorder.BEPutUint16(b[38:], c.localPort)
	ip := c.peerIP.As16()
	copy(b[40:56], ip[:])
	mac := siphash128(key, b)
	return append(b, mac[:]...)
}

// parseCookie authenticates and decodes a cookie. It does not check the
// cookie's age.
func parseCookie(key *[16]byte, b []byte) (cookie, bool) {
	if len(b) != cookieLen || b[0] != cookieVersion {
		return cookie{}, false
	}
	mac := siphash128(key, b[:cookieBody])
	var diff byte
	for i := range mac {
		diff |= mac[i] ^ b[cookieBody+i]
	}
	if diff != 0 {
		return cookie{}, false
	}
	var ip [16]byte
	copy(ip[:], b[40:56])
	return cookie{
		flags:          b[1],
		created:        time.UnixMilli(int64(byteorder.BEUint64(b[4:]))),
		myTag:          byteorder.BEUint32(b[12:]),
		peerTag:        byteorder.BEUint32(b[16:]),
		myInitialTSN:   byteorder.BEUint32(b[20:]),
		peerInitialTSN: byteorder.BEUint32(b[24:]),
		peerArwnd:      byteorder.BEUint32(b[28:]),
		numOut:         byteorder.BEUint16(b[32:]),
		numIn:          byteorder.BEUint16(b[34:]),
		peerPort:       byteorder.BEUint16(b[36:]),
		localPort:      byteorder.BEUint16(b[38:]),
		peerIP:         netip.AddrFrom16(ip).Unmap(),
	}, true
}

// siphash128 is SipHash-2-4 with a 128-bit output.
func siphash128(key *[16]byte, m []byte) [16]byte {
	k0 := byteorder.LEUint64(key[0:])
	k1 := byteorder.LEUint64(key[8:])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d ^ 0xee
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}
	n := len(m)
	for len(m) >= 8 {
		w := byteorder.LEUint64(m)
		v3 ^= w
		round()
		round()
		v0 ^= w
		m = m[8:]
	}
	var last [8]byte
	copy(last[:], m)
	last[7] = byte(n)
	w := byteorder.LEUint64(last[:])
	v3 ^= w
	round()
	round()
	v0 ^= w
	v2 ^= 0xee
	for range 4 {
		round()
	}
	var out [16]byte
	byteorder.LEPutUint64(out[0:], v0^v1^v2^v3)
	v1 ^= 0xdd
	for range 4 {
		round()
	}
	byteorder.LEPutUint64(out[8:], v0^v1^v2^v3)
	return out
}
