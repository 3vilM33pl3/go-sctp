// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"syscall"
	"testing"
	"time"
)

// requireSCTP skips the test when the running kernel has no SCTP stack
// (the module is not loaded, or the protocol is compiled out).
func requireSCTP(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("kernel SCTP unavailable: %v", err)
	}
	syscall.Close(fd)
}

// readUserMessageSCTP reads the next user message from conn, skipping any
// notifications that precede it.
func readUserMessageSCTP(t *testing.T, conn *SCTPConn, buf []byte) (int, *SCTPAddr, *SCTPRcvInfo) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline error: %v", err)
	}
	for {
		n, _, flags, from, info, err := conn.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v", err)
		}
		if flags&sctpMsgNotification != 0 {
			continue
		}
		return n, from, info
	}
}

// TestDialSCTPAddrTypes checks that a dialed (one-to-one, SOCK_STREAM)
// connection still reports SCTP addresses: netFD.addrFunc used to key on
// the socket type alone and handed back *TCPAddr, which made every
// internal *SCTPAddr assertion fail silently.
func TestDialSCTPAddrTypes(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	saddr, ok := srv.LocalAddr().(*SCTPAddr)
	if !ok {
		t.Fatalf("listener LocalAddr type = %T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTP("sctp4", nil, saddr)
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	la, ok := cli.LocalAddr().(*SCTPAddr)
	if !ok || la == nil || la.Port == 0 {
		t.Fatalf("dialed LocalAddr = %v (%T); want a bound *SCTPAddr", cli.LocalAddr(), cli.LocalAddr())
	}
	ra, ok := cli.RemoteAddr().(*SCTPAddr)
	if !ok || ra == nil || ra.Port != saddr.Port {
		t.Fatalf("dialed RemoteAddr = %v (%T); want *SCTPAddr with port %d", cli.RemoteAddr(), cli.RemoteAddr(), saddr.Port)
	}
	if cli.LocalAddr().Network() != "sctp" || cli.RemoteAddr().Network() != "sctp" {
		t.Fatalf("dialed address networks = %q/%q; want sctp", cli.LocalAddr().Network(), cli.RemoteAddr().Network())
	}

	locals, err := cli.LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs error: %v", err)
	}
	if len(locals) == 0 || locals[0].Port != la.Port {
		t.Fatalf("LocalAddrs = %v; want the dialed local port %d", locals, la.Port)
	}
	peers, err := cli.PeerAddrs()
	if err != nil {
		t.Fatalf("PeerAddrs error: %v", err)
	}
	if len(peers) == 0 || peers[0].Port != saddr.Port {
		t.Fatalf("PeerAddrs = %v; want the listener port %d", peers, saddr.Port)
	}
}
