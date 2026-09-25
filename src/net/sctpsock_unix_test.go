// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"bytes"
	"errors"
	"os"
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

// fdFlags returns the descriptor's F_GETFD and F_GETFL flags.
func fdFlags(t *testing.T, c *SCTPConn) (fdflags, flflags int) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn error: %v", err)
	}
	if err := rc.Control(func(fd uintptr) {
		r, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if e != 0 {
			t.Fatalf("fcntl(F_GETFD) error: %v", e)
		}
		fdflags = int(r)
		r, _, e = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if e != 0 {
			t.Fatalf("fcntl(F_GETFL) error: %v", e)
		}
		flflags = int(r)
	}); err != nil {
		t.Fatalf("Control error: %v", err)
	}
	return fdflags, flflags
}

// TestSCTPAssocStatusAndPeelOff peels an association off a one-to-many
// listener and checks the peeled descriptor is a proper net descriptor:
// non-blocking (so deadlines work), close-on-exec, and reporting SCTP
// addresses.
func TestSCTPAssocStatusAndPeelOff(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	if err := srv.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo error: %v", err)
	}
	saddr := srv.LocalAddr().(*SCTPAddr)

	cli, err := DialSCTP("sctp4", nil, saddr)
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	first := []byte("assoc-status-peeloff")
	if _, err := cli.WriteToSCTP(first, nil, &SCTPSndInfo{Stream: 2, PPID: 44}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	buf := make([]byte, 256)
	n, _, info := readUserMessageSCTP(t, srv, buf)
	if !bytes.Equal(buf[:n], first) {
		t.Fatalf("server payload = %q; want %q", buf[:n], first)
	}
	if info == nil || info.AssocID == 0 {
		t.Fatalf("server RcvInfo = %+v; want a non-zero association id", info)
	}

	status, err := srv.AssocStatus(info.AssocID)
	if err != nil {
		t.Fatalf("AssocStatus error: %v", err)
	}
	if status.AssocID != info.AssocID || status.State == 0 {
		t.Fatalf("AssocStatus = %+v; want id %d and a non-zero state", status, info.AssocID)
	}
	ids, err := srv.AssocIDs()
	if err != nil {
		t.Fatalf("AssocIDs error: %v", err)
	}
	if len(ids) != 1 || ids[0] != info.AssocID {
		t.Fatalf("AssocIDs = %v; want [%d]", ids, info.AssocID)
	}

	peeled, err := srv.PeelOff(info.AssocID)
	if err != nil {
		t.Fatalf("PeelOff error: %v", err)
	}
	defer peeled.Close()

	fdflags, flflags := fdFlags(t, peeled)
	if fdflags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("peeled descriptor lacks FD_CLOEXEC (F_GETFD = %#x)", fdflags)
	}
	if flflags&syscall.O_NONBLOCK == 0 {
		t.Errorf("peeled descriptor is blocking (F_GETFL = %#x)", flflags)
	}
	if _, ok := peeled.LocalAddr().(*SCTPAddr); !ok {
		t.Errorf("peeled LocalAddr type = %T; want *SCTPAddr", peeled.LocalAddr())
	}
	if ra, ok := peeled.RemoteAddr().(*SCTPAddr); !ok || ra.Port != cli.LocalAddr().(*SCTPAddr).Port {
		t.Errorf("peeled RemoteAddr = %v; want the client address %v", peeled.RemoteAddr(), cli.LocalAddr())
	}

	// Nothing is queued on the peeled socket yet, so a read must honour
	// its deadline instead of blocking in the kernel.
	if err := peeled.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline error: %v", err)
	}
	if _, err := peeled.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read on idle peeled conn = %v; want deadline exceeded", err)
	}

	second := []byte("peeled-payload")
	if _, err := cli.WriteToSCTP(second, nil, &SCTPSndInfo{Stream: 3, PPID: 45}); err != nil {
		t.Fatalf("second WriteToSCTP error: %v", err)
	}
	n, _, info = readUserMessageSCTP(t, peeled, buf)
	if !bytes.Equal(buf[:n], second) {
		t.Fatalf("peeled payload = %q; want %q", buf[:n], second)
	}
	if info == nil || info.Stream != 3 || info.PPID != 45 {
		t.Fatalf("peeled RcvInfo = %+v; want stream 3, ppid 45", info)
	}
	if _, err := peeled.WriteToSCTP([]byte("reply"), nil, &SCTPSndInfo{Stream: 1}); err != nil {
		t.Fatalf("peeled WriteToSCTP error: %v", err)
	}
	n, _, _ = readUserMessageSCTP(t, cli, buf)
	if string(buf[:n]) != "reply" {
		t.Fatalf("client payload = %q; want %q", buf[:n], "reply")
	}
}
