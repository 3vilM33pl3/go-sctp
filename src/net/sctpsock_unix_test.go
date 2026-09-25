// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"bytes"
	"errors"
	"os"
	"sync"
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

// TestSCTPConnConcurrentState drives the association bookkeeping from
// several goroutines at once. Under -race it catches unsynchronised access
// to SCTPConn.assocID (written by ReadFromSCTP, read by every option
// method) and to the multihoming address slices.
func TestSCTPConnConcurrentState(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	if err := srv.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo error: %v", err)
	}
	cli, err := DialSCTP("sctp4", nil, srv.LocalAddr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	const msgs = 64
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < msgs; i++ {
			if _, err := cli.WriteToSCTP([]byte("tick"), nil, &SCTPSndInfo{Stream: uint16(i % 4)}); err != nil {
				t.Errorf("WriteToSCTP error: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("SetReadDeadline error: %v", err)
			return
		}
		for got := 0; got < msgs; {
			_, _, flags, _, _, err := srv.ReadFromSCTP(buf)
			if err != nil {
				t.Errorf("ReadFromSCTP error: %v", err)
				return
			}
			if flags&sctpMsgNotification == 0 {
				got++
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < msgs; i++ {
			for _, c := range []*SCTPConn{srv, cli} {
				if _, err := c.LocalAddrs(); err != nil {
					t.Errorf("LocalAddrs error: %v", err)
					return
				}
				if _, err := c.PeerAddrs(); err != nil {
					t.Errorf("PeerAddrs error: %v", err)
					return
				}
				if err := c.SetMaxBurst(4); err != nil {
					t.Errorf("SetMaxBurst error: %v", err)
					return
				}
			}
		}
	}()
	wg.Wait()
}

// TestSCTPRawSockaddrPortByteOrder checks that the sockaddr lists handed to
// bindx/connectx carry the port in network byte order. Both kernels place
// the port at offset 2 of sockaddr_in and sockaddr_in6 and the address at
// offset 4 and 8 respectively; the parser used for SCTP_STATUS must read
// the same bytes back.
func TestSCTPRawSockaddrPortByteOrder(t *testing.T) {
	for _, tc := range []struct {
		family int
		addr   SCTPAddr
		ipOff  int
	}{
		{syscall.AF_INET, SCTPAddr{IP: IPv4(10, 1, 2, 3), Port: 0x1234}, 4},
		{syscall.AF_INET6, SCTPAddr{IP: ParseIP("2001:db8::7"), Port: 0xabcd}, 8},
	} {
		b, err := marshalRawSockaddrsSCTP(tc.family, []SCTPAddr{tc.addr})
		if err != nil {
			t.Fatalf("marshalRawSockaddrsSCTP(%v) error: %v", tc.addr, err)
		}
		if b[2] != byte(tc.addr.Port>>8) || b[3] != byte(tc.addr.Port) {
			t.Errorf("%v: port bytes = %#02x %#02x; want %#04x big-endian", tc.addr, b[2], b[3], tc.addr.Port)
		}
		wantIP := tc.addr.IP.To4()
		if tc.family == syscall.AF_INET6 {
			wantIP = tc.addr.IP.To16()
		}
		if got := b[tc.ipOff : tc.ipOff+len(wantIP)]; !bytes.Equal(got, wantIP) {
			t.Errorf("%v: address bytes = %v; want %v", tc.addr, got, wantIP)
		}
		storage := make([]byte, sockaddrStorageSize)
		copy(storage, b)
		got, err := parseSockaddrStorage(storage)
		if err != nil || got == nil {
			t.Fatalf("parseSockaddrStorage(%v) = %v, %v", tc.addr, got, err)
		}
		if got.Port != tc.addr.Port || !got.IP.Equal(tc.addr.IP) {
			t.Errorf("round trip of %v = %v", tc.addr, got)
		}
	}
}

// TestDialSCTPOneToOneAssocOptions checks that option calls on a dialed
// (one-to-one) connection work without an explicit association id. Linux
// answers SCTP_GET_ASSOC_ID_LIST with EOPNOTSUPP on such sockets and
// connectx reports no id while the connect is in flight, so the resolver
// must not depend on either.
func TestDialSCTPOneToOneAssocOptions(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	saddr := srv.LocalAddr().(*SCTPAddr)

	for _, dial := range []struct {
		name string
		fn   func() (*SCTPConn, error)
	}{
		{"DialSCTP", func() (*SCTPConn, error) { return DialSCTP("sctp4", nil, saddr) }},
		{"DialSCTPMulti", func() (*SCTPConn, error) {
			return DialSCTPMulti("sctp4", nil, &SCTPMultiAddr{Addrs: []SCTPAddr{*saddr}})
		}},
	} {
		t.Run(dial.name, func(t *testing.T) {
			cli, err := dial.fn()
			if err != nil {
				t.Fatalf("%s error: %v", dial.name, err)
			}
			defer cli.Close()
			if _, err := cli.WriteToSCTP([]byte("probe"), nil, &SCTPSndInfo{Stream: 1}); err != nil {
				t.Fatalf("WriteToSCTP error: %v", err)
			}
			buf := make([]byte, 64)
			readUserMessageSCTP(t, srv, buf)

			status, err := cli.AssocStatus(0)
			if err != nil {
				t.Fatalf("AssocStatus(0) error: %v", err)
			}
			if status.AssocID == 0 || status.State == 0 || status.OutStreams == 0 {
				t.Fatalf("AssocStatus(0) = %+v; want a live association", status)
			}
			if err := cli.SetMaxBurst(3); err != nil {
				t.Fatalf("SetMaxBurst error: %v", err)
			}
			if err := cli.SetRTOInfo(SCTPRTOInfo{Initial: 1200, Max: 3000, Min: 600}); err != nil {
				t.Fatalf("SetRTOInfo error: %v", err)
			}
			if err := cli.SetDelayedSack(SCTPDelayedSackInfo{Delay: 200, Frequency: 2}); err != nil {
				t.Fatalf("SetDelayedSack error: %v", err)
			}
		})
	}
}

// TestSCTPNotificationDelivery subscribes to every event type (the kernel
// rejects unknown SCTP_EVENT types with EINVAL, so this also checks the
// constants) and verifies that a peer connecting, sending and closing
// produces both the data and at least one notification.
func TestSCTPNotificationDelivery(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	all := SCTPEventMask{
		DataIO: true, Association: true, Address: true, SendFailure: true,
		PeerError: true, Shutdown: true, PartialDelivery: true, Adaptation: true,
		Authentication: true, SenderDry: true, StreamReset: true, AssocReset: true,
		StreamChange: true,
	}
	if err := srv.SubscribeEvents(all); err != nil {
		t.Fatalf("SubscribeEvents(all) error: %v", err)
	}
	if err := srv.SubscribeEvents(SCTPEventMask{DataIO: true, Association: true, Shutdown: true}); err != nil {
		t.Fatalf("SubscribeEvents error: %v", err)
	}

	cli, err := DialSCTPInit("sctp4", nil, srv.LocalAddr().(*SCTPAddr), SCTPInitOptions{NumOStreams: 8, MaxInStreams: 8})
	if err != nil {
		t.Fatalf("DialSCTPInit error: %v", err)
	}
	if err := cli.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline error: %v", err)
	}
	if _, err := cli.WriteToSCTP([]byte("notify-probe"), nil, &SCTPSndInfo{Stream: 1, PPID: 7}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	cli.Close()

	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline error: %v", err)
	}
	buf := make([]byte, 512)
	var sawData, sawNotification bool
	for !(sawData && sawNotification) {
		n, _, flags, _, info, err := srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v (data=%v notification=%v)", err, sawData, sawNotification)
		}
		if flags&sctpMsgNotification != 0 {
			sawNotification = true
			continue
		}
		if string(buf[:n]) != "notify-probe" {
			t.Fatalf("payload = %q; want notify-probe", buf[:n])
		}
		if info == nil || info.Stream != 1 || info.PPID != 7 {
			t.Fatalf("RcvInfo = %+v; want stream 1, ppid 7 (DataIO must enable SCTP_RECVRCVINFO)", info)
		}
		sawData = true
	}
}
