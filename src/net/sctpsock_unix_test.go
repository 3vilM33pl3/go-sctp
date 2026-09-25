// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
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
	var (
		sawData, sawUp, sawDown bool
		dataAssoc               int32
	)
	for !(sawData && sawUp && sawDown) {
		n, _, flags, _, info, err := srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v (data=%v up=%v down=%v)", err, sawData, sawUp, sawDown)
		}
		if flags&SCTPMsgNotification != 0 {
			nt, err := ParseSCTPNotification(buf[:n])
			if err != nil {
				t.Fatalf("ParseSCTPNotification(% x) error: %v", buf[:n], err)
			}
			switch nt.Type {
			case SCTPNotifyAssocChange:
				switch nt.AssocChange.State {
				case SCTPCommUp:
					if nt.AssocChange.OutboundStreams == 0 || nt.AssocChange.InboundStreams == 0 {
						t.Errorf("COMM_UP with zero streams: %+v", nt.AssocChange)
					}
					sawUp = true
				case SCTPShutdownComp:
					sawDown = true
				}
			case SCTPNotifyShutdown:
				sawDown = true
			}
			if nt.AssocID == 0 {
				t.Errorf("%v notification without an association id", nt.Type)
			}
			if sawData && nt.AssocID != dataAssoc {
				t.Errorf("%v notification for association %d; data came on %d", nt.Type, nt.AssocID, dataAssoc)
			}
			continue
		}
		if string(buf[:n]) != "notify-probe" {
			t.Fatalf("payload = %q; want notify-probe", buf[:n])
		}
		if info == nil || info.Stream != 1 || info.PPID != 7 {
			t.Fatalf("RcvInfo = %+v; want stream 1, ppid 7 (DataIO must enable SCTP_RECVRCVINFO)", info)
		}
		dataAssoc = info.AssocID
		sawData = true
	}
}

// sctpNotifyRawValues holds the kernel's own numbering for the notification
// layouts built by TestParseSCTPNotificationLayouts; each backend's test
// file fills it in from its header.
type sctpNotifyRawValues struct {
	assocChange, peerAddrChange, remoteError, sendFailed, shutdown, streamReset uint16
	commLost                                                                    uint16
	addrConfirmed                                                               uint32
	dataSent                                                                    uint16
}

// notifyBytes lays out a notification in host byte order: the sctp_tlv
// header followed by the fields, with the length filled in.
func notifyBytes(t *testing.T, typ, flags uint16, fields ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range append([]any{typ, flags, uint32(0)}, fields...) {
		if b, ok := f.([]byte); ok {
			buf.Write(b)
			continue
		}
		if err := binary.Write(&buf, binary.NativeEndian, f); err != nil {
			t.Fatalf("binary.Write(%T) error: %v", f, err)
		}
	}
	out := buf.Bytes()
	binary.NativeEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

func TestParseSCTPNotificationLayouts(t *testing.T) {
	raw := sctpNotifyRaw

	t.Run("AssocChange", func(t *testing.T) {
		b := notifyBytes(t, raw.assocChange, 0, raw.commLost, uint16(0x0d), uint16(5), uint16(7), int32(42), []byte{0xaa, 0xbb, 0xcc, 0xdd})
		n, err := ParseSCTPNotification(b)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n.Type != SCTPNotifyAssocChange || n.AssocID != 42 || n.AssocChange == nil {
			t.Fatalf("decoded %+v", n)
		}
		ac := n.AssocChange
		if ac.State != SCTPCommLost || ac.Error != 0x0d || ac.OutboundStreams != 5 || ac.InboundStreams != 7 || !bytes.Equal(ac.Info, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
			t.Fatalf("AssocChange = %+v", ac)
		}
	})
	t.Run("PeerAddrChange", func(t *testing.T) {
		sa, err := marshalRawSockaddrsSCTP(syscall.AF_INET, []SCTPAddr{{IP: IPv4(10, 0, 0, 9), Port: 5000}})
		if err != nil {
			t.Fatal(err)
		}
		storage := make([]byte, sockaddrStorageSize)
		copy(storage, sa)
		b := notifyBytes(t, raw.peerAddrChange, 0, storage, raw.addrConfirmed, uint32(0), int32(7))
		if len(b) != 148 {
			t.Fatalf("layout is %d bytes; want 148", len(b))
		}
		n, err := ParseSCTPNotification(b)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n.Type != SCTPNotifyPeerAddrChange || n.AssocID != 7 || n.PeerAddrChange == nil {
			t.Fatalf("decoded %+v", n)
		}
		pc := n.PeerAddrChange
		if pc.State != SCTPAddrConfirmed || pc.Error != 0 || !pc.Addr.IP.Equal(IPv4(10, 0, 0, 9)) || pc.Addr.Port != 5000 {
			t.Fatalf("PeerAddrChange = %+v", pc)
		}
	})
	t.Run("RemoteError", func(t *testing.T) {
		// The cause code is in network byte order (RFC 6458, 6.1.3).
		b := notifyBytes(t, raw.remoteError, 0, []byte{0x00, 0x0c}, uint16(0), int32(3), []byte{1, 2, 3, 4})
		n, err := ParseSCTPNotification(b)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n.Type != SCTPNotifyRemoteError || n.AssocID != 3 || n.RemoteError == nil || n.RemoteError.Error != 0x0c || !bytes.Equal(n.RemoteError.Data, []byte{1, 2, 3, 4}) {
			t.Fatalf("decoded %+v / %+v", n, n.RemoteError)
		}
	})
	t.Run("SendFailed", func(t *testing.T) {
		b := notifyBytes(t, raw.sendFailed, raw.dataSent, uint32(0x20),
			uint16(4), uint16(SCTPUnordered), uint32(99), uint32(8), int32(11), // sctp_sndinfo
			int32(11), []byte("hi"))
		n, err := ParseSCTPNotification(b)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n.Type != SCTPNotifySendFailed || n.AssocID != 11 || n.SendFailed == nil {
			t.Fatalf("decoded %+v", n)
		}
		sf := n.SendFailed
		if !sf.Sent || sf.Error != 0x20 || sf.Info.Stream != 4 || sf.Info.Flags != SCTPUnordered || sf.Info.PPID != 99 || sf.Info.Context != 8 || sf.Info.AssocID != 11 || string(sf.Data) != "hi" {
			t.Fatalf("SendFailed = %+v", sf)
		}
	})
	t.Run("Shutdown", func(t *testing.T) {
		n, err := ParseSCTPNotification(notifyBytes(t, raw.shutdown, 0, int32(5)))
		if err != nil || n.Type != SCTPNotifyShutdown || n.AssocID != 5 {
			t.Fatalf("decoded %+v, %v", n, err)
		}
	})
	t.Run("StreamReset", func(t *testing.T) {
		flags := uint16(SCTPStreamResetOutgoing | SCTPStreamResetDenied)
		n, err := ParseSCTPNotification(notifyBytes(t, raw.streamReset, flags, int32(9), uint16(2), uint16(3)))
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n.Type != SCTPNotifyStreamReset || n.AssocID != 9 || n.StreamReset == nil || n.StreamReset.Flags != flags || !slicesEqualUint16(n.StreamReset.Streams, []uint16{2, 3}) {
			t.Fatalf("decoded %+v / %+v", n, n.StreamReset)
		}
	})
	t.Run("Malformed", func(t *testing.T) {
		if _, err := ParseSCTPNotification(make([]byte, 7)); err == nil {
			t.Error("7-byte buffer accepted")
		}
		b := notifyBytes(t, raw.shutdown, 0, int32(5))
		binary.NativeEndian.PutUint32(b[4:], 64) // longer than the buffer
		if _, err := ParseSCTPNotification(b); err == nil {
			t.Error("over-long length accepted")
		}
		binary.NativeEndian.PutUint32(b[4:], 4) // shorter than the header
		if _, err := ParseSCTPNotification(b); err == nil {
			t.Error("under-long length accepted")
		}
		if _, err := ParseSCTPNotification(notifyBytes(t, raw.assocChange, 0, uint16(1))); err == nil {
			t.Error("truncated assoc change accepted")
		}
	})
	t.Run("String", func(t *testing.T) {
		if got := SCTPNotifyShutdown.String(); got != "shutdown" {
			t.Errorf("SCTPNotifyShutdown.String() = %q", got)
		}
		if got := SCTPNotificationType(99).String(); got != "unknown(99)" {
			t.Errorf("SCTPNotificationType(99).String() = %q", got)
		}
	})
}

func slicesEqualUint16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSCTPReadFromEOF checks that a peer shutting the association down is
// reported as a bare io.EOF from both Read and ReadFromSCTP, like net.Conn
// implementations do, rather than an *OpError wrapping it.
func TestSCTPReadFromEOF(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	cli, err := DialSCTP("sctp4", nil, srv.LocalAddr().(*SCTPAddr))
	if err != nil {
		srv.Close()
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()
	if _, err := cli.WriteToSCTP([]byte("bye"), nil, nil); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	buf := make([]byte, 64)
	readUserMessageSCTP(t, srv, buf)
	srv.Close()

	if err := cli.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline error: %v", err)
	}
	n, _, _, _, _, err := cli.ReadFromSCTP(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("ReadFromSCTP after peer close = %d, %v; want 0, io.EOF", n, err)
	}
	if n, err := cli.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("Read after peer close = %d, %v; want 0, io.EOF", n, err)
	}
}

// TestSCTPListenerAccept exercises net.Listen("sctp") end to end: the
// listener is an *SCTPListener, net.Dial reaches it, the accepted connection
// is a one-to-one SCTPConn with SCTP addresses, data flows both ways, and
// deadlines and Close behave like TCPListener's.
func TestSCTPListenerAccept(t *testing.T) {
	requireSCTP(t)

	ln, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer ln.Close()
	sl, ok := ln.(*SCTPListener)
	if !ok {
		t.Fatalf("Listen(sctp4) returned %T; want *SCTPListener", ln)
	}
	if _, ok := ln.Addr().(*SCTPAddr); !ok || ln.Addr().(*SCTPAddr).Port == 0 {
		t.Fatalf("listener Addr = %v (%T); want a bound *SCTPAddr", ln.Addr(), ln.Addr())
	}

	cli, err := Dial("sctp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer cli.Close()
	if _, ok := cli.(*SCTPConn); !ok {
		t.Fatalf("Dial(sctp4) returned %T; want *SCTPConn", cli)
	}

	if err := sl.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline error: %v", err)
	}
	srv, err := sl.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP error: %v", err)
	}
	defer srv.Close()
	if ra, ok := srv.RemoteAddr().(*SCTPAddr); !ok || ra.Port != cli.LocalAddr().(*SCTPAddr).Port {
		t.Fatalf("accepted RemoteAddr = %v; want the dialer's %v", srv.RemoteAddr(), cli.LocalAddr())
	}
	if la, ok := srv.LocalAddr().(*SCTPAddr); !ok || la.Port != ln.Addr().(*SCTPAddr).Port {
		t.Fatalf("accepted LocalAddr = %v; want the listener's %v", srv.LocalAddr(), ln.Addr())
	}

	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	buf := make([]byte, 64)
	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := srv.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, %v; want hello", buf[:n], err)
	}
	if _, err := srv.WriteToSCTP([]byte("reply"), nil, &SCTPSndInfo{Stream: 1, PPID: 9}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	n, _, _ = readUserMessageSCTP(t, cli.(*SCTPConn), buf)
	if string(buf[:n]) != "reply" {
		t.Fatalf("client Read = %q; want reply", buf[:n])
	}
	if status, err := srv.AssocStatus(0); err != nil || status.State == 0 {
		t.Fatalf("accepted AssocStatus = %+v, %v; want a live association", status, err)
	}

	// An idle listener honours its deadline, and Accept after Close fails
	// with ErrClosed, like TCPListener.
	if err := sl.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := sl.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept on idle listener = %v; want deadline exceeded", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if _, err := sl.Accept(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept after Close = %v; want ErrClosed", err)
	}
}

func TestListenSCTPOneToOneErrors(t *testing.T) {
	requireSCTP(t)
	if _, err := ListenSCTPOneToOne("bogus", nil); err == nil || !errors.Is(err, UnknownNetworkError("bogus")) {
		var une UnknownNetworkError
		if !errors.As(err, &une) {
			t.Fatalf("ListenSCTPOneToOne(bogus) = %v; want UnknownNetworkError", err)
		}
	}
	ln, err := ListenSCTPOneToOne("sctp", nil)
	if err != nil {
		t.Fatalf("ListenSCTPOneToOne(wildcard) error: %v", err)
	}
	defer ln.Close()
	if ln.Addr().(*SCTPAddr).Port == 0 {
		t.Fatalf("wildcard listener got port 0: %v", ln.Addr())
	}
	if _, err := ln.SyscallConn(); err != nil {
		t.Fatalf("SyscallConn error: %v", err)
	}
	f, err := ln.File()
	if err != nil {
		t.Fatalf("File error: %v", err)
	}
	f.Close()
}

// TestSCTPOptionSetters exercises the option methods that had no coverage,
// on the socket type each applies to, and checks the errno for the ones the
// kernel may not support rather than skipping on any error.
func TestSCTPOptionSetters(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()
	cli, err := DialSCTP("sctp4", nil, srv.LocalAddr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	optional := func(name string, err error) {
		t.Helper()
		if err == nil {
			return
		}
		// ENOPROTOOPT/EOPNOTSUPP: the kernel lacks the option or the
		// feature was not negotiated; EACCES: Linux with
		// net.sctp.auth_enable=0 refuses the AUTH options.
		if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EACCES) {
			t.Logf("%s: not enabled on this kernel: %v", name, err)
			return
		}
		t.Errorf("%s error: %v", name, err)
	}

	// Socket-level defaults on the one-to-many listener.
	if err := srv.SetFragmentInterleave(1); err != nil {
		t.Errorf("SetFragmentInterleave error: %v", err)
	}
	if err := srv.SetDefaultPRInfo(SCTPPRInfo{Policy: SCTPPRTTL, Value: 500}); err != nil {
		t.Errorf("SetDefaultPRInfo error: %v", err)
	}
	if err := srv.SetDefaultSendInfo(SCTPSndInfo{Stream: 2, PPID: 77}); err != nil {
		t.Errorf("SetDefaultSendInfo error: %v", err)
	}
	if err := srv.SetNoDelay(true); err != nil {
		t.Errorf("SetNoDelay error: %v", err)
	}
	if err := srv.SetRecvNxtInfo(true); err != nil {
		t.Errorf("SetRecvNxtInfo error: %v", err)
	}
	optional("SetStreamScheduler", srv.SetStreamScheduler(SCTPSchedulerRR))
	optional("SetAuthChunks", srv.SetAuthChunks([]uint8{0x0e}))

	// AUTH keys on the dialed association.
	if _, err := cli.WriteToSCTP([]byte("probe"), nil, nil); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	readUserMessageSCTP(t, srv, make([]byte, 64))
	key := SCTPAuthKey{KeyID: 7, Secret: []byte("sixteen-byte-key")}
	if err := cli.SetAuthKey(key); err != nil {
		optional("SetAuthKey", err)
	} else {
		optional("ActivateAuthKey", cli.ActivateAuthKey(0, 7))
		optional("DeleteAuthKey", cli.DeleteAuthKey(0, 7))
	}
	optional("SetStreamSchedulerValue", cli.SetStreamSchedulerValue(0, 1))

	// Per-association values on the one-to-one socket, without an id.
	if err := cli.SetDefaultPRInfo(SCTPPRInfo{Policy: SCTPPRRTX, Value: 3}); err != nil {
		t.Errorf("SetDefaultPRInfo(assoc) error: %v", err)
	}
	if err := cli.SetMaxSeg(1200); err != nil {
		t.Errorf("SetMaxSeg error: %v", err)
	}
	if err := cli.SetReadBuffer(1 << 16); err != nil {
		t.Errorf("SetReadBuffer error: %v", err)
	}
	if err := cli.SetWriteBuffer(1 << 16); err != nil {
		t.Errorf("SetWriteBuffer error: %v", err)
	}
	if err := cli.SetAutoClose(1); err == nil {
		t.Errorf("SetAutoClose on a one-to-one socket succeeded; SCTP_AUTOCLOSE is one-to-many only")
	}
}

// TestSCTPPacketConn drives the PacketConn methods on a one-to-many socket
// pair, including the address checks WriteTo performs.
func TestSCTPPacketConn(t *testing.T) {
	requireSCTP(t)

	a, err := ListenPacket("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error: %v", err)
	}
	defer a.Close()
	b, err := ListenPacket("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error: %v", err)
	}
	defer b.Close()
	if _, ok := a.(*SCTPConn); !ok {
		t.Fatalf("ListenPacket(sctp4) returned %T; want *SCTPConn", a)
	}

	if _, err := a.WriteTo([]byte("x"), &UDPAddr{IP: IPv4(127, 0, 0, 1), Port: 1}); err == nil {
		t.Error("WriteTo with a *UDPAddr succeeded")
	}
	if _, err := a.WriteTo([]byte("to-b"), b.LocalAddr()); err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if err := b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	for {
		n, from, err := b.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom error: %v", err)
		}
		if n == 0 || from == nil {
			continue // a notification would carry no user data
		}
		if string(buf[:n]) != "to-b" {
			t.Fatalf("ReadFrom = %q; want to-b", buf[:n])
		}
		if from.(*SCTPAddr).Port != a.LocalAddr().(*SCTPAddr).Port {
			t.Fatalf("ReadFrom from = %v; want %v", from, a.LocalAddr())
		}
		break
	}

	// An idle read honours its deadline.
	if err := b.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle ReadFrom = %v; want deadline exceeded", err)
	}
}

// TestSCTPIPv6Loopback runs the basic exchange over sctp6 with DialSCTPInit.
func TestSCTPIPv6Loopback(t *testing.T) {
	requireSCTP(t)
	if !supportsIPv6() {
		t.Skip("IPv6 is not supported")
	}

	srv, err := ListenSCTPInit("sctp6", &SCTPAddr{IP: IPv6loopback}, SCTPInitOptions{NumOStreams: 4, MaxInStreams: 4})
	if err != nil {
		t.Fatalf("ListenSCTPInit(sctp6) error: %v", err)
	}
	defer srv.Close()
	cli, err := DialSCTPInit("sctp6", nil, srv.LocalAddr().(*SCTPAddr), SCTPInitOptions{NumOStreams: 4, MaxInStreams: 4})
	if err != nil {
		t.Fatalf("DialSCTPInit(sctp6) error: %v", err)
	}
	defer cli.Close()
	if la := cli.LocalAddr().(*SCTPAddr); la.IP.To4() != nil {
		t.Fatalf("sctp6 LocalAddr = %v; want an IPv6 address", la)
	}
	if _, err := cli.WriteToSCTP([]byte("v6"), nil, &SCTPSndInfo{Stream: 3, PPID: 6}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	buf := make([]byte, 64)
	n, from, info := readUserMessageSCTP(t, srv, buf)
	if string(buf[:n]) != "v6" || from == nil || from.IP.To4() != nil {
		t.Fatalf("server got %q from %v", buf[:n], from)
	}
	if info == nil || info.Stream != 3 || info.PPID != 6 {
		t.Fatalf("RcvInfo = %+v; want stream 3, ppid 6", info)
	}
	if status, err := cli.AssocStatus(0); err != nil || status.OutStreams != 4 {
		t.Fatalf("AssocStatus = %+v, %v; want 4 outbound streams from the INIT options", status, err)
	}
}
