// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package net

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const sctpMsgNotification = 0x8000

func requireSCTP(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("kernel SCTP unavailable: %v", err)
	}
	syscall.Close(fd)
}

func TestSCTPLoopbackReadWrite(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()

	if err := srv.SetInitOptions(SCTPInitOptions{NumOStreams: 8, MaxInStreams: 8}); err != nil {
		t.Fatalf("SetInitOptions(server) error: %v", err)
	}
	if err := srv.SubscribeEvents(SCTPEventMask{Association: true, Shutdown: true, DataIO: true}); err != nil {
		t.Fatalf("SubscribeEvents(server) error: %v", err)
	}

	saddr, ok := srv.LocalAddr().(*SCTPAddr)
	if !ok {
		t.Fatalf("server LocalAddr type = %T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTP("sctp4", nil, saddr)
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	if err := cli.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay(client) error: %v", err)
	}

	payload := []byte("sctp-loopback-test")
	snd := &SCTPSndInfo{Stream: 2, PPID: 42}
	if _, err := cli.WriteToSCTP(payload, nil, snd); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}

	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server) error: %v", err)
	}

	buf := make([]byte, 256)
	var (
		n     int
		flags int
		from  *SCTPAddr
		info  *SCTPRcvInfo
	)
	for {
		n, _, flags, from, info, err = srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v", err)
		}
		if flags&sctpMsgNotification != 0 {
			continue
		}
		break
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch got %q want %q", buf[:n], payload)
	}
	if from == nil {
		t.Fatalf("ReadFromSCTP from=nil")
	}
	if info == nil {
		t.Fatalf("ReadFromSCTP info=nil; want SCTP_RCVINFO")
	}
	if info.Stream != snd.Stream {
		t.Fatalf("ReadFromSCTP stream=%d; want %d", info.Stream, snd.Stream)
	}
}

func TestSCTPUnsupportedOnBadNetwork(t *testing.T) {
	requireSCTP(t)
	_, err := DialSCTP("udp", nil, &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 1})
	var nerr UnknownNetworkError
	if !errors.As(err, &nerr) {
		t.Fatalf("DialSCTP error=%v; want UnknownNetworkError", err)
	}
}

func TestSCTPMultiListenLocalAddrs(t *testing.T) {
	requireSCTP(t)

	laddr := &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: 0},
			{IP: IPv4(127, 0, 0, 2), Port: 0},
		},
	}
	srv, err := ListenSCTPMulti("sctp4", laddr)
	if err != nil {
		t.Skipf("multihome listen unavailable: %v", err)
	}
	defer srv.Close()

	addrs, err := srv.LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatalf("LocalAddrs returned no addresses")
	}
	var sawLoopback2 bool
	for i := range addrs {
		if addrs[i].IP.Equal(IPv4(127, 0, 0, 2)) {
			sawLoopback2 = true
			break
		}
	}
	if !sawLoopback2 {
		t.Fatalf("LocalAddrs missing 127.0.0.2: got=%v", addrs)
	}
}

func TestDialSCTPMultiRemoteMulti(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTPMulti("sctp4", &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: 0},
			{IP: IPv4(127, 0, 0, 2), Port: 0},
		},
	})
	if err != nil {
		t.Skipf("multihome listen unavailable: %v", err)
	}
	defer srv.Close()

	sla, ok := srv.LocalAddr().(*SCTPAddr)
	if !ok || sla == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTPMulti("sctp4", nil, &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: sla.Port},
			{IP: IPv4(127, 0, 0, 2), Port: sla.Port},
		},
	})
	if err != nil {
		t.Skipf("remote multihome dial unavailable: %v", err)
	}
	defer cli.Close()

	payload := []byte("sctp-multi-remote")
	if _, err := cli.WriteToSCTP(payload, nil, &SCTPSndInfo{Stream: 1, PPID: 11}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}
	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server) error: %v", err)
	}
	buf := make([]byte, 256)
	for {
		n, _, flags, _, _, err := srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v", err)
		}
		if flags&sctpMsgNotification != 0 {
			continue
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("payload mismatch got %q want %q", buf[:n], payload)
		}
		break
	}
}

func TestDialSCTPMultiPeerAddrs(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTPMulti("sctp4", &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: 0},
			{IP: IPv4(127, 0, 0, 2), Port: 0},
		},
	})
	if err != nil {
		t.Skipf("multihome listen unavailable: %v", err)
	}
	defer srv.Close()

	sla, _ := srv.LocalAddr().(*SCTPAddr)
	if sla == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTPMulti("sctp4", nil, &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: sla.Port},
			{IP: IPv4(127, 0, 0, 2), Port: sla.Port},
		},
	})
	if err != nil {
		t.Skipf("remote multihome dial unavailable: %v", err)
	}
	defer cli.Close()

	paddrs, err := cli.PeerAddrs()
	if err != nil {
		t.Fatalf("PeerAddrs error: %v", err)
	}
	if len(paddrs) != 2 {
		t.Fatalf("PeerAddrs len=%d; want 2 (got=%v)", len(paddrs), paddrs)
	}
}

func TestDialSCTPMultiWriteFallback(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTPMulti("sctp4", &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: 0},
			{IP: IPv4(127, 0, 0, 2), Port: 0},
		},
	})
	if err != nil {
		t.Skipf("multihome listen unavailable: %v", err)
	}
	defer srv.Close()

	sla, _ := srv.LocalAddr().(*SCTPAddr)
	if sla == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTPMulti("sctp4", nil, &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			// First path is intentionally unavailable to exercise fallback.
			{IP: IPv4(127, 0, 0, 3), Port: sla.Port},
			{IP: IPv4(127, 0, 0, 1), Port: sla.Port},
			{IP: IPv4(127, 0, 0, 2), Port: sla.Port},
		},
	})
	if err != nil {
		t.Skipf("remote multihome dial unavailable: %v", err)
	}
	defer cli.Close()

	payload := []byte("sctp-multi-fallback")
	if _, err := cli.WriteToSCTP(payload, nil, &SCTPSndInfo{Stream: 3, PPID: 77}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}

	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server) error: %v", err)
	}
	buf := make([]byte, 256)
	for {
		n, _, flags, _, _, err := srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v", err)
		}
		if flags&sctpMsgNotification != 0 {
			continue
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("payload mismatch got %q want %q", buf[:n], payload)
		}
		break
	}
}

func TestSCTPDefaultSendInfoAndRecvNxtInfo(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()

	saddr, _ := srv.LocalAddr().(*SCTPAddr)
	if saddr == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}
	if err := srv.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo(server) error: %v", err)
	}

	cli, err := DialSCTP("sctp4", nil, saddr)
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	if err := cli.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo error: %v", err)
	}
	if err := cli.SetRecvNxtInfo(true); err != nil {
		t.Fatalf("SetRecvNxtInfo error: %v", err)
	}
	if err := cli.SetDefaultSendInfo(SCTPSndInfo{Stream: 9, PPID: 901}); err != nil {
		t.Fatalf("SetDefaultSendInfo error: %v", err)
	}
	if _, err := cli.WriteToSCTP([]byte("default-sndinfo"), nil, &SCTPSndInfo{Stream: 9, PPID: 901}); err != nil {
		t.Fatalf("WriteToSCTP(default send info) error: %v", err)
	}

	buf := make([]byte, 256)
	n, from, info := readUserMessageSCTP(t, srv, buf)
	if got, want := string(buf[:n]), "default-sndinfo"; got != want {
		t.Fatalf("payload mismatch got %q want %q", got, want)
	}
	if from == nil || info == nil {
		t.Fatalf("missing SCTP metadata from=%v info=%v", from, info)
	}
	if info.Stream != 9 || info.PPID != 901 {
		t.Fatalf("default send metadata mismatch stream=%d ppid=%d", info.Stream, info.PPID)
	}
	_ = from

	oob := make([]byte, syscall.CmsgSpace(sizeofSCTPRcvInfoLinux)+syscall.CmsgSpace(sizeofSCTPNxtInfoLinux))
	rcvHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	rcvHdr.Level = syscall.IPPROTO_SCTP
	rcvHdr.Type = sctpCmsgTypeRcvInfo
	rcvHdr.SetLen(syscall.CmsgLen(sizeofSCTPRcvInfoLinux))
	rcv := sctpRcvInfoLinux{Stream: 10, PPID: 1001, AssocID: 77}
	copy(oob[syscall.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&rcv)), sizeofSCTPRcvInfoLinux))
	offset := syscall.CmsgSpace(sizeofSCTPRcvInfoLinux)
	nxtHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[offset]))
	nxtHdr.Level = syscall.IPPROTO_SCTP
	nxtHdr.Type = sctpCmsgTypeNxtInfo
	nxtHdr.SetLen(syscall.CmsgLen(sizeofSCTPNxtInfoLinux))
	nxt := sctpNxtInfoLinux{Stream: 11, PPID: 1002, Length: uint32(len("nxt-second")), AssocID: 77}
	copy(oob[offset+syscall.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&nxt)), sizeofSCTPNxtInfoLinux))
	parsed, err := parseSCTPRcvInfo(oob)
	if err != nil {
		t.Fatalf("parseSCTPRcvInfo error: %v", err)
	}
	if parsed == nil || parsed.Next == nil {
		t.Fatalf("parsed next info missing: %+v", parsed)
	}
	if parsed.Next.Stream != 11 || parsed.Next.PPID != 1002 || parsed.Next.Length != uint32(len("nxt-second")) {
		t.Fatalf("unexpected parsed next info: %+v", parsed.Next)
	}
}

func TestSCTPAssocStatusAndPeelOff(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenSCTP error: %v", err)
	}
	defer srv.Close()

	saddr, _ := srv.LocalAddr().(*SCTPAddr)
	if saddr == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTP("sctp4", nil, saddr)
	if err != nil {
		t.Fatalf("DialSCTP error: %v", err)
	}
	defer cli.Close()

	payload := []byte("assoc-status-peeloff")
	if _, err := cli.WriteToSCTP(payload, nil, &SCTPSndInfo{Stream: 2, PPID: 44}); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}

	ids, err := cli.AssocIDs()
	if err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SCTP assoc id listing unavailable: %v", err)
		}
		t.Fatalf("AssocIDs error: %v", err)
	}
	if len(ids) == 0 || ids[0] == 0 {
		t.Fatalf("AssocIDs=%v; want at least one non-zero id", ids)
	}

	status, err := cli.AssocStatus(ids[0])
	if err != nil {
		t.Fatalf("AssocStatus error: %v", err)
	}
	if status.AssocID == 0 {
		t.Fatalf("AssocStatus=%+v; want non-zero assoc id", status)
	}
	if status.State == 0 {
		t.Fatalf("AssocStatus=%+v; want non-zero state", status)
	}

	peeled, err := cli.PeelOff(0)
	if err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SCTP peeloff unavailable: %v", err)
		}
		t.Fatalf("PeelOff error: %v", err)
	}
	defer peeled.Close()

	peeledPayload := []byte("peeled-payload")
	if _, err := peeled.WriteToSCTP(peeledPayload, nil, &SCTPSndInfo{Stream: 3, PPID: 45}); err != nil {
		t.Fatalf("peeled WriteToSCTP error: %v", err)
	}
	buf := make([]byte, 256)
	n, _, _ := readUserMessageSCTP(t, srv, buf)
	if !bytes.Equal(buf[:n], payload) && !bytes.Equal(buf[:n], peeledPayload) {
		t.Fatalf("unexpected server payload %q", buf[:n])
	}
	n, _, _ = readUserMessageSCTP(t, srv, buf)
	if !bytes.Equal(buf[:n], payload) && !bytes.Equal(buf[:n], peeledPayload) {
		t.Fatalf("unexpected second server payload %q", buf[:n])
	}
}

func TestSCTPMultiSocketControls(t *testing.T) {
	requireSCTP(t)

	srv, err := ListenSCTPMulti("sctp4", &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: 0},
			{IP: IPv4(127, 0, 0, 2), Port: 0},
		},
	})
	if err != nil {
		t.Skipf("multihome listen unavailable: %v", err)
	}
	defer srv.Close()

	sla, _ := srv.LocalAddr().(*SCTPAddr)
	if sla == nil {
		t.Fatalf("server LocalAddr type=%T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTPMulti("sctp4", nil, &SCTPMultiAddr{
		Addrs: []SCTPAddr{
			{IP: IPv4(127, 0, 0, 1), Port: sla.Port},
			{IP: IPv4(127, 0, 0, 2), Port: sla.Port},
		},
	})
	if err != nil {
		t.Skipf("remote multihome dial unavailable: %v", err)
	}
	defer cli.Close()

	pre, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenSCTP(pre-bind) error: %v", err)
	}
	if err := pre.BindAddrs([]SCTPAddr{{IP: IPv4(127, 0, 0, 3), Port: 0}}); err != nil {
		pre.Close()
		t.Fatalf("BindAddrs error: %v", err)
	}
	if err := pre.UnbindAddrs([]SCTPAddr{{IP: IPv4(127, 0, 0, 3), Port: 0}}); err != nil {
		pre.Close()
		t.Fatalf("UnbindAddrs error: %v", err)
	}
	pre.Close()

	if _, err := cli.WriteToSCTP([]byte("control-probe"), nil, &SCTPSndInfo{Stream: 1, PPID: 1}); err != nil {
		t.Fatalf("WriteToSCTP(control probe) error: %v", err)
	}
	ids, err := cli.AssocIDs()
	if err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SCTP assoc id listing unavailable: %v", err)
		}
		t.Fatalf("AssocIDs error: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("AssocIDs returned no ids")
	}

	if err := cli.SetRTOInfo(SCTPRTOInfo{AssocID: ids[0], Initial: 1200, Max: 3000, Min: 600}); err != nil {
		t.Fatalf("SetRTOInfo error: %v", err)
	}
	if err := cli.SetDelayedSack(SCTPDelayedSackInfo{Delay: 200, Frequency: 2}); err != nil {
		t.Fatalf("SetDelayedSack error: %v", err)
	}
	if err := cli.SetMaxBurst(2); err != nil {
		t.Fatalf("SetMaxBurst error: %v", err)
	}
	if err := cli.SetMaxSeg(1200); err != nil {
		t.Fatalf("SetMaxSeg error: %v", err)
	}
	if err := cli.SetAutoClose(5); err != nil {
		t.Fatalf("SetAutoClose error: %v", err)
	}

	paddrs, err := cli.PeerAddrs()
	if err != nil {
		t.Fatalf("PeerAddrs error: %v", err)
	}
	if len(paddrs) < 2 {
		t.Fatalf("PeerAddrs len=%d; want at least 2", len(paddrs))
	}
	if err := cli.SetPrimaryAddr(&paddrs[len(paddrs)-1]); err != nil {
		t.Fatalf("SetPrimaryAddr error: %v", err)
	}
	laddrs, err := cli.LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs error: %v", err)
	}
	if len(laddrs) == 0 {
		t.Fatal("LocalAddrs returned no addresses")
	}
	if err := cli.SetPeerPrimaryAddr(&laddrs[0]); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("peer primary address request requires additional privilege on this kernel: %v", err)
		}
		t.Fatalf("SetPeerPrimaryAddr error: %v", err)
	}
	if err := cli.EnableStreamReset(SCTPStreamResetIncoming | SCTPStreamResetOutgoing); err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("stream reset unavailable: %v", err)
		}
		t.Fatalf("EnableStreamReset error: %v", err)
	}
	if err := cli.ResetStreams(SCTPStreamResetOutgoing, []uint16{1}); err != nil {
		t.Fatalf("ResetStreams error: %v", err)
	}
	if err := cli.AddStreams(1, 1); err != nil {
		t.Fatalf("AddStreams error: %v", err)
	}
}

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
