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
