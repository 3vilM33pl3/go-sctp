// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd && amd64

package net

import (
	"bytes"
	"testing"
	"time"
)

const sctpMsgNotification = 0x2000

func TestSCTPFreeBSDLoopbackReadWrite(t *testing.T) {
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
	if err := srv.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo(server) error: %v", err)
	}

	saddr, ok := srv.LocalAddr().(*SCTPAddr)
	if !ok {
		t.Fatalf("server LocalAddr type = %T; want *SCTPAddr", srv.LocalAddr())
	}

	cli, err := DialSCTPInit("sctp4", nil, saddr, SCTPInitOptions{NumOStreams: 8, MaxInStreams: 8})
	if err != nil {
		t.Fatalf("DialSCTPInit error: %v", err)
	}
	defer cli.Close()

	payload := []byte("sctp-freebsd-loopback-test")
	snd := &SCTPSndInfo{Stream: 2, PPID: 42}
	if _, err := cli.WriteToSCTP(payload, nil, snd); err != nil {
		t.Fatalf("WriteToSCTP error: %v", err)
	}

	if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server) error: %v", err)
	}

	buf := make([]byte, 256)
	for {
		n, _, flags, from, info, err := srv.ReadFromSCTP(buf)
		if err != nil {
			t.Fatalf("ReadFromSCTP error: %v", err)
		}
		if flags&sctpMsgNotification != 0 {
			continue
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("payload mismatch got %q want %q", buf[:n], payload)
		}
		if from == nil {
			t.Fatalf("ReadFromSCTP from=nil")
		}
		if info != nil {
			if info.Stream != snd.Stream {
				t.Fatalf("ReadFromSCTP stream=%d; want %d", info.Stream, snd.Stream)
			}
			if info.PPID != snd.PPID {
				t.Fatalf("ReadFromSCTP ppid=%d; want %d", info.PPID, snd.PPID)
			}
		}
		break
	}
}
