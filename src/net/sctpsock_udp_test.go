// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package net

import (
	"bytes"
	"context"
	"errors"
	"internal/goarch"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

var udpOnly = SCTPTransportConfig{Policy: SCTPUDPOnly}

// closeWait closes c and waits until its UDP socket is gone, so no
// shutdown work outlives the test.
func closeWait(t *testing.T, c *SCTPConn) {
	t.Helper()
	c.Close()
	if c.udp == nil {
		return
	}
	select {
	case <-c.udp.done:
	case <-time.After(2 * sctpUDPLinger):
		t.Error("UDP socket still open after close")
	}
}

func kernelHasSCTP() bool {
	s, err := sysSocket(syscall.AF_INET, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP)
	if err != nil {
		return false
	}
	syscall.Close(s)
	return true
}

func listenUDPSCTP(t *testing.T) *SCTPConn {
	t.Helper()
	ln, err := ListenSCTPConfig(context.Background(), "sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)}, SCTPInitOptions{}, udpOnly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWait(t, ln) })
	if ln.Transport() != SCTPTransportUDP {
		t.Fatalf("listener transport = %v", ln.Transport())
	}
	return ln
}

func dialUDPSCTP(t *testing.T, ln *SCTPConn) *SCTPConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := DialSCTPConfig(ctx, "sctp4", nil, ln.LocalAddr().(*SCTPAddr), SCTPInitOptions{}, udpOnly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWait(t, c) })
	return c
}

// readData reads the next data message, skipping notifications.
func readData(t *testing.T, c *SCTPConn, b []byte) (int, *SCTPAddr, *SCTPRcvInfo) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		n, _, flags, addr, info, err := c.ReadFromSCTP(b)
		if err != nil {
			t.Fatal(err)
		}
		if flags&sctpUDPMsgNotification != 0 {
			continue
		}
		return n, addr, info
	}
}

func TestSCTPUDPEcho(t *testing.T) {
	ln := listenUDPSCTP(t)
	if err := ln.SetRecvRcvInfo(true); err != nil {
		t.Fatal(err)
	}
	c := dialUDPSCTP(t, ln)
	if c.Transport() != SCTPTransportUDP {
		t.Fatal("dialed conn is not UDP")
	}
	if _, err := c.WriteToSCTP([]byte("hello"), nil, &SCTPSndInfo{Stream: 3, PPID: 77}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	n, from, info := readData(t, ln, b)
	if string(b[:n]) != "hello" {
		t.Fatalf("got %q", b[:n])
	}
	if info == nil || info.Stream != 3 || info.PPID != 77 || info.AssocID == 0 {
		t.Fatalf("rcvinfo = %+v", info)
	}
	if from.Port != c.LocalAddr().(*SCTPAddr).Port {
		t.Fatalf("from = %v, want port of %v", from, c.LocalAddr())
	}
	if _, err := ln.WriteToSCTP([]byte("world"), from, &SCTPSndInfo{Stream: 3, PPID: 78}); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "world" {
		t.Fatalf("Read = %q, %v", b[:n], err)
	}
	if ids, _ := ln.AssocIDs(); len(ids) != 1 {
		t.Fatalf("AssocIDs = %v", ids)
	}
	st, err := c.AssocStatus(0)
	if err != nil || st.State != 4 || st.OutStreams == 0 {
		t.Fatalf("AssocStatus = %+v, %v", st, err)
	}
}

func TestSCTPUDPDefaultFallback(t *testing.T) {
	if kernelHasSCTP() {
		t.Skip("kernel SCTP present; fallback not exercised")
	}
	ln, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer closeWait(t, ln)
	if ln.Transport() != SCTPTransportUDP {
		t.Fatal("ListenSCTP did not fall back to UDP")
	}
	c, err := DialSCTP("sctp4", nil, ln.LocalAddr().(*SCTPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer closeWait(t, c)
	if _, err := c.Write([]byte("seamless")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, _, _ := readData(t, ln, b)
	if string(b[:n]) != "seamless" {
		t.Fatalf("got %q", b[:n])
	}

	// Dialer.Dial and ListenPacket take the same path.
	d := Dialer{Timeout: 10 * time.Second}
	dc, err := d.Dial("sctp4", ln.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	closeWait(t, dc.(*SCTPConn))
	pc, err := ListenPacket("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closeWait(t, pc.(*SCTPConn))
}

func TestSCTPUDPGODEBUG(t *testing.T) {
	if kernelHasSCTP() {
		t.Setenv("GODEBUG", "sctptransport=udp")
		ln, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer closeWait(t, ln)
		if ln.Transport() != SCTPTransportUDP {
			t.Fatal("sctptransport=udp ignored")
		}
		return
	}
	t.Setenv("GODEBUG", "sctptransport=native")
	_, err := ListenSCTP("sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)})
	if err == nil {
		t.Fatal("sctptransport=native: ListenSCTP succeeded without kernel SCTP")
	}
	// An explicit policy wins over GODEBUG.
	listenUDPSCTP(t)
}

func TestSCTPUDPLargeAndPartialRead(t *testing.T) {
	ln := listenUDPSCTP(t)
	c := dialUDPSCTP(t, ln)
	msg := make([]byte, 300_000)
	for i := range msg {
		msg[i] = byte(i * 13)
	}
	go c.Write(msg)
	// Read in small pieces: MSG_EOR marks the last one.
	var got []byte
	b := make([]byte, 7000)
	ln.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		n, _, flags, _, _, err := ln.ReadFromSCTP(b)
		if err != nil {
			t.Fatal(err)
		}
		if flags&sctpUDPMsgNotification != 0 {
			continue
		}
		got = append(got, b[:n]...)
		if flags&sctpUDPMsgEOR != 0 {
			break
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %d bytes, want %d (equal prefix: %v)", len(got), len(msg), bytes.HasPrefix(msg, got))
	}
}

func TestSCTPUDPManyMessagesOrdered(t *testing.T) {
	ln := listenUDPSCTP(t)
	c := dialUDPSCTP(t, ln)
	const n = 2000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range n {
			msg := []byte{byte(i >> 8), byte(i)}
			msg = append(msg, bytes.Repeat([]byte{'x'}, i%1500)...)
			if _, err := c.WriteToSCTP(msg, nil, &SCTPSndInfo{Stream: uint16(i % 5)}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	ln.SetRecvRcvInfo(true)
	next := map[uint16]int{}
	b := make([]byte, 4096)
	for got := 0; got < n; got++ {
		k, _, info := readData(t, ln, b)
		i := int(b[0])<<8 | int(b[1])
		if i%5 != int(info.Stream) || k != 2+i%1500 {
			t.Fatalf("message %d on stream %d with %d bytes", i, info.Stream, k)
		}
		if i < next[info.Stream] {
			t.Fatalf("stream %d: message %d after %d", info.Stream, i, next[info.Stream])
		}
		next[info.Stream] = i + 1
	}
	wg.Wait()
}

func TestSCTPUDPReadDeadline(t *testing.T) {
	ln := listenUDPSCTP(t)
	ln.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, _, _, _, err := ln.ReadFromSCTP(make([]byte, 10))
	var ne Error
	if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want timeout", err)
	}
}

// notifState returns the sac_state of an SCTP_ASSOC_CHANGE notification.
func notifState(b []byte) uint16 {
	if goarchBigEndian() {
		return uint16(b[8])<<8 | uint16(b[9])
	}
	return uint16(b[8]) | uint16(b[9])<<8
}

func TestSCTPUDPNotifications(t *testing.T) {
	ln := listenUDPSCTP(t)
	if err := ln.SubscribeEvents(SCTPEventMask{Association: true, Shutdown: true}); err != nil {
		t.Fatal(err)
	}
	c := dialUDPSCTP(t, ln)
	c.Write([]byte("x"))
	b := make([]byte, 100)
	ln.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, flags, _, _, err := ln.ReadFromSCTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if flags&sctpUDPMsgNotification == 0 || n != 20 || notifState(b) != sctpCommUp {
		t.Fatalf("first read: flags %#x, %d bytes %x; want COMM_UP", flags, n, b[:n])
	}
	readData(t, ln, b)
	c.Close()
	sawShutdown, sawComp := false, false
	for !(sawShutdown && sawComp) {
		n, _, flags, _, _, err := ln.ReadFromSCTP(b)
		if err != nil {
			t.Fatalf("after close: %v (shutdown event %v, SHUTDOWN_COMP %v)", err, sawShutdown, sawComp)
		}
		if flags&sctpUDPMsgNotification == 0 {
			continue
		}
		typ := uint16(b[0]) | uint16(b[1])<<8
		if goarchBigEndian() {
			typ = uint16(b[0])<<8 | uint16(b[1])
		}
		switch typ & 0xff {
		case sctpNotifShutdown:
			sawShutdown = true
		case sctpNotifAssocChange:
			if n == 20 && notifState(b) == sctpShutdownComp {
				sawComp = true
			}
		}
	}
}

func TestSCTPUDPCloseSemantics(t *testing.T) {
	ln := listenUDPSCTP(t)
	c := dialUDPSCTP(t, ln)
	c.Write([]byte("bye"))
	b := make([]byte, 16)
	_, from, _ := readData(t, ln, b)
	// The server ends the association; the client sees EOF.
	if _, err := ln.WriteToSCTP(nil, from, &SCTPSndInfo{Flags: sctpUDPFlagEOF}); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(b); err != io.EOF {
		t.Fatalf("Read after peer shutdown = %v, want io.EOF itself", err)
	}
	c.Close()
	if _, err := c.Read(b); !errors.Is(err, ErrClosed) {
		t.Fatalf("Read after Close = %v, want ErrClosed", err)
	}
	if err := c.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("second Close = %v", err)
	}
}

func TestSCTPUDPDialRefused(t *testing.T) {
	// A UDP endpoint that does not accept associations answers INIT with ABORT.
	o, err := listenSCTPUDP(context.Background(), ListenConfig{}, "sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)}, nil, SCTPUDPConfig{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeWait(t, o)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = DialSCTPConfig(ctx, "sctp4", nil, o.LocalAddr().(*SCTPAddr), SCTPInitOptions{}, udpOnly)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want ECONNREFUSED", err)
	}
}

func TestSCTPUDPDialTimeout(t *testing.T) {
	// Nothing listens: the INITs go unanswered until the context ends.
	pc, _ := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ra := &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: pc.LocalAddr().(*UDPAddr).Port}
	_, err := DialSCTPConfig(ctx, "sctp4", nil, ra, SCTPInitOptions{}, udpOnly)
	if err == nil {
		t.Fatal("dial succeeded")
	}
}

func TestSCTPUDPUnsupportedOptions(t *testing.T) {
	ln := listenUDPSCTP(t)
	for name, err := range map[string]error{
		"BindAddrs":    ln.BindAddrs([]SCTPAddr{{IP: IPv4(127, 0, 0, 2)}}),
		"SetAuthKey":   ln.SetAuthKey(SCTPAuthKey{KeyID: 1, Secret: []byte("k")}),
		"SetNoDelay":   ln.SetNoDelay(false),
		"SetScheduler": ln.SetStreamScheduler(SCTPSchedulerRR),
	} {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s: err = %v, want ErrUnsupported", name, err)
		}
	}
	if _, err := ln.SyscallConn(); err == nil {
		t.Error("SyscallConn succeeded")
	}
	for name, err := range map[string]error{
		"SetNoDelay(true)":  ln.SetNoDelay(true),
		"SetRTOInfo":        ln.SetRTOInfo(SCTPRTOInfo{Initial: 500, Min: 200, Max: 5000}),
		"SetDelayedSack":    ln.SetDelayedSack(SCTPDelayedSackInfo{Delay: 100, Frequency: 2}),
		"SetDefaultPRInfo":  ln.SetDefaultPRInfo(SCTPPRInfo{Policy: SCTPPRTTL, Value: 1000}),
		"SetInitOptions":    ln.SetInitOptions(SCTPInitOptions{NumOStreams: 20, MaxInStreams: 20}),
		"EnableStreamReset": ln.EnableStreamReset(SCTPStreamResetOutgoing),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSCTPUDPStreamReconfig(t *testing.T) {
	ln := listenUDPSCTP(t)
	ln.SetRecvRcvInfo(true)
	ln.SubscribeEvents(SCTPEventMask{StreamReset: true})
	c := dialUDPSCTP(t, ln)
	b := make([]byte, 64)
	c.WriteToSCTP([]byte("a"), nil, &SCTPSndInfo{Stream: 1})
	c.WriteToSCTP([]byte("b"), nil, &SCTPSndInfo{Stream: 1})
	readData(t, ln, b)
	readData(t, ln, b)
	if err := c.ResetStreams(SCTPStreamResetOutgoing, []uint16{1}); err != nil {
		t.Fatal(err)
	}
	c.WriteToSCTP([]byte("c"), nil, &SCTPSndInfo{Stream: 1})
	_, _, info := readData(t, ln, b)
	if info.SSN != 0 {
		t.Fatalf("SSN after reset = %d, want 0", info.SSN)
	}
	st, _ := c.AssocStatus(0)
	if err := c.AddStreams(0, 2); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st2, _ := c.AssocStatus(0)
		if st2.OutStreams == st.OutStreams+2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("OutStreams = %d, want %d", st2.OutStreams, st.OutStreams+2)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.WriteToSCTP([]byte("d"), nil, &SCTPSndInfo{Stream: st.OutStreams + 1}); err != nil {
		t.Fatal(err)
	}
	_, _, info = readData(t, ln, b)
	if info.Stream != st.OutStreams+1 {
		t.Fatalf("stream = %d", info.Stream)
	}
}

func TestSCTPUDPOneToManyImplicitSetup(t *testing.T) {
	a := listenUDPSCTP(t)
	b := listenUDPSCTP(t)
	// a sends to b with no prior association: sendmsg semantics.
	if _, err := a.WriteToSCTP([]byte("implicit"), b.LocalAddr().(*SCTPAddr), &SCTPSndInfo{Stream: 0}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, _ := readData(t, b, buf)
	if string(buf[:n]) != "implicit" || from.Port != a.LocalAddr().(*SCTPAddr).Port {
		t.Fatalf("got %q from %v", buf[:n], from)
	}
}

func TestSCTPUDPEncapPorts(t *testing.T) {
	// Default: the UDP port is the SCTP port.
	ln := listenUDPSCTP(t)
	if u, s := ln.udp.pc.LocalAddr().(*UDPAddr).Port, ln.LocalAddr().(*SCTPAddr).Port; u != s {
		t.Fatalf("default: UDP port %d != SCTP port %d", u, s)
	}

	// Explicit encapsulation ports, different from the SCTP ports.
	free, _ := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	encap := free.LocalAddr().(*UDPAddr).Port
	free.Close()
	ln2, err := ListenSCTPConfig(context.Background(), "sctp4", &SCTPAddr{IP: IPv4(127, 0, 0, 1)}, SCTPInitOptions{},
		SCTPTransportConfig{Policy: SCTPUDPOnly, UDP: SCTPUDPConfig{LocalEncapPort: uint16(encap)}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeWait(t, ln2)
	sctpPort := ln2.LocalAddr().(*SCTPAddr).Port
	if ln2.udp.pc.LocalAddr().(*UDPAddr).Port != encap || sctpPort == encap {
		t.Fatalf("UDP port %d, SCTP port %d; want UDP %d and a different SCTP port", ln2.udp.pc.LocalAddr().(*UDPAddr).Port, sctpPort, encap)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := DialSCTPConfig(ctx, "sctp4", nil, &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: sctpPort}, SCTPInitOptions{},
		SCTPTransportConfig{Policy: SCTPUDPOnly, UDP: SCTPUDPConfig{RemoteEncapPort: uint16(encap)}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeWait(t, c)
	c.Write([]byte("ports"))
	b := make([]byte, 16)
	n, _, _ := readData(t, ln2, b)
	if string(b[:n]) != "ports" {
		t.Fatalf("got %q", b[:n])
	}

	// A wrong SCTP port is dropped, so the dial times out.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if c, err := DialSCTPConfig(ctx2, "sctp4", nil, &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: sctpPort + 1}, SCTPInitOptions{},
		SCTPTransportConfig{Policy: SCTPUDPOnly, UDP: SCTPUDPConfig{RemoteEncapPort: uint16(encap)}}); err == nil {
		c.Close()
		t.Fatal("dial to the wrong SCTP port succeeded")
	}
}

func goarchBigEndian() bool { return goarch.BigEndian }

func TestSCTPUDPWriteDeadline(t *testing.T) {
	ln := listenUDPSCTP(t)
	c := dialUDPSCTP(t, ln)
	if _, err := c.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.Write([]byte("after")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after deadline = %v, want ErrDeadlineExceeded", err)
	}
	c.SetWriteDeadline(time.Time{})
	if _, err := c.Write([]byte("again")); err != nil {
		t.Fatalf("Write after clearing deadline = %v", err)
	}
}

func TestSCTPUDPMessageLargerThanWindow(t *testing.T) {
	ln := listenUDPSCTP(t)
	if err := ln.SetReadBuffer(8000); err != nil {
		t.Fatal(err)
	}
	c := dialUDPSCTP(t, ln)
	big := make([]byte, 64<<10)
	for i := range big {
		big[i] = byte(i * 31)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(big)
		errc <- err
	}()
	var got []byte
	b := make([]byte, 4096)
	ln.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		n, _, flags, _, _, err := ln.ReadFromSCTP(b)
		if err != nil {
			t.Fatalf("after %d bytes: %v", len(got), err)
		}
		if flags&sctpUDPMsgNotification != 0 {
			continue
		}
		got = append(got, b[:n]...)
		if flags&sctpUDPMsgEOR != 0 {
			break
		}
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("got %d bytes, want %d intact", len(got), len(big))
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestSCTPUDPReadDeadlineWithQueuedData(t *testing.T) {
	ln := listenUDPSCTP(t)
	c := dialUDPSCTP(t, ln)
	for _, m := range []string{"one", "two"} {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 16)
	readData(t, ln, b)
	// Wait until the second message is queued, then expire the deadline.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ln.udp.mu.Lock()
		_, ok := ln.udp.ep.PeekMessage()
		ln.udp.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second message never arrived")
		}
		time.Sleep(time.Millisecond)
	}
	ln.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, _, _, _, err := ln.ReadFromSCTP(b); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read with queued data after deadline = %v, want ErrDeadlineExceeded", err)
	}
}
