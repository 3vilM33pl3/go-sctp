// Command goecho is an SCTP echo client/server used for RFC 6951 interop.
//
//	goecho -mode server -addr 127.0.0.1:9899 [-transport udp|native] [-lencap N -rencap N]
//	goecho -mode client -addr 127.0.0.1:9899 [-local 127.0.0.1:0] ...
//
// The client sends -n messages; message i goes on stream i%streams with
// PPID 0x10000+i, and message n/2 is -big bytes. The server echoes each
// message back on the same stream with the same PPID. The client checks
// payload, stream and PPID, then shuts down gracefully (SCTP_EOF) and waits
// for SHUTDOWN_COMPLETE.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"
)

// Kernel ABI values, which go-sctp's UDP transport reproduces per OS.
var (
	freebsd         = runtime.GOOS == "freebsd"
	msgNotification = pick(0x2000, 0x8000)
	msgEOR          = syscall.MSG_EOR
	flagEOF         = uint16(pick(0x0100, 0x0200)) // SCTP_EOF / MSG_FIN
	notifAssoc      = uint16(pick(0x0001, 0x8001))
	notifShutdown   = uint16(pick(0x0005, 0x8005))
	stateCommLost   = uint16(pick(2, 1))
	stateShutComp   = uint16(pick(4, 3))
)

func pick(onFreeBSD, onLinux int) int {
	if freebsd {
		return onFreeBSD
	}
	return onLinux
}

var (
	mode      = flag.String("mode", "server", "server or client")
	addr      = flag.String("addr", "127.0.0.1:9899", "server address")
	local     = flag.String("local", "", "client local address")
	transport = flag.String("transport", "udp", "udp or native")
	lencap    = flag.Int("lencap", 0, "local UDP encapsulation port (0 = SCTP port)")
	rencap    = flag.Int("rencap", 0, "remote UDP encapsulation port (0 = SCTP port)")
	n         = flag.Int("n", 100, "messages")
	big       = flag.Int("big", 200*1024, "size of message n/2")
	streams   = flag.Int("streams", 5, "streams used")
	timeout   = flag.Duration("timeout", 60*time.Second, "overall timeout")
)

func cfg() net.SCTPTransportConfig {
	if *transport == "native" {
		return net.SCTPTransportConfig{Policy: net.SCTPNativeOnly}
	}
	return net.SCTPTransportConfig{Policy: net.SCTPUDPOnly,
		UDP: net.SCTPUDPConfig{LocalEncapPort: uint16(*lencap), RemoteEncapPort: uint16(*rencap)}}
}

func payload(i int) []byte {
	size := 64 + (i*37)%2000
	if i == *n/2 {
		size = *big
	}
	b := make([]byte, size)
	for j := range b {
		b[j] = byte(j*7 + i)
	}
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}

func notif(b []byte) string {
	if len(b) < 8 {
		return fmt.Sprintf("short(%x)", b)
	}
	t := binary.NativeEndian.Uint16(b)
	switch t {
	case notifAssoc:
		return fmt.Sprintf("ASSOC_CHANGE state=%d", binary.NativeEndian.Uint16(b[8:]))
	case notifShutdown:
		return "SHUTDOWN_EVENT"
	}
	return fmt.Sprintf("type=%#x", t)
}

func isShutdownComp(b []byte) bool {
	return len(b) >= 10 && binary.NativeEndian.Uint16(b) == notifAssoc && binary.NativeEndian.Uint16(b[8:]) == stateShutComp
}

func isCommLost(b []byte) bool {
	return len(b) >= 10 && binary.NativeEndian.Uint16(b) == notifAssoc && binary.NativeEndian.Uint16(b[8:]) == stateCommLost
}

type msg struct {
	data []byte
	info *net.SCTPRcvInfo
	from *net.SCTPAddr
}

// reader reassembles messages across partial reads.
type reader struct {
	c   *net.SCTPConn
	buf []byte
	acc []byte
}

func (r *reader) next() (m msg, notification []byte, err error) {
	for {
		nr, _, flags, from, info, err := r.c.ReadFromSCTP(r.buf)
		if err != nil {
			return msg{}, nil, err
		}
		if flags&msgNotification != 0 {
			return msg{}, append([]byte(nil), r.buf[:nr]...), nil
		}
		r.acc = append(r.acc, r.buf[:nr]...)
		if flags&msgEOR == 0 {
			continue
		}
		m = msg{data: r.acc, info: info, from: from}
		r.acc = nil
		return m, nil, nil
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds)
	log.SetPrefix("[go-" + *mode + "] ")
	go func() { time.Sleep(*timeout); log.Fatalf("FAIL: timeout after %v", *timeout) }()
	ra, err := net.ResolveSCTPAddr("sctp4", *addr)
	if err != nil {
		log.Fatal(err)
	}
	init := net.SCTPInitOptions{NumOStreams: 10, MaxInStreams: 10}
	switch *mode {
	case "server":
		server(ra, init)
	case "client":
		client(ra, init)
	default:
		log.Fatalf("bad mode %q", *mode)
	}
}

func server(la *net.SCTPAddr, init net.SCTPInitOptions) {
	c, err := net.ListenSCTPConfig(context.Background(), "sctp4", la, init, cfg())
	if err != nil {
		log.Fatalf("FAIL: listen: %v", err)
	}
	defer c.Close()
	must(c.SetRecvRcvInfo(true), "SetRecvRcvInfo")
	must(c.SubscribeEvents(net.SCTPEventMask{Association: true, Shutdown: true}), "SubscribeEvents")
	log.Printf("listening on %v transport=%v", c.LocalAddr(), *transport)
	r := &reader{c: c, buf: make([]byte, 64*1024)}
	count, bytesIn := 0, 0
	for {
		m, nb, err := r.next()
		if err != nil {
			log.Fatalf("FAIL: read after %d msgs: %v", count, err)
		}
		if nb != nil {
			log.Printf("notification %s", notif(nb))
			if isShutdownComp(nb) {
				log.Printf("PASS: echoed %d messages (%d bytes), graceful shutdown complete", count, bytesIn)
				return
			}
			if isCommLost(nb) {
				log.Fatalf("FAIL: COMM_LOST after %d messages", count)
			}
			continue
		}
		if m.info == nil {
			log.Fatalf("FAIL: no rcvinfo")
		}
		count++
		bytesIn += len(m.data)
		si := &net.SCTPSndInfo{Stream: m.info.Stream, PPID: m.info.PPID, AssocID: m.info.AssocID}
		if _, err := c.WriteToSCTP(m.data, m.from, si); err != nil {
			log.Fatalf("FAIL: echo msg %d (len %d): %v", count, len(m.data), err)
		}
	}
}

func client(ra *net.SCTPAddr, init net.SCTPInitOptions) {
	var la *net.SCTPAddr
	if *local != "" {
		var err error
		if la, err = net.ResolveSCTPAddr("sctp4", *local); err != nil {
			log.Fatal(err)
		}
	}
	start := time.Now()
	c, err := net.DialSCTPConfig(context.Background(), "sctp4", la, ra, init, cfg())
	if err != nil {
		log.Fatalf("FAIL: dial: %v", err)
	}
	log.Printf("connected %v -> %v transport=%v in %v", c.LocalAddr(), c.RemoteAddr(), c.Transport(), time.Since(start))
	must(c.SetRecvRcvInfo(true), "SetRecvRcvInfo")
	must(c.SubscribeEvents(net.SCTPEventMask{Association: true, Shutdown: true}), "SubscribeEvents")
	werr := make(chan error, 1)
	go func() {
		for i := 0; i < *n; i++ {
			p := payload(i)
			si := &net.SCTPSndInfo{Stream: uint16(i % *streams), PPID: uint32(0x10000 + i)}
			if _, err := c.WriteToSCTP(p, nil, si); err != nil {
				werr <- fmt.Errorf("write %d (len %d): %v", i, len(p), err)
				return
			}
		}
		werr <- nil
	}()
	r := &reader{c: c, buf: make([]byte, 64*1024)}
	got := 0
	perStream := map[uint16]int{}
	for got < *n {
		m, nb, err := r.next()
		if err != nil {
			log.Fatalf("FAIL: read after %d echoes: %v", got, err)
		}
		if nb != nil {
			log.Printf("notification %s", notif(nb))
			continue
		}
		i := int(binary.BigEndian.Uint32(m.data))
		if i < 0 || i >= *n {
			log.Fatalf("FAIL: bad index %d", i)
		}
		if !bytes.Equal(m.data, payload(i)) {
			log.Fatalf("FAIL: payload mismatch for msg %d (len %d want %d)", i, len(m.data), len(payload(i)))
		}
		if m.info == nil || m.info.Stream != uint16(i%*streams) || m.info.PPID != uint32(0x10000+i) {
			log.Fatalf("FAIL: msg %d metadata %+v", i, m.info)
		}
		// Ordered delivery within a stream.
		if i/(*streams) != perStream[m.info.Stream] {
			log.Fatalf("FAIL: msg %d out of order on stream %d", i, m.info.Stream)
		}
		perStream[m.info.Stream]++
		got++
	}
	if err := <-werr; err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	log.Printf("verified %d echoes (big=%d bytes) on %d streams in %v", got, *big, len(perStream), time.Since(start))
	// Graceful shutdown. Native dialed sockets are one-to-one, where Linux
	// rejects SCTP_EOF (EINVAL) and SCTPConn has no shutdown(SHUT_WR): close
	// and let the peer confirm SHUTDOWN_COMPLETE. UDP: SCTP_EOF, then wait.
	if *transport == "native" {
		c.Close()
		time.Sleep(time.Second) // let the kernel finish SHUTDOWN
		log.Printf("PASS: %d messages echoed and verified, closed (server confirms shutdown) in %v", got, time.Since(start))
		return
	}
	if _, err := c.WriteToSCTP(nil, nil, &net.SCTPSndInfo{Flags: flagEOF}); err != nil {
		log.Fatalf("FAIL: SCTP_EOF: %v", err)
	}
	for {
		_, nb, err := r.next()
		if err == io.EOF {
			log.Printf("read EOF after shutdown")
			break
		}
		if err != nil {
			log.Fatalf("FAIL: waiting for shutdown: %v", err)
		}
		if nb != nil {
			log.Printf("notification %s", notif(nb))
			if isShutdownComp(nb) {
				break
			}
			if isCommLost(nb) {
				log.Fatalf("FAIL: COMM_LOST during shutdown")
			}
		}
	}
	c.Close()
	log.Printf("PASS: %d messages echoed and verified, graceful shutdown in %v", got, time.Since(start))
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("FAIL: %s: %v", what, err)
	}
}
