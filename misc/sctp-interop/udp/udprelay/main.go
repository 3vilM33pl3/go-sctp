// Command udprelay forwards SCTP-over-UDP datagrams between a client and a
// server, logging each SCTP chunk and writing a pcap (LINKTYPE_IPV4 with
// synthesized IPv4/UDP headers; Wireshark decodes it with
// "Decode As... UDP port -> SCTP"). It stands in for tcpdump, which needs root.
//
//	udprelay -listen 127.0.0.1:P -server 127.0.0.1:Q -pcap out.pcap
//
// The client sends to P; the relay forwards from one socket to Q and relays
// the server's replies back to the client's source port.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var chunkNames = map[byte]string{0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK",
	6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE",
	0x80: "ASCONF_ACK", 0x82: "RECONFIG", 0xc0: "FORWARD_TSN", 0xc1: "ASCONF", 0x0f: "AUTH"}

func summary(b []byte) string {
	if len(b) < 12 {
		return fmt.Sprintf("short %d", len(b))
	}
	s := fmt.Sprintf("sctp %d>%d vtag=%#x", binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint32(b[4:]))
	var cs []string
	for p := b[12:]; len(p) >= 4; {
		t, f, l := p[0], p[1], int(binary.BigEndian.Uint16(p[2:]))
		name := chunkNames[t]
		if name == "" {
			name = fmt.Sprintf("0x%02x", t)
		}
		extra := ""
		switch t {
		case 0:
			if l >= 16 {
				extra = fmt.Sprintf("(tsn=%d sid=%d ssn=%d ppid=%#x flags=%#x len=%d)", binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint16(p[8:]), binary.BigEndian.Uint16(p[10:]), binary.BigEndian.Uint32(p[12:]), f, l-16)
			}
		case 1, 2:
			if l >= 20 {
				extra = fmt.Sprintf("(itag=%#x a_rwnd=%d os=%d mis=%d itsn=%d len=%d)", binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:]), binary.BigEndian.Uint16(p[12:]), binary.BigEndian.Uint16(p[14:]), binary.BigEndian.Uint32(p[16:]), l)
			}
		case 3:
			if l >= 16 {
				extra = fmt.Sprintf("(cum=%d a_rwnd=%d gaps=%d dups=%d)", binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:]), binary.BigEndian.Uint16(p[12:]), binary.BigEndian.Uint16(p[14:]))
			}
		case 6, 9:
			extra = fmt.Sprintf("(T=%d causes=%x)", f&1, p[4:min(l, len(p))])
		}
		cs = append(cs, name+extra)
		if l < 4 {
			break
		}
		l = (l + 3) &^ 3
		if l > len(p) {
			break
		}
		p = p[l:]
	}
	return s + " " + strings.Join(cs, " ")
}

type pcap struct {
	mu sync.Mutex
	f  *os.File
}

func (p *pcap) write(src, dst *net.UDPAddr, b []byte) {
	if p == nil || src == nil || dst == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ip := make([]byte, 28)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(28+len(b)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], src.IP.To4())
	copy(ip[16:], dst.IP.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(ip[20:], uint16(src.Port))
	binary.BigEndian.PutUint16(ip[22:], uint16(dst.Port))
	binary.BigEndian.PutUint16(ip[24:], uint16(8+len(b)))
	now := time.Now()
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, uint32(now.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(ip)+len(b)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(ip)+len(b)))
	p.f.Write(h)
	p.f.Write(ip)
	p.f.Write(b)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:29000", "address clients send to")
	server := flag.String("server", "127.0.0.1:9899", "server UDP address")
	out := flag.String("pcap", "", "pcap output")
	flag.Parse()
	log.SetFlags(log.Lmicroseconds)
	la, _ := net.ResolveUDPAddr("udp4", *listen)
	sa, _ := net.ResolveUDPAddr("udp4", *server)
	front, err := net.ListenUDP("udp4", la)
	if err != nil {
		log.Fatal(err)
	}
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: la.IP})
	if err != nil {
		log.Fatal(err)
	}
	var pc *pcap
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		h := make([]byte, 24)
		binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
		binary.LittleEndian.PutUint16(h[4:], 2)
		binary.LittleEndian.PutUint16(h[6:], 4)
		binary.LittleEndian.PutUint32(h[16:], 65535)
		binary.LittleEndian.PutUint32(h[20:], 228) // LINKTYPE_IPV4
		f.Write(h)
		pc = &pcap{f: f}
	}
	log.Printf("relay %v -> %v (backend socket %v)", front.LocalAddr(), sa, back.LocalAddr())
	var mu sync.Mutex
	var client *net.UDPAddr
	go func() {
		b := make([]byte, 65536)
		for {
			n, from, err := back.ReadFromUDP(b)
			if err != nil {
				log.Fatal(err)
			}
			mu.Lock()
			c := client
			mu.Unlock()
			log.Printf("S->C %v -> %v %s", from, c, summary(b[:n]))
			pc.write(from, c, b[:n])
			if c != nil {
				front.WriteToUDP(b[:n], c)
			}
		}
	}()
	b := make([]byte, 65536)
	for {
		n, from, err := front.ReadFromUDP(b)
		if err != nil {
			log.Fatal(err)
		}
		mu.Lock()
		client = from
		mu.Unlock()
		log.Printf("C->S %v -> %v %s", from, sa, summary(b[:n]))
		pc.write(from, sa, b[:n])
		back.WriteToUDP(b[:n], sa)
	}
}
