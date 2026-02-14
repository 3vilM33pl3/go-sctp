package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func parseHosts(arg string) []string {
	if arg == "" {
		return []string{"127.0.0.1", "127.0.0.2"}
	}
	parts := strings.Split(arg, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"127.0.0.1", "127.0.0.2"}
	}
	return out
}

func parseUint16(s string, def uint16) uint16 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid uint16 value %q: %v\n", s, err)
		os.Exit(1)
	}
	return uint16(v)
}

func parseUint32(s string, def uint32) uint32 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid uint32 value %q: %v\n", s, err)
		os.Exit(1)
	}
	return uint32(v)
}

func main() {
	hosts := parseHosts("")
	port := 19002
	payload := "go-multi-to-go-multi"
	stream := uint16(6)
	ppid := uint32(404)

	if len(os.Args) > 1 {
		hosts = parseHosts(os.Args[1])
	}
	if len(os.Args) > 2 {
		p, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid port: %v\n", err)
			os.Exit(1)
		}
		port = p
	}
	if len(os.Args) > 3 {
		payload = os.Args[3]
	}
	if len(os.Args) > 4 {
		stream = parseUint16(os.Args[4], stream)
	}
	if len(os.Args) > 5 {
		ppid = parseUint32(os.Args[5], ppid)
	}

	rawAddrs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		rawAddrs = append(rawAddrs, net.JoinHostPort(h, strconv.Itoa(port)))
	}
	raddr, err := net.ResolveSCTPMultiAddr("sctp4", rawAddrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveSCTPMultiAddr: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialSCTPMulti("sctp4", nil, raddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialSCTPMulti: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	_, err = conn.WriteToSCTP([]byte(payload), nil, &net.SCTPSndInfo{Stream: stream, PPID: ppid})
	if err != nil {
		fmt.Fprintf(os.Stderr, "WriteToSCTP: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("GO_MULTI_CLIENT_SENT stream=%d ppid=%d payload=%s\n", stream, ppid, payload)
}
