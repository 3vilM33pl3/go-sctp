package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const msgNotification = 0x8000

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

func main() {
	hosts := parseHosts("")
	port := 19002
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
	// The number of user messages to wait for before exiting. Exiting early
	// tears the association down while the client is still sending.
	want := 1
	if len(os.Args) > 3 {
		w, err := strconv.Atoi(os.Args[3])
		if err != nil || w < 1 {
			fmt.Fprintf(os.Stderr, "invalid message count %q\n", os.Args[3])
			os.Exit(1)
		}
		want = w
	}

	rawAddrs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		rawAddrs = append(rawAddrs, net.JoinHostPort(h, strconv.Itoa(port)))
	}
	laddr, err := net.ResolveSCTPMultiAddr("sctp4", rawAddrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveSCTPMultiAddr: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenSCTPMulti("sctp4", laddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenSCTPMulti: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.SetInitOptions(net.SCTPInitOptions{NumOStreams: 8, MaxInStreams: 8})
	_ = conn.SubscribeEvents(net.SCTPEventMask{Association: true, Shutdown: true, DataIO: true})
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, info, err := conn.ReadFromSCTP(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadFromSCTP: %v\n", err)
			os.Exit(1)
		}
		if flags&msgNotification != 0 {
			fmt.Printf("GO_MULTI_SERVER_NOTIFY flags=%d\n", flags)
			continue
		}

		stream := -1
		ppid := uint32(0)
		if info != nil {
			stream = int(info.Stream)
			ppid = info.PPID
		}
		fmt.Printf("GO_MULTI_SERVER_RECV stream=%d ppid=%d payload=%s\n", stream, ppid, string(buf[:n]))
		if want--; want == 0 {
			return
		}
	}
}
