package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const msgNotification = 0x8000

func main() {
	host := "127.0.0.1"
	port := 19000
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		p, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid port: %v\n", err)
			os.Exit(1)
		}
		port = p
	}

	addr, err := net.ResolveSCTPAddr("sctp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveSCTPAddr: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenSCTP("sctp4", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenSCTP: %v\n", err)
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
			fmt.Printf("GO_SERVER_NOTIFY flags=%d\n", flags)
			continue
		}

		stream := -1
		ppid := uint32(0)
		if info != nil {
			stream = int(info.Stream)
			ppid = info.PPID
		}
		fmt.Printf("GO_SERVER_RECV stream=%d ppid=%d payload=%s\n", stream, ppid, string(buf[:n]))
		return
	}
}
