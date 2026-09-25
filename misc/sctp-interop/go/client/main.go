package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func main() {
	host := "127.0.0.1"
	port := 19001
	payload := "hello-from-go"
	stream := uint16(2)
	ppid := uint32(7)

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
	if len(os.Args) > 3 {
		payload = os.Args[3]
	}
	if len(os.Args) > 4 {
		s, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid stream: %v\n", err)
			os.Exit(1)
		}
		stream = uint16(s)
	}
	if len(os.Args) > 5 {
		p, err := strconv.Atoi(os.Args[5])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ppid: %v\n", err)
			os.Exit(1)
		}
		ppid = uint32(p)
	}

	addr, err := net.ResolveSCTPAddr("sctp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveSCTPAddr: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialSCTP("sctp4", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialSCTP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.SetNoDelay(true)
	_, err = conn.WriteToSCTP([]byte(payload), nil, &net.SCTPSndInfo{Stream: stream, PPID: ppid})
	if err != nil {
		fmt.Fprintf(os.Stderr, "WriteToSCTP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("GO_CLIENT_SENT stream=%d ppid=%d payload=%s\n", stream, ppid, payload)
}
