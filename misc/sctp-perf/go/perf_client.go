package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	clientMsgNotification = 0x8000

	clientFrameData   = byte(1)
	clientFrameStop   = byte(2)
	clientFrameResult = byte(3)

	clientPPID = uint32(0x50524631) // "PRF1"
)

func clientEncodeFrame(kind byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func clientDecodeFrame(frame []byte) (byte, []byte, error) {
	if len(frame) < 5 {
		return 0, nil, errors.New("short frame")
	}
	size := int(binary.BigEndian.Uint32(frame[1:5]))
	if size != len(frame)-5 {
		return 0, nil, fmt.Errorf("length mismatch: got=%d want=%d", len(frame)-5, size)
	}
	return frame[0], frame[5:], nil
}

func recvDataFrame(conn *net.SCTPConn, buf []byte) (byte, []byte, error) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, _, flags, _, _, err := conn.ReadFromSCTP(buf)
		if err != nil {
			return 0, nil, err
		}
		if flags&clientMsgNotification != 0 {
			continue
		}
		return clientDecodeFrame(buf[:n])
	}
}

func main() {
	host := "127.0.0.1"
	port := 19100
	mode := "rtt"
	iterations := 200
	payloadSize := 256

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
		mode = os.Args[3]
	}
	if len(os.Args) > 4 {
		v, err := strconv.Atoi(os.Args[4])
		if err != nil || v <= 0 {
			fmt.Fprintf(os.Stderr, "invalid iterations: %v\n", err)
			os.Exit(1)
		}
		iterations = v
	}
	if len(os.Args) > 5 {
		v, err := strconv.Atoi(os.Args[5])
		if err != nil || v <= 0 {
			fmt.Fprintf(os.Stderr, "invalid payload size: %v\n", err)
			os.Exit(1)
		}
		payloadSize = v
	}
	if mode != "rtt" && mode != "throughput" {
		fmt.Fprintf(os.Stderr, "invalid mode %q (expected rtt|throughput)\n", mode)
		os.Exit(1)
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
	snd := &net.SCTPSndInfo{Stream: 0, PPID: clientPPID}
	payload := bytes.Repeat([]byte{'x'}, payloadSize)
	recvBuf := make([]byte, payloadSize+4096)

	start := time.Now()
	switch mode {
	case "rtt":
		for i := 0; i < iterations; i++ {
			if _, err := conn.WriteToSCTP(clientEncodeFrame(clientFrameData, payload), nil, snd); err != nil {
				fmt.Fprintf(os.Stderr, "WriteToSCTP data: %v\n", err)
				os.Exit(1)
			}
			kind, echoPayload, err := recvDataFrame(conn, recvBuf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ReadFromSCTP echo: %v\n", err)
				os.Exit(1)
			}
			if kind != clientFrameData {
				fmt.Fprintf(os.Stderr, "unexpected echo frame type: %d\n", kind)
				os.Exit(1)
			}
			if len(echoPayload) != len(payload) {
				fmt.Fprintf(os.Stderr, "unexpected echo payload size: %d\n", len(echoPayload))
				os.Exit(1)
			}
		}
		elapsed := time.Since(start).Seconds()
		rttUs := (elapsed / float64(iterations)) * 1_000_000.0
		fmt.Printf("PERF_CLIENT_RESULT lang=go mode=rtt iterations=%d size=%d elapsed_s=%.6f rtt_us_avg=%.3f throughput_mbps=0.000\n", iterations, payloadSize, elapsed, rttUs)
	case "throughput":
		for i := 0; i < iterations; i++ {
			if _, err := conn.WriteToSCTP(clientEncodeFrame(clientFrameData, payload), nil, snd); err != nil {
				fmt.Fprintf(os.Stderr, "WriteToSCTP data: %v\n", err)
				os.Exit(1)
			}
		}
		if _, err := conn.WriteToSCTP(clientEncodeFrame(clientFrameStop, nil), nil, snd); err != nil {
			fmt.Fprintf(os.Stderr, "WriteToSCTP stop: %v\n", err)
			os.Exit(1)
		}
		kind, _, err := recvDataFrame(conn, recvBuf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadFromSCTP result: %v\n", err)
			os.Exit(1)
		}
		if kind != clientFrameResult {
			fmt.Fprintf(os.Stderr, "unexpected result frame type: %d\n", kind)
			os.Exit(1)
		}
		elapsed := time.Since(start).Seconds()
		throughputMbps := (float64(iterations*payloadSize) * 8.0) / elapsed / 1_000_000.0
		fmt.Printf("PERF_CLIENT_RESULT lang=go mode=throughput iterations=%d size=%d elapsed_s=%.6f rtt_us_avg=0.000 throughput_mbps=%.3f\n", iterations, payloadSize, elapsed, throughputMbps)
	}
}
