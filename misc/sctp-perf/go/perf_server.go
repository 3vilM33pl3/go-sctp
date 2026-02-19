package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	msgNotification = 0x8000

	frameData   = byte(1)
	frameStop   = byte(2)
	frameResult = byte(3)

	defaultPPID = uint32(0x50524631) // "PRF1"
)

func encodeFrame(kind byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func decodeFrame(frame []byte) (byte, []byte, error) {
	if len(frame) < 5 {
		return 0, nil, errors.New("short frame")
	}
	size := int(binary.BigEndian.Uint32(frame[1:5]))
	if size != len(frame)-5 {
		return 0, nil, fmt.Errorf("length mismatch: got=%d want=%d", len(frame)-5, size)
	}
	return frame[0], frame[5:], nil
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

	conn, err := net.ListenSCTP("sctp4", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenSCTP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.SetInitOptions(net.SCTPInitOptions{NumOStreams: 8, MaxInStreams: 8})
	_ = conn.SubscribeEvents(net.SCTPEventMask{Association: true, Shutdown: true, DataIO: true})

	fmt.Printf("PERF_SERVER_READY lang=go mode=%s bind=%s iterations=%d size=%d\n", mode, net.JoinHostPort(host, strconv.Itoa(port)), iterations, payloadSize)

	buf := make([]byte, payloadSize+4096)
	var started bool
	var start time.Time
	var msgs int
	var bytesTotal int

	for {
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, _, flags, peer, info, err := conn.ReadFromSCTP(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadFromSCTP: %v\n", err)
			os.Exit(1)
		}
		if flags&msgNotification != 0 {
			continue
		}

		kind, payload, err := decodeFrame(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode frame: %v\n", err)
			os.Exit(1)
		}

		switch mode {
		case "rtt":
			if kind != frameData {
				fmt.Fprintf(os.Stderr, "unexpected frame type in rtt: %d\n", kind)
				os.Exit(1)
			}
			if !started {
				started = true
				start = time.Now()
			}
			msgs++
			bytesTotal += len(payload)

			snd := &net.SCTPSndInfo{PPID: defaultPPID}
			if info != nil {
				snd.Stream = info.Stream
				snd.PPID = info.PPID
			}
			if _, err := conn.WriteToSCTP(encodeFrame(frameData, payload), peer, snd); err != nil {
				fmt.Fprintf(os.Stderr, "WriteToSCTP echo: %v\n", err)
				os.Exit(1)
			}
			if msgs >= iterations {
				elapsed := time.Since(start).Seconds()
				fmt.Printf("PERF_SERVER_DONE lang=go mode=rtt messages=%d bytes=%d seconds=%.6f\n", msgs, bytesTotal, elapsed)
				return
			}
		case "throughput":
			if kind == frameData {
				if !started {
					started = true
					start = time.Now()
				}
				msgs++
				bytesTotal += len(payload)
				continue
			}
			if kind != frameStop {
				fmt.Fprintf(os.Stderr, "unexpected frame type in throughput: %d\n", kind)
				os.Exit(1)
			}
			elapsed := time.Since(start).Seconds()
			result := []byte(fmt.Sprintf("messages=%d bytes=%d seconds=%.6f", msgs, bytesTotal, elapsed))
			snd := &net.SCTPSndInfo{PPID: defaultPPID}
			if info != nil {
				snd.Stream = info.Stream
				snd.PPID = info.PPID
			}
			if _, err := conn.WriteToSCTP(encodeFrame(frameResult, result), peer, snd); err != nil {
				fmt.Fprintf(os.Stderr, "WriteToSCTP result: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("PERF_SERVER_DONE lang=go mode=throughput messages=%d bytes=%d seconds=%.6f\n", msgs, bytesTotal, elapsed)
			return
		}
	}
}
