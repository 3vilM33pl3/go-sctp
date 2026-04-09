package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const sctpMsgNotification = 0x8000

type messageSpec struct {
	payload string
	stream  uint16
	ppid    uint32
}

type messageFlags []messageSpec

func (m *messageFlags) String() string {
	parts := make([]string, 0, len(*m))
	for _, item := range *m {
		parts = append(parts, fmt.Sprintf("%s:%d:%d", item.payload, item.stream, item.ppid))
	}
	return strings.Join(parts, ",")
}

func (m *messageFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid message %q", value)
	}
	stream, err := parseUint16(parts[1])
	if err != nil {
		return err
	}
	ppid, err := parseUint32(parts[2])
	if err != nil {
		return err
	}
	*m = append(*m, messageSpec{payload: parts[0], stream: stream, ppid: ppid})
	return nil
}

type options struct {
	mode          string
	bind          string
	connect       string
	readMessages  int
	expectFailure string
	messages      messageFlags
}

func main() {
	if len(os.Args) < 2 {
		fatalf("missing mode")
	}
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fatalf("%v", err)
	}
	switch opts.mode {
	case "server":
		if err := runServer(opts); err != nil {
			emit(map[string]any{"event": "error", "message": err.Error()})
			os.Exit(1)
		}
	case "client":
		if err := runClient(opts); err != nil {
			emit(map[string]any{"event": "error", "message": err.Error()})
			os.Exit(1)
		}
	default:
		fatalf("unsupported mode %q", opts.mode)
	}
}

func parseArgs(args []string) (options, error) {
	opts := options{mode: args[0]}
	fs := flag.NewFlagSet(opts.mode, flag.ContinueOnError)
	fs.StringVar(&opts.bind, "bind", "", "")
	fs.StringVar(&opts.connect, "connect", "", "")
	fs.StringVar(&opts.expectFailure, "expect-failure", "", "")
	fs.IntVar(&opts.readMessages, "read-messages", 0, "")
	fs.Var(&opts.messages, "message", "")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, err
	}
	return opts, nil
}

func runServer(opts options) error {
	if opts.bind == "" {
		return errors.New("server mode requires --bind")
	}
	addr, err := net.ResolveSCTPAddr("sctp4", opts.bind)
	if err != nil {
		return err
	}
	conn, err := net.ListenSCTP("sctp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	localAddrs, _ := conn.LocalAddrs()
	emit(map[string]any{"event": "ready", "local_addrs": formatSCTPAddrs(localAddrs)})

	buf := make([]byte, 8192)
	recvCount := 0
	for recvCount < opts.readMessages {
		n, _, flags, _, info, err := conn.ReadFromSCTP(buf)
		if err != nil {
			return err
		}
		if flags&sctpMsgNotification != 0 {
			emit(map[string]any{"event": "notify", "flags": flags})
			continue
		}
		stream := 0
		ppid := uint32(0)
		assocID := 0
		if info != nil {
			stream = int(info.Stream)
			ppid = info.PPID
			assocID = int(info.AssocID)
		}
		emit(map[string]any{
			"event":    "recv",
			"payload":  string(buf[:n]),
			"stream":   stream,
			"ppid":     int(ppid),
			"assoc_id": assocID,
		})
		recvCount++
	}
	emit(map[string]any{"event": "complete", "recv_count": recvCount})
	return nil
}

func runClient(opts options) error {
	if opts.connect == "" {
		return errors.New("client mode requires --connect")
	}
	addr, err := net.ResolveSCTPAddr("sctp4", opts.connect)
	if err != nil {
		return err
	}
	conn, err := net.DialSCTP("sctp4", nil, addr)
	if err != nil {
		if opts.expectFailure == "connect" || opts.expectFailure == "connect_or_send" {
			emit(map[string]any{"event": "expected_failure", "stage": "connect", "message": err.Error()})
			return nil
		}
		return err
	}
	defer conn.Close()

	for _, message := range opts.messages {
		_, err := conn.WriteToSCTP([]byte(message.payload), nil, &net.SCTPSndInfo{
			Stream: message.stream,
			PPID:   message.ppid,
		})
		if err != nil {
			if opts.expectFailure == "send" || opts.expectFailure == "connect_or_send" {
				emit(map[string]any{"event": "expected_failure", "stage": "send", "message": err.Error()})
				return nil
			}
			return err
		}
		emit(map[string]any{
			"event":   "sent",
			"payload": message.payload,
			"stream":  int(message.stream),
			"ppid":    int(message.ppid),
		})
	}

	if opts.expectFailure == "connect" || opts.expectFailure == "send" || opts.expectFailure == "connect_or_send" {
		return fmt.Errorf("expected failure %q was not observed", opts.expectFailure)
	}
	emit(map[string]any{"event": "complete", "sent_count": len(opts.messages)})
	return nil
}

func formatSCTPAddrs(addrs []net.SCTPAddr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func parseUint16(raw string) (uint16, error) {
	var value uint16
	_, err := fmt.Sscanf(raw, "%d", &value)
	return value, err
}

func parseUint32(raw string) (uint32, error) {
	var value uint32
	_, err := fmt.Sscanf(raw, "%d", &value)
	return value, err
}

func emit(item map[string]any) {
	line, err := json.Marshal(item)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(line))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
