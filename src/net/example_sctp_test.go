// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net_test

import (
	"fmt"
	"io"
	"log"
	"net"
)

func ExampleDialSCTP() {
	raddr, err := net.ResolveSCTPAddr("sctp", "127.0.0.1:9000")
	if err != nil {
		log.Fatal(err)
	}
	// DialSCTP opens a one-to-one association, like a TCP connection.
	conn, err := net.DialSCTP("sctp", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Each message names its stream and carries a payload protocol
	// identifier, the SCTP way of telling the receiver what the bytes are.
	if _, err := conn.WriteToSCTP([]byte("hello"), nil, &net.SCTPSndInfo{Stream: 1, PPID: 42}); err != nil {
		log.Fatal(err)
	}
}

func ExampleListenSCTP() {
	// A one-to-many socket receives every association on one descriptor.
	ln, err := net.ListenSCTP("sctp", &net.SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	// DataIO delivers an SCTPRcvInfo with every message; Association makes
	// the kernel report new and ended associations as notifications.
	if err := ln.SubscribeEvents(net.SCTPEventMask{DataIO: true, Association: true}); err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 64*1024)
	for {
		n, _, flags, from, info, err := ln.ReadFromSCTP(buf)
		if err != nil {
			log.Fatal(err)
		}
		if flags&net.SCTPMsgNotification != 0 {
			notif, err := net.ParseSCTPNotification(buf[:n])
			if err != nil {
				log.Fatal(err)
			}
			if notif.Type == net.SCTPNotifyAssocChange && notif.AssocChange.State == net.SCTPCommUp {
				fmt.Printf("association %d from %v, %d inbound streams\n", notif.AssocID, from, notif.AssocChange.InboundStreams)
			}
			continue
		}
		fmt.Printf("%d bytes from %v on association %d, stream %d, ppid %d\n", n, from, info.AssocID, info.Stream, info.PPID)
	}
}

func ExampleListen_sctp() {
	// For the SCTP networks, Listen returns an *SCTPListener: every
	// association is accepted as its own connection, like TCP.
	ln, err := net.Listen("sctp", "127.0.0.1:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(conn)
	}
}
