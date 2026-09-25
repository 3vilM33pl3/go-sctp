// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"context"
	"os"
	"syscall"
)

// controlCtxFn adapts the Dialer's Control/ControlContext callbacks to the
// form internetSocket takes, as dialTCP and friends do inline.
func (sd *sysDialer) controlCtxFn() func(context.Context, string, string, syscall.RawConn) error {
	if sd.Dialer.ControlContext != nil {
		return sd.Dialer.ControlContext
	}
	if sd.Dialer.Control != nil {
		return func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sd.Dialer.Control(network, address, c)
		}
	}
	return nil
}

// controlCtxFn adapts ListenConfig.Control the same way.
func (sl *sysListener) controlCtxFn() func(context.Context, string, string, syscall.RawConn) error {
	if sl.ListenConfig.Control != nil {
		return func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sl.ListenConfig.Control(network, address, c)
		}
	}
	return nil
}

func (c *SCTPConn) readFromSCTP(b []byte) (n int, oobn int, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	oob := make([]byte, sctpOOBBufferSize())
	var sa syscall.Sockaddr
	n, oobn, flags, sa, err = c.fd.readMsg(b, oob, 0)
	if err != nil {
		// readMsg reports a zero-length read on a connected socket as io.EOF.
		return n, oobn, flags, nil, nil, err
	}
	if saAddr := sockaddrToSCTP(sa); saAddr != nil {
		addr = saAddr.(*SCTPAddr)
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		return n, oobn, flags, addr, nil, errSCTPControlTruncated
	}
	info, err = parseSCTPRcvInfo(oob[:oobn])
	if err != nil {
		return n, oobn, flags, addr, nil, err
	}
	return
}

func (c *SCTPConn) writeToSCTP(b []byte, addr *SCTPAddr, info *SCTPSndInfo) (int, error) {
	if c.fd.isConnected && addr != nil {
		return 0, ErrWriteToConnected
	}
	oob, err := marshalSCTPSndInfo(info)
	if err != nil {
		return 0, err
	}
	if !c.fd.isConnected && addr == nil {
		if ra, ok := c.fd.raddr.(*SCTPAddr); ok {
			addr = ra
		} else {
			return 0, errMissingAddress
		}
	}

	var sa syscall.Sockaddr
	if addr != nil {
		sa, err = addr.sockaddr(c.fd.family)
		if err != nil {
			return 0, err
		}
	}
	n, _, err := c.fd.writeMsg(b, oob, sa)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (sd *sysDialer) dialSCTP(ctx context.Context, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	ctrlCtxFn := sd.controlCtxFn()
	// Dialed SCTP sockets use one-to-one style semantics so the client side can
	// interoperate cleanly with remote SCTP stacks over connect(2).
	var la sockaddr
	if laddr != nil {
		la = laddr
	}
	fd, err := internetSocket(ctx, sd.network, la, raddr, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP, "dial", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}

func (sd *sysDialer) openSCTP(ctx context.Context, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	ctrlCtxFn := sd.controlCtxFn()
	var la sockaddr
	if laddr != nil {
		la = laddr
	}
	fd, err := internetSocket(ctx, sd.network, la, nil, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP, "dial", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	fd.raddr = raddr
	return newSCTPConn(fd), nil
}

func (sl *sysListener) listenSCTP(ctx context.Context, laddr *SCTPAddr) (*SCTPConn, error) {
	ctrlCtxFn := sl.controlCtxFn()
	fd, err := internetSocket(ctx, sl.network, laddr, nil, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP, "listen", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}

func (sl *sysListener) openSCTP(ctx context.Context, laddr *SCTPAddr) (*SCTPConn, error) {
	ctrlCtxFn := sl.controlCtxFn()
	family, ipv6only := favoriteAddrFamily(sl.network, laddr, nil, "listen")
	s, err := sysSocket(family, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err := setDefaultSockopts(s, family, syscall.SOCK_SEQPACKET, ipv6only); err != nil {
		syscall.Close(s)
		return nil, err
	}
	fd := newFD(s, family, syscall.SOCK_SEQPACKET, sl.network)
	if err := fd.listenDatagram(ctx, laddr, ctrlCtxFn); err != nil {
		fd.Close()
		return nil, err
	}
	return newSCTPConn(fd), nil
}

func (ln *SCTPListener) accept() (*SCTPConn, error) {
	fd, err := ln.fd.accept()
	if err != nil {
		return nil, err
	}
	c := newSCTPConn(fd)
	if la, ok := fd.laddr.(*SCTPAddr); ok && la != nil {
		c.setLocalAddrs([]SCTPAddr{*la})
	}
	if ra, ok := fd.raddr.(*SCTPAddr); ok && ra != nil {
		c.setPeerAddrs([]SCTPAddr{*ra})
	}
	return c, nil
}

func (ln *SCTPListener) close() error { return ln.fd.Close() }

func (ln *SCTPListener) file() (*os.File, error) { return ln.fd.dup() }

// listenSCTPOneToOne opens a one-to-one style (SOCK_STREAM) listening
// socket, the SCTP counterpart of listenTCP.
func (sl *sysListener) listenSCTPOneToOne(ctx context.Context, laddr *SCTPAddr) (*SCTPListener, error) {
	ctrlCtxFn := sl.controlCtxFn()
	fd, err := internetSocket(ctx, sl.network, laddr, nil, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP, "listen", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return &SCTPListener{fd: fd, lc: sl.ListenConfig}, nil
}
