// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package net

import (
	"context"
	"syscall"
)

func sockaddrToSCTP(sa syscall.Sockaddr) Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &SCTPAddr{IP: sa.Addr[0:], Port: sa.Port}
	case *syscall.SockaddrInet6:
		return &SCTPAddr{IP: sa.Addr[0:], Port: sa.Port, Zone: zoneCache.name(int(sa.ZoneId))}
	}
	return nil
}

func (a *SCTPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (a *SCTPAddr) sockaddr(family int) (syscall.Sockaddr, error) {
	if a == nil {
		return nil, nil
	}
	return ipToSockaddr(family, a.IP, a.Port, a.Zone)
}

func (a *SCTPAddr) toLocal(net string) sockaddr {
	return &SCTPAddr{loopbackIP(net), a.Port, a.Zone}
}

func (c *SCTPConn) readFromSCTP(b []byte) (n int, oobn int, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	oob := make([]byte, sctpOOBBufferSize())
	var sa syscall.Sockaddr
	n, oobn, flags, sa, err = c.fd.readMsg(b, oob, 0)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if saAddr := sockaddrToSCTP(sa); saAddr != nil {
		addr = saAddr.(*SCTPAddr)
	}
	info, err = parseSCTPRcvInfo(oob[:oobn])
	if err != nil {
		return 0, 0, 0, nil, nil, err
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
	ctrlCtxFn := sd.Dialer.ControlContext
	if ctrlCtxFn == nil && sd.Dialer.Control != nil {
		ctrlCtxFn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sd.Dialer.Control(network, address, c)
		}
	}
	// Use one-to-many style sockets in v1: bind locally without connect(2),
	// and retain remote address as the default destination for WriteToSCTP(nil addr).
	var la sockaddr
	if laddr != nil {
		la = laddr
	}
	fd, err := internetSocket(ctx, sd.network, la, nil, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP, "dial", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	fd.raddr = raddr
	return newSCTPConn(fd), nil
}

func (sl *sysListener) listenSCTP(ctx context.Context, laddr *SCTPAddr) (*SCTPConn, error) {
	var ctrlCtxFn func(ctx context.Context, network, address string, c syscall.RawConn) error
	if sl.ListenConfig.Control != nil {
		ctrlCtxFn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sl.ListenConfig.Control(network, address, c)
		}
	}
	fd, err := internetSocket(ctx, sl.network, laddr, nil, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP, "listen", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}
