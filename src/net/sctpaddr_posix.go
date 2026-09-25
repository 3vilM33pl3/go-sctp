// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix || js || wasip1 || windows

package net

import "syscall"

// SCTPAddr's sockaddr conversions, shared by the kernel-backed backends and
// the stubs: the resolver and dispatch code in dial.go and ipsock.go need
// them on every platform that has syscall.Sockaddr.

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
	if a.isIPv4() {
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
