// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package net

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux SCTP constants that are not provided by the frozen syscall package.
const (
	sctpSockoptInitMsg     = 2
	sctpSockoptNoDelay     = 3
	sctpSockoptEvent       = 127
	sctpSockoptRecvRcvInfo = 32
	sctpSockoptBindxAdd    = 100
	sctpSockoptConnectxOld = 107
	sctpSockoptConnectx    = 110
	sctpGetPeerAddrs       = 108
	sctpGetLocalAddrs      = 109

	sctpCmsgTypeSndInfo = 2
	sctpCmsgTypeRcvInfo = 3

	sctpEventDataIO          = 0x8000
	sctpEventAssociation     = 0x8001
	sctpEventAddress         = 0x8002
	sctpEventSendFailure     = 0x8003
	sctpEventPeerError       = 0x8004
	sctpEventShutdown        = 0x8005
	sctpEventPartialDelivery = 0x8006
	sctpEventAdaptation      = 0x8007
	sctpEventAuthentication  = 0x8008
	sctpEventSenderDry       = 0x8009
	sctpEventStreamReset     = 0x800a
)

type sctpInitMsg struct {
	NumOStreams    uint16
	MaxInStreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

type sctpSndInfoLinux struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

type sctpRcvInfoLinux struct {
	Stream  uint16
	SSN     uint16
	Flags   uint16
	_       uint16
	PPID    uint32
	TSN     uint32
	CumTSN  uint32
	Context uint32
	AssocID int32
}

type sctpEvent struct {
	AssocID int32
	Type    uint16
	On      uint8
	_       uint8
}

type sctpGetAddrs struct {
	AssocID int32
	AddrNum uint32
}

const (
	sizeofSCTPInitMsg      = int(unsafe.Sizeof(sctpInitMsg{}))
	sizeofSCTPSndInfoLinux = int(unsafe.Sizeof(sctpSndInfoLinux{}))
	sizeofSCTPRcvInfoLinux = int(unsafe.Sizeof(sctpRcvInfoLinux{}))
	sizeofSCTPEvent        = int(unsafe.Sizeof(sctpEvent{}))
	sizeofSCTPGetAddrs     = int(unsafe.Sizeof(sctpGetAddrs{}))
)

func sctpOOBBufferSize() int {
	return syscall.CmsgSpace(sizeofSCTPRcvInfoLinux)
}

func marshalSCTPSndInfo(info *SCTPSndInfo) ([]byte, error) {
	if info == nil {
		return nil, nil
	}

	buf := make([]byte, syscall.CmsgSpace(sizeofSCTPSndInfoLinux))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = syscall.IPPROTO_SCTP
	h.Type = sctpCmsgTypeSndInfo
	h.SetLen(syscall.CmsgLen(sizeofSCTPSndInfoLinux))

	si := sctpSndInfoLinux{
		Stream:  info.Stream,
		Flags:   info.Flags,
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	copy(buf[syscall.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&si)), sizeofSCTPSndInfoLinux))
	return buf, nil
}

func parseSCTPRcvInfo(oob []byte) (*SCTPRcvInfo, error) {
	if len(oob) == 0 {
		return nil, nil
	}

	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, scm := range scms {
		if scm.Header.Level != syscall.IPPROTO_SCTP || scm.Header.Type != sctpCmsgTypeRcvInfo {
			continue
		}
		if len(scm.Data) < sizeofSCTPRcvInfoLinux {
			return nil, errors.New("short SCTP_RCVINFO control message")
		}
		var ri sctpRcvInfoLinux
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&ri)), sizeofSCTPRcvInfoLinux), scm.Data[:sizeofSCTPRcvInfoLinux])
		return &SCTPRcvInfo{
			Stream:  ri.Stream,
			SSN:     ri.SSN,
			Flags:   ri.Flags,
			PPID:    ri.PPID,
			TSN:     ri.TSN,
			CumTSN:  ri.CumTSN,
			Context: ri.Context,
			AssocID: ri.AssocID,
		}, nil
	}
	return nil, nil
}

func setNoDelaySCTP(fd *netFD, noDelay bool) error {
	err := fd.pfd.SetsockoptInt(syscall.IPPROTO_SCTP, sctpSockoptNoDelay, boolint(noDelay))
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
}

func setSCTPInitOptions(fd *netFD, opts SCTPInitOptions) error {
	sim := sctpInitMsg{
		NumOStreams:    opts.NumOStreams,
		MaxInStreams:   opts.MaxInStreams,
		MaxAttempts:    opts.MaxAttempts,
		MaxInitTimeout: opts.MaxInitTimeout,
	}
	if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptInitMsg, unsafe.Slice((*byte)(unsafe.Pointer(&sim)), sizeofSCTPInitMsg)); err != nil {
		return err
	}
	if err := fd.pfd.SetsockoptInt(syscall.IPPROTO_SCTP, sctpSockoptRecvRcvInfo, 1); err != nil {
		runtime.KeepAlive(fd)
		return wrapSyscallError("setsockopt", err)
	}
	runtime.KeepAlive(fd)
	return nil
}

func subscribeSCTPEvents(fd *netFD, mask SCTPEventMask) error {
	events := []struct {
		typeID uint16
		on     bool
	}{
		{typeID: sctpEventDataIO, on: mask.DataIO},
		{typeID: sctpEventAssociation, on: mask.Association},
		{typeID: sctpEventAddress, on: mask.Address},
		{typeID: sctpEventSendFailure, on: mask.SendFailure},
		{typeID: sctpEventPeerError, on: mask.PeerError},
		{typeID: sctpEventShutdown, on: mask.Shutdown},
		{typeID: sctpEventPartialDelivery, on: mask.PartialDelivery},
		{typeID: sctpEventAdaptation, on: mask.Adaptation},
		{typeID: sctpEventAuthentication, on: mask.Authentication},
		{typeID: sctpEventSenderDry, on: mask.SenderDry},
		{typeID: sctpEventStreamReset, on: mask.StreamReset},
	}
	for _, evt := range events {
		e := sctpEvent{Type: evt.typeID, On: uint8(boolint(evt.on))}
		if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptEvent, unsafe.Slice((*byte)(unsafe.Pointer(&e)), sizeofSCTPEvent)); err != nil {
			return err
		}
	}
	return nil
}

func setSockoptBytes(fd *netFD, level, name int, value []byte) error {
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd.pfd.Sysfd),
		uintptr(level),
		uintptr(name),
		uintptr(ptr),
		uintptr(len(value)),
		0,
	)
	runtime.KeepAlive(fd)
	if errno != 0 {
		return wrapSyscallError("setsockopt", errno)
	}
	return nil
}

func bindAddrsSCTP(fd *netFD, addrs []SCTPAddr) error {
	if len(addrs) == 0 {
		return nil
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return err
	}
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptBindxAdd, b)
}

func connectAddrsSCTP(fd *netFD, addrs []SCTPAddr) (int32, error) {
	if len(addrs) == 0 {
		return 0, errMissingAddress
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return 0, err
	}
	r0, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd.pfd.Sysfd),
		uintptr(syscall.IPPROTO_SCTP),
		uintptr(sctpSockoptConnectx),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	runtime.KeepAlive(fd)
	if errno == 0 || errno == syscall.EINPROGRESS || errno == syscall.EALREADY {
		return int32(r0), nil
	}
	if errno != syscall.ENOPROTOOPT {
		return 0, wrapSyscallError("setsockopt", errno)
	}
	// Fallback used by older kernels.
	r0, _, errno = syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd.pfd.Sysfd),
		uintptr(syscall.IPPROTO_SCTP),
		uintptr(sctpSockoptConnectxOld),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	runtime.KeepAlive(fd)
	if errno != 0 && errno != syscall.EINPROGRESS && errno != syscall.EALREADY {
		return 0, wrapSyscallError("setsockopt", errno)
	}
	return int32(r0), nil
}

func localAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetLocalAddrs, assocID)
}

func peerAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetPeerAddrs, assocID)
}

func getAddrsSCTP(fd *netFD, opt int, assocID int32) ([]SCTPAddr, error) {
	// Enough space for header + dozens of sockaddr storage entries.
	buf := make([]byte, 64*1024)
	h := (*sctpGetAddrs)(unsafe.Pointer(&buf[0]))
	h.AssocID = assocID
	optLen := uint32(len(buf))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd.pfd.Sysfd),
		uintptr(syscall.IPPROTO_SCTP),
		uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&optLen)),
		0,
	)
	runtime.KeepAlive(fd)
	if errno != 0 {
		return nil, wrapSyscallError("getsockopt", errno)
	}
	if optLen < uint32(sizeofSCTPGetAddrs) {
		return nil, errors.New("short SCTP getaddrs response")
	}
	h = (*sctpGetAddrs)(unsafe.Pointer(&buf[0]))
	return parseRawSockaddrsSCTP(buf[sizeofSCTPGetAddrs:optLen], int(h.AddrNum))
}

func parseRawSockaddrsSCTP(data []byte, n int) ([]SCTPAddr, error) {
	out := make([]SCTPAddr, 0, n)
	for i := 0; i < n && len(data) >= 2; i++ {
		fam := *(*uint16)(unsafe.Pointer(&data[0]))
		switch fam {
		case syscall.AF_INET:
			if len(data) < syscall.SizeofSockaddrInet4 {
				return nil, errors.New("short sockaddr_in in SCTP getaddrs response")
			}
			var sa syscall.RawSockaddrInet4
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet4), data[:syscall.SizeofSockaddrInet4])
			ip := make(IP, IPv4len)
			copy(ip, sa.Addr[:])
			out = append(out, SCTPAddr{IP: ip, Port: int(ntohs(sa.Port))})
			data = data[syscall.SizeofSockaddrInet4:]
		case syscall.AF_INET6:
			if len(data) < syscall.SizeofSockaddrInet6 {
				return nil, errors.New("short sockaddr_in6 in SCTP getaddrs response")
			}
			var sa syscall.RawSockaddrInet6
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet6), data[:syscall.SizeofSockaddrInet6])
			ip := make(IP, IPv6len)
			copy(ip, sa.Addr[:])
			out = append(out, SCTPAddr{
				IP:   ip,
				Port: int(ntohs(sa.Port)),
				Zone: zoneCache.name(int(sa.Scope_id)),
			})
			data = data[syscall.SizeofSockaddrInet6:]
		default:
			return nil, errors.New("unsupported sockaddr family in SCTP getaddrs response")
		}
	}
	return out, nil
}

func marshalRawSockaddrsSCTP(family int, addrs []SCTPAddr) ([]byte, error) {
	buf := make([]byte, 0, len(addrs)*syscall.SizeofSockaddrInet6)
	for i := range addrs {
		sa, err := addrs[i].sockaddr(family)
		if err != nil {
			return nil, err
		}
		switch sa := sa.(type) {
		case *syscall.SockaddrInet4:
			raw := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Port: htons(uint16(sa.Port)), Addr: sa.Addr}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet4)...)
		case *syscall.SockaddrInet6:
			raw := syscall.RawSockaddrInet6{
				Family:   syscall.AF_INET6,
				Port:     htons(uint16(sa.Port)),
				Addr:     sa.Addr,
				Scope_id: sa.ZoneId,
			}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet6)...)
		default:
			return nil, errors.New("unsupported sockaddr type for SCTP bindx")
		}
	}
	return buf, nil
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func ntohs(v uint16) uint16 { return (v << 8) | (v >> 8) }
