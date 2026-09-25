// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package net

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux SCTP constants that are not provided by the frozen syscall package.
const (
	sctpSockoptRTOInfo        = 0
	sctpSockoptInitMsg        = 2
	sctpSockoptNoDelay        = 3
	sctpSockoptAutoClose      = 4
	sctpSockoptSetPeerPrimary = 5
	sctpSockoptPrimaryAddr    = 6
	sctpSockoptMaxSeg         = 13
	sctpSockoptStatus         = 14
	sctpSockoptDelayedSack    = 16
	sctpSockoptFragmentInter  = 18
	sctpSockoptMaxBurst       = 20
	sctpSockoptAuthChunk      = 21
	sctpSockoptAuthKey        = 23
	sctpSockoptAuthActiveKey  = 24
	sctpSockoptAuthDeleteKey  = 25
	sctpSockoptAssocIDList    = 29
	sctpSockoptRecvRcvInfo    = 32
	sctpSockoptRecvNxtInfo    = 33
	sctpSockoptDefaultSndInfo = 34
	sctpSockoptBindxAdd       = 100
	sctpSockoptBindxRem       = 101
	sctpSockoptPeeloff        = 102
	sctpSockoptPeeloffFlags   = 122
	sctpSockoptConnectxOld    = 107
	sctpGetPeerAddrs          = 108
	sctpGetLocalAddrs         = 109
	sctpSockoptConnectx       = 110
	sctpSockoptDefaultPRInfo  = 114
	sctpSockoptEnableStrReset = 118
	sctpSockoptResetStreams   = 119
	sctpSockoptAddStreams     = 121
	sctpSockoptStreamSched    = 123
	sctpSockoptStreamSchedVal = 124
	sctpSockoptEvent          = 127

	sctpCmsgTypeSndInfo = 2
	sctpCmsgTypeRcvInfo = 3
	sctpCmsgTypeNxtInfo = 4

	// enum sctp_sn_type; SCTP_SEND_FAILED (0x8003) is the legacy form and
	// is deliberately not subscribed, see SCTPEventMask.SendFailure.
	sctpEventAssociation     = 0x8001
	sctpEventAddress         = 0x8002
	sctpEventPeerError       = 0x8004
	sctpEventShutdown        = 0x8005
	sctpEventPartialDelivery = 0x8006
	sctpEventAdaptation      = 0x8007
	sctpEventAuthentication  = 0x8008
	sctpEventSenderDry       = 0x8009
	sctpEventStreamReset     = 0x800a
	sctpEventAssocReset      = 0x800b
	sctpEventStreamChange    = 0x800c
	sctpEventSendFailure     = 0x800d

	sockaddrStorageSize = 128
)

// SCTPMsgNotification is the recvmsg flag, in the flags word returned by
// [SCTPConn.ReadFromSCTP], marking a message as an SCTP notification rather
// than user data. It is the platform's MSG_NOTIFICATION.
const SCTPMsgNotification = 0x8000

const sctpNotificationsSupported = true

// enum sctp_sn_type notification types; the event subscription constants
// above share the numbering.
func sctpNotificationType(raw uint16) SCTPNotificationType {
	switch raw {
	case 0x8001:
		return SCTPNotifyAssocChange
	case 0x8002:
		return SCTPNotifyPeerAddrChange
	case 0x8004:
		return SCTPNotifyRemoteError
	case 0x8003, 0x800d: // legacy SCTP_SEND_FAILED shares the RFC 6458 header layout
		return SCTPNotifySendFailed
	case 0x8005:
		return SCTPNotifyShutdown
	case 0x8006:
		return SCTPNotifyPartialDelivery
	case 0x8007:
		return SCTPNotifyAdaptation
	case 0x8008:
		return SCTPNotifyAuthentication
	case 0x8009:
		return SCTPNotifySenderDry
	case 0x800a:
		return SCTPNotifyStreamReset
	case 0x800b:
		return SCTPNotifyAssocReset
	case 0x800c:
		return SCTPNotifyStreamChange
	}
	return 0
}

// enum sctp_sac_state and enum sctp_spc_state count from 0 on Linux.
func sctpAssocState(raw uint16) SCTPAssocState {
	if raw <= uint16(SCTPCantStartAssoc-1) {
		return SCTPAssocState(raw + 1)
	}
	return 0
}

func sctpPeerAddrState(raw uint32) SCTPPeerAddrState {
	if raw <= uint32(SCTPAddrPotentiallyFailed-1) {
		return SCTPPeerAddrState(raw + 1)
	}
	return 0
}

// SCTP_DATA_UNSENT is 0 and SCTP_DATA_SENT 1 on Linux.
func sctpSendFailedSent(flags uint16) bool { return flags == 1 }

// struct sctp_pdapi_event: pdapi_assoc_id follows the 32-bit indication.
const sctpPDAPIAssocIDOffset = 12

// The portable send/receive flag values are Linux's own.
func sctpSndFlagsToKernel(flags uint16) uint16   { return flags }
func sctpRcvFlagsFromKernel(flags uint16) uint16 { return flags }

type sctpPRInfoLinux struct {
	AssocID int32
	Value   uint32
	Policy  uint16
}

type sctpPrimaryAddrLinux struct {
	AssocID int32
	Addr    [sockaddrStorageSize]byte
}

type sctpPeerAddrInfoLinux struct {
	AssocID int32
	Addr    [sockaddrStorageSize]byte
	State   int32
	CWND    uint32
	SRTT    uint32
	RTO     uint32
	MTU     uint32
}

type sctpStatusLinux struct {
	AssocID            int32
	State              int32
	RWND               uint32
	UnackedData        uint16
	PendingData        uint16
	InStreams          uint16
	OutStreams         uint16
	FragmentationPoint uint32
	Primary            sctpPeerAddrInfoLinux
}

type sctpGetAddrs struct {
	AssocID int32
	AddrNum uint32
}

type sctpPeeloffArg struct {
	AssocID int32
	FD      int32
}

type sctpPeeloffFlagsArg struct {
	sctpPeeloffArg
	Flags uint32
}

const (
	sizeofSCTPPRInfoLinux      = int(unsafe.Sizeof(sctpPRInfoLinux{}))
	sizeofSCTPPrimaryAddrLinux = int(unsafe.Sizeof(sctpPrimaryAddrLinux{}))
	sizeofSCTPStatusLinux      = int(unsafe.Sizeof(sctpStatusLinux{}))
	sizeofSCTPGetAddrs         = int(unsafe.Sizeof(sctpGetAddrs{}))
	sizeofSCTPPeeloffArg       = int(unsafe.Sizeof(sctpPeeloffArg{}))
	sizeofSCTPPeeloffFlagsArg  = int(unsafe.Sizeof(sctpPeeloffFlagsArg{}))
)

func setSCTPMaxSeg(fd *netFD, value uint32) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptMaxSeg, int(value))
}

func setSCTPDefaultPRInfo(c *SCTPConn, info SCTPPRInfo) error {
	if info.AssocID == 0 {
		info.AssocID = c.assocID.Load()
	}
	raw := sctpPRInfoLinux{
		AssocID: info.AssocID,
		Value:   info.Value,
		Policy:  uint16(info.Policy),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultPRInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPPRInfoLinux))
}

func setSCTPPrimaryAddr(c *SCTPConn, addr *SCTPAddr) error {
	if addr == nil {
		return errMissingAddress
	}
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	raw, err := marshalSockaddrStorage(c.fd.family, addr)
	if err != nil {
		return err
	}
	req := sctpPrimaryAddrLinux{AssocID: assocID}
	copy(req.Addr[:], raw)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptPrimaryAddr, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPPrimaryAddrLinux))
}

func setSCTPPeerPrimaryAddr(c *SCTPConn, addr *SCTPAddr) error {
	if addr == nil {
		return errMissingAddress
	}
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	raw, err := marshalSockaddrStorage(c.fd.family, addr)
	if err != nil {
		return err
	}
	req := sctpPrimaryAddrLinux{AssocID: assocID}
	copy(req.Addr[:], raw)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptSetPeerPrimary, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPPrimaryAddrLinux))
}

func peelOffSCTP(c *SCTPConn, assocID int32) (*SCTPConn, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	// SCTP_SOCKOPT_PEELOFF_FLAGS (Linux 4.14) creates the descriptor
	// non-blocking and close-on-exec atomically, the way accept4 does.
	req := sctpPeeloffFlagsArg{sctpPeeloffArg: sctpPeeloffArg{AssocID: resolved}, Flags: syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPPeeloffFlagsArg)
	_, err = getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptPeeloffFlags, buf)
	if err == nil {
		return wrapPeeledSCTPFD(int(req.FD), c.fd.family, c.fd.net, resolved)
	}
	if !errors.Is(err, syscall.ENOPROTOOPT) {
		return nil, err
	}
	// Older kernels only have SCTP_SOCKOPT_PEELOFF, which inherits nothing.
	// Hold ForkLock so a concurrent fork cannot inherit the descriptor
	// before CloseOnExec marks it; see syscall/exec_unix.go.
	old := sctpPeeloffArg{AssocID: resolved}
	buf = unsafe.Slice((*byte)(unsafe.Pointer(&old)), sizeofSCTPPeeloffArg)
	syscall.ForkLock.RLock()
	_, err = getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptPeeloff, buf)
	if err == nil {
		syscall.CloseOnExec(int(old.FD))
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	return wrapPeeledSCTPFD(int(old.FD), c.fd.family, c.fd.net, resolved)
}

func assocStatusSCTP(c *SCTPConn, assocID int32) (*SCTPAssocStatus, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	raw := sctpStatusLinux{AssocID: resolved}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPStatusLinux)
	if _, err := getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStatus, buf); err != nil {
		// A one-to-many socket whose only association just went away
		// answers the cached id with EINVAL; the endpoint-level status
		// (id 0) still describes the socket, so fall back to it once.
		if assocID == 0 && resolved != 0 && errors.Is(err, syscall.EINVAL) {
			raw.AssocID = 0
			if _, retryErr := getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStatus, buf); retryErr != nil {
				return nil, retryErr
			}
		} else {
			return nil, err
		}
	}
	addr, err := parseSockaddrStorage(raw.Primary.Addr[:])
	if err != nil {
		return nil, err
	}
	status := &SCTPAssocStatus{
		AssocID:            raw.AssocID,
		State:              raw.State,
		RWND:               raw.RWND,
		UnackedData:        raw.UnackedData,
		PendingData:        raw.PendingData,
		InStreams:          raw.InStreams,
		OutStreams:         raw.OutStreams,
		FragmentationPoint: raw.FragmentationPoint,
		PrimaryState:       raw.Primary.State,
		PrimaryCWND:        raw.Primary.CWND,
		PrimarySRTT:        raw.Primary.SRTT,
		PrimaryRTO:         raw.Primary.RTO,
		PrimaryMTU:         raw.Primary.MTU,
	}
	if addr != nil {
		status.PrimaryAddr = *addr
	}
	return status, nil
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

func unbindAddrsSCTP(fd *netFD, addrs []SCTPAddr) error {
	if len(addrs) == 0 {
		return nil
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return err
	}
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptBindxRem, b)
}

func connectAddrsSCTP(fd *netFD, addrs []SCTPAddr) (int32, error) {
	if len(addrs) == 0 {
		return 0, errMissingAddress
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return 0, err
	}
	id, errno, err := connectxSCTP(fd, sctpSockoptConnectx, b)
	if err != nil {
		return 0, err
	}
	if errno == syscall.ENOPROTOOPT {
		// Kernels before SCTP_SOCKOPT_CONNECTX only know the _OLD variant.
		if id, errno, err = connectxSCTP(fd, sctpSockoptConnectxOld, b); err != nil {
			return 0, err
		}
	}
	switch errno {
	case 0:
		return id, nil
	case syscall.EINPROGRESS, syscall.EALREADY:
		// The non-blocking connect is still in flight and the return
		// value is -1, not an id. Callers fall back to resolving the id
		// later (or, on one-to-one sockets, never need it).
		return 0, nil
	}
	return 0, wrapSyscallError("setsockopt", errno)
}

// connectxSCTP issues one SCTP_SOCKOPT_CONNECTX* call and returns the
// kernel's return value (the association id on success) and errno. The
// error is non-nil only when the descriptor is already closed.
func connectxSCTP(fd *netFD, opt int, b []byte) (int32, syscall.Errno, error) {
	var (
		r0    uintptr
		errno syscall.Errno
	)
	if err := fd.pfd.RawControl(func(s uintptr) {
		r0, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, s, uintptr(syscall.IPPROTO_SCTP), uintptr(opt), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	}); err != nil {
		return 0, 0, err
	}
	runtime.KeepAlive(fd)
	return int32(r0), errno, nil
}

func localAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetLocalAddrs, assocID)
}

func peerAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetPeerAddrs, assocID)
}

func getAddrsSCTP(fd *netFD, opt int, assocID int32) ([]SCTPAddr, error) {
	buf := make([]byte, 64*1024)
	h := (*sctpGetAddrs)(unsafe.Pointer(&buf[0]))
	h.AssocID = assocID
	n, err := getSockoptBytes(fd, syscall.IPPROTO_SCTP, opt, buf)
	if err != nil {
		return nil, err
	}
	if n < sizeofSCTPGetAddrs {
		return nil, errors.New("short SCTP getaddrs response")
	}
	return parseRawSockaddrsSCTP(buf[sizeofSCTPGetAddrs:n], int(h.AddrNum))
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
			out = append(out, SCTPAddr{IP: ip, Port: portFromRaw(sa.Port)})
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
				Port: portFromRaw(sa.Port),
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
			raw := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Port: rawPort(sa.Port), Addr: sa.Addr}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet4)...)
		case *syscall.SockaddrInet6:
			raw := syscall.RawSockaddrInet6{
				Family:   syscall.AF_INET6,
				Port:     rawPort(sa.Port),
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

func parseSockaddrStorage(data []byte) (*SCTPAddr, error) {
	// An all-zero sockaddr_storage (sa_family AF_UNSPEC) is how SCTP_STATUS
	// reports an association without a primary address yet.
	if len(data) < 2 || hostUint16(data) == 0 {
		return nil, nil
	}
	addrs, err := parseRawSockaddrsSCTP(data, 1)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	return &addrs[0], nil
}

// dialSCTPInitPlatform: Linux applies SCTP_INITMSG through the dialer's
// ControlContext before connect, so the portable path is used.
func dialSCTPInitPlatform(context.Context, *Dialer, string, *SCTPAddr, *SCTPAddr, SCTPInitOptions) (*SCTPConn, bool, error) {
	return nil, false, nil
}
