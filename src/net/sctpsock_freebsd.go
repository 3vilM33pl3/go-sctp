// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd && amd64

package net

import (
	"context"
	"errors"
	"syscall"
	"unsafe"
)

const (
	sctpSockoptRTOInfo        = 0x00000001
	sctpSockoptInitMsg        = 0x00000003
	sctpSockoptNoDelay        = 0x00000004
	sctpSockoptAutoClose      = 0x00000005
	sctpSockoptSetPeerPrimary = 0x00000006
	sctpSockoptPrimaryAddr    = 0x00000007
	sctpSockoptMaxSeg         = 0x0000000e
	sctpSockoptDelayedSack    = 0x0000000f
	sctpSockoptFragmentInter  = 0x00000010
	sctpSockoptAuthChunk      = 0x00000012
	sctpSockoptAuthKey        = 0x00000013
	sctpSockoptAuthActiveKey  = 0x00000015
	sctpSockoptAuthDeleteKey  = 0x00000016
	sctpSockoptMaxBurst       = 0x00000019
	sctpSockoptEvent          = 0x0000001e
	sctpSockoptRecvRcvInfo    = 0x0000001f
	sctpSockoptRecvNxtInfo    = 0x00000020
	sctpSockoptDefaultSndInfo = 0x00000021
	sctpSockoptDefaultPRInfo  = 0x00000022
	sctpSockoptStatus         = 0x00000100
	sctpSockoptAssocIDList    = 0x00000105
	sctpSockoptEnableStrReset = 0x00000900
	sctpSockoptResetStreams   = 0x00000901
	sctpSockoptAddStreams     = 0x00000903
	sctpSockoptStreamSched    = 0x00001203
	sctpSockoptStreamSchedVal = 0x00001204

	sctpBindxAdd          = 0x00008001
	sctpBindxRem          = 0x00008002
	sctpGetPeerAddrs      = 0x00008003
	sctpGetLocalAddrs     = 0x00008004
	sctpGetLocalAddrSize  = 0x00008005
	sctpGetRemoteAddrSize = 0x00008006
	sctpSockoptConnectx   = 0x00008007

	sctpCmsgTypeSndInfo = 0x0004
	sctpCmsgTypeRcvInfo = 0x0005
	sctpCmsgTypeNxtInfo = 0x0006

	sctpEventAssociation     = 0x0001
	sctpEventAddress         = 0x0002
	sctpEventPeerError       = 0x0003
	sctpEventSendFailure     = 0x000e
	sctpEventShutdown        = 0x0005
	sctpEventPartialDelivery = 0x0007
	sctpEventAdaptation      = 0x0006
	sctpEventAuthentication  = 0x0008
	sctpEventSenderDry       = 0x000a
	sctpEventStreamReset     = 0x0009
	sctpEventAssocReset      = 0x000c
	sctpEventStreamChange    = 0x000d

	sockaddrStorageSize = 128
)

const sctpNotificationsSupported = true

// sctp_uio.h notification types.
func sctpNotificationType(raw uint16) SCTPNotificationType {
	switch raw {
	case 0x0001:
		return SCTPNotifyAssocChange
	case 0x0002:
		return SCTPNotifyPeerAddrChange
	case 0x0003:
		return SCTPNotifyRemoteError
	case 0x000e:
		return SCTPNotifySendFailed
	case 0x0005:
		return SCTPNotifyShutdown
	case 0x0007:
		return SCTPNotifyPartialDelivery
	case 0x0006:
		return SCTPNotifyAdaptation
	case 0x0008:
		return SCTPNotifyAuthentication
	case 0x000a:
		return SCTPNotifySenderDry
	case 0x0009:
		return SCTPNotifyStreamReset
	case 0x000c:
		return SCTPNotifyAssocReset
	case 0x000d:
		return SCTPNotifyStreamChange
	}
	return 0
}

// FreeBSD numbers association and address states from 1, matching the
// portable constants.
func sctpAssocState(raw uint16) SCTPAssocState {
	if raw >= 1 && raw <= uint16(SCTPCantStartAssoc) {
		return SCTPAssocState(raw)
	}
	return 0
}

func sctpPeerAddrState(raw uint32) SCTPPeerAddrState {
	if raw >= 1 && raw <= uint32(SCTPAddrConfirmed) {
		return SCTPPeerAddrState(raw)
	}
	return 0
}

// SCTP_DATA_UNSENT is 1 and SCTP_DATA_SENT 2 on FreeBSD.
func sctpSendFailedSent(flags uint16) bool { return flags == 2 }

// struct sctp_pdapi_event: pdapi_assoc_id follows two 16-bit fields.
const sctpPDAPIAssocIDOffset = 16

type sctpDefaultPRInfoFreeBSD struct {
	Policy  uint16
	_       uint16
	Value   uint32
	AssocID int32
}

type sctpSetPrimFreeBSD struct {
	Addr    [sockaddrStorageSize]byte
	AssocID int32
	Padding [4]byte
}

type sctpSetPeerPrimFreeBSD struct {
	Addr    [sockaddrStorageSize]byte
	AssocID int32
	Padding [4]byte
}

type sctpPAddrInfoFreeBSD struct {
	Addr    [sockaddrStorageSize]byte
	AssocID int32
	State   int32
	CWND    uint32
	SRTT    uint32
	RTO     uint32
	MTU     uint32
}

type sctpStatusFreeBSD struct {
	AssocID            int32
	State              int32
	RWND               uint32
	UnackedData        uint16
	PendingData        uint16
	InStreams          uint16
	OutStreams         uint16
	FragmentationPoint uint32
	Primary            sctpPAddrInfoFreeBSD
}

const (
	sizeofSCTPDefaultPRInfoFreeBSD = int(unsafe.Sizeof(sctpDefaultPRInfoFreeBSD{}))
	sizeofSCTPSetPrimFreeBSD       = int(unsafe.Sizeof(sctpSetPrimFreeBSD{}))
	sizeofSCTPSetPeerPrimFreeBSD   = int(unsafe.Sizeof(sctpSetPeerPrimFreeBSD{}))
	sizeofSCTPStatusFreeBSD        = int(unsafe.Sizeof(sctpStatusFreeBSD{}))
)

func setSCTPMaxSeg(fd *netFD, value uint32) error {
	req := sctpAssocValue{AssocID: 0, Value: value}
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptMaxSeg, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValue))
}

func setSCTPDefaultPRInfo(c *SCTPConn, info SCTPPRInfo) error {
	if info.AssocID == 0 {
		info.AssocID = c.assocID.Load()
	}
	raw := sctpDefaultPRInfoFreeBSD{
		Policy:  uint16(info.Policy),
		Value:   info.Value,
		AssocID: info.AssocID,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultPRInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPDefaultPRInfoFreeBSD))
}

func setSCTPPrimaryAddr(c *SCTPConn, addr *SCTPAddr) error {
	if addr == nil {
		return errMissingAddress
	}
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	rawAddr, err := marshalSockaddrStorage(c.fd.family, addr)
	if err != nil {
		return err
	}
	req := sctpSetPrimFreeBSD{AssocID: assocID}
	copy(req.Addr[:], rawAddr)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptPrimaryAddr, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPSetPrimFreeBSD))
}

func setSCTPPeerPrimaryAddr(c *SCTPConn, addr *SCTPAddr) error {
	if addr == nil {
		return errMissingAddress
	}
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	rawAddr, err := marshalSockaddrStorage(c.fd.family, addr)
	if err != nil {
		return err
	}
	req := sctpSetPeerPrimFreeBSD{AssocID: assocID}
	copy(req.Addr[:], rawAddr)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptSetPeerPrimary, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPSetPeerPrimFreeBSD))
}

func peelOffSCTP(c *SCTPConn, assocID int32) (*SCTPConn, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	// sctp_peeloff(2) takes no flags. Hold ForkLock so a concurrent fork
	// cannot inherit the descriptor before CloseOnExec marks it; see
	// syscall/exec_unix.go.
	var newfd int
	syscall.ForkLock.RLock()
	err = rawSockopt(c.fd, func(s uintptr) syscall.Errno {
		r0, _, errno := syscall.Syscall(syscall.SYS_SCTP_PEELOFF, s, uintptr(uint32(resolved)), 0)
		if errno == 0 {
			newfd = int(r0)
			syscall.CloseOnExec(newfd)
		}
		return errno
	})
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, wrapSyscallError("sctp_peeloff", err)
	}
	return wrapPeeledSCTPFD(newfd, c.fd.family, c.fd.net, resolved)
}

func assocStatusSCTP(c *SCTPConn, assocID int32) (*SCTPAssocStatus, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	raw := sctpStatusFreeBSD{AssocID: resolved}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPStatusFreeBSD)
	if _, err := getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStatus, buf); err != nil {
		return nil, err
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
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpBindxAdd, b)
}

func unbindAddrsSCTP(fd *netFD, addrs []SCTPAddr) error {
	if len(addrs) == 0 {
		return nil
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return err
	}
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpBindxRem, b)
}

func connectAddrsSCTP(fd *netFD, addrs []SCTPAddr) (int32, error) {
	if len(addrs) == 0 {
		return 0, errMissingAddress
	}
	b, err := marshalRawSockaddrsSCTP(fd.family, addrs)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, len(b)+4)
	copy(buf, b)
	if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptConnectx, buf); err != nil {
		return 0, err
	}
	return *(*int32)(unsafe.Pointer(&buf[len(b)])), nil
}

func localAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetLocalAddrSize, sctpGetLocalAddrs, assocID)
}

func peerAddrsSCTP(fd *netFD, assocID int32) ([]SCTPAddr, error) {
	return getAddrsSCTP(fd, sctpGetRemoteAddrSize, sctpGetPeerAddrs, assocID)
}

func getAddrsSCTP(fd *netFD, sizeOpt int, addrsOpt int, assocID int32) ([]SCTPAddr, error) {
	sizeBuf := make([]byte, 4)
	*(*int32)(unsafe.Pointer(&sizeBuf[0])) = assocID
	n, err := getSockoptBytes(fd, syscall.IPPROTO_SCTP, sizeOpt, sizeBuf)
	if err != nil {
		return nil, err
	}
	if n < 4 {
		return nil, errors.New("short SCTP getaddrs size response")
	}
	size := int(*(*uint32)(unsafe.Pointer(&sizeBuf[0])))
	if size < 4 {
		return nil, nil
	}
	buf := make([]byte, size)
	*(*int32)(unsafe.Pointer(&buf[0])) = assocID
	n, err = getSockoptBytes(fd, syscall.IPPROTO_SCTP, addrsOpt, buf)
	if err != nil {
		return nil, err
	}
	if n < 4 {
		return nil, errors.New("short SCTP getaddrs response")
	}
	return parseRawSockaddrsSCTP(buf[4:n])
}

func sockaddrSpan(data []byte) (addrLen int, family int, size int, err error) {
	if len(data) < 2 {
		return 0, 0, 0, errors.New("short sockaddr in SCTP response")
	}
	addrLen = int(data[0])
	family = int(data[1])
	switch family {
	case syscall.AF_INET:
		size = syscall.SizeofSockaddrInet4
	case syscall.AF_INET6:
		size = syscall.SizeofSockaddrInet6
	default:
		return 0, 0, 0, errors.New("unsupported sockaddr family in SCTP response")
	}
	if addrLen == 0 {
		addrLen = size
	}
	return addrLen, family, size, nil
}

func parseRawSockaddrsSCTP(data []byte) ([]SCTPAddr, error) {
	var out []SCTPAddr
	for len(data) >= 2 {
		addrLen, family, size, err := sockaddrSpan(data)
		if err != nil {
			return nil, err
		}
		if len(data) < size {
			return nil, errors.New("short sockaddr in SCTP address list")
		}
		switch family {
		case syscall.AF_INET:
			var sa syscall.RawSockaddrInet4
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet4), data[:syscall.SizeofSockaddrInet4])
			ip := make(IP, IPv4len)
			copy(ip, sa.Addr[:])
			out = append(out, SCTPAddr{IP: ip, Port: portFromRaw(sa.Port)})
		case syscall.AF_INET6:
			var sa syscall.RawSockaddrInet6
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet6), data[:syscall.SizeofSockaddrInet6])
			ip := make(IP, IPv6len)
			copy(ip, sa.Addr[:])
			out = append(out, SCTPAddr{
				IP:   ip,
				Port: portFromRaw(sa.Port),
				Zone: zoneCache.name(int(sa.Scope_id)),
			})
		default:
			return nil, errors.New("unsupported sockaddr family in SCTP address list")
		}
		if addrLen < size {
			addrLen = size
		}
		if addrLen > len(data) {
			return nil, errors.New("truncated sockaddr in SCTP address list")
		}
		data = data[addrLen:]
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
			raw := syscall.RawSockaddrInet4{
				Len:    syscall.SizeofSockaddrInet4,
				Family: syscall.AF_INET,
				Port:   rawPort(sa.Port),
				Addr:   sa.Addr,
			}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet4)...)
		case *syscall.SockaddrInet6:
			raw := syscall.RawSockaddrInet6{
				Len:      syscall.SizeofSockaddrInet6,
				Family:   syscall.AF_INET6,
				Port:     rawPort(sa.Port),
				Addr:     sa.Addr,
				Scope_id: sa.ZoneId,
			}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet6)...)
		default:
			return nil, errors.New("unsupported sockaddr type for SCTP address list")
		}
	}
	return buf, nil
}

func parseSockaddrStorage(data []byte) (*SCTPAddr, error) {
	// An all-zero sockaddr_storage (sa_family AF_UNSPEC) is how SCTP_STATUS
	// reports an association without a primary address yet.
	if len(data) < 2 || data[1] == 0 {
		return nil, nil
	}
	_, family, _, err := sockaddrSpan(data)
	if err != nil {
		return nil, err
	}
	switch family {
	case syscall.AF_INET:
		if len(data) < syscall.SizeofSockaddrInet4 {
			return nil, errors.New("short sockaddr_in in SCTP sockaddr_storage")
		}
		var sa syscall.RawSockaddrInet4
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet4), data[:syscall.SizeofSockaddrInet4])
		ip := make(IP, IPv4len)
		copy(ip, sa.Addr[:])
		return &SCTPAddr{IP: ip, Port: portFromRaw(sa.Port)}, nil
	case syscall.AF_INET6:
		if len(data) < syscall.SizeofSockaddrInet6 {
			return nil, errors.New("short sockaddr_in6 in SCTP sockaddr_storage")
		}
		var sa syscall.RawSockaddrInet6
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet6), data[:syscall.SizeofSockaddrInet6])
		ip := make(IP, IPv6len)
		copy(ip, sa.Addr[:])
		return &SCTPAddr{
			IP:   ip,
			Port: portFromRaw(sa.Port),
			Zone: zoneCache.name(int(sa.Scope_id)),
		}, nil
	}
	return nil, nil
}

// dialSCTPInitPlatform implements DialSCTPInit on FreeBSD: the socket is opened
// unconnected, SCTP_INITMSG is applied, and only then is connect(2) issued, since
// FreeBSD rejects INITMSG changes on a connecting one-to-one socket.
func dialSCTPInitPlatform(ctx context.Context, d *Dialer, network string, laddr, raddr *SCTPAddr, opts SCTPInitOptions) (*SCTPConn, bool, error) {
	c, err := openDialSCTP(ctx, d, network, laddr, raddr)
	if err != nil {
		return nil, true, err
	}
	if err := setSCTPInitOptions(c.fd, opts); err != nil {
		c.Close()
		return nil, true, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	var lsa syscall.Sockaddr
	if laddr != nil {
		var err error
		lsa, err = laddr.sockaddr(c.fd.family)
		if err != nil {
			c.Close()
			return nil, true, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
		}
	}
	rsa, err := raddr.sockaddr(c.fd.family)
	if err != nil {
		c.Close()
		return nil, true, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	crsa, err := c.fd.connect(ctx, lsa, rsa)
	if err != nil {
		c.Close()
		return nil, true, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	c.fd.isConnected = true
	if lsa != nil {
		c.fd.laddr = c.fd.addrFunc()(lsa)
	}
	if crsa != nil {
		c.fd.raddr = c.fd.addrFunc()(crsa)
	} else {
		c.fd.raddr = c.fd.addrFunc()(rsa)
	}
	c.setPeerAddrs([]SCTPAddr{*raddr})
	if la, ok := c.LocalAddr().(*SCTPAddr); ok && la != nil {
		c.setLocalAddrs([]SCTPAddr{*la})
	}
	return c, true, nil

}
