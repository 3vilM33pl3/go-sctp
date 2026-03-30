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
	sctpSockoptRTOInfo        = 0
	sctpSockoptInitMsg        = 2
	sctpSockoptNoDelay        = 3
	sctpSockoptAutoClose      = 4
	sctpSockoptSetPeerPrimary = 5
	sctpSockoptPrimaryAddr    = 6
	sctpSockoptStatus         = 14
	sctpSockoptFragmentInter  = 18
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

	sockaddrStorageSize = 128
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

type sctpNxtInfoLinux struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Length  uint32
	AssocID int32
}

type sctpRTOInfoLinux struct {
	AssocID int32
	Initial uint32
	Max     uint32
	Min     uint32
}

type sctpPRInfoLinux struct {
	AssocID int32
	Value   uint32
	Policy  uint16
}

type sctpAuthChunkLinux struct {
	Chunk uint8
}

type sctpAuthKeyIDLinux struct {
	AssocID int32
	KeyID   uint16
}

type sctpAuthKeyHeaderLinux struct {
	AssocID   int32
	KeyID     uint16
	KeyLength uint16
}

type sctpAssocValueLinux struct {
	AssocID int32
	Value   uint32
}

type sctpStreamValueLinux struct {
	AssocID int32
	Stream  uint16
	Value   uint16
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

type sctpAssocIDsHeader struct {
	Count uint32
}

type sctpPeeloffArg struct {
	AssocID int32
	FD      int32
}

type sctpResetStreamsHeader struct {
	AssocID       int32
	Flags         uint16
	NumberStreams uint16
}

type sctpAddStreamsLinux struct {
	AssocID    int32
	InStreams  uint16
	OutStreams uint16
}

const (
	sizeofSCTPInitMsg          = int(unsafe.Sizeof(sctpInitMsg{}))
	sizeofSCTPSndInfoLinux     = int(unsafe.Sizeof(sctpSndInfoLinux{}))
	sizeofSCTPRcvInfoLinux     = int(unsafe.Sizeof(sctpRcvInfoLinux{}))
	sizeofSCTPNxtInfoLinux     = int(unsafe.Sizeof(sctpNxtInfoLinux{}))
	sizeofSCTPRTOInfoLinux     = int(unsafe.Sizeof(sctpRTOInfoLinux{}))
	sizeofSCTPPRInfoLinux      = int(unsafe.Sizeof(sctpPRInfoLinux{}))
	sizeofSCTPAuthChunkLinux   = int(unsafe.Sizeof(sctpAuthChunkLinux{}))
	sizeofSCTPAuthKeyIDLinux   = int(unsafe.Sizeof(sctpAuthKeyIDLinux{}))
	sizeofSCTPAuthKeyHdrLinux  = int(unsafe.Sizeof(sctpAuthKeyHeaderLinux{}))
	sizeofSCTPAssocValueLinux  = int(unsafe.Sizeof(sctpAssocValueLinux{}))
	sizeofSCTPStreamValueLinux = int(unsafe.Sizeof(sctpStreamValueLinux{}))
	sizeofSCTPPrimaryAddrLinux = int(unsafe.Sizeof(sctpPrimaryAddrLinux{}))
	sizeofSCTPStatusLinux      = int(unsafe.Sizeof(sctpStatusLinux{}))
	sizeofSCTPEvent            = int(unsafe.Sizeof(sctpEvent{}))
	sizeofSCTPGetAddrs         = int(unsafe.Sizeof(sctpGetAddrs{}))
	sizeofSCTPAssocIDsHeader   = int(unsafe.Sizeof(sctpAssocIDsHeader{}))
	sizeofSCTPPeeloffArg       = int(unsafe.Sizeof(sctpPeeloffArg{}))
	sizeofSCTPResetStreamsHdr  = int(unsafe.Sizeof(sctpResetStreamsHeader{}))
	sizeofSCTPAddStreamsLinux  = int(unsafe.Sizeof(sctpAddStreamsLinux{}))
)

func sctpOOBBufferSize() int {
	return syscall.CmsgSpace(sizeofSCTPRcvInfoLinux) + syscall.CmsgSpace(sizeofSCTPNxtInfoLinux)
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
	var info *SCTPRcvInfo
	var nxt *SCTPNxtInfo
	for _, scm := range scms {
		if scm.Header.Level != syscall.IPPROTO_SCTP {
			continue
		}
		switch scm.Header.Type {
		case sctpCmsgTypeRcvInfo:
			if len(scm.Data) < sizeofSCTPRcvInfoLinux {
				return nil, errors.New("short SCTP_RCVINFO control message")
			}
			var ri sctpRcvInfoLinux
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ri)), sizeofSCTPRcvInfoLinux), scm.Data[:sizeofSCTPRcvInfoLinux])
			info = &SCTPRcvInfo{
				Stream:  ri.Stream,
				SSN:     ri.SSN,
				Flags:   ri.Flags,
				PPID:    ri.PPID,
				TSN:     ri.TSN,
				CumTSN:  ri.CumTSN,
				Context: ri.Context,
				AssocID: ri.AssocID,
			}
		case sctpCmsgTypeNxtInfo:
			if len(scm.Data) < sizeofSCTPNxtInfoLinux {
				return nil, errors.New("short SCTP_NXTINFO control message")
			}
			var ni sctpNxtInfoLinux
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ni)), sizeofSCTPNxtInfoLinux), scm.Data[:sizeofSCTPNxtInfoLinux])
			nxt = &SCTPNxtInfo{
				Stream:  ni.Stream,
				Flags:   ni.Flags,
				PPID:    ni.PPID,
				Length:  ni.Length,
				AssocID: ni.AssocID,
			}
		}
	}
	if info == nil && nxt == nil {
		return nil, nil
	}
	if info == nil {
		info = &SCTPRcvInfo{}
	}
	info.Next = nxt
	return info, nil
}

func setNoDelaySCTP(fd *netFD, noDelay bool) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptNoDelay, boolint(noDelay))
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
	return setSCTPRecvRcvInfo(fd, true)
}

func setSCTPInitOptionsSockFD(sysfd int, opts SCTPInitOptions) error {
	sim := sctpInitMsg{
		NumOStreams:    opts.NumOStreams,
		MaxInStreams:   opts.MaxInStreams,
		MaxAttempts:    opts.MaxAttempts,
		MaxInitTimeout: opts.MaxInitTimeout,
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&sim)), sizeofSCTPInitMsg)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(sysfd),
		uintptr(syscall.IPPROTO_SCTP),
		uintptr(sctpSockoptInitMsg),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	if errno != 0 {
		return wrapSyscallError("setsockopt", errno)
	}
	one := 1
	_, _, errno = syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(sysfd),
		uintptr(syscall.IPPROTO_SCTP),
		uintptr(sctpSockoptRecvRcvInfo),
		uintptr(unsafe.Pointer(&one)),
		uintptr(unsafe.Sizeof(one)),
		0,
	)
	if errno != 0 {
		return wrapSyscallError("setsockopt", errno)
	}
	return nil
}

func setSCTPRecvRcvInfo(fd *netFD, on bool) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptRecvRcvInfo, boolint(on))
}

func setSCTPRecvNxtInfo(fd *netFD, on bool) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptRecvNxtInfo, boolint(on))
}

func setSCTPAutoClose(fd *netFD, seconds uint32) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptAutoClose, int(seconds))
}

func setSCTPFragmentInterleave(fd *netFD, level int) error {
	return setSockoptInt(fd, syscall.IPPROTO_SCTP, sctpSockoptFragmentInter, level)
}

func setSCTPRTOInfo(c *SCTPConn, info SCTPRTOInfo) error {
	if info.AssocID == 0 && c.assocID != 0 {
		info.AssocID = c.assocID
	}
	raw := sctpRTOInfoLinux{
		AssocID: info.AssocID,
		Initial: info.Initial,
		Max:     info.Max,
		Min:     info.Min,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptRTOInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPRTOInfoLinux))
}

func setSCTPDefaultPRInfo(c *SCTPConn, info SCTPPRInfo) error {
	if info.AssocID == 0 && c.assocID != 0 {
		info.AssocID = c.assocID
	}
	raw := sctpPRInfoLinux{
		AssocID: info.AssocID,
		Value:   info.Value,
		Policy:  uint16(info.Policy),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultPRInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPPRInfoLinux))
}

func setSCTPDefaultSendInfo(c *SCTPConn, info SCTPSndInfo) error {
	raw := sctpSndInfoLinux{
		Stream:  info.Stream,
		Flags:   info.Flags,
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultSndInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPSndInfoLinux))
}

func setSCTPAuthChunks(fd *netFD, chunks []uint8) error {
	for _, chunk := range chunks {
		raw := sctpAuthChunkLinux{Chunk: chunk}
		if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptAuthChunk, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthChunkLinux)); err != nil {
			return err
		}
	}
	return nil
}

func setSCTPAuthKey(c *SCTPConn, key SCTPAuthKey) error {
	if key.AssocID == 0 && c.assocID != 0 {
		key.AssocID = c.assocID
	}
	buf := make([]byte, sizeofSCTPAuthKeyHdrLinux+len(key.Secret))
	hdr := (*sctpAuthKeyHeaderLinux)(unsafe.Pointer(&buf[0]))
	hdr.AssocID = key.AssocID
	hdr.KeyID = key.KeyID
	hdr.KeyLength = uint16(len(key.Secret))
	copy(buf[sizeofSCTPAuthKeyHdrLinux:], key.Secret)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthKey, buf)
}

func setSCTPActiveAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 && c.assocID != 0 {
		assocID = c.assocID
	}
	raw := sctpAuthKeyIDLinux{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthActiveKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyIDLinux))
}

func deleteSCTPAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 && c.assocID != 0 {
		assocID = c.assocID
	}
	raw := sctpAuthKeyIDLinux{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthDeleteKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyIDLinux))
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

func enableSCTPStreamReset(c *SCTPConn, flags uint16) error {
	req := sctpAssocValueLinux{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(flags),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptEnableStrReset, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueLinux))
}

func resetSCTPStreams(c *SCTPConn, flags uint16, streams []uint16) error {
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	buf := make([]byte, sizeofSCTPResetStreamsHdr+len(streams)*2)
	hdr := (*sctpResetStreamsHeader)(unsafe.Pointer(&buf[0]))
	hdr.AssocID = assocID
	hdr.Flags = flags
	hdr.NumberStreams = uint16(len(streams))
	offset := sizeofSCTPResetStreamsHdr
	for _, stream := range streams {
		*(*uint16)(unsafe.Pointer(&buf[offset])) = stream
		offset += 2
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptResetStreams, buf)
}

func addSCTPStreams(c *SCTPConn, in, out uint16) error {
	assocID, err := resolveSCTPAssocID(c, 0)
	if err != nil {
		return err
	}
	req := sctpAddStreamsLinux{AssocID: assocID, InStreams: in, OutStreams: out}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAddStreams, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAddStreamsLinux))
}

func setSCTPStreamScheduler(c *SCTPConn, policy SCTPScheduler) error {
	req := sctpAssocValueLinux{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(policy),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSched, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueLinux))
}

func setSCTPStreamSchedulerValue(c *SCTPConn, stream uint16, value uint16) error {
	req := sctpStreamValueLinux{
		AssocID: optionalSCTPAssocID(c),
		Stream:  stream,
		Value:   value,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSchedVal, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPStreamValueLinux))
}

func peelOffSCTP(c *SCTPConn, assocID int32) (*SCTPConn, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	req := sctpPeeloffArg{AssocID: resolved}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPPeeloffArg)
	if _, err := getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptPeeloff, buf); err != nil {
		return nil, err
	}
	return wrapPeeledSCTPFD(req.FD, c.fd.family, c.fd.net, resolved)
}

func assocIDsSCTP(fd *netFD) ([]int32, error) {
	buf := make([]byte, 4096)
	n, err := getSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptAssocIDList, buf)
	if err != nil {
		return nil, err
	}
	if n < sizeofSCTPAssocIDsHeader {
		return nil, errors.New("short SCTP assoc id list response")
	}
	hdr := (*sctpAssocIDsHeader)(unsafe.Pointer(&buf[0]))
	count := int(hdr.Count)
	if count == 0 {
		return nil, nil
	}
	if n < sizeofSCTPAssocIDsHeader+count*4 {
		return nil, errors.New("truncated SCTP assoc id list response")
	}
	ids := make([]int32, count)
	offset := sizeofSCTPAssocIDsHeader
	for i := 0; i < count; i++ {
		ids[i] = *(*int32)(unsafe.Pointer(&buf[offset]))
		offset += 4
	}
	return ids, nil
}

func assocStatusSCTP(c *SCTPConn, assocID int32) (*SCTPAssocStatus, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	raw := sctpStatusLinux{AssocID: resolved}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPStatusLinux)
	if _, err := getSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStatus, buf); err != nil {
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

func setSockoptInt(fd *netFD, level, name, value int) error {
	err := fd.pfd.SetsockoptInt(level, name, value)
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
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

func getSockoptBytes(fd *netFD, level, name int, value []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	size := uint32(len(value))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd.pfd.Sysfd),
		uintptr(level),
		uintptr(name),
		uintptr(ptr),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	runtime.KeepAlive(fd)
	if errno != 0 {
		return 0, wrapSyscallError("getsockopt", errno)
	}
	return int(size), nil
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

func marshalSockaddrStorage(family int, addr *SCTPAddr) ([]byte, error) {
	if addr == nil {
		return nil, errMissingAddress
	}
	addrs, err := marshalRawSockaddrsSCTP(family, []SCTPAddr{*addr})
	if err != nil {
		return nil, err
	}
	if len(addrs) > sockaddrStorageSize {
		return nil, errors.New("sockaddr does not fit in sockaddr_storage")
	}
	buf := make([]byte, sockaddrStorageSize)
	copy(buf, addrs)
	return buf, nil
}

func parseSockaddrStorage(data []byte) (*SCTPAddr, error) {
	addrs, err := parseRawSockaddrsSCTP(data, 1)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	return &addrs[0], nil
}

func optionalSCTPAssocID(c *SCTPConn) int32 {
	if c.assocID != 0 {
		return c.assocID
	}
	ids, err := assocIDsSCTP(c.fd)
	if err == nil && len(ids) == 1 {
		c.assocID = ids[0]
		return ids[0]
	}
	return 0
}

func resolveSCTPAssocID(c *SCTPConn, assocID int32) (int32, error) {
	if assocID != 0 {
		return assocID, nil
	}
	ids, err := assocIDsSCTP(c.fd)
	if err == nil && len(ids) == 1 {
		c.assocID = ids[0]
		return ids[0], nil
	}
	if c.assocID != 0 {
		return c.assocID, nil
	}
	if err != nil {
		return 0, err
	}
	if len(ids) == 1 {
		c.assocID = ids[0]
		return ids[0], nil
	}
	if len(ids) == 0 {
		return 0, errors.New("sctp association id is not available yet")
	}
	return 0, errors.New("multiple SCTP associations are present; specify an association id explicitly")
}

func wrapPeeledSCTPFD(sysfd int32, family int, net string, assocID int32) (*SCTPConn, error) {
	sotype, err := syscall.GetsockoptInt(int(sysfd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		syscall.Close(int(sysfd))
		return nil, wrapSyscallError("getsockopt", err)
	}
	fd, err := newFD(int(sysfd), family, sotype, net)
	if err != nil {
		syscall.Close(int(sysfd))
		return nil, err
	}
	if err := fd.init(); err != nil {
		fd.Close()
		return nil, err
	}
	fd.isConnected = true
	lsa, _ := syscall.Getsockname(fd.pfd.Sysfd)
	rsa, _ := syscall.Getpeername(fd.pfd.Sysfd)
	fd.setAddr(fd.addrFunc()(lsa), fd.addrFunc()(rsa))
	conn := newSCTPConn(fd)
	conn.assocID = assocID
	if la, ok := conn.LocalAddr().(*SCTPAddr); ok && la != nil {
		conn.multiLocal = []SCTPAddr{*la}
	}
	if ra, ok := conn.RemoteAddr().(*SCTPAddr); ok && ra != nil {
		conn.multiPeer = []SCTPAddr{*ra}
	}
	return conn, nil
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func ntohs(v uint16) uint16 { return (v << 8) | (v >> 8) }
