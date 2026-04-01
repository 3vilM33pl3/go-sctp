// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd && amd64

package net

import (
	"errors"
	"runtime"
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
	sctpSockoptEventsCompat   = 0x0000000c
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

	sockaddrStorageSize = 128
)

type sctpInitMsg struct {
	NumOStreams    uint16
	MaxInStreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

type sctpSndInfoFreeBSD struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

type sctpRcvInfoFreeBSD struct {
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

type sctpNxtInfoFreeBSD struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Length  uint32
	AssocID int32
}

type sctpEventSubscribeFreeBSD struct {
	DataIO          uint8
	Association     uint8
	Address         uint8
	SendFailure     uint8
	PeerError       uint8
	Shutdown        uint8
	PartialDelivery uint8
	Adaptation      uint8
	Authentication  uint8
	SenderDry       uint8
	StreamReset     uint8
}

type sctpRTOInfoFreeBSD struct {
	AssocID int32
	Initial uint32
	Max     uint32
	Min     uint32
}

type sctpDelayedSackInfoFreeBSD struct {
	AssocID int32
	Delay   uint32
	Freq    uint32
}

type sctpDefaultPRInfoFreeBSD struct {
	Policy  uint16
	_       uint16
	Value   uint32
	AssocID int32
}

type sctpAuthChunkFreeBSD struct {
	Chunk uint8
}

type sctpAuthKeyIDFreeBSD struct {
	AssocID int32
	KeyID   uint16
	_       uint16
}

type sctpAuthKeyHeaderFreeBSD struct {
	AssocID   int32
	KeyID     uint16
	KeyLength uint16
}

type sctpAssocValueFreeBSD struct {
	AssocID int32
	Value   uint32
}

type sctpStreamValueFreeBSD struct {
	AssocID int32
	Stream  uint16
	Value   uint16
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

type sctpEvent struct {
	AssocID int32
	Type    uint16
	On      uint8
	_       uint8
}

type sctpAssocIDsHeader struct {
	Count uint32
}

type sctpResetStreamsHeader struct {
	AssocID       int32
	Flags         uint16
	NumberStreams uint16
}

type sctpAddStreamsFreeBSD struct {
	AssocID    int32
	InStreams  uint16
	OutStreams uint16
}

const (
	sizeofSCTPInitMsg              = int(unsafe.Sizeof(sctpInitMsg{}))
	sizeofSCTPSndInfoFreeBSD       = int(unsafe.Sizeof(sctpSndInfoFreeBSD{}))
	sizeofSCTPRcvInfoFreeBSD       = int(unsafe.Sizeof(sctpRcvInfoFreeBSD{}))
	sizeofSCTPNxtInfoFreeBSD       = int(unsafe.Sizeof(sctpNxtInfoFreeBSD{}))
	sizeofSCTPEventSubscribeCompat = int(unsafe.Sizeof(sctpEventSubscribeFreeBSD{}))
	sizeofSCTPRTOInfoFreeBSD       = int(unsafe.Sizeof(sctpRTOInfoFreeBSD{}))
	sizeofSCTPDelayedSackInfo      = int(unsafe.Sizeof(sctpDelayedSackInfoFreeBSD{}))
	sizeofSCTPDefaultPRInfoFreeBSD = int(unsafe.Sizeof(sctpDefaultPRInfoFreeBSD{}))
	sizeofSCTPAuthChunkFreeBSD     = int(unsafe.Sizeof(sctpAuthChunkFreeBSD{}))
	sizeofSCTPAuthKeyIDFreeBSD     = int(unsafe.Sizeof(sctpAuthKeyIDFreeBSD{}))
	sizeofSCTPAuthKeyHdrFreeBSD    = int(unsafe.Sizeof(sctpAuthKeyHeaderFreeBSD{}))
	sizeofSCTPAssocValueFreeBSD    = int(unsafe.Sizeof(sctpAssocValueFreeBSD{}))
	sizeofSCTPStreamValueFreeBSD   = int(unsafe.Sizeof(sctpStreamValueFreeBSD{}))
	sizeofSCTPSetPrimFreeBSD       = int(unsafe.Sizeof(sctpSetPrimFreeBSD{}))
	sizeofSCTPSetPeerPrimFreeBSD   = int(unsafe.Sizeof(sctpSetPeerPrimFreeBSD{}))
	sizeofSCTPStatusFreeBSD        = int(unsafe.Sizeof(sctpStatusFreeBSD{}))
	sizeofSCTPEvent                = int(unsafe.Sizeof(sctpEvent{}))
	sizeofSCTPAssocIDsHeader       = int(unsafe.Sizeof(sctpAssocIDsHeader{}))
	sizeofSCTPResetStreamsHdr      = int(unsafe.Sizeof(sctpResetStreamsHeader{}))
	sizeofSCTPAddStreamsFreeBSD    = int(unsafe.Sizeof(sctpAddStreamsFreeBSD{}))
)

func sctpOOBBufferSize() int {
	return syscall.CmsgSpace(sizeofSCTPRcvInfoFreeBSD) + syscall.CmsgSpace(sizeofSCTPNxtInfoFreeBSD)
}

func marshalSCTPSndInfo(info *SCTPSndInfo) ([]byte, error) {
	if info == nil {
		return nil, nil
	}

	buf := make([]byte, syscall.CmsgSpace(sizeofSCTPSndInfoFreeBSD))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = syscall.IPPROTO_SCTP
	h.Type = sctpCmsgTypeSndInfo
	h.SetLen(syscall.CmsgLen(sizeofSCTPSndInfoFreeBSD))

	si := sctpSndInfoFreeBSD{
		Stream:  info.Stream,
		Flags:   info.Flags,
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	copy(buf[syscall.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&si)), sizeofSCTPSndInfoFreeBSD))
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
			if len(scm.Data) < sizeofSCTPRcvInfoFreeBSD {
				return nil, errors.New("short SCTP_RCVINFO control message")
			}
			var ri sctpRcvInfoFreeBSD
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ri)), sizeofSCTPRcvInfoFreeBSD), scm.Data[:sizeofSCTPRcvInfoFreeBSD])
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
			if len(scm.Data) < sizeofSCTPNxtInfoFreeBSD {
				return nil, errors.New("short SCTP_NXTINFO control message")
			}
			var ni sctpNxtInfoFreeBSD
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ni)), sizeofSCTPNxtInfoFreeBSD), scm.Data[:sizeofSCTPNxtInfoFreeBSD])
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

func setSCTPMaxBurst(c *SCTPConn, value uint32) error {
	req := sctpAssocValueFreeBSD{
		AssocID: optionalSCTPAssocID(c),
		Value:   value,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptMaxBurst, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueFreeBSD))
}

func setSCTPMaxSeg(fd *netFD, value uint32) error {
	req := sctpAssocValueFreeBSD{AssocID: 0, Value: value}
	return setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptMaxSeg, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueFreeBSD))
}

func setSCTPRTOInfo(c *SCTPConn, info SCTPRTOInfo) error {
	if info.AssocID == 0 && c.assocID != 0 {
		info.AssocID = c.assocID
	}
	raw := sctpRTOInfoFreeBSD{
		AssocID: info.AssocID,
		Initial: info.Initial,
		Max:     info.Max,
		Min:     info.Min,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptRTOInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPRTOInfoFreeBSD))
}

func setSCTPDelayedSack(c *SCTPConn, info SCTPDelayedSackInfo) error {
	if info.AssocID == 0 && c.assocID != 0 {
		info.AssocID = c.assocID
	}
	raw := sctpDelayedSackInfoFreeBSD{
		AssocID: info.AssocID,
		Delay:   info.Delay,
		Freq:    info.Frequency,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDelayedSack, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPDelayedSackInfo))
}

func setSCTPDefaultPRInfo(c *SCTPConn, info SCTPPRInfo) error {
	if info.AssocID == 0 && c.assocID != 0 {
		info.AssocID = c.assocID
	}
	raw := sctpDefaultPRInfoFreeBSD{
		Policy:  uint16(info.Policy),
		Value:   info.Value,
		AssocID: info.AssocID,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultPRInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPDefaultPRInfoFreeBSD))
}

func setSCTPDefaultSendInfo(c *SCTPConn, info SCTPSndInfo) error {
	raw := sctpSndInfoFreeBSD{
		Stream:  info.Stream,
		Flags:   info.Flags,
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultSndInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPSndInfoFreeBSD))
}

func setSCTPAuthChunks(fd *netFD, chunks []uint8) error {
	for _, chunk := range chunks {
		raw := sctpAuthChunkFreeBSD{Chunk: chunk}
		if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptAuthChunk, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthChunkFreeBSD)); err != nil {
			return err
		}
	}
	return nil
}

func setSCTPAuthKey(c *SCTPConn, key SCTPAuthKey) error {
	if key.AssocID == 0 && c.assocID != 0 {
		key.AssocID = c.assocID
	}
	buf := make([]byte, sizeofSCTPAuthKeyHdrFreeBSD+len(key.Secret))
	hdr := (*sctpAuthKeyHeaderFreeBSD)(unsafe.Pointer(&buf[0]))
	hdr.AssocID = key.AssocID
	hdr.KeyID = key.KeyID
	hdr.KeyLength = uint16(len(key.Secret))
	copy(buf[sizeofSCTPAuthKeyHdrFreeBSD:], key.Secret)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthKey, buf)
}

func setSCTPActiveAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 && c.assocID != 0 {
		assocID = c.assocID
	}
	raw := sctpAuthKeyIDFreeBSD{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthActiveKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyIDFreeBSD))
}

func deleteSCTPAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 && c.assocID != 0 {
		assocID = c.assocID
	}
	raw := sctpAuthKeyIDFreeBSD{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthDeleteKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyIDFreeBSD))
}

func subscribeSCTPEvents(fd *netFD, mask SCTPEventMask) error {
	compat := sctpEventSubscribeFreeBSD{
		DataIO:          uint8(boolint(mask.DataIO)),
		Association:     uint8(boolint(mask.Association)),
		Address:         uint8(boolint(mask.Address)),
		SendFailure:     uint8(boolint(mask.SendFailure)),
		PeerError:       uint8(boolint(mask.PeerError)),
		Shutdown:        uint8(boolint(mask.Shutdown)),
		PartialDelivery: uint8(boolint(mask.PartialDelivery)),
		Adaptation:      uint8(boolint(mask.Adaptation)),
		Authentication:  uint8(boolint(mask.Authentication)),
		SenderDry:       uint8(boolint(mask.SenderDry)),
		StreamReset:     uint8(boolint(mask.StreamReset)),
	}
	if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptEventsCompat, unsafe.Slice((*byte)(unsafe.Pointer(&compat)), sizeofSCTPEventSubscribeCompat)); err != nil {
		return err
	}
	if mask.DataIO {
		if err := setSCTPRecvRcvInfo(fd, true); err != nil {
			return err
		}
	}
	events := []struct {
		typeID uint16
		on     bool
	}{
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

func enableSCTPStreamReset(c *SCTPConn, flags uint16) error {
	req := sctpAssocValueFreeBSD{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(flags),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptEnableStrReset, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueFreeBSD))
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
	req := sctpAddStreamsFreeBSD{AssocID: assocID, InStreams: in, OutStreams: out}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAddStreams, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAddStreamsFreeBSD))
}

func setSCTPStreamScheduler(c *SCTPConn, policy SCTPScheduler) error {
	req := sctpAssocValueFreeBSD{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(policy),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSched, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValueFreeBSD))
}

func setSCTPStreamSchedulerValue(c *SCTPConn, stream uint16, value uint16) error {
	req := sctpStreamValueFreeBSD{
		AssocID: optionalSCTPAssocID(c),
		Stream:  stream,
		Value:   value,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSchedVal, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPStreamValueFreeBSD))
}

func peelOffSCTP(c *SCTPConn, assocID int32) (*SCTPConn, error) {
	resolved, err := resolveSCTPAssocID(c, assocID)
	if err != nil {
		return nil, err
	}
	r0, _, errno := syscall.Syscall(syscall.SYS_SCTP_PEELOFF, uintptr(c.fd.pfd.Sysfd), uintptr(uint32(resolved)), 0)
	runtime.KeepAlive(c.fd)
	if errno != 0 {
		return nil, wrapSyscallError("sctp_peeloff", errno)
	}
	return wrapPeeledSCTPFD(int32(r0), c.fd.family, c.fd.net, resolved)
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
			out = append(out, SCTPAddr{IP: ip, Port: int(ntohs(sa.Port))})
		case syscall.AF_INET6:
			var sa syscall.RawSockaddrInet6
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), syscall.SizeofSockaddrInet6), data[:syscall.SizeofSockaddrInet6])
			ip := make(IP, IPv6len)
			copy(ip, sa.Addr[:])
			out = append(out, SCTPAddr{
				IP:   ip,
				Port: int(ntohs(sa.Port)),
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
				Port:   htons(uint16(sa.Port)),
				Addr:   sa.Addr,
			}
			buf = append(buf, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), syscall.SizeofSockaddrInet4)...)
		case *syscall.SockaddrInet6:
			raw := syscall.RawSockaddrInet6{
				Len:      syscall.SizeofSockaddrInet6,
				Family:   syscall.AF_INET6,
				Port:     htons(uint16(sa.Port)),
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
	if len(data) < 2 {
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
		return &SCTPAddr{IP: ip, Port: int(ntohs(sa.Port))}, nil
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
			Port: int(ntohs(sa.Port)),
			Zone: zoneCache.name(int(sa.Scope_id)),
		}, nil
	}
	return nil, nil
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
