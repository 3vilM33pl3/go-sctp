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

const (
	sizeofSCTPInitMsg      = int(unsafe.Sizeof(sctpInitMsg{}))
	sizeofSCTPSndInfoLinux = int(unsafe.Sizeof(sctpSndInfoLinux{}))
	sizeofSCTPRcvInfoLinux = int(unsafe.Sizeof(sctpRcvInfoLinux{}))
	sizeofSCTPEvent        = int(unsafe.Sizeof(sctpEvent{}))
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
