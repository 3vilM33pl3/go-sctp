// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Socket option plumbing shared by the Linux and FreeBSD SCTP backends.
//
// poll.FD only wraps the integer-valued socket options, so the SCTP options
// that carry structs or variable-length address lists go through raw
// setsockopt/getsockopt calls. Those run inside fd.pfd.RawControl, which
// holds a reference on the descriptor for the duration of the call; a
// concurrent Close therefore cannot recycle the descriptor number underneath
// the syscall, and a closed connection reports ErrNetClosing like every
// other operation on it.

// rawSockopt runs f against the socket descriptor while poll.FD holds a
// reference on it. f returns the errno of the raw syscall it made.
func rawSockopt(fd *netFD, f func(s uintptr) syscall.Errno) error {
	var errno syscall.Errno
	if err := fd.pfd.RawControl(func(s uintptr) { errno = f(s) }); err != nil {
		return err
	}
	runtime.KeepAlive(fd)
	if errno != 0 {
		return errno
	}
	return nil
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
	err := rawSockopt(fd, func(s uintptr) syscall.Errno {
		_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, s, uintptr(level), uintptr(name), uintptr(ptr), uintptr(len(value)), 0)
		return errno
	})
	return wrapSyscallError("setsockopt", err)
}

// getSockoptBytes fills value and returns the length the kernel reported.
func getSockoptBytes(fd *netFD, level, name int, value []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	size := uint32(len(value))
	err := rawSockopt(fd, func(s uintptr) syscall.Errno {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, s, uintptr(level), uintptr(name), uintptr(ptr), uintptr(unsafe.Pointer(&size)), 0)
		return errno
	})
	if err != nil {
		return 0, wrapSyscallError("getsockopt", err)
	}
	return int(size), nil
}

// setSCTPInitOptionsSockFD applies SCTP_INITMSG and enables SCTP_RECVRCVINFO
// on a bare descriptor. It is called from a Dialer.ControlContext callback,
// where the caller already holds the descriptor reference.
func setSCTPInitOptionsSockFD(sysfd int, opts SCTPInitOptions) error {
	sim := sctpInitMsg{
		NumOStreams:    opts.NumOStreams,
		MaxInStreams:   opts.MaxInStreams,
		MaxAttempts:    opts.MaxAttempts,
		MaxInitTimeout: opts.MaxInitTimeout,
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sysfd), uintptr(syscall.IPPROTO_SCTP), uintptr(sctpSockoptInitMsg), uintptr(unsafe.Pointer(&sim)), unsafe.Sizeof(sim), 0); errno != 0 {
		return wrapSyscallError("setsockopt", errno)
	}
	// Both kernels read this option as a C int.
	var one int32 = 1
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sysfd), uintptr(syscall.IPPROTO_SCTP), uintptr(sctpSockoptRecvRcvInfo), uintptr(unsafe.Pointer(&one)), unsafe.Sizeof(one), 0); errno != 0 {
		return wrapSyscallError("setsockopt", errno)
	}
	return nil
}

// wrapPeeledSCTPFD turns a descriptor returned by the platform peel-off
// primitive into a connected SCTPConn on the netpoller.
func wrapPeeledSCTPFD(sysfd int, family int, net string, assocID int32) (*SCTPConn, error) {
	// The netpoller requires a non-blocking descriptor. Setting the flag on
	// one that already has it is harmless, so every peel-off path funnels
	// through here rather than trusting what the kernel handed back.
	if err := syscall.SetNonblock(sysfd, true); err != nil {
		syscall.Close(sysfd)
		return nil, wrapSyscallError("setnonblock", err)
	}
	sotype, err := syscall.GetsockoptInt(sysfd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		syscall.Close(sysfd)
		return nil, wrapSyscallError("getsockopt", err)
	}
	fd := newFD(sysfd, family, sotype, net)
	if err := fd.init(); err != nil {
		fd.Close()
		return nil, err
	}
	fd.isConnected = true
	lsa, err := syscall.Getsockname(fd.pfd.Sysfd)
	if err != nil {
		fd.Close()
		return nil, wrapSyscallError("getsockname", err)
	}
	rsa, err := syscall.Getpeername(fd.pfd.Sysfd)
	if err != nil {
		fd.Close()
		return nil, wrapSyscallError("getpeername", err)
	}
	fd.setAddr(fd.addrFunc()(lsa), fd.addrFunc()(rsa))
	conn := newSCTPConn(fd)
	conn.assocID.Store(assocID)
	if la, ok := conn.LocalAddr().(*SCTPAddr); ok && la != nil {
		conn.setLocalAddrs([]SCTPAddr{*la})
	}
	if ra, ok := conn.RemoteAddr().(*SCTPAddr); ok && ra != nil {
		conn.setPeerAddrs([]SCTPAddr{*ra})
	}
	return conn, nil
}

// sizeofSCTPSndRcvInfo is struct sctp_sndrcvinfo, the deprecated ancillary
// data a peer-configured or legacy application may still switch on.
const sizeofSCTPSndRcvInfo = 32

// sctpOOBBufferSize is the receive control buffer: room for SCTP_RCVINFO,
// SCTP_NXTINFO and the legacy SCTP_SNDRCV cmsg, so that nothing this package
// or a raw setsockopt can enable leads to MSG_CTRUNC.
func sctpOOBBufferSize() int {
	return syscall.CmsgSpace(sizeofSCTPRcvInfo) + syscall.CmsgSpace(sizeofSCTPNxtInfo) + syscall.CmsgSpace(sizeofSCTPSndRcvInfo)
}

// rawPort converts port to the in-memory layout of sin_port/sin6_port,
// which is network byte order regardless of the host's own. A plain
// 16-bit swap only happens to work on little-endian machines.
func rawPort(port int) uint16 {
	var p [2]byte
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return *(*uint16)(unsafe.Pointer(&p[0]))
}

// portFromRaw is the inverse of rawPort.
func portFromRaw(raw uint16) int {
	p := (*[2]byte)(unsafe.Pointer(&raw))
	return int(p[0])<<8 | int(p[1])
}

// resolveSCTPAssocID picks the association an option call applies to: the
// caller's explicit id, otherwise the socket's single association.
//
// One-to-one sockets (dialed connections) carry exactly one association and
// both kernels ignore the id for them, so the cached value, possibly 0, is
// returned as is. Linux also rejects SCTP_GET_ASSOC_ID_LIST on them with
// EOPNOTSUPP, so listing is only attempted on one-to-many sockets.
func resolveSCTPAssocID(c *SCTPConn, assocID int32) (int32, error) {
	if assocID != 0 {
		return assocID, nil
	}
	if c.fd.sotype == syscall.SOCK_STREAM {
		return c.assocID.Load(), nil
	}
	ids, err := assocIDsSCTP(c.fd)
	if err == nil && len(ids) == 1 {
		c.assocID.Store(ids[0])
		return ids[0], nil
	}
	if id := c.assocID.Load(); id != 0 {
		return id, nil
	}
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, errors.New("sctp association id is not available yet")
	}
	return 0, errors.New("multiple SCTP associations are present; specify an association id explicitly")
}

// optionalSCTPAssocID is resolveSCTPAssocID for options where 0 is an
// acceptable answer (the kernel then applies the endpoint default).
func optionalSCTPAssocID(c *SCTPConn) int32 {
	if id := c.assocID.Load(); id != 0 {
		return id
	}
	if c.fd.sotype == syscall.SOCK_STREAM {
		return 0
	}
	ids, err := assocIDsSCTP(c.fd)
	if err == nil && len(ids) == 1 {
		c.assocID.Store(ids[0])
		return ids[0]
	}
	return 0
}

// sctpEvent is struct sctp_event, the SCTP_EVENT argument on both kernels.
type sctpEvent struct {
	AssocID int32
	Type    uint16
	On      uint8
	_       uint8
}

const sizeofSCTPEvent = int(unsafe.Sizeof(sctpEvent{}))

// subscribeSCTPEvents applies mask through SCTP_EVENT, one call per event
// type. The deprecated SCTP_EVENTS bitmap is not used: on Linux it (and the
// SCTP_DATA_IO_EVENT type) would also enable the legacy sctp_sndrcvinfo
// ancillary data, whose extra cmsg does not fit the receive buffer sized
// for SCTPRcvInfo, and on FreeBSD its send-failure bit selects the legacy
// SCTP_SEND_FAILED notification instead of SCTP_SEND_FAILED_EVENT.
func subscribeSCTPEvents(fd *netFD, mask SCTPEventMask) error {
	if mask.DataIO {
		if err := setSCTPRecvRcvInfo(fd, true); err != nil {
			return err
		}
	}
	events := []struct {
		typeID uint16
		on     bool
	}{
		{sctpEventAssociation, mask.Association},
		{sctpEventAddress, mask.Address},
		{sctpEventSendFailure, mask.SendFailure},
		{sctpEventPeerError, mask.PeerError},
		{sctpEventShutdown, mask.Shutdown},
		{sctpEventPartialDelivery, mask.PartialDelivery},
		{sctpEventAdaptation, mask.Adaptation},
		{sctpEventAuthentication, mask.Authentication},
		{sctpEventSenderDry, mask.SenderDry},
		{sctpEventStreamReset, mask.StreamReset},
		{sctpEventAssocReset, mask.AssocReset},
		{sctpEventStreamChange, mask.StreamChange},
	}
	for _, evt := range events {
		e := sctpEvent{Type: evt.typeID, On: uint8(boolint(evt.on))}
		if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptEvent, unsafe.Slice((*byte)(unsafe.Pointer(&e)), sizeofSCTPEvent)); err != nil {
			return err
		}
	}
	return nil
}

// completeSCTPConnectx blocks until the association initiated by connectx
// is established or has failed, the way netFD.connect completes a
// non-blocking connect(2): wait for the socket to become writable, then read
// the pending socket error. The kernel sends the INIT to the first address
// and moves to the others only on timeout; a peer that answers with an
// ABORT (a reachable address with no endpoint, say) fails the whole attempt,
// which is reported here rather than on the first write.
//
// On success the socket is marked connected: writes must then not name a
// destination, so the kernel's path management chooses among the confirmed
// paths, and WriteTo with an address reports ErrWriteToConnected like any
// connected socket.
func completeSCTPConnectx(ctx context.Context, fd *netFD) error {
	if deadline, ok := ctx.Deadline(); ok {
		fd.pfd.SetWriteDeadline(deadline)
		defer fd.pfd.SetWriteDeadline(noDeadline)
	}
	for {
		if err := fd.pfd.WaitWrite(); err != nil {
			return err
		}
		var nerr int
		err := rawSockopt(fd, func(s uintptr) syscall.Errno {
			var errno syscall.Errno
			nerr, errno = getsockoptIntSysfd(int(s), syscall.SOL_SOCKET, syscall.SO_ERROR)
			return errno
		})
		if err != nil {
			return wrapSyscallError("getsockopt", err)
		}
		switch errno := syscall.Errno(nerr); errno {
		case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
			continue
		case 0, syscall.EISCONN:
			fd.isConnected = true
			// The kernel picked the local address and port during the
			// connect when the caller gave none; report what it chose.
			if lsa, err := syscall.Getsockname(fd.pfd.Sysfd); err == nil {
				fd.laddr = fd.addrFunc()(lsa)
			}
			return nil
		default:
			return wrapSyscallError("connectx", errno)
		}
	}
}

func getsockoptIntSysfd(s, level, name int) (int, syscall.Errno) {
	v, err := syscall.GetsockoptInt(s, level, name)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}
	return v, 0
}

type sctpInitMsg struct {
	NumOStreams    uint16
	MaxInStreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

type sctpSndInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

type sctpRcvInfo struct {
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

type sctpNxtInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Length  uint32
	AssocID int32
}

type sctpRTOInfo struct {
	AssocID int32
	Initial uint32
	Max     uint32
	Min     uint32
}

type sctpDelayedSackInfo struct {
	AssocID int32
	Delay   uint32
	Freq    uint32
}

type sctpAuthChunk struct {
	Chunk uint8
}

type sctpAuthKeyHeader struct {
	AssocID   int32
	KeyID     uint16
	KeyLength uint16
}

type sctpAssocValue struct {
	AssocID int32
	Value   uint32
}

type sctpStreamValue struct {
	AssocID int32
	Stream  uint16
	Value   uint16
}

type sctpAssocIDsHeader struct {
	Count uint32
}

type sctpResetStreamsHeader struct {
	AssocID       int32
	Flags         uint16
	NumberStreams uint16
}

type sctpAddStreams struct {
	AssocID    int32
	InStreams  uint16
	OutStreams uint16
}

func marshalSCTPSndInfo(info *SCTPSndInfo) ([]byte, error) {
	if info == nil {
		return nil, nil
	}

	buf := make([]byte, syscall.CmsgSpace(sizeofSCTPSndInfo))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = syscall.IPPROTO_SCTP
	h.Type = sctpCmsgTypeSndInfo
	h.SetLen(syscall.CmsgLen(sizeofSCTPSndInfo))

	si := sctpSndInfo{
		Stream:  info.Stream,
		Flags:   sctpSndFlagsToKernel(info.Flags),
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	copy(buf[syscall.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&si)), sizeofSCTPSndInfo))
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
			if len(scm.Data) < sizeofSCTPRcvInfo {
				return nil, errors.New("short SCTP_RCVINFO control message")
			}
			var ri sctpRcvInfo
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ri)), sizeofSCTPRcvInfo), scm.Data[:sizeofSCTPRcvInfo])
			info = &SCTPRcvInfo{
				Stream:  ri.Stream,
				SSN:     ri.SSN,
				Flags:   sctpRcvFlagsFromKernel(ri.Flags),
				PPID:    ri.PPID,
				TSN:     ri.TSN,
				CumTSN:  ri.CumTSN,
				Context: ri.Context,
				AssocID: ri.AssocID,
			}
		case sctpCmsgTypeNxtInfo:
			if len(scm.Data) < sizeofSCTPNxtInfo {
				return nil, errors.New("short SCTP_NXTINFO control message")
			}
			var ni sctpNxtInfo
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ni)), sizeofSCTPNxtInfo), scm.Data[:sizeofSCTPNxtInfo])
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
	req := sctpAssocValue{
		AssocID: optionalSCTPAssocID(c),
		Value:   value,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptMaxBurst, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValue))
}

func setSCTPRTOInfo(c *SCTPConn, info SCTPRTOInfo) error {
	if info.AssocID == 0 {
		info.AssocID = c.assocID.Load()
	}
	raw := sctpRTOInfo{
		AssocID: info.AssocID,
		Initial: info.Initial,
		Max:     info.Max,
		Min:     info.Min,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptRTOInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPRTOInfo))
}

func setSCTPDelayedSack(c *SCTPConn, info SCTPDelayedSackInfo) error {
	if info.AssocID == 0 {
		info.AssocID = c.assocID.Load()
	}
	raw := sctpDelayedSackInfo{
		AssocID: info.AssocID,
		Delay:   info.Delay,
		Freq:    info.Frequency,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDelayedSack, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPDelayedSackInfo))
}

func setSCTPDefaultSendInfo(c *SCTPConn, info SCTPSndInfo) error {
	raw := sctpSndInfo{
		Stream:  info.Stream,
		Flags:   sctpSndFlagsToKernel(info.Flags),
		PPID:    info.PPID,
		Context: info.Context,
		AssocID: info.AssocID,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptDefaultSndInfo, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPSndInfo))
}

func setSCTPAuthChunks(fd *netFD, chunks []uint8) error {
	for _, chunk := range chunks {
		raw := sctpAuthChunk{Chunk: chunk}
		if err := setSockoptBytes(fd, syscall.IPPROTO_SCTP, sctpSockoptAuthChunk, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthChunk)); err != nil {
			return err
		}
	}
	return nil
}

func setSCTPAuthKey(c *SCTPConn, key SCTPAuthKey) error {
	if key.AssocID == 0 {
		key.AssocID = c.assocID.Load()
	}
	buf := make([]byte, sizeofSCTPAuthKeyHdr+len(key.Secret))
	hdr := (*sctpAuthKeyHeader)(unsafe.Pointer(&buf[0]))
	hdr.AssocID = key.AssocID
	hdr.KeyID = key.KeyID
	hdr.KeyLength = uint16(len(key.Secret))
	copy(buf[sizeofSCTPAuthKeyHdr:], key.Secret)
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthKey, buf)
}

func setSCTPActiveAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 {
		assocID = c.assocID.Load()
	}
	raw := sctpAuthKeyID{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthActiveKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyID))
}

func deleteSCTPAuthKey(c *SCTPConn, assocID int32, keyID uint16) error {
	if assocID == 0 {
		assocID = c.assocID.Load()
	}
	raw := sctpAuthKeyID{AssocID: assocID, KeyID: keyID}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAuthDeleteKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofSCTPAuthKeyID))
}

func enableSCTPStreamReset(c *SCTPConn, flags uint16) error {
	req := sctpAssocValue{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(flags),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptEnableStrReset, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValue))
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
	req := sctpAddStreams{AssocID: assocID, InStreams: in, OutStreams: out}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptAddStreams, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAddStreams))
}

func setSCTPStreamScheduler(c *SCTPConn, policy SCTPScheduler) error {
	req := sctpAssocValue{
		AssocID: optionalSCTPAssocID(c),
		Value:   uint32(policy),
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSched, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPAssocValue))
}

func setSCTPStreamSchedulerValue(c *SCTPConn, stream uint16, value uint16) error {
	req := sctpStreamValue{
		AssocID: optionalSCTPAssocID(c),
		Stream:  stream,
		Value:   value,
	}
	return setSockoptBytes(c.fd, syscall.IPPROTO_SCTP, sctpSockoptStreamSchedVal, unsafe.Slice((*byte)(unsafe.Pointer(&req)), sizeofSCTPStreamValue))
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

// sctpAuthKeyID is struct sctp_authkeyid on both kernels: the association
// id, the key number and two bytes of padding.
type sctpAuthKeyID struct {
	AssocID int32
	KeyID   uint16
	_       uint16
}

const (
	sizeofSCTPAuthKeyID       = int(unsafe.Sizeof(sctpAuthKeyID{}))
	sizeofSCTPAddStreams      = int(unsafe.Sizeof(sctpAddStreams{}))
	sizeofSCTPAssocIDsHeader  = int(unsafe.Sizeof(sctpAssocIDsHeader{}))
	sizeofSCTPAssocValue      = int(unsafe.Sizeof(sctpAssocValue{}))
	sizeofSCTPAuthChunk       = int(unsafe.Sizeof(sctpAuthChunk{}))
	sizeofSCTPAuthKeyHdr      = int(unsafe.Sizeof(sctpAuthKeyHeader{}))
	sizeofSCTPDelayedSackInfo = int(unsafe.Sizeof(sctpDelayedSackInfo{}))
	sizeofSCTPInitMsg         = int(unsafe.Sizeof(sctpInitMsg{}))
	sizeofSCTPNxtInfo         = int(unsafe.Sizeof(sctpNxtInfo{}))
	sizeofSCTPRTOInfo         = int(unsafe.Sizeof(sctpRTOInfo{}))
	sizeofSCTPRcvInfo         = int(unsafe.Sizeof(sctpRcvInfo{}))
	sizeofSCTPResetStreamsHdr = int(unsafe.Sizeof(sctpResetStreamsHeader{}))
	sizeofSCTPSndInfo         = int(unsafe.Sizeof(sctpSndInfo{}))
	sizeofSCTPStreamValue     = int(unsafe.Sizeof(sctpStreamValue{}))
)
