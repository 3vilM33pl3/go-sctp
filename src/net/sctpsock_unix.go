// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
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
