// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (freebsd && amd64)

package net

import (
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
