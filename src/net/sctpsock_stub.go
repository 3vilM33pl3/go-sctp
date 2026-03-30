// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && (unix || js || wasip1 || windows)

package net

import (
	"context"
	"errors"
	"syscall"
)

var errSCTPUnsupported = errors.New("sctp is not supported on this platform")

func sockaddrToSCTP(syscall.Sockaddr) Addr { return nil }

func (a *SCTPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
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

func (c *SCTPConn) readFromSCTP([]byte) (n int, oobn int, flags int, addr *SCTPAddr, info *SCTPRcvInfo, err error) {
	return 0, 0, 0, nil, nil, errSCTPUnsupported
}

func (c *SCTPConn) writeToSCTP([]byte, *SCTPAddr, *SCTPSndInfo) (int, error) {
	return 0, errSCTPUnsupported
}

func (sd *sysDialer) dialSCTP(context.Context, *SCTPAddr, *SCTPAddr) (*SCTPConn, error) {
	return nil, errSCTPUnsupported
}

func (sl *sysListener) listenSCTP(context.Context, *SCTPAddr) (*SCTPConn, error) {
	return nil, errSCTPUnsupported
}

func sctpOOBBufferSize() int { return 0 }

func marshalSCTPSndInfo(*SCTPSndInfo) ([]byte, error) { return nil, errSCTPUnsupported }

func parseSCTPRcvInfo([]byte) (*SCTPRcvInfo, error) { return nil, errSCTPUnsupported }

func setNoDelaySCTP(*netFD, bool) error { return errSCTPUnsupported }

func setSCTPInitOptions(*netFD, SCTPInitOptions) error    { return errSCTPUnsupported }
func setSCTPInitOptionsSockFD(int, SCTPInitOptions) error { return errSCTPUnsupported }

func setSCTPRecvRcvInfo(*netFD, bool) error { return errSCTPUnsupported }

func setSCTPRecvNxtInfo(*netFD, bool) error { return errSCTPUnsupported }

func setSCTPAutoClose(*netFD, uint32) error { return errSCTPUnsupported }

func setSCTPDelayedSack(*SCTPConn, SCTPDelayedSackInfo) error { return errSCTPUnsupported }

func setSCTPRTOInfo(*SCTPConn, SCTPRTOInfo) error { return errSCTPUnsupported }

func setSCTPDefaultPRInfo(*SCTPConn, SCTPPRInfo) error { return errSCTPUnsupported }

func setSCTPDefaultSendInfo(*SCTPConn, SCTPSndInfo) error { return errSCTPUnsupported }

func setSCTPAuthChunks(*netFD, []uint8) error { return errSCTPUnsupported }

func setSCTPAuthKey(*SCTPConn, SCTPAuthKey) error { return errSCTPUnsupported }

func setSCTPActiveAuthKey(*SCTPConn, int32, uint16) error { return errSCTPUnsupported }

func deleteSCTPAuthKey(*SCTPConn, int32, uint16) error { return errSCTPUnsupported }

func setSCTPFragmentInterleave(*netFD, int) error { return errSCTPUnsupported }

func setSCTPMaxBurst(*SCTPConn, uint32) error { return errSCTPUnsupported }

func setSCTPMaxSeg(*netFD, uint32) error { return errSCTPUnsupported }

func subscribeSCTPEvents(*netFD, SCTPEventMask) error { return errSCTPUnsupported }

func bindAddrsSCTP(*netFD, []SCTPAddr) error { return errSCTPUnsupported }

func unbindAddrsSCTP(*netFD, []SCTPAddr) error { return errSCTPUnsupported }

func connectAddrsSCTP(*netFD, []SCTPAddr) (int32, error) { return 0, errSCTPUnsupported }

func localAddrsSCTP(*netFD, int32) ([]SCTPAddr, error) { return nil, errSCTPUnsupported }

func peerAddrsSCTP(*netFD, int32) ([]SCTPAddr, error) { return nil, errSCTPUnsupported }

func setSCTPPrimaryAddr(*SCTPConn, *SCTPAddr) error { return errSCTPUnsupported }

func setSCTPPeerPrimaryAddr(*SCTPConn, *SCTPAddr) error { return errSCTPUnsupported }

func peelOffSCTP(*SCTPConn, int32) (*SCTPConn, error) { return nil, errSCTPUnsupported }

func assocIDsSCTP(*netFD) ([]int32, error) { return nil, errSCTPUnsupported }

func assocStatusSCTP(*SCTPConn, int32) (*SCTPAssocStatus, error) { return nil, errSCTPUnsupported }

func enableSCTPStreamReset(*SCTPConn, uint16) error { return errSCTPUnsupported }

func resetSCTPStreams(*SCTPConn, uint16, []uint16) error { return errSCTPUnsupported }

func addSCTPStreams(*SCTPConn, uint16, uint16) error { return errSCTPUnsupported }

func setSCTPStreamScheduler(*SCTPConn, SCTPScheduler) error { return errSCTPUnsupported }

func setSCTPStreamSchedulerValue(*SCTPConn, uint16, uint16) error { return errSCTPUnsupported }
