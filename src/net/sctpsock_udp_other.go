// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !unix

package net

import (
	"context"
	"errors"
	"time"
)

// SCTP over UDP is only provided on Unix systems. These stubs keep the
// shared SCTPConn code compiling elsewhere.

type sctpUDPConn struct {
	net          string
	laddr, raddr *SCTPAddr
}

func dialSCTPUDP(context.Context, *Dialer, string, *SCTPAddr, *SCTPAddr, *SCTPInitOptions, SCTPUDPConfig) (*SCTPConn, error) {
	return nil, errSCTPUDPUnsupported
}

func listenSCTPUDP(context.Context, ListenConfig, string, *SCTPAddr, *SCTPInitOptions, SCTPUDPConfig, bool) (*SCTPConn, error) {
	return nil, errSCTPUDPUnsupported
}

func sctpNoKernelSupport(err error) bool { return errors.Is(err, errSCTPUnsupported) }
func sctpConnectFailed(error) bool       { return false }

func (*sctpUDPConn) readFrom([]byte) (int, int, int, *SCTPAddr, *SCTPRcvInfo, error) {
	return 0, 0, 0, nil, nil, errSCTPUDPUnsupported
}
func (*sctpUDPConn) writeTo([]byte, *SCTPAddr, *SCTPSndInfo) (int, error) {
	return 0, errSCTPUDPUnsupported
}
func (*sctpUDPConn) close() error                                { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setDeadline(time.Time, bool, bool)           {}
func (*sctpUDPConn) setBuffers(int, int) error                   { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setNoDelay(bool) error                       { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setInit(SCTPInitOptions) error               { return errSCTPUDPUnsupported }
func (*sctpUDPConn) subscribe(SCTPEventMask) error               { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setRTO(SCTPRTOInfo) error                    { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setDelayedSack(SCTPDelayedSackInfo) error    { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setDefaultPR(SCTPPRInfo) error               { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setDefaultSend(SCTPSndInfo) error            { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setRecvRcvInfo(bool) error                   { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setRecvNxtInfo(bool) error                   { return errSCTPUDPUnsupported }
func (*sctpUDPConn) setScheduler(SCTPScheduler) error            { return errSCTPUDPUnsupported }
func (*sctpUDPConn) assocIDs() []int32                           { return nil }
func (*sctpUDPConn) assocStatus(int32) (*SCTPAssocStatus, error) { return nil, errSCTPUDPUnsupported }
func (*sctpUDPConn) defaultAssocID() int32                       { return 0 }
func (*sctpUDPConn) resetStreams(int32, uint16, []uint16) error  { return errSCTPUDPUnsupported }
func (*sctpUDPConn) addStreams(int32, uint16, uint16) error      { return errSCTPUDPUnsupported }
