// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build plan9

package net

import (
	"context"
	"errors"
)

var errSCTPUnsupported = errors.New("sctp is not supported on this platform")

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

func setSCTPInitOptions(*netFD, SCTPInitOptions) error { return errSCTPUnsupported }

func subscribeSCTPEvents(*netFD, SCTPEventMask) error { return errSCTPUnsupported }

func bindAddrsSCTP(*netFD, []SCTPAddr) error { return errSCTPUnsupported }

func connectAddrsSCTP(*netFD, []SCTPAddr) error { return errSCTPUnsupported }

func localAddrsSCTP(*netFD, int32) ([]SCTPAddr, error) { return nil, errSCTPUnsupported }

func peerAddrsSCTP(*netFD, int32) ([]SCTPAddr, error) { return nil, errSCTPUnsupported }
