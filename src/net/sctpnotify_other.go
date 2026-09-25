// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !freebsd

package net

// SCTPMsgNotification is the recvmsg flag, in the flags word returned by
// [SCTPConn.ReadFromSCTP], marking a message as an SCTP notification rather
// than user data. It is 0 on platforms without SCTP support.
const SCTPMsgNotification = 0
