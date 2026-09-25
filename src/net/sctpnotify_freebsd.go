// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd

package net

// SCTPMsgNotification is the recvmsg flag, in the flags word returned by
// [SCTPConn.ReadFromSCTP], marking a message as an SCTP notification rather
// than user data. It is the platform's MSG_NOTIFICATION.
const SCTPMsgNotification = 0x2000
