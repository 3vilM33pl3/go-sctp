// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"internal/byteorder"
	"internal/goarch"
	"internal/strconv"
)

// SCTPNotificationType identifies the kind of an [SCTPNotification]. The
// values are portable; the kernels number notifications differently.
type SCTPNotificationType uint16

const (
	SCTPNotifyAssocChange     SCTPNotificationType = iota + 1 // SCTP_ASSOC_CHANGE
	SCTPNotifyPeerAddrChange                                  // SCTP_PEER_ADDR_CHANGE
	SCTPNotifyRemoteError                                     // SCTP_REMOTE_ERROR
	SCTPNotifySendFailed                                      // SCTP_SEND_FAILED_EVENT
	SCTPNotifyShutdown                                        // SCTP_SHUTDOWN_EVENT
	SCTPNotifyAdaptation                                      // SCTP_ADAPTATION_INDICATION
	SCTPNotifyPartialDelivery                                 // SCTP_PARTIAL_DELIVERY_EVENT
	SCTPNotifyAuthentication                                  // SCTP_AUTHENTICATION_EVENT
	SCTPNotifyStreamReset                                     // SCTP_STREAM_RESET_EVENT
	SCTPNotifySenderDry                                       // SCTP_SENDER_DRY_EVENT
	SCTPNotifyAssocReset                                      // SCTP_ASSOC_RESET_EVENT
	SCTPNotifyStreamChange                                    // SCTP_STREAM_CHANGE_EVENT
)

var sctpNotificationTypeNames = [...]string{
	SCTPNotifyAssocChange:     "assoc change",
	SCTPNotifyPeerAddrChange:  "peer addr change",
	SCTPNotifyRemoteError:     "remote error",
	SCTPNotifySendFailed:      "send failed",
	SCTPNotifyShutdown:        "shutdown",
	SCTPNotifyAdaptation:      "adaptation",
	SCTPNotifyPartialDelivery: "partial delivery",
	SCTPNotifyAuthentication:  "authentication",
	SCTPNotifyStreamReset:     "stream reset",
	SCTPNotifySenderDry:       "sender dry",
	SCTPNotifyAssocReset:      "assoc reset",
	SCTPNotifyStreamChange:    "stream change",
}

func (t SCTPNotificationType) String() string {
	if int(t) < len(sctpNotificationTypeNames) && sctpNotificationTypeNames[t] != "" {
		return sctpNotificationTypeNames[t]
	}
	return "unknown(" + strconv.Itoa(int(t)) + ")"
}

// SCTPAssocState is the state reported by an SCTP_ASSOC_CHANGE notification.
type SCTPAssocState uint16

const (
	SCTPCommUp         SCTPAssocState = iota + 1 // a new association is ready
	SCTPCommLost                                 // the association failed
	SCTPRestart                                  // the peer restarted
	SCTPShutdownComp                             // the association shut down gracefully
	SCTPCantStartAssoc                           // the association could not be established
)

// SCTPPeerAddrState is the state reported by an SCTP_PEER_ADDR_CHANGE
// notification.
type SCTPPeerAddrState uint32

const (
	SCTPAddrAvailable         SCTPPeerAddrState = iota + 1 // the address is reachable again
	SCTPAddrUnreachable                                    // the address can no longer be reached
	SCTPAddrRemoved                                        // the peer removed the address
	SCTPAddrAdded                                          // the peer added the address
	SCTPAddrMadePrimary                                    // the address became the primary destination
	SCTPAddrConfirmed                                      // the address was confirmed
	SCTPAddrPotentiallyFailed                              // the address may have failed (Linux only)
)

// SCTPAssocChange is the body of an [SCTPNotifyAssocChange] notification.
type SCTPAssocChange struct {
	State           SCTPAssocState
	Error           uint16 // protocol error cause, when State is SCTPCommLost or SCTPCantStartAssoc
	OutboundStreams uint16
	InboundStreams  uint16
	Info            []byte // ABORT chunk contents or supported-feature list, if any
}

// SCTPPeerAddrChange is the body of an [SCTPNotifyPeerAddrChange] notification.
type SCTPPeerAddrChange struct {
	Addr  SCTPAddr
	State SCTPPeerAddrState
	Error uint32
}

// SCTPRemoteError is the body of an [SCTPNotifyRemoteError] notification.
type SCTPRemoteError struct {
	Error uint16 // the peer's error cause code
	Data  []byte // the error cause parameters, as sent by the peer
}

// SCTPSendFailed is the body of an [SCTPNotifySendFailed] notification.
type SCTPSendFailed struct {
	Sent  bool        // the data had been put on the wire (SCTP_DATA_SENT) rather than never sent
	Error uint32      // the reason the send failed
	Info  SCTPSndInfo // the metadata the message was sent with
	Data  []byte      // the undelivered payload, as much as the kernel retained
}

// SCTPStreamReset is the body of an [SCTPNotifyStreamReset] notification.
type SCTPStreamReset struct {
	Flags   uint16   // SCTPStreamResetIncoming, SCTPStreamResetOutgoing, SCTPStreamResetDenied, SCTPStreamResetFailed
	Streams []uint16 // the affected stream identifiers; empty means all streams
}

// SCTPNotification is a decoded SCTP notification (RFC 6458, section 6).
// Notifications are read with [SCTPConn.ReadFromSCTP] on a socket that
// subscribed to them with [SCTPConn.SubscribeEvents]; the read's flags word
// has [SCTPMsgNotification] set and the payload decodes with
// [ParseSCTPNotification].
type SCTPNotification struct {
	Type    SCTPNotificationType
	Flags   uint16 // the notification's own flags field, as the kernel reports it
	AssocID int32

	// The field matching Type is set; the others are nil.
	AssocChange    *SCTPAssocChange
	PeerAddrChange *SCTPPeerAddrChange
	RemoteError    *SCTPRemoteError
	SendFailed     *SCTPSendFailed
	StreamReset    *SCTPStreamReset

	// Raw is the complete notification as the kernel delivered it, for
	// types without a decoded body. It aliases the buffer passed to
	// ParseSCTPNotification.
	Raw []byte
}

var errShortSCTPNotification = errors.New("short SCTP notification")

// ParseSCTPNotification decodes the notification in b, the payload of a
// [SCTPConn.ReadFromSCTP] whose flags include [SCTPMsgNotification].
func ParseSCTPNotification(b []byte) (*SCTPNotification, error) {
	if !sctpNotificationsSupported {
		return nil, errSCTPUnsupported
	}
	// Every notification starts with the sctp_tlv header:
	// uint16 type, uint16 flags, uint32 length (including the header).
	if len(b) < 8 {
		return nil, errShortSCTPNotification
	}
	length := int(hostUint32(b[4:]))
	if length < 8 || length > len(b) {
		return nil, errors.New("SCTP notification length out of range")
	}
	b = b[:length]
	n := &SCTPNotification{
		Type:  sctpNotificationType(hostUint16(b[0:])),
		Flags: hostUint16(b[2:]),
		Raw:   b,
	}
	need := func(size int) error {
		if len(b) < size {
			return errShortSCTPNotification
		}
		return nil
	}
	switch n.Type {
	case SCTPNotifyAssocChange:
		// state@8 error@10 outbound@12 inbound@14 assoc@16 info@20
		if err := need(20); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[16:]))
		n.AssocChange = &SCTPAssocChange{
			State:           sctpAssocState(hostUint16(b[8:])),
			Error:           hostUint16(b[10:]),
			OutboundStreams: hostUint16(b[12:]),
			InboundStreams:  hostUint16(b[14:]),
			Info:            b[20:],
		}
	case SCTPNotifyPeerAddrChange:
		// sockaddr_storage@8 state@136 error@140 assoc@144
		if err := need(148); err != nil {
			return nil, err
		}
		addr, err := parseSockaddrStorage(b[8:136])
		if err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[144:]))
		n.PeerAddrChange = &SCTPPeerAddrChange{
			State: sctpPeerAddrState(hostUint32(b[136:])),
			Error: hostUint32(b[140:]),
		}
		if addr != nil {
			n.PeerAddrChange.Addr = *addr
		}
	case SCTPNotifyRemoteError:
		// error@8 (network byte order, RFC 6458 6.1.3) assoc@12 data@16
		if err := need(16); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[12:]))
		n.RemoteError = &SCTPRemoteError{Error: byteorder.BEUint16(b[8:]), Data: b[16:]}
	case SCTPNotifySendFailed:
		// error@8 sctp_sndinfo@12 assoc@28 data@32
		if err := need(32); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[28:]))
		n.SendFailed = &SCTPSendFailed{
			Sent:  sctpSendFailedSent(n.Flags),
			Error: hostUint32(b[8:]),
			Info: SCTPSndInfo{
				Stream:  hostUint16(b[12:]),
				Flags:   hostUint16(b[14:]),
				PPID:    hostUint32(b[16:]),
				Context: hostUint32(b[20:]),
				AssocID: int32(hostUint32(b[24:])),
			},
			Data: b[32:],
		}
	case SCTPNotifyStreamReset:
		// assoc@8 stream list@12
		if err := need(12); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[8:]))
		streams := make([]uint16, 0, (len(b)-12)/2)
		for off := 12; off+2 <= len(b); off += 2 {
			streams = append(streams, hostUint16(b[off:]))
		}
		n.StreamReset = &SCTPStreamReset{Flags: n.Flags, Streams: streams}
	case SCTPNotifyShutdown, SCTPNotifySenderDry, SCTPNotifyAssocReset, SCTPNotifyStreamChange:
		// assoc@8 on all four.
		if err := need(12); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[8:]))
	case SCTPNotifyAdaptation:
		// indication@8 assoc@12
		if err := need(16); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[12:]))
	case SCTPNotifyAuthentication:
		// keynumber@8 altkeynumber@10 indication@12 assoc@16
		if err := need(20); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[16:]))
	case SCTPNotifyPartialDelivery:
		// The kernels lay this one out differently.
		if err := need(sctpPDAPIAssocIDOffset + 4); err != nil {
			return nil, err
		}
		n.AssocID = int32(hostUint32(b[sctpPDAPIAssocIDOffset:]))
	}
	return n, nil
}

// hostUint16 and hostUint32 read kernel structures, which are in host byte
// order, without assuming alignment.
func hostUint16(b []byte) uint16 {
	if goarch.BigEndian {
		return byteorder.BEUint16(b)
	}
	return byteorder.LEUint16(b)
}

func hostUint32(b []byte) uint32 {
	if goarch.BigEndian {
		return byteorder.BEUint32(b)
	}
	return byteorder.LEUint32(b)
}
