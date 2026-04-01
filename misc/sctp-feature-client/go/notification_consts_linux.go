//go:build linux

package main

const (
	msgNotification               = 0x8000
	sctpNotificationAssocChange   = 0x8001
	sctpNotificationPeerAddr      = 0x8002
	sctpNotificationSendFailed    = 0x8003
	sctpNotificationShutdown      = 0x8005
	sctpNotificationPartialDeliv  = 0x8006
	sctpNotificationAdaptation    = 0x8007
	sctpNotificationAuth          = 0x8008
	sctpNotificationSenderDry     = 0x8009
	sctpNotificationStreamReset   = 0x800a
	sctpNotificationAssocReset    = 0x800b
	sctpNotificationStreamChange  = 0x800c
	sctpNotificationSendFailedEvt = 0x800d
)
