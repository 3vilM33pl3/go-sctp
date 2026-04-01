//go:build freebsd

package main

const (
	msgNotification               = 0x2000
	sctpNotificationAssocChange   = 0x0001
	sctpNotificationPeerAddr      = 0x0002
	sctpNotificationSendFailed    = 0x0003
	sctpNotificationShutdown      = 0x0005
	sctpNotificationPartialDeliv  = 0x0007
	sctpNotificationAdaptation    = 0x0006
	sctpNotificationAuth          = 0x0008
	sctpNotificationSenderDry     = 0x000a
	sctpNotificationStreamReset   = 0x0009
	sctpNotificationAssocReset    = 0x000b
	sctpNotificationStreamChange  = 0x000c
	sctpNotificationSendFailedEvt = 0x000e
)
