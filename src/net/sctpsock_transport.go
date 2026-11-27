// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"internal/godebug"
	"io"
	"os"
	"time"
)

// SCTPTransportPolicy selects how SCTP traffic is carried.
//
// By default SCTP uses the operating system's SCTP stack when it has one
// and otherwise carries SCTP over UDP (RFC 6951) through a user-space
// engine in this package. The UDP transport is single-homed, has no
// encryption or authentication, and does not support every socket
// option; unsupported calls return an error matching
// [errors.ErrUnsupported].
//
// The GODEBUG setting sctptransport overrides the default policy for
// calls that do not pass one: sctptransport=native uses only the kernel,
// sctptransport=udp always uses UDP, and sctptransport=preferred (the
// default) uses the kernel when present.
type SCTPTransportPolicy int

const (
	// SCTPTransportDefault uses the GODEBUG sctptransport setting, which
	// defaults to SCTPNativePreferred.
	SCTPTransportDefault SCTPTransportPolicy = iota

	// SCTPNativePreferred uses kernel SCTP and switches to UDP
	// encapsulation when the host has no kernel SCTP.
	SCTPNativePreferred

	// SCTPNativeOnly uses kernel SCTP only.
	SCTPNativeOnly

	// SCTPNativePreferredWithConnectFallback is like SCTPNativePreferred,
	// and when dialing also retries over UDP if the native association
	// attempt is refused or times out, for peers that only listen over UDP.
	SCTPNativePreferredWithConnectFallback

	// SCTPUDPOnly always carries SCTP over UDP.
	SCTPUDPOnly
)

// SCTPUDPConfig configures UDP encapsulation.
type SCTPUDPConfig struct {
	// LocalEncapPort is the local UDP port. Zero uses the local SCTP port.
	LocalEncapPort uint16

	// RemoteEncapPort is the peer's UDP port. Zero uses the peer's SCTP
	// port. Replies follow the port the peer actually sends from.
	RemoteEncapPort uint16
}

// SCTPTransportConfig configures transport selection for
// [DialSCTPConfig] and [ListenSCTPConfig].
type SCTPTransportConfig struct {
	Policy SCTPTransportPolicy
	UDP    SCTPUDPConfig
}

// SCTPTransport reports how an [SCTPConn] carries SCTP.
type SCTPTransport int

const (
	// SCTPTransportNative is the operating system's SCTP stack.
	SCTPTransportNative SCTPTransport = iota

	// SCTPTransportUDP is SCTP over UDP (RFC 6951).
	SCTPTransportUDP
)

func (t SCTPTransport) String() string {
	switch t {
	case SCTPTransportNative:
		return "native"
	case SCTPTransportUDP:
		return "udp"
	}
	return "unknown"
}

// Transport reports whether the connection uses kernel SCTP or SCTP over UDP.
func (c *SCTPConn) Transport() SCTPTransport {
	if c != nil && c.udp != nil {
		return SCTPTransportUDP
	}
	return SCTPTransportNative
}

var sctptransport = godebug.New("sctptransport")

func (t SCTPTransportConfig) policy() SCTPTransportPolicy {
	if t.Policy != SCTPTransportDefault {
		return t.Policy
	}
	switch sctptransport.Value() {
	case "native":
		return SCTPNativeOnly
	case "udp":
		return SCTPUDPOnly
	}
	return SCTPNativePreferred
}

// sctpWithFallback runs native and, as the policy allows, udp.
func sctpWithFallback(t SCTPTransportConfig, dial bool, native func() (*SCTPConn, error), udp func(SCTPUDPConfig) (*SCTPConn, error)) (*SCTPConn, error) {
	p := t.policy()
	if p == SCTPUDPOnly {
		return udp(t.UDP)
	}
	c, err := native()
	if err == nil || p == SCTPNativeOnly {
		return c, err
	}
	if sctpNoKernelSupport(err) || (dial && p == SCTPNativePreferredWithConnectFallback && sctpConnectFailed(err)) {
		uc, uerr := udp(t.UDP)
		if uerr == nil {
			return uc, nil
		}
		if errors.Is(uerr, errSCTPUDPUnsupported) {
			return nil, err
		}
		return nil, uerr
	}
	return nil, err
}

// sctpUDPUnsupportedError is returned for operations the UDP transport
// cannot perform. It matches errors.ErrUnsupported.
type sctpUDPUnsupportedError struct{}

func (sctpUDPUnsupportedError) Error() string {
	return "operation not supported by SCTP over UDP"
}

func (sctpUDPUnsupportedError) Is(target error) bool { return target == errors.ErrUnsupported }

var errSCTPUDPUnsupported error = sctpUDPUnsupportedError{}

// ok reports whether c is usable, over either transport.
func (c *SCTPConn) ok() bool { return c != nil && (c.fd != nil || c.udp != nil) }

func (c *SCTPConn) udpOpErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if _, ok := err.(*OpError); ok {
		return err
	}
	var raddr Addr
	if c.udp.raddr != nil {
		raddr = c.udp.raddr
	}
	return &OpError{Op: op, Net: c.udp.net, Source: c.udp.laddr, Addr: raddr, Err: err}
}

// udpAssocID resolves an association ID the way the kernel does: zero
// means the connection's own association when there is one.
func (c *SCTPConn) udpAssocID(id int32) int32 {
	if id != 0 {
		return id
	}
	if c.assocID != 0 {
		return c.assocID
	}
	return c.udp.defaultAssocID()
}

// The methods below route the [Conn] methods inherited from conn to the
// UDP transport when it is in use.

// Read implements the [Conn] Read method.
func (c *SCTPConn) Read(b []byte) (int, error) {
	if c != nil && c.udp != nil {
		n, _, _, _, _, err := c.udp.readFrom(b)
		return n, c.udpOpErr("read", err)
	}
	return c.conn.Read(b)
}

// Write implements the [Conn] Write method.
func (c *SCTPConn) Write(b []byte) (int, error) {
	if c != nil && c.udp != nil {
		n, err := c.udp.writeTo(b, nil, nil)
		return n, c.udpOpErr("write", err)
	}
	return c.conn.Write(b)
}

// Close closes the connection. Over UDP, associations shut down
// gracefully in the background, as the kernel does.
func (c *SCTPConn) Close() error {
	if c != nil && c.udp != nil {
		return c.udpOpErr("close", c.udp.close())
	}
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *SCTPConn) LocalAddr() Addr {
	if c != nil && c.udp != nil {
		return c.udp.laddr
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (c *SCTPConn) RemoteAddr() Addr {
	if c != nil && c.udp != nil {
		if c.udp.raddr == nil {
			return nil
		}
		return c.udp.raddr
	}
	return c.conn.RemoteAddr()
}

// SetDeadline implements the [Conn] SetDeadline method.
func (c *SCTPConn) SetDeadline(t time.Time) error {
	if c != nil && c.udp != nil {
		c.udp.setDeadline(t, true, true)
		return nil
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements the [Conn] SetReadDeadline method.
func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	if c != nil && c.udp != nil {
		c.udp.setDeadline(t, true, false)
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements the [Conn] SetWriteDeadline method.
func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	if c != nil && c.udp != nil {
		c.udp.setDeadline(t, false, true)
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

// SetReadBuffer sets the size of the receive buffer. Over UDP it sets the
// advertised receiver window for new associations.
func (c *SCTPConn) SetReadBuffer(bytes int) error {
	if c != nil && c.udp != nil {
		return c.udpOpErr("set", c.udp.setBuffers(bytes, 0))
	}
	return c.conn.SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the send buffer. Over UDP it sets the
// per-association send buffer.
func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	if c != nil && c.udp != nil {
		return c.udpOpErr("set", c.udp.setBuffers(0, bytes))
	}
	return c.conn.SetWriteBuffer(bytes)
}

// File returns a copy of the underlying [os.File]. It is not supported
// over UDP.
func (c *SCTPConn) File() (f *os.File, err error) {
	if c != nil && c.udp != nil {
		return nil, c.udpOpErr("file", errSCTPUDPUnsupported)
	}
	return c.conn.File()
}
