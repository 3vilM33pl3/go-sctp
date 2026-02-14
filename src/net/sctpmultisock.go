// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"strings"
	"syscall"
)

// SCTPMultiAddr represents a static set of SCTP endpoint addresses.
// All addresses in the set must use the same port and address family.
type SCTPMultiAddr struct {
	Addrs []SCTPAddr
}

// Network returns the address's network name, "sctp".
func (*SCTPMultiAddr) Network() string { return "sctp" }

func (a *SCTPMultiAddr) String() string {
	if a == nil || len(a.Addrs) == 0 {
		return "<nil>"
	}
	parts := make([]string, 0, len(a.Addrs))
	for i := range a.Addrs {
		parts = append(parts, a.Addrs[i].String())
	}
	return strings.Join(parts, ",")
}

func (a *SCTPMultiAddr) copy() *SCTPMultiAddr {
	if a == nil {
		return nil
	}
	out := &SCTPMultiAddr{Addrs: make([]SCTPAddr, len(a.Addrs))}
	copy(out.Addrs, a.Addrs)
	return out
}

func (a *SCTPMultiAddr) first() *SCTPAddr {
	if a == nil || len(a.Addrs) == 0 {
		return nil
	}
	return &a.Addrs[0]
}

func copySCTPAddrs(in []SCTPAddr) []SCTPAddr {
	if len(in) == 0 {
		return nil
	}
	out := make([]SCTPAddr, len(in))
	copy(out, in)
	return out
}

// ResolveSCTPMultiAddr resolves a list of SCTP endpoint addresses.
func ResolveSCTPMultiAddr(network string, addresses []string) (*SCTPMultiAddr, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, UnknownNetworkError(network)
	}
	if len(addresses) == 0 {
		return nil, errMissingAddress
	}
	out := &SCTPMultiAddr{Addrs: make([]SCTPAddr, len(addresses))}
	for i, s := range addresses {
		a, err := ResolveSCTPAddr(network, s)
		if err != nil {
			return nil, err
		}
		out.Addrs[i] = *a
	}
	if err := validateSCTPMultiAddr(network, out.Addrs, false); err != nil {
		return nil, err
	}
	return out, nil
}

func validateSCTPMultiAddr(network string, addrs []SCTPAddr, allowZeroPort bool) error {
	if len(addrs) == 0 {
		return errMissingAddress
	}
	var (
		family int
		port   int
	)
	for i := range addrs {
		a := &addrs[i]
		if err := validateSCTPAddrFamily(network, a); err != nil {
			return err
		}
		af := a.family()
		if i == 0 {
			family = af
		} else if af != family {
			return &AddrError{Err: "mixed address family in sctp multi-address", Addr: a.String()}
		}
		switch {
		case i == 0:
			port = a.Port
		case a.Port == port:
		case allowZeroPort && (a.Port == 0 || port == 0):
			if port == 0 {
				port = a.Port
			}
		default:
			return &AddrError{Err: "mismatched port in sctp multi-address", Addr: a.String()}
		}
	}
	return nil
}

func validateSCTPAddrFamily(network string, a *SCTPAddr) error {
	if a == nil {
		return nil
	}
	switch network {
	case "sctp4":
		if len(a.IP) != 0 && a.IP.To4() == nil {
			return &AddrError{Err: "non-IPv4 address", Addr: a.String()}
		}
	case "sctp6":
		if len(a.IP) != 0 && (a.IP.To16() == nil || a.IP.To4() != nil) {
			return &AddrError{Err: "non-IPv6 address", Addr: a.String()}
		}
	}
	return nil
}

// DialSCTPMulti acts like [DialSCTP] for multi-address local endpoints.
// Remote multi-address setup requires connectx-style association setup and
// is not supported by this v1 API.
func DialSCTPMulti(network string, laddr, raddr *SCTPMultiAddr) (*SCTPConn, error) {
	return dialSCTPMulti(context.Background(), nil, network, laddr, raddr)
}

func dialSCTPMulti(ctx context.Context, dialer *Dialer, network string, laddr, raddr *SCTPMultiAddr) (*SCTPConn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: UnknownNetworkError(network)}
	}
	if raddr == nil || len(raddr.Addrs) == 0 {
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: errMissingAddress}
	}
	if err := validateSCTPMultiAddr(network, raddr.Addrs, false); err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}
	if laddr != nil && len(laddr.Addrs) > 0 {
		if err := validateSCTPMultiAddr(network, laddr.Addrs, true); err != nil {
			return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
		}
	}

	var la, ra *SCTPAddr
	if laddr != nil && len(laddr.Addrs) > 0 {
		la = &laddr.Addrs[0]
	}
	ra = &raddr.Addrs[0]

	c, err := dialSCTP(ctx, dialer, network, la, ra)
	if err != nil {
		return nil, err
	}
	c.multiPeer = copySCTPAddrs(raddr.Addrs)
	if laddr != nil && len(laddr.Addrs) > 1 {
		extra := make([]SCTPAddr, len(laddr.Addrs)-1)
		copy(extra, laddr.Addrs[1:])
		if laa, ok := c.LocalAddr().(*SCTPAddr); ok {
			for i := range extra {
				if extra[i].Port == 0 {
					extra[i].Port = laa.Port
				}
			}
		}
		if err := bindAddrsSCTP(c.fd, extra); err != nil {
			c.Close()
			return nil, &OpError{Op: "dial", Net: network, Source: la.opAddr(), Addr: ra.opAddr(), Err: err}
		}
		base, _ := c.LocalAddr().(*SCTPAddr)
		if base != nil {
			c.multiLocal = append([]SCTPAddr{*base}, extra...)
		}
	} else if la != nil {
		base, _ := c.LocalAddr().(*SCTPAddr)
		if base != nil {
			c.multiLocal = []SCTPAddr{*base}
		}
	}
	if len(raddr.Addrs) > 1 {
		assocID, err := connectAddrsSCTP(c.fd, raddr.Addrs)
		if err != nil {
			c.Close()
			return nil, &OpError{Op: "dial", Net: network, Source: la.opAddr(), Addr: ra.opAddr(), Err: err}
		}
		c.assocID = assocID
		// Prefer a non-primary destination as the default send target to avoid
		// getting pinned to an unavailable first address in multi-homed lists.
		fallback := raddr.Addrs[1]
		c.fd.raddr = &fallback
	}
	return c, nil
}

// ListenSCTPMulti acts like [ListenSCTP] for multi-address local endpoints.
func ListenSCTPMulti(network string, laddr *SCTPMultiAddr) (*SCTPConn, error) {
	return listenSCTPMulti(context.Background(), ListenConfig{}, network, laddr)
}

func listenSCTPMulti(ctx context.Context, lc ListenConfig, network string, laddr *SCTPMultiAddr) (*SCTPConn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: UnknownNetworkError(network)}
	}
	if laddr != nil && len(laddr.Addrs) > 0 {
		if err := validateSCTPMultiAddr(network, laddr.Addrs, true); err != nil {
			return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
		}
	}

	var la *SCTPAddr
	if laddr != nil && len(laddr.Addrs) > 0 {
		la = &laddr.Addrs[0]
	}
	c, err := listenSCTP(ctx, lc, network, la)
	if err != nil {
		return nil, err
	}
	if base, ok := c.LocalAddr().(*SCTPAddr); ok && base != nil {
		c.multiLocal = []SCTPAddr{*base}
	}
	if laddr != nil && len(laddr.Addrs) > 1 {
		extra := make([]SCTPAddr, len(laddr.Addrs)-1)
		copy(extra, laddr.Addrs[1:])
		if laa, ok := c.LocalAddr().(*SCTPAddr); ok {
			for i := range extra {
				if extra[i].Port == 0 {
					extra[i].Port = laa.Port
				}
			}
		}
		if err := bindAddrsSCTP(c.fd, extra); err != nil {
			c.Close()
			return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: la.opAddr(), Err: err}
		}
		if base, ok := c.LocalAddr().(*SCTPAddr); ok && base != nil {
			c.multiLocal = append([]SCTPAddr{*base}, extra...)
		}
	}
	return c, nil
}

// ListenSCTPMultiInit acts like [ListenSCTPMulti] and configures SCTP_INITMSG.
func ListenSCTPMultiInit(network string, laddr *SCTPMultiAddr, opts SCTPInitOptions) (*SCTPConn, error) {
	c, err := listenSCTPMulti(context.Background(), ListenConfig{}, network, laddr)
	if err != nil {
		return nil, err
	}
	if err := c.SetInitOptions(opts); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// LocalAddrs returns the local SCTP endpoint addresses for the association.
func (c *SCTPConn) LocalAddrs() ([]SCTPAddr, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	if len(c.multiLocal) > 0 {
		return copySCTPAddrs(c.multiLocal), nil
	}
	if a, ok := c.LocalAddr().(*SCTPAddr); ok && a != nil {
		return []SCTPAddr{*a}, nil
	}
	return nil, nil
}

// PeerAddrs returns the peer SCTP endpoint addresses for the association.
func (c *SCTPConn) PeerAddrs() ([]SCTPAddr, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	if len(c.multiPeer) > 0 {
		return copySCTPAddrs(c.multiPeer), nil
	}
	if a, ok := c.fd.raddr.(*SCTPAddr); ok && a != nil {
		return []SCTPAddr{*a}, nil
	}
	return nil, nil
}
