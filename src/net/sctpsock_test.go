// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestResolveSCTPAddrUnknownNetwork(t *testing.T) {
	_, err := ResolveSCTPAddr("bogus", "127.0.0.1:9000")
	var nerr UnknownNetworkError
	if !errors.As(err, &nerr) {
		t.Fatalf("ResolveSCTPAddr error = %v; want UnknownNetworkError", err)
	}
}

func TestParseNetworkSCTP(t *testing.T) {
	afnet, proto, err := parseNetwork(context.Background(), "sctp4", true)
	if err != nil {
		t.Fatalf("parseNetwork(sctp4) error = %v", err)
	}
	if afnet != "sctp4" {
		t.Fatalf("parseNetwork(sctp4) afnet = %q; want %q", afnet, "sctp4")
	}
	if proto != 0 {
		t.Fatalf("parseNetwork(sctp4) proto = %d; want 0", proto)
	}
}

func TestSCTPAddrString(t *testing.T) {
	a := &SCTPAddr{IP: IPv4(127, 0, 0, 1), Port: 4242}
	if got, want := a.String(), "127.0.0.1:4242"; got != want {
		t.Fatalf("SCTPAddr.String() = %q; want %q", got, want)
	}
}

func TestSCTPUnsupportedErrorIsErrUnsupported(t *testing.T) {
	if !errors.Is(errSCTPUnsupported, errors.ErrUnsupported) {
		t.Fatalf("errors.Is(%v, errors.ErrUnsupported) = false", errSCTPUnsupported)
	}
	wrapped := &OpError{Op: "dial", Net: "sctp", Err: errSCTPUnsupported}
	if !errors.Is(wrapped, errors.ErrUnsupported) {
		t.Fatalf("errors.Is(%v, errors.ErrUnsupported) = false", wrapped)
	}
}

func TestSCTPAddrPortRoundTrip(t *testing.T) {
	for _, s := range []string{"10.1.2.3:4242", "[2001:db8::7]:53", "[fe80::1%eth0]:80"} {
		ap := netip.MustParseAddrPort(s)
		a := SCTPAddrFromAddrPort(ap)
		if a.Port != int(ap.Port()) || a.Zone != ap.Addr().Zone() || !a.IP.Equal(IP(ap.Addr().AsSlice())) {
			t.Errorf("SCTPAddrFromAddrPort(%s) = %+v", s, a)
		}
		if got := a.AddrPort(); got != ap {
			t.Errorf("SCTPAddrFromAddrPort(%s).AddrPort() = %v", s, got)
		}
		if a.String() != s {
			t.Errorf("SCTPAddrFromAddrPort(%s).String() = %q", s, a.String())
		}
	}
	var nilAddr *SCTPAddr
	if got := nilAddr.AddrPort(); got.IsValid() {
		t.Errorf("(*SCTPAddr)(nil).AddrPort() = %v; want the zero value", got)
	}
	if got := SCTPAddrFromAddrPort(netip.AddrPort{}); got.IP != nil {
		t.Errorf("SCTPAddrFromAddrPort(zero) = %+v; want a nil IP", got)
	}
	if got := nilAddr.String(); got != "<nil>" {
		t.Errorf("(*SCTPAddr)(nil).String() = %q", got)
	}
	if got := (&SCTPAddr{}).Network(); got != "sctp" {
		t.Errorf("Network() = %q", got)
	}
}

func TestSCTPMultiAddrString(t *testing.T) {
	m := &SCTPMultiAddr{Addrs: []SCTPAddr{{IP: IPv4(10, 0, 0, 1), Port: 7}, {IP: ParseIP("2001:db8::1"), Port: 7}}}
	if got, want := m.String(), "10.0.0.1:7,[2001:db8::1]:7"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	if got := (*SCTPMultiAddr)(nil).String(); got != "<nil>" {
		t.Errorf("nil String() = %q", got)
	}
}
