// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
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
