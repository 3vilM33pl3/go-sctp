// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"testing"
)

func TestResolveSCTPMultiAddrUnknownNetwork(t *testing.T) {
	_, err := ResolveSCTPMultiAddr("bogus", []string{"127.0.0.1:9000"})
	var nerr UnknownNetworkError
	if !errors.As(err, &nerr) {
		t.Fatalf("ResolveSCTPMultiAddr error = %v; want UnknownNetworkError", err)
	}
}

func TestResolveSCTPMultiAddrMismatchedPorts(t *testing.T) {
	_, err := ResolveSCTPMultiAddr("sctp4", []string{"127.0.0.1:9000", "127.0.0.2:9001"})
	var aerr *AddrError
	if !errors.As(err, &aerr) {
		t.Fatalf("ResolveSCTPMultiAddr error = %v; want AddrError", err)
	}
}
