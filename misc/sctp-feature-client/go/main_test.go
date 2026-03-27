package main

import (
	"slices"
	"testing"
)

func TestParseFeatureFilter(t *testing.T) {
	got := parseFeatureFilter("bind_listen_connect, nodelay ,,ppid")
	want := map[string]bool{
		"bind_listen_connect": true,
		"nodelay":             true,
		"ppid":                true,
	}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d, want %d", len(got), len(want))
	}
	for key := range want {
		if !got[key] {
			t.Fatalf("missing key %q", key)
		}
	}
}

func TestBuildEventMask(t *testing.T) {
	mask := buildEventMask([]string{"association", "shutdown", "dataio", "stream_reset"})
	if !mask.Association || !mask.Shutdown || !mask.DataIO || !mask.StreamReset {
		t.Fatalf("unexpected mask: %+v", mask)
	}
	if mask.Address || mask.PeerError {
		t.Fatalf("unexpected extra mask bits: %+v", mask)
	}
}

func TestFeatureMappingsDoNotOverlap(t *testing.T) {
	for id := range supportedFeatureHandlers {
		if _, ok := unsupportedFeatureSpecs[id]; ok {
			t.Fatalf("feature %q is both supported and unsupported", id)
		}
	}
}

func TestMustFeatureIDsSorted(t *testing.T) {
	ids := mustFeatureIDs()
	if !slices.IsSorted(ids) {
		t.Fatalf("feature ids are not sorted: %v", ids)
	}
	if len(ids) == 0 {
		t.Fatal("expected at least one feature id")
	}
}

func TestKnownTerminalState(t *testing.T) {
	for _, state := range []string{statePassed, stateFailed, stateUnsupported, stateTimedOut} {
		if !knownTerminalState(state) {
			t.Fatalf("state %q should be terminal", state)
		}
	}
	for _, state := range []string{statePending, stateActive, "weird"} {
		if knownTerminalState(state) {
			t.Fatalf("state %q should not be terminal", state)
		}
	}
}
