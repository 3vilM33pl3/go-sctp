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

func TestScenarioCatalogIsWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(scenarioCatalog))
	for _, scenario := range scenarioCatalog {
		if scenario.FeatureID == "" {
			t.Fatal("scenario feature id should not be empty")
		}
		if scenario.DashboardTitle == "" || scenario.DashboardCategory == "" {
			t.Fatalf("scenario %q missing dashboard metadata: %+v", scenario.FeatureID, scenario)
		}
		if scenario.ImplementationKey == "" || scenario.SourceSymbol == "" {
			t.Fatalf("scenario %q missing implementation metadata: %+v", scenario.FeatureID, scenario)
		}
		if scenario.Handler == nil {
			t.Fatalf("scenario %q missing handler", scenario.FeatureID)
		}
		if seen[scenario.FeatureID] {
			t.Fatalf("duplicate scenario feature id %q", scenario.FeatureID)
		}
		seen[scenario.FeatureID] = true
	}
}

func TestClientFeatureManifestMatchesScenarioCatalog(t *testing.T) {
	manifest := clientFeatureManifest()
	if len(manifest) != len(scenarioCatalog) {
		t.Fatalf("len(manifest)=%d, want %d", len(manifest), len(scenarioCatalog))
	}
	for i, entry := range manifest {
		scenario := scenarioCatalog[i]
		if entry.FeatureID != scenario.FeatureID {
			t.Fatalf("manifest[%d].FeatureID=%q, want %q", i, entry.FeatureID, scenario.FeatureID)
		}
		if entry.ImplementationKey != scenario.ImplementationKey {
			t.Fatalf("manifest[%d].ImplementationKey=%q, want %q", i, entry.ImplementationKey, scenario.ImplementationKey)
		}
		if entry.SourceSymbol != scenario.SourceSymbol {
			t.Fatalf("manifest[%d].SourceSymbol=%q, want %q", i, entry.SourceSymbol, scenario.SourceSymbol)
		}
		if entry.SourcePath == "" || entry.Description == "" {
			t.Fatalf("manifest[%d] missing path or description: %+v", i, entry)
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
