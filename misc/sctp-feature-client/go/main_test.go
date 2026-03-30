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

func TestScenarioSummariesMatchScenarioCatalog(t *testing.T) {
	summaries := scenarioSummaries()
	if len(summaries) != len(scenarioCatalog) {
		t.Fatalf("len(summaries)=%d, want %d", len(summaries), len(scenarioCatalog))
	}
	for i, entry := range summaries {
		scenario := scenarioCatalog[i]
		if entry.FeatureID != scenario.FeatureID {
			t.Fatalf("summaries[%d].FeatureID=%q, want %q", i, entry.FeatureID, scenario.FeatureID)
		}
		if entry.DashboardTitle != scenario.DashboardTitle {
			t.Fatalf("summaries[%d].DashboardTitle=%q, want %q", i, entry.DashboardTitle, scenario.DashboardTitle)
		}
		if entry.DashboardCategory != scenario.DashboardCategory {
			t.Fatalf("summaries[%d].DashboardCategory=%q, want %q", i, entry.DashboardCategory, scenario.DashboardCategory)
		}
		if entry.ImplementationKey != scenario.ImplementationKey {
			t.Fatalf("summaries[%d].ImplementationKey=%q, want %q", i, entry.ImplementationKey, scenario.ImplementationKey)
		}
		if entry.SourceSymbol != scenario.SourceSymbol {
			t.Fatalf("summaries[%d].SourceSymbol=%q, want %q", i, entry.SourceSymbol, scenario.SourceSymbol)
		}
		if entry.SourcePath == "" || entry.Description == "" {
			t.Fatalf("summaries[%d] missing path or description: %+v", i, entry)
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
