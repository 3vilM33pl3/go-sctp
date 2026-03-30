package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type cliConfig struct {
	baseURL            string
	agentName          string
	environmentName    string
	listScenarios      bool
	includeManualSetup bool
	featureFilter      map[string]bool
}

type featureEvent struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	FeatureID string `json:"feature_id,omitempty"`
	State     string `json:"state,omitempty"`
	Message   string `json:"message,omitempty"`
}

type summaryEvent struct {
	Type      string         `json:"type"`
	SessionID string         `json:"session_id"`
	Counts    summaryCounts  `json:"counts"`
	Complete  bool           `json:"complete"`
	Features  []featureState `json:"features"`
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	client := newFeatureServerClient(cfg.baseURL)
	if cfg.listScenarios {
		emitJSON(scenarioSummaries())
		return 0
	}
	if err := client.healthz(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "healthz: %v\n", err)
		return 1
	}

	catalog, err := client.features(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "features: %v\n", err)
		return 1
	}

	session, err := client.createSession(context.Background(), cfg.agentName, cfg.environmentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create session: %v\n", err)
		return 1
	}

	runner := runner{client: client}
	exitCode := 0
	executed := 0
	for _, feature := range catalog.Features {
		if len(cfg.featureFilter) > 0 && !cfg.featureFilter[feature.ID] {
			continue
		}
		if len(cfg.featureFilter) == 0 && feature.ManualSetupRequired && !cfg.includeManualSetup {
			emitJSON(featureEvent{
				Type:      "feature_skipped",
				SessionID: session.SessionID,
				FeatureID: feature.ID,
				State:     "skipped",
				Message:   "skipped by default because the feature requires manual host setup; rerun with --include-manual-setup or explicitly select it with --features",
			})
			continue
		}
		executed++
		state, err := runner.runFeature(context.Background(), session.SessionID, feature)
		if err != nil {
			fmt.Fprintf(os.Stderr, "feature %s: %v\n", feature.ID, err)
			exitCode = 1
			break
		}
		emitJSON(featureEvent{
			Type:      "feature_result",
			SessionID: session.SessionID,
			FeatureID: state.ID,
			State:     state.State,
			Message:   state.Message,
		})
		if state.State != statePassed && state.State != stateUnsupported {
			exitCode = 1
			break
		}
	}

	summary, err := client.summary(context.Background(), session.SessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "summary: %v\n", err)
		return 1
	}
	emitJSON(summaryEvent{
		Type:      "summary",
		SessionID: session.SessionID,
		Counts: summaryCounts{
			Passed:      summary.Passed,
			Failed:      summary.Failed,
			Unsupported: summary.Unsupported,
			TimedOut:    summary.TimedOut,
			Pending:     summary.Pending,
			Active:      summary.Active,
		},
		Complete: summary.Complete,
		Features: summary.Features,
	})

	if executed == 0 {
		fmt.Fprintln(os.Stderr, "no features selected")
		return 2
	}
	if exitCode != 0 {
		return exitCode
	}
	return 0
}

func parseFlags(args []string) (cliConfig, error) {
	fs := flag.NewFlagSet("sctp-feature-client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg cliConfig
	var features string
	fs.StringVar(&cfg.baseURL, "base-url", "", "HTTP base URL of the SCTP feature server")
	fs.StringVar(&cfg.agentName, "agent-name", "go-sctp-feature-client", "agent name reported to the server")
	fs.StringVar(&cfg.environmentName, "environment-name", "go-sctp", "environment name reported to the server")
	fs.BoolVar(&cfg.listScenarios, "list-scenarios", false, "print the client scenario map keyed by feature_id and exit")
	fs.BoolVar(&cfg.includeManualSetup, "include-manual-setup", false, "run features whose server contract declares manual host setup requirements")
	fs.StringVar(&features, "features", "", "optional comma-separated feature allowlist")
	if err := fs.Parse(args); err != nil {
		return cliConfig{}, err
	}
	if cfg.baseURL == "" && !cfg.listScenarios {
		return cliConfig{}, fmt.Errorf("--base-url is required")
	}
	cfg.featureFilter = parseFeatureFilter(features)
	return cfg, nil
}

func parseFeatureFilter(raw string) map[string]bool {
	out := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out[part] = true
	}
	return out
}

func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
