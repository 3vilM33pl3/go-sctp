package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	completionServerObserved = "server_observed"
	completionAgentReported  = "agent_reported"
	completionHybrid         = "hybrid"

	statePending     = "pending"
	stateActive      = "active"
	statePassed      = "passed"
	stateFailed      = "failed"
	stateUnsupported = "unsupported"
	stateTimedOut    = "timed_out"
)

type featureServerClient struct {
	baseURL string
	client  *http.Client
}

type catalogResponse struct {
	Server   string           `json:"server"`
	Features []catalogFeature `json:"features"`
}

type catalogFeature struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Category       string `json:"category"`
	Summary        string `json:"summary"`
	CompletionMode string `json:"completion_mode"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type sessionResponse struct {
	SessionID     string `json:"session_id"`
	DashboardPath string `json:"dashboard_path"`
}

type messageSpec struct {
	Payload string `json:"payload"`
	Stream  uint16 `json:"stream"`
	PPID    uint32 `json:"ppid"`
}

type scenarioContract struct {
	FeatureID          string        `json:"feature_id"`
	CompletionMode     string        `json:"completion_mode"`
	Transport          string        `json:"transport"`
	ConnectAddresses   []string      `json:"connect_addresses"`
	ClientSocketOpts   []string      `json:"client_socket_options"`
	ClientSubs         []string      `json:"client_subscriptions"`
	ClientSendMessages []messageSpec `json:"client_send_messages"`
	ServerSendMessages []messageSpec `json:"server_send_messages"`
	TriggerPayload     string        `json:"trigger_payload"`
	NegativeTarget     string        `json:"negative_connect_target"`
	TimeoutSeconds     int           `json:"timeout_seconds"`
	ReportPrompt       string        `json:"report_prompt"`
	InstructionsText   string        `json:"instructions_text"`
}

type featureState struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Message  string            `json:"message"`
	Contract *scenarioContract `json:"contract,omitempty"`
}

type summaryCounts struct {
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	Unsupported int `json:"unsupported"`
	TimedOut    int `json:"timed_out"`
	Pending     int `json:"pending"`
	Active      int `json:"active"`
}

type summaryResponse struct {
	SessionID   string         `json:"session_id"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
	Unsupported int            `json:"unsupported"`
	TimedOut    int            `json:"timed_out"`
	Pending     int            `json:"pending"`
	Active      int            `json:"active"`
	Complete    bool           `json:"complete"`
	Features    []featureState `json:"features"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type completionPayload struct {
	EvidenceKind string `json:"evidence_kind"`
	EvidenceText string `json:"evidence_text"`
	ReportText   string `json:"report_text"`
}

type unsupportedPayload struct {
	Reason       string `json:"reason"`
	EvidenceKind string `json:"evidence_kind"`
	EvidenceText string `json:"evidence_text"`
}

func newFeatureServerClient(baseURL string) *featureServerClient {
	return &featureServerClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *featureServerClient) healthz(ctx context.Context) error {
	var out map[string]bool
	if err := c.doJSON(ctx, http.MethodGet, "/healthz", nil, &out); err != nil {
		return err
	}
	if !out["ok"] {
		return fmt.Errorf("healthz returned not ok")
	}
	return nil
}

func (c *featureServerClient) features(ctx context.Context) (*catalogResponse, error) {
	var out catalogResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/features", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) createSession(ctx context.Context, agentName, environmentName string) (*sessionResponse, error) {
	body := map[string]string{
		"agent_name":       agentName,
		"environment_name": environmentName,
	}
	var out sessionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sessions", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) startFeature(ctx context.Context, sessionID, featureID string) (*featureState, error) {
	var out featureState
	path := fmt.Sprintf("/v1/sessions/%s/features/%s/start", sessionID, featureID)
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) getFeature(ctx context.Context, sessionID, featureID string) (*featureState, error) {
	var out featureState
	path := fmt.Sprintf("/v1/sessions/%s/features/%s", sessionID, featureID)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) completeFeature(ctx context.Context, sessionID, featureID string, payload completionPayload) (*featureState, error) {
	var out featureState
	path := fmt.Sprintf("/v1/sessions/%s/features/%s/complete", sessionID, featureID)
	if err := c.doJSON(ctx, http.MethodPost, path, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) unsupportedFeature(ctx context.Context, sessionID, featureID string, payload unsupportedPayload) (*featureState, error) {
	var out featureState
	path := fmt.Sprintf("/v1/sessions/%s/features/%s/unsupported", sessionID, featureID)
	if err := c.doJSON(ctx, http.MethodPost, path, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) summary(ctx context.Context, sessionID string) (*summaryResponse, error) {
	var out summaryResponse
	path := fmt.Sprintf("/v1/sessions/%s/summary", sessionID)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *featureServerClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		buf := &bytes.Buffer{}
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return err
		}
		payload = buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
		}
		if apiErr.Error == "" {
			return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
		}
		return fmt.Errorf("%s %s: %s", method, path, apiErr.Error)
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
