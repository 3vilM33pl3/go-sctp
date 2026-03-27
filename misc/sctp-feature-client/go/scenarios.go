package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	msgNotification = 0x8000
	sctpUnordered   = 0x0001
)

type runner struct {
	client *featureServerClient
}

type featureHandler func(context.Context, *runner, *scenarioContract) (*completionPayload, error)

type unsupportedSpec struct {
	Reason       string
	EvidenceKind string
	EvidenceText string
}

var supportedFeatureHandlers = map[string]featureHandler{
	"socket_create":                    handleSocketCreate,
	"bind_listen_connect":              handleBasicSend,
	"single_message_boundary":          handleBasicSend,
	"multi_message_boundary":           handleBasicSend,
	"stream_id":                        handleBasicSend,
	"ppid":                             handleBasicSend,
	"nodelay":                          handleNoDelay,
	"initmsg":                          handleInitMsg,
	"notifications":                    handleNotificationScenario,
	"event_subscription_matrix":        handleNotificationScenario,
	"association_shutdown_notifications": handleNotificationScenario,
	"multi_bind":                       handleMultiBind,
	"local_addr_enum":                  handleLocalAddrEnum,
	"peer_addr_enum":                   handlePeerAddrEnum,
	"negative_connect_error":           handleNegativeConnectError,
	"unordered_delivery":               handleUnorderedDelivery,
}

var unsupportedFeatureSpecs = map[string]unsupportedSpec{
	"rto_assoc_parameters": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP_RTOINFO in the current public SCTP client API",
	},
	"default_sndinfo_recvrcvinfo": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp exposes per-message SCTPSndInfo but not a socket-level SCTP_DEFAULT_SNDINFO setter",
	},
	"recvnxtinfo": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP_RECVNXTINFO or next-message metadata in the current API",
	},
	"autoclose": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP_AUTOCLOSE in the current public SCTP client API",
	},
	"bindx_add_remove": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp can dial multi-address associations but does not expose SCTP_BINDX add/remove controls for the client socket",
	},
	"primary_addr_management": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose local primary-address management in the current SCTP client API",
	},
	"peer_primary_addr_request": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose peer primary-address request controls in the current SCTP client API",
	},
	"peeloff_assoc": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP peeloff in the current public SCTP client API",
	},
	"assoc_id_listing": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose association identifier listing in the current SCTP client API",
	},
	"assoc_status_opt_info": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP_STATUS or sctp_opt_info-style association status queries in the current API",
	},
	"stream_reconfig_reset": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP stream reset controls in the current public SCTP client API",
	},
	"stream_reconfig_add_streams": {
		Reason:       "missing API",
		EvidenceKind: "client_gap",
		EvidenceText: "go-sctp does not expose SCTP add-stream reconfiguration controls in the current public SCTP client API",
	},
}

func (r *runner) runFeature(ctx context.Context, sessionID string, feature catalogFeature) (*featureState, error) {
	if spec, ok := unsupportedFeatureSpecs[feature.ID]; ok {
		return r.client.unsupportedFeature(ctx, sessionID, feature.ID, unsupportedPayload{
			Reason:       spec.Reason,
			EvidenceKind: spec.EvidenceKind,
			EvidenceText: spec.EvidenceText,
		})
	}

	handler, ok := supportedFeatureHandlers[feature.ID]
	if !ok {
		return r.client.unsupportedFeature(ctx, sessionID, feature.ID, unsupportedPayload{
			Reason:       "unmapped feature",
			EvidenceKind: "client_gap",
			EvidenceText: "the go-sctp feature client does not implement this feature id",
		})
	}

	started, err := r.client.startFeature(ctx, sessionID, feature.ID)
	if err != nil {
		return nil, err
	}
	if started.Contract == nil {
		return nil, fmt.Errorf("feature %s did not include a contract", feature.ID)
	}

	completion, err := handler(ctx, r, started.Contract)
	if err != nil {
		return nil, err
	}
	if feature.CompletionMode != completionServerObserved {
		if completion == nil {
			completion = &completionPayload{
				EvidenceKind: "runtime",
				EvidenceText: "feature completed locally",
				ReportText:   "client completed the feature",
			}
		}
		if _, err := r.client.completeFeature(ctx, sessionID, feature.ID, *completion); err != nil {
			return nil, err
		}
	}

	return r.waitForTerminal(ctx, sessionID, feature.ID, started.Contract.TimeoutSeconds)
}

func (r *runner) waitForTerminal(ctx context.Context, sessionID, featureID string, timeoutSeconds int) (*featureState, error) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds+2) * time.Second)
	for {
		state, err := r.client.getFeature(ctx, sessionID, featureID)
		if err != nil {
			return nil, err
		}
		switch state.State {
		case statePassed, stateFailed, stateUnsupported, stateTimedOut:
			return state, nil
		}
		if time.Now().After(deadline) {
			return state, fmt.Errorf("timed out waiting for terminal state on %s", featureID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func handleSocketCreate(_ context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := net.ListenSCTP("sctp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "created SCTP listen socket successfully",
		ReportText:   contract.ReportPrompt,
	}, nil
}

func handleBasicSend(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	if contract.CompletionMode == completionHybrid {
		return &completionPayload{
			EvidenceKind: "runtime",
			EvidenceText: "sent expected SCTP payloads",
			ReportText:   "client sent the expected SCTP payload sequence",
		}, nil
	}
	return nil, nil
}

func handleNoDelay(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		return nil, err
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "SetNoDelay(true) succeeded before sending data",
		ReportText:   "client enabled SCTP_NODELAY and sent the probe payload",
	}, nil
}

func handleInitMsg(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	opts := net.SCTPInitOptions{
		NumOStreams:  8,
		MaxInStreams: 8,
	}
	if err := conn.SetInitOptions(opts); err != nil {
		return nil, err
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "SetInitOptions succeeded with NumOStreams=8 MaxInStreams=8",
		ReportText:   "client applied SCTP_INITMSG before the first outbound SCTP message",
	}, nil
}

func handleNotificationScenario(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	mask := buildEventMask(contract.ClientSubs)
	if err := conn.SubscribeEvents(mask); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(contract.TimeoutSeconds) * time.Second)); err != nil {
		return nil, err
	}
	if contract.TriggerPayload != "" {
		if _, err := conn.WriteToSCTP([]byte(contract.TriggerPayload), nil, nil); err != nil {
			return nil, err
		}
	}
	notifications, err := readServerMessages(conn, contract.ServerSendMessages)
	if err != nil {
		return nil, err
	}
	if notifications.count == 0 {
		return nil, fmt.Errorf("no SCTP notification traffic observed")
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("observed %d SCTP notification frame(s)", notifications.count),
		ReportText:   fmt.Sprintf("observed notification flags %s", notifications.renderedFlags()),
	}, nil
}

func handleMultiBind(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("dialed with %d advertised addresses", len(contract.ConnectAddresses)),
		ReportText:   fmt.Sprintf("client attempted multihome connect using %s", strings.Join(contract.ConnectAddresses, ",")),
	}, nil
}

func handleLocalAddrEnum(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	addrs, err := conn.LocalAddrs()
	if err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("enumerated %d local SCTP address(es)", len(addrs)),
		ReportText:   fmt.Sprintf("local addresses: %s", renderSCTPAddrs(addrs)),
	}, nil
}

func handlePeerAddrEnum(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	addrs, err := conn.PeerAddrs()
	if err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("enumerated %d peer SCTP address(es)", len(addrs)),
		ReportText:   fmt.Sprintf("peer addresses: %s", renderSCTPAddrs(addrs)),
	}, nil
}

func handleNegativeConnectError(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	raddr, err := net.ResolveSCTPAddr("sctp4", contract.NegativeTarget)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialSCTP("sctp4", nil, raddr)
	if err != nil {
		return &completionPayload{
			EvidenceKind: "runtime",
			EvidenceText: err.Error(),
			ReportText:   "DialSCTP failed for the invalid target as expected",
		}, nil
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	_, err = conn.WriteToSCTP([]byte("negative-connect-probe"), nil, nil)
	if err == nil {
		return nil, fmt.Errorf("unexpected success writing to invalid SCTP target %s", contract.NegativeTarget)
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: err.Error(),
		ReportText:   "first outbound SCTP write to the invalid target failed as expected",
	}, nil
}

func handleUnorderedDelivery(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for _, msg := range contract.ClientSendMessages {
		info := &net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
			Flags:  sctpUnordered,
		}
		if _, err := conn.WriteToSCTP([]byte(msg.Payload), nil, info); err != nil {
			return nil, err
		}
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "sent the probe payload with SCTPSndInfo.Flags set to SCTP_UNORDERED",
		ReportText:   "client attempted unordered delivery using SCTPSndInfo.Flags",
	}, nil
}

func dialContract(contract *scenarioContract) (*net.SCTPConn, error) {
	switch len(contract.ConnectAddresses) {
	case 0:
		return nil, fmt.Errorf("feature %s did not provide connect addresses", contract.FeatureID)
	case 1:
		raddr, err := net.ResolveSCTPAddr(contract.Transport, contract.ConnectAddresses[0])
		if err != nil {
			return nil, err
		}
		return net.DialSCTP(contract.Transport, nil, raddr)
	default:
		raddr, err := net.ResolveSCTPMultiAddr(contract.Transport, contract.ConnectAddresses)
		if err != nil {
			return nil, err
		}
		return net.DialSCTPMulti(contract.Transport, nil, raddr)
	}
}

func sendContractMessages(conn *net.SCTPConn, messages []messageSpec) error {
	for _, msg := range messages {
		info := &net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
		}
		if _, err := conn.WriteToSCTP([]byte(msg.Payload), nil, info); err != nil {
			return err
		}
	}
	return nil
}

type notificationSummary struct {
	count int
	flags map[int]int
}

func readServerMessages(conn *net.SCTPConn, expected []messageSpec) (notificationSummary, error) {
	summary := notificationSummary{flags: make(map[int]int)}
	buf := make([]byte, 4096)
	receivedMessages := 0
	for receivedMessages < len(expected) {
		n, _, flags, _, info, err := conn.ReadFromSCTP(buf)
		if err != nil {
			return summary, err
		}
		if flags&msgNotification != 0 {
			summary.count++
			summary.flags[flags]++
			continue
		}
		want := expected[receivedMessages]
		if string(buf[:n]) != want.Payload {
			return summary, fmt.Errorf("unexpected server payload %q, want %q", string(buf[:n]), want.Payload)
		}
		if info == nil {
			return summary, fmt.Errorf("missing SCTP recv info for server payload")
		}
		if info.Stream != want.Stream {
			return summary, fmt.Errorf("unexpected server stream %d, want %d", info.Stream, want.Stream)
		}
		if info.PPID != want.PPID {
			return summary, fmt.Errorf("unexpected server ppid %d, want %d", info.PPID, want.PPID)
		}
		receivedMessages++
	}

	if err := conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond)); err == nil {
		for {
			_, _, flags, _, _, err := conn.ReadFromSCTP(buf)
			if err != nil {
				break
			}
			if flags&msgNotification != 0 {
				summary.count++
				summary.flags[flags]++
			}
		}
	}
	return summary, nil
}

func (n notificationSummary) renderedFlags() string {
	if len(n.flags) == 0 {
		return "[]"
	}
	keys := make([]int, 0, len(n.flags))
	for flag := range n.flags {
		keys = append(keys, flag)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, flag := range keys {
		parts = append(parts, fmt.Sprintf("%d(x%d)", flag, n.flags[flag]))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func buildEventMask(subscriptions []string) net.SCTPEventMask {
	var mask net.SCTPEventMask
	for _, sub := range subscriptions {
		switch sub {
		case "association":
			mask.Association = true
		case "shutdown":
			mask.Shutdown = true
		case "dataio":
			mask.DataIO = true
		case "address":
			mask.Address = true
		case "peer_error":
			mask.PeerError = true
		case "stream_reset":
			mask.StreamReset = true
		}
	}
	return mask
}

func renderSCTPAddrs(addrs []net.SCTPAddr) string {
	if len(addrs) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return strings.Join(out, ",")
}

func mustFeatureIDs() []string {
	ids := make([]string, 0, len(supportedFeatureHandlers)+len(unsupportedFeatureSpecs))
	for id := range supportedFeatureHandlers {
		ids = append(ids, id)
	}
	for id := range unsupportedFeatureSpecs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func knownTerminalState(state string) bool {
	switch state {
	case statePassed, stateFailed, stateUnsupported, stateTimedOut:
		return true
	default:
		return false
	}
}

func parseTimeoutSeconds(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
