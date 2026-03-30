package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	msgNotification = 0x8000
)

type runner struct {
	client *featureServerClient
}

type featureHandler func(context.Context, *runner, *scenarioContract) (*completionPayload, error)

type scenarioDefinition struct {
	FeatureID         string
	DashboardTitle    string
	DashboardCategory string
	ImplementationKey string
	SourceSymbol      string
	Description       string
	Handler           featureHandler
}

type scenarioSummary struct {
	FeatureID         string `json:"feature_id"`
	DashboardTitle    string `json:"dashboard_title"`
	DashboardCategory string `json:"dashboard_category"`
	ImplementationKey string `json:"implementation_key"`
	SourceSymbol      string `json:"source_symbol"`
	SourcePath        string `json:"source_path"`
	Description       string `json:"description"`
}

const scenarioSourcePath = "misc/sctp-feature-client/go/scenarios.go"

// scenarioCatalog mirrors the server/dashboard feature order on purpose.
// FeatureID is the dashboard/API identifier; ImplementationKey groups shared
// Go-side logic when multiple dashboard scenarios reuse the same handler.
var scenarioCatalog = []scenarioDefinition{
	// Endpoint / association bring-up.
	{"socket_create", "Create SCTP socket", "endpoint", "socket_create", "handleSocketCreate", "Create an SCTP socket locally and report whether the environment exposes the API.", handleSocketCreate},
	{"bind_listen_connect", "Bind, listen, and connect", "association", "basic_send", "handleBasicSend", "Dial the server and send one probe payload on a basic SCTP association.", handleBasicSend},

	// Messaging and metadata.
	{"single_message_boundary", "Single message boundary", "messaging", "basic_send", "handleBasicSend", "Send one SCTP message and rely on the server to verify boundary preservation.", handleBasicSend},
	{"multi_message_boundary", "Multiple message boundaries", "messaging", "basic_send", "handleBasicSend", "Send two SCTP messages in order and preserve boundaries.", handleBasicSend},
	{"stream_id", "Stream identifier metadata", "metadata", "basic_send", "handleBasicSend", "Send the probe payload on a specific SCTP stream.", handleBasicSend},
	{"ppid", "PPID metadata", "metadata", "basic_send", "handleBasicSend", "Send the probe payload with a specific SCTP PPID.", handleBasicSend},
	{"nodelay", "SCTP_NODELAY", "socket_option", "nodelay", "handleNoDelay", "Enable SCTP_NODELAY before sending the probe payload.", handleNoDelay},
	{"initmsg", "SCTP_INITMSG", "socket_option", "initmsg", "handleInitMsg", "Apply SCTP_INITMSG before association setup and then send the probe payload.", handleInitMsg},
	{"rto_assoc_parameters", "SCTP_RTOINFO", "socket_option", "rto_info", "handleRTOInfo", "Apply association RTO parameters and send the probe payload.", handleRTOInfo},
	{"default_sndinfo_recvrcvinfo", "SCTP_DEFAULT_SNDINFO / RECVRCVINFO", "metadata", "default_send_info", "handleDefaultSendInfo", "Set default send metadata and confirm it via RECVRCVINFO.", handleDefaultSendInfo},
	{"unordered_delivery", "Unordered delivery", "messaging", "unordered_delivery", "handleUnorderedDelivery", "Attempt unordered SCTP delivery and report whether the environment accepts it.", handleUnorderedDelivery},
	{"recvnxtinfo", "SCTP_RECVNXTINFO", "metadata", "recv_nxtinfo", "handleRecvNxtInfo", "Receive two server messages and report next-message metadata from the first receive.", handleRecvNxtInfo},
	{"autoclose", "SCTP_AUTOCLOSE", "socket_option", "autoclose", "handleAutoClose", "Attempt to configure SCTP_AUTOCLOSE on the client socket and report whether it is accepted.", handleAutoClose},

	// Events and notifications.
	{"notifications", "Association and shutdown notifications", "events", "notification_observer", "handleNotificationScenario", "Subscribe to SCTP notifications and report the association and shutdown events observed.", handleNotificationScenario},
	{"event_subscription_matrix", "Event subscription matrix", "events", "notification_observer", "handleNotificationScenario", "Subscribe to the available SCTP events and report which notifications were delivered.", handleNotificationScenario},
	{"association_shutdown_notifications", "Association shutdown notifications", "events", "notification_observer", "handleNotificationScenario", "Observe graceful association teardown notifications after the server trigger.", handleNotificationScenario},

	// Multihoming and address control.
	{"multi_bind", "Multihome reference server", "multihoming", "multi_bind", "handleMultiBind", "Connect to the reference server using all advertised peer addresses.", handleMultiBind},
	{"local_addr_enum", "Local address enumeration", "multihoming", "local_addr_enum", "handleLocalAddrEnum", "Enumerate the client's local SCTP addresses after association setup.", handleLocalAddrEnum},
	{"peer_addr_enum", "Peer address enumeration", "multihoming", "peer_addr_enum", "handlePeerAddrEnum", "Enumerate the server's SCTP addresses after association setup.", handlePeerAddrEnum},
	{"bindx_add_remove", "SCTP_BINDX add/remove", "multihoming", "bindx_add_remove", "handleBindxAddRemove", "Exercise local SCTP bindx add/remove controls before connecting.", handleBindxAddRemove},
	{"primary_addr_management", "Primary address management", "multihoming", "primary_addr_management", "handlePrimaryAddrManagement", "Attempt a local primary-address change on a multihomed association.", handlePrimaryAddrManagement},
	{"peer_primary_addr_request", "Peer primary address request", "multihoming", "peer_primary_addr_request", "handlePeerPrimaryAddrRequest", "Attempt a peer primary-address change request on a multihomed association.", handlePeerPrimaryAddrRequest},

	// Association management and introspection.
	{"peeloff_assoc", "Association peeloff", "association", "peeloff_assoc", "handlePeelOffAssoc", "Attempt to peel the association onto a dedicated SCTP socket.", handlePeelOffAssoc},
	{"assoc_id_listing", "Association identifier listing", "association", "assoc_id_listing", "handleAssocIDListing", "Enumerate association identifiers after sending the probe payload.", handleAssocIDListing},
	{"assoc_status_opt_info", "SCTP_STATUS / opt_info", "introspection", "assoc_status", "handleAssocStatus", "Query association status and report the returned state summary.", handleAssocStatus},

	// Reconfiguration.
	{"stream_reconfig_reset", "Stream reconfiguration reset", "reconfiguration", "stream_reset", "handleStreamReset", "Attempt SCTP stream reset on the active association after the server trigger.", handleStreamReset},
	{"stream_reconfig_add_streams", "Stream reconfiguration add streams", "reconfiguration", "stream_add_streams", "handleStreamAddStreams", "Attempt SCTP stream addition on the active association after the server trigger.", handleStreamAddStreams},
	{"pr_sctp_ttl", "PR-SCTP TTL policy", "reliability", "pr_sctp", "handlePRTTL", "Apply a TTL-based partially reliable send and verify forward progress under manual impairment.", handlePRTTL},
	{"pr_sctp_rtx", "PR-SCTP retransmission policy", "reliability", "pr_sctp", "handlePRRTX", "Apply a retransmission-limited partially reliable send and verify forward progress under manual impairment.", handlePRRTX},
	{"auth_required_chunks", "SCTP AUTH required chunks", "authentication", "auth_required_chunks", "handleAuthRequiredChunks", "Configure SCTP AUTH chunk coverage and shared keys before sending the probe payload.", handleAuthRequiredChunks},
	{"auth_key_rotation", "SCTP AUTH key rotation", "authentication", "auth_key_rotation", "handleAuthKeyRotation", "Install SCTP AUTH keys, rotate the active key, and send the probe payload.", handleAuthKeyRotation},
	{"asconf_add_remove", "ASCONF address add/remove", "multihoming", "asconf_add_remove", "handleASCONFAddRemove", "Attempt SCTP dynamic address reconfiguration on the connected association.", handleASCONFAddRemove},
	{"idata_interleaving", "I-DATA / fragment interleaving", "messaging", "idata_interleaving", "handleIDataInterleaving", "Enable fragment interleaving and receive the server's large-plus-small message burst.", handleIDataInterleaving},
	{"stream_scheduler_policy", "Stream scheduler policy", "scheduler", "stream_scheduler_policy", "handleStreamSchedulerPolicy", "Apply a non-default SCTP stream scheduler policy on the active association.", handleStreamSchedulerPolicy},
	{"stream_scheduler_value", "Stream scheduler value", "scheduler", "stream_scheduler_value", "handleStreamSchedulerValue", "Apply per-stream SCTP scheduler values on the active association.", handleStreamSchedulerValue},

	// Negative/error path.
	{"negative_connect_error", "Negative connect path", "error_path", "negative_connect_error", "handleNegativeConnectError", "Attempt an invalid SCTP connection target and report the surfaced error.", handleNegativeConnectError},
}

var scenarioByFeatureID = buildScenarioIndex()

func buildScenarioIndex() map[string]scenarioDefinition {
	out := make(map[string]scenarioDefinition, len(scenarioCatalog))
	for _, scenario := range scenarioCatalog {
		out[scenario.FeatureID] = scenario
	}
	return out
}

func scenarioSummaries() []scenarioSummary {
	out := make([]scenarioSummary, 0, len(scenarioCatalog))
	for _, scenario := range scenarioCatalog {
		out = append(out, scenarioSummary{
			FeatureID:         scenario.FeatureID,
			DashboardTitle:    scenario.DashboardTitle,
			DashboardCategory: scenario.DashboardCategory,
			ImplementationKey: scenario.ImplementationKey,
			SourceSymbol:      scenario.SourceSymbol,
			SourcePath:        scenarioSourcePath,
			Description:       scenario.Description,
		})
	}
	return out
}

func (r *runner) runFeature(ctx context.Context, sessionID string, feature catalogFeature) (*featureState, error) {
	scenario, ok := scenarioByFeatureID[feature.ID]
	if !ok {
		return r.client.unsupportedFeature(ctx, sessionID, feature.ID, unsupportedPayload{
			Reason:       "unmapped feature",
			EvidenceKind: "client_gap",
			EvidenceText: "the go-sctp feature client does not implement this feature id",
		})
	}
	if scenario.DashboardTitle != feature.Title || scenario.DashboardCategory != feature.Category {
		return nil, fmt.Errorf(
			"feature %s metadata drift: client has %q/%q, server has %q/%q",
			feature.ID,
			scenario.DashboardCategory,
			scenario.DashboardTitle,
			feature.Category,
			feature.Title,
		)
	}

	started, err := r.client.startFeature(ctx, sessionID, feature.ID)
	if err != nil {
		return nil, err
	}
	if started.Contract == nil {
		return nil, fmt.Errorf("feature %s did not include a contract", feature.ID)
	}

	completion, err := scenario.Handler(ctx, r, started.Contract)
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

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
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
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
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
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "SetInitOptions succeeded with NumOStreams=8 MaxInStreams=8",
		ReportText:   "client applied SCTP_INITMSG before the first outbound SCTP message",
	}, nil
}

func handleRTOInfo(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	info := net.SCTPRTOInfo{Initial: 1500, Max: 4000, Min: 800}
	if err := conn.SetRTOInfo(info); err != nil {
		return nil, err
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetRTOInfo succeeded with initial=%d max=%d min=%d", info.Initial, info.Max, info.Min),
		ReportText:   fmt.Sprintf("client applied SCTP_RTOINFO initial=%d max=%d min=%d", info.Initial, info.Max, info.Min),
	}, nil
}

func handleDefaultSendInfo(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if len(contract.ClientSendMessages) == 0 {
		return nil, fmt.Errorf("feature %s did not provide client send messages", contract.FeatureID)
	}
	msg := contract.ClientSendMessages[0]
	info := net.SCTPSndInfo{Stream: msg.Stream, PPID: msg.PPID}
	if err := conn.SetDefaultSendInfo(info); err != nil {
		return nil, err
	}
	if _, err := conn.WriteToSCTP([]byte(msg.Payload), nil, nil); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetDefaultSendInfo succeeded with stream=%d ppid=%d and send used default metadata", msg.Stream, msg.PPID),
		ReportText:   fmt.Sprintf("client applied SCTP_DEFAULT_SNDINFO stream=%d ppid=%d", msg.Stream, msg.PPID),
	}, nil
}

func handleRecvNxtInfo(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if err := conn.SetRecvNxtInfo(true); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(contract.TimeoutSeconds) * time.Second)); err != nil {
		return nil, err
	}
	if contract.TriggerPayload != "" {
		if _, err := conn.WriteToSCTP([]byte(contract.TriggerPayload), nil, nil); err != nil {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(contract.ServerSendMessages) < 2 {
		return nil, fmt.Errorf("feature %s requires two server messages", contract.FeatureID)
	}
	buf := make([]byte, 4096)
	n, _, flags, _, info, err := conn.ReadFromSCTP(buf)
	if err != nil {
		return nil, err
	}
	if flags&msgNotification != 0 {
		return nil, fmt.Errorf("received notification before first server message")
	}
	if got, want := string(buf[:n]), contract.ServerSendMessages[0].Payload; got != want {
		return nil, fmt.Errorf("unexpected first payload %q, want %q", got, want)
	}
	if info == nil || info.Next == nil {
		return nil, fmt.Errorf("missing next-message metadata on first receive")
	}
	next := contract.ServerSendMessages[1]
	if info.Next.Stream != next.Stream {
		return nil, fmt.Errorf("unexpected next stream %d, want %d", info.Next.Stream, next.Stream)
	}
	if info.Next.PPID != next.PPID {
		return nil, fmt.Errorf("unexpected next ppid %d, want %d", info.Next.PPID, next.PPID)
	}
	if int(info.Next.Length) != len(next.Payload) {
		return nil, fmt.Errorf("unexpected next length %d, want %d", info.Next.Length, len(next.Payload))
	}
	if _, err := readServerMessages(conn, contract.ServerSendMessages[1:]); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("observed next-message metadata stream=%d ppid=%d length=%d", info.Next.Stream, info.Next.PPID, info.Next.Length),
		ReportText:   fmt.Sprintf("client observed SCTP_RECVNXTINFO for stream=%d ppid=%d length=%d", info.Next.Stream, info.Next.PPID, info.Next.Length),
	}, nil
}

func handleAutoClose(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := net.ListenSCTP("sctp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	const seconds = 7
	if err := conn.SetAutoClose(seconds); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetAutoClose(%d) succeeded", seconds),
		ReportText:   fmt.Sprintf("client applied SCTP_AUTOCLOSE=%d", seconds),
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
	if err := conn.SetRecvRcvInfo(true); err != nil {
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

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
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

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
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

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
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

func handleBindxAddRemove(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	bindConn, _, extra, err := openBoundFeatureSocket(contract)
	if err != nil {
		return nil, err
	}
	defer bindConn.Close()

	if len(extra) > 0 {
		if err := bindConn.BindAddrs(extra); err != nil {
			return nil, err
		}
		if err := bindConn.UnbindAddrs(extra); err != nil {
			return nil, err
		}
		if err := bindConn.BindAddrs(extra); err != nil {
			return nil, err
		}
	}
	if err := bindConn.Close(); err != nil {
		return nil, err
	}
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("performed bindx add/remove using local addresses %s", renderSCTPAddrs(extra)),
		ReportText:   fmt.Sprintf("client added, removed, and re-added local SCTP addresses %s", renderSCTPAddrs(extra)),
	}, nil
}

func handlePrimaryAddrManagement(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peerAddrs, enumErr := conn.PeerAddrs()
	var opErr error
	var target *net.SCTPAddr
	if enumErr == nil && len(peerAddrs) > 0 {
		target = &peerAddrs[len(peerAddrs)-1]
		opErr = conn.SetPrimaryAddr(target)
	} else if enumErr == nil {
		opErr = fmt.Errorf("no peer addresses available for primary-address management")
	} else {
		opErr = enumErr
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	evidence := "local primary-address management succeeded"
	report := "client requested a local primary-address change successfully"
	if opErr != nil {
		evidence = fmt.Sprintf("local primary-address management was not accepted: %v", opErr)
		report = "client attempted local primary-address management, but the call was not accepted"
	} else if target != nil {
		evidence = fmt.Sprintf("SetPrimaryAddr succeeded for %s", target.String())
		report = fmt.Sprintf("client requested peer address %s as the primary destination", target.String())
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func handlePeerPrimaryAddrRequest(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddrs, enumErr := conn.LocalAddrs()
	var opErr error
	var target *net.SCTPAddr
	if enumErr == nil && len(localAddrs) > 0 {
		target = &localAddrs[0]
		opErr = conn.SetPeerPrimaryAddr(target)
	} else if enumErr == nil {
		opErr = fmt.Errorf("no local addresses available for peer primary-address request")
	} else {
		opErr = enumErr
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	evidence := "peer primary-address request succeeded"
	report := "client requested a peer primary-address change successfully"
	if opErr != nil {
		evidence = fmt.Sprintf("peer primary-address request was not accepted: %v", opErr)
		report = "client attempted a peer primary-address request, but the call was not accepted"
	} else if target != nil {
		evidence = fmt.Sprintf("SetPeerPrimaryAddr succeeded for %s", target.String())
		report = fmt.Sprintf("client requested peer primary address change to local address %s", target.String())
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func handlePeelOffAssoc(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peeled, peelErr := conn.PeelOff(0)
	var sendConn *net.SCTPConn
	if peelErr == nil {
		defer peeled.Close()
		sendConn = peeled
	} else {
		sendConn = conn
	}
	if err := sendContractMessages(sendConn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	evidence := "PeelOff(0) succeeded and the peeled association sent the probe payload"
	report := "client peeled the association onto a dedicated socket and sent the probe payload there"
	if peelErr != nil {
		evidence = fmt.Sprintf("association peeloff was not accepted: %v", peelErr)
		report = "client attempted association peeloff, but the API call was not accepted"
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func handleAssocIDListing(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	ids, listErr := conn.AssocIDs()
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: func() string {
			if listErr != nil {
				return fmt.Sprintf("association identifier listing was not available: %v", listErr)
			}
			return fmt.Sprintf("enumerated %d association id(s)", len(ids))
		}(),
		ReportText: func() string {
			if listErr != nil {
				return "client attempted association identifier listing, but the API call was not accepted"
			}
			return fmt.Sprintf("association ids: %s", renderAssocIDs(ids))
		}(),
	}, nil
}

func handleAssocStatus(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	status, statusErr := conn.AssocStatus(0)
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: func() string {
			if statusErr != nil {
				return fmt.Sprintf("association status was not available: %v", statusErr)
			}
			return fmt.Sprintf("association state=%d in_streams=%d out_streams=%d primary=%s", status.State, status.InStreams, status.OutStreams, status.PrimaryAddr.String())
		}(),
		ReportText: func() string {
			if statusErr != nil {
				return "client attempted association status introspection, but the API call was not accepted"
			}
			return fmt.Sprintf("association status state=%d in_streams=%d out_streams=%d primary=%s", status.State, status.InStreams, status.OutStreams, status.PrimaryAddr.String())
		}(),
	}, nil
}

func handleStreamReset(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	opErr := conn.EnableStreamReset(net.SCTPStreamResetIncoming | net.SCTPStreamResetOutgoing)
	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	if opErr == nil {
		opErr = conn.ResetStreams(net.SCTPStreamResetOutgoing, []uint16{contract.ServerSendMessages[0].Stream})
	}
	evidence := fmt.Sprintf("stream reset request succeeded for stream=%d", contract.ServerSendMessages[0].Stream)
	report := fmt.Sprintf("client requested SCTP stream reset for stream=%d", contract.ServerSendMessages[0].Stream)
	if opErr != nil {
		evidence = fmt.Sprintf("stream reset request was not accepted: %v", opErr)
		report = "client attempted SCTP stream reset, but the API call was not accepted"
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func handleStreamAddStreams(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	opErr := conn.EnableStreamReset(net.SCTPStreamResetIncoming | net.SCTPStreamResetOutgoing)
	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	if opErr == nil {
		opErr = conn.AddStreams(1, 1)
	}
	evidence := "AddStreams(1,1) succeeded"
	report := "client requested one additional inbound stream and one additional outbound stream"
	if opErr != nil {
		evidence = fmt.Sprintf("AddStreams(1,1) was not accepted: %v", opErr)
		report = "client attempted stream addition, but the API call was not accepted"
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func handlePRTTL(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	return handlePRScenario(ctx, contract, "ttl")
}

func handlePRRTX(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	return handlePRScenario(ctx, contract, "rtx")
}

func handlePRScenario(ctx context.Context, contract *scenarioContract, mode string) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	evidence := fmt.Sprintf("applied PR-SCTP %s policy and sent the configured payload sequence", mode)
	if contract.ManualSetupRequired {
		evidence += "; manual impairment was required: " + strings.Join(contract.ManualSetupInstructions, " | ")
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   fmt.Sprintf("client applied PR-SCTP %s with the documented impairment and sent the follow-up reliable payload", mode),
	}, nil
}

func handleAuthRequiredChunks(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContractWithAuth(ctx, contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("configured AUTH chunk coverage %v and sent the probe payload", contract.Auth.ChunkTypes),
		ReportText:   fmt.Sprintf("client configured SCTP AUTH chunk coverage %v with key ids %d/%d", contract.Auth.ChunkTypes, contract.Auth.PrimaryKeyID, contract.Auth.SecondaryKeyID),
	}, nil
}

func handleAuthKeyRotation(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContractWithAuth(ctx, contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.ActivateAuthKey(0, contract.Auth.SecondaryKeyID); err != nil {
		if err := rawActivateAuthKeyConn(conn, contract.Auth.SecondaryKeyID); err != nil {
			return nil, err
		}
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("installed AUTH keys %d/%d and activated key %d before sending", contract.Auth.PrimaryKeyID, contract.Auth.SecondaryKeyID, contract.Auth.SecondaryKeyID),
		ReportText:   fmt.Sprintf("client rotated the active SCTP AUTH key from %d to %d", contract.Auth.PrimaryKeyID, contract.Auth.SecondaryKeyID),
	}, nil
}

func handleASCONFAddRemove(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if contract.AddressReconfig == nil {
		return nil, fmt.Errorf("missing address-reconfiguration contract")
	}

	addAddrs, err := resolveContractSCTPAddrs(contract.Transport, contract.AddressReconfig.AddAddresses)
	if err != nil {
		return nil, err
	}
	removeAddrs, err := resolveContractSCTPAddrs(contract.Transport, contract.AddressReconfig.RemoveAddresses)
	if err != nil {
		return nil, err
	}
	if len(addAddrs) > 0 {
		if err := conn.BindAddrs(addAddrs); err != nil {
			return nil, err
		}
	}
	if len(removeAddrs) > 0 {
		if err := conn.UnbindAddrs(removeAddrs); err != nil {
			return nil, err
		}
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("attempted dynamic address reconfiguration add=%v remove=%v", contract.AddressReconfig.AddAddresses, contract.AddressReconfig.RemoveAddresses),
		ReportText:   fmt.Sprintf("client attempted SCTP ASCONF add=%v remove=%v", contract.AddressReconfig.AddAddresses, contract.AddressReconfig.RemoveAddresses),
	}, nil
}

func handleIDataInterleaving(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	level := 2
	if contract.Interleaving != nil && contract.Interleaving.FragmentInterleaveLevel > 0 {
		level = contract.Interleaving.FragmentInterleaveLevel
	}
	if err := conn.SetFragmentInterleave(level); err != nil {
		return nil, err
	}
	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetFragmentInterleave(%d) succeeded and the server burst was received", level),
		ReportText:   fmt.Sprintf("client enabled fragment interleaving level %d and received the server's large-plus-small message burst", level),
	}, nil
}

func handleStreamSchedulerPolicy(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	policy, err := parseSchedulerPolicy(contract.Scheduler)
	if err != nil {
		return nil, err
	}
	if err := conn.SetStreamScheduler(policy); err != nil {
		return nil, err
	}
	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetStreamScheduler(%s) succeeded", contract.Scheduler.Policy),
		ReportText:   fmt.Sprintf("client applied SCTP stream scheduler policy %s", contract.Scheduler.Policy),
	}, nil
}

func handleStreamSchedulerValue(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	policy, err := parseSchedulerPolicy(contract.Scheduler)
	if err != nil {
		return nil, err
	}
	if err := conn.SetStreamScheduler(policy); err != nil {
		return nil, err
	}
	if err := conn.SetStreamSchedulerValue(contract.Scheduler.PrimaryStream, contract.Scheduler.PrimaryValue); err != nil {
		return nil, err
	}
	if err := conn.SetStreamSchedulerValue(contract.Scheduler.SecondaryStream, contract.Scheduler.SecondaryValue); err != nil {
		return nil, err
	}
	if err := conn.SetRecvRcvInfo(true); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetStreamSchedulerValue succeeded for streams %d/%d with values %d/%d", contract.Scheduler.PrimaryStream, contract.Scheduler.SecondaryStream, contract.Scheduler.PrimaryValue, contract.Scheduler.SecondaryValue),
		ReportText:   fmt.Sprintf("client applied scheduler values stream %d=%d and stream %d=%d", contract.Scheduler.PrimaryStream, contract.Scheduler.PrimaryValue, contract.Scheduler.SecondaryStream, contract.Scheduler.SecondaryValue),
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

	if len(contract.ClientSendMessages) == 0 {
		conn.Close()
		return nil, fmt.Errorf("feature %s did not provide client send messages", contract.FeatureID)
	}
	accepted := true
	var firstErr error
	for _, msg := range contract.ClientSendMessages {
		info := net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
			Flags:  net.SCTPUnordered,
		}
		if err := conn.SetDefaultSendInfo(info); err == nil {
			if _, err := conn.WriteToSCTP([]byte(msg.Payload), nil, nil); err == nil {
				continue
			} else {
				firstErr = err
			}
		} else {
			firstErr = err
		}
		accepted = false
		break
	}
	conn.Close()
	if !accepted {
		conn, err = dialContract(contract)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		for _, msg := range contract.ClientSendMessages {
			if _, err := conn.Write([]byte(msg.Payload)); err != nil {
				return nil, err
			}
		}
	} else {
		defer conn.Close()
	}
	evidence := "sent the probe payload with unordered delivery enabled via SCTP_DEFAULT_SNDINFO"
	report := "client attempted unordered delivery using net.SCTPUnordered in SCTP_DEFAULT_SNDINFO"
	if !accepted {
		evidence = fmt.Sprintf("unordered delivery controls were exposed but rejected by the send path: %v", firstErr)
		report = "client attempted unordered delivery, but the Linux SCTP send path rejected the unordered flag"
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: evidence,
		ReportText:   report,
	}, nil
}

func dialContract(contract *scenarioContract) (*net.SCTPConn, error) {
	if len(contract.ConnectAddresses) == 0 {
		return nil, fmt.Errorf("feature %s did not provide connect addresses", contract.FeatureID)
	}
	raddr, err := net.ResolveSCTPAddr(contract.Transport, contract.ConnectAddresses[0])
	if err != nil {
		return nil, err
	}
	return net.DialSCTPInit(contract.Transport, nil, raddr, net.SCTPInitOptions{
		NumOStreams:  32,
		MaxInStreams: 32,
	})
}

func dialContractWithAuth(ctx context.Context, contract *scenarioContract) (*net.SCTPConn, error) {
	if contract.Auth == nil {
		return nil, fmt.Errorf("missing auth contract")
	}
	if len(contract.ConnectAddresses) == 0 {
		return nil, fmt.Errorf("feature %s did not provide connect addresses", contract.FeatureID)
	}
	dialer := net.Dialer{
		ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				controlErr = rawConfigureAuthSocket(int(fd), contract.Auth)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	conn, err := dialer.DialContext(ctx, contract.Transport, contract.ConnectAddresses[0])
	if err != nil {
		return nil, err
	}
	sctpConn, ok := conn.(*net.SCTPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("DialContext returned %T, want *net.SCTPConn", conn)
	}
	return sctpConn, nil
}

func materializeMessagePayload(msg messageSpec) string {
	if msg.SizeBytes <= 0 || msg.SizeBytes <= len(msg.Payload) {
		return msg.Payload
	}
	if msg.Payload == "" {
		return strings.Repeat("x", msg.SizeBytes)
	}
	var builder strings.Builder
	builder.Grow(msg.SizeBytes)
	for builder.Len() < msg.SizeBytes {
		remaining := msg.SizeBytes - builder.Len()
		if remaining >= len(msg.Payload) {
			builder.WriteString(msg.Payload)
			continue
		}
		builder.WriteString(msg.Payload[:remaining])
	}
	return builder.String()
}

func parsePRPolicy(raw string) (net.SCTPPRPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none":
		return net.SCTPPRNone, nil
	case "ttl":
		return net.SCTPPRTTL, nil
	case "rtx":
		return net.SCTPPRRTX, nil
	case "priority":
		return net.SCTPPRPriority, nil
	default:
		return 0, fmt.Errorf("unknown PR-SCTP policy %q", raw)
	}
}

func parseSchedulerPolicy(config *schedulerContract) (net.SCTPScheduler, error) {
	if config == nil {
		return 0, fmt.Errorf("missing scheduler contract")
	}
	switch strings.ToLower(strings.TrimSpace(config.Policy)) {
	case "fcfs":
		return net.SCTPSchedulerFCFS, nil
	case "priority":
		return net.SCTPSchedulerPriority, nil
	case "rr":
		return net.SCTPSchedulerRR, nil
	case "fc":
		return net.SCTPSchedulerFC, nil
	case "wfq":
		return net.SCTPSchedulerWFQ, nil
	default:
		return 0, fmt.Errorf("unknown scheduler policy %q", config.Policy)
	}
}

func applyAuthContract(conn *net.SCTPConn, auth *authContract) error {
	if auth == nil {
		return fmt.Errorf("missing auth contract")
	}
	if err := conn.SetAuthChunks(auth.ChunkTypes); err != nil {
		return err
	}
	if err := conn.SetAuthKey(net.SCTPAuthKey{KeyID: auth.PrimaryKeyID, Secret: []byte(auth.PrimarySecret)}); err != nil {
		return err
	}
	if auth.SecondaryKeyID != 0 || auth.SecondarySecret != "" {
		if err := conn.SetAuthKey(net.SCTPAuthKey{KeyID: auth.SecondaryKeyID, Secret: []byte(auth.SecondarySecret)}); err != nil {
			return err
		}
	}
	if auth.PrimaryKeyID != 0 {
		if err := conn.ActivateAuthKey(0, auth.PrimaryKeyID); err != nil {
			return err
		}
	}
	return nil
}

const (
	rawSCTPSockoptAuthChunk     = 21
	rawSCTPSockoptAuthKey       = 23
	rawSCTPSockoptAuthActiveKey = 24
)

type rawSCTPAuthChunk struct {
	Chunk uint8
}

type rawSCTPAuthKeyHeader struct {
	AssocID   int32
	KeyID     uint16
	KeyLength uint16
}

type rawSCTPAuthKeyID struct {
	AssocID int32
	KeyID   uint16
}

func rawSetSockoptBytes(fd, level, name int, value []byte) error {
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(ptr),
		uintptr(len(value)),
		0,
	)
	if errno != 0 {
		return os.NewSyscallError("setsockopt", errno)
	}
	return nil
}

func rawConfigureAuthSocket(fd int, auth *authContract) error {
	for _, chunk := range auth.ChunkTypes {
		raw := rawSCTPAuthChunk{Chunk: chunk}
		if err := rawSetSockoptBytes(fd, syscall.IPPROTO_SCTP, rawSCTPSockoptAuthChunk, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), int(unsafe.Sizeof(raw)))); err != nil {
			return err
		}
	}
	if err := rawInstallAuthKey(fd, auth.PrimaryKeyID, auth.PrimarySecret); err != nil {
		return err
	}
	if auth.SecondaryKeyID != 0 || auth.SecondarySecret != "" {
		if err := rawInstallAuthKey(fd, auth.SecondaryKeyID, auth.SecondarySecret); err != nil {
			return err
		}
	}
	if auth.PrimaryKeyID != 0 {
		if err := rawActivateAuthKeyFD(fd, auth.PrimaryKeyID); err != nil {
			return err
		}
	}
	return nil
}

func rawInstallAuthKey(fd int, keyID uint16, secret string) error {
	buf := make([]byte, int(unsafe.Sizeof(rawSCTPAuthKeyHeader{}))+len(secret))
	hdr := (*rawSCTPAuthKeyHeader)(unsafe.Pointer(&buf[0]))
	hdr.KeyID = keyID
	hdr.KeyLength = uint16(len(secret))
	copy(buf[int(unsafe.Sizeof(rawSCTPAuthKeyHeader{})):], []byte(secret))
	return rawSetSockoptBytes(fd, syscall.IPPROTO_SCTP, rawSCTPSockoptAuthKey, buf)
}

func rawActivateAuthKeyFD(fd int, keyID uint16) error {
	raw := rawSCTPAuthKeyID{KeyID: keyID}
	return rawSetSockoptBytes(fd, syscall.IPPROTO_SCTP, rawSCTPSockoptAuthActiveKey, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), int(unsafe.Sizeof(raw))))
}

func rawActivateAuthKeyConn(conn *net.SCTPConn, keyID uint16) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = rawActivateAuthKeyFD(int(fd), keyID)
	}); err != nil {
		return err
	}
	return controlErr
}

func applyMessageSendControls(conn *net.SCTPConn, msg messageSpec, contract *scenarioContract) error {
	if msg.PRPolicy != "" {
		policy, err := parsePRPolicy(msg.PRPolicy)
		if err != nil {
			return err
		}
		if err := conn.SetDefaultPRInfo(net.SCTPPRInfo{Policy: policy, Value: msg.PRValue}); err != nil {
			return err
		}
	} else {
		if err := conn.SetDefaultPRInfo(net.SCTPPRInfo{Policy: net.SCTPPRNone, Value: 0}); err != nil {
			return err
		}
	}
	if msg.AuthKeyID != 0 {
		if contract.Auth == nil {
			return fmt.Errorf("message requested auth key %d without auth contract", msg.AuthKeyID)
		}
		if err := conn.ActivateAuthKey(0, msg.AuthKeyID); err != nil {
			return err
		}
	}
	return nil
}

func resolveContractSCTPAddrs(network string, rawAddrs []string) ([]net.SCTPAddr, error) {
	if len(rawAddrs) == 0 {
		return nil, nil
	}
	out := make([]net.SCTPAddr, 0, len(rawAddrs))
	for _, raw := range rawAddrs {
		addr, err := net.ResolveSCTPAddr(network, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, *addr)
	}
	return out, nil
}

func sendContractMessages(conn *net.SCTPConn, messages []messageSpec, contract *scenarioContract) error {
	for _, msg := range messages {
		if err := applyMessageSendControls(conn, msg, contract); err != nil {
			return err
		}
		info := &net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
		}
		if msg.Unordered {
			info.Flags |= net.SCTPUnordered
		}
		payload := materializeMessagePayload(msg)
		if _, err := conn.WriteToSCTP([]byte(payload), nil, info); err != nil {
			return err
		}
	}
	return nil
}

func sendContractMessagesToPeer(conn *net.SCTPConn, peer *net.SCTPAddr, messages []messageSpec, contract *scenarioContract) error {
	if peer == nil {
		return fmt.Errorf("no peer address available")
	}
	for _, msg := range messages {
		if err := applyMessageSendControls(conn, msg, contract); err != nil {
			return err
		}
		info := &net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
		}
		if msg.Unordered {
			info.Flags |= net.SCTPUnordered
		}
		payload := materializeMessagePayload(msg)
		if _, err := conn.WriteToSCTP([]byte(payload), peer, info); err != nil {
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
	buf := make([]byte, maxExpectedPayloadSize(expected))
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
		wantPayload := materializeMessagePayload(want)
		if string(buf[:n]) != wantPayload {
			return summary, fmt.Errorf("unexpected server payload %q, want %q", string(buf[:n]), wantPayload)
		}
		if info != nil {
			if info.Stream != want.Stream {
				return summary, fmt.Errorf("unexpected server stream %d, want %d", info.Stream, want.Stream)
			}
			if info.PPID != want.PPID {
				return summary, fmt.Errorf("unexpected server ppid %d, want %d", info.PPID, want.PPID)
			}
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

func maxExpectedPayloadSize(expected []messageSpec) int {
	maxSize := 4096
	for _, msg := range expected {
		size := len(materializeMessagePayload(msg))
		if size > maxSize {
			maxSize = size
		}
	}
	return maxSize
}

func runTriggerAndRead(conn *net.SCTPConn, contract *scenarioContract) (notificationSummary, error) {
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(contract.TimeoutSeconds) * time.Second)); err != nil {
		return notificationSummary{}, err
	}
	if contract.TriggerPayload != "" {
		if _, err := conn.WriteToSCTP([]byte(contract.TriggerPayload), nil, nil); err != nil {
			return notificationSummary{}, err
		}
	}
	return readServerMessages(conn, contract.ServerSendMessages)
}

func openBoundFeatureSocket(contract *scenarioContract) (*net.SCTPConn, *net.SCTPAddr, []net.SCTPAddr, error) {
	if len(contract.ConnectAddresses) == 0 {
		return nil, nil, nil, fmt.Errorf("feature %s did not provide connect addresses", contract.FeatureID)
	}
	raddr, err := net.ResolveSCTPAddr(contract.Transport, contract.ConnectAddresses[0])
	if err != nil {
		return nil, nil, nil, err
	}
	localBase, extras, err := selectBindxLocalAddrs(raddr)
	if err != nil {
		return nil, nil, nil, err
	}
	conn, err := net.ListenSCTP(contract.Transport, localBase)
	if err != nil {
		return nil, nil, nil, err
	}
	return conn, raddr, extras, nil
}

func selectBindxLocalAddrs(remote *net.SCTPAddr) (*net.SCTPAddr, []net.SCTPAddr, error) {
	udpConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remote.IP, Port: remote.Port})
	if err == nil {
		defer udpConn.Close()
		if la, ok := udpConn.LocalAddr().(*net.UDPAddr); ok && la != nil && la.IP != nil {
			base := &net.SCTPAddr{IP: la.IP, Port: 0}
			if !la.IP.IsLoopback() {
				return base, []net.SCTPAddr{{IP: net.IPv4(127, 0, 0, 2), Port: 0}}, nil
			}
			return base, []net.SCTPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}}, nil
		}
	}
	return &net.SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, []net.SCTPAddr{{IP: net.IPv4(127, 0, 0, 2), Port: 0}}, nil
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
	ids := make([]string, 0, len(scenarioCatalog))
	for _, scenario := range scenarioCatalog {
		ids = append(ids, scenario.FeatureID)
	}
	slices.Sort(ids)
	return ids
}

func renderAssocIDs(ids []int32) string {
	if len(ids) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.Itoa(int(id)))
	}
	return "[" + strings.Join(out, ",") + "]"
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
