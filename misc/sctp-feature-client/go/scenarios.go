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
)

type runner struct {
	client *featureServerClient
}

type featureHandler func(context.Context, *runner, *scenarioContract) (*completionPayload, error)

var supportedFeatureHandlers = map[string]featureHandler{
	"socket_create":                      handleSocketCreate,
	"bind_listen_connect":                handleBasicSend,
	"single_message_boundary":            handleBasicSend,
	"multi_message_boundary":             handleBasicSend,
	"stream_id":                          handleBasicSend,
	"ppid":                               handleBasicSend,
	"nodelay":                            handleNoDelay,
	"initmsg":                            handleInitMsg,
	"rto_assoc_parameters":               handleRTOInfo,
	"default_sndinfo_recvrcvinfo":        handleDefaultSendInfo,
	"recvnxtinfo":                        handleRecvNxtInfo,
	"autoclose":                          handleAutoClose,
	"notifications":                      handleNotificationScenario,
	"event_subscription_matrix":          handleNotificationScenario,
	"association_shutdown_notifications": handleNotificationScenario,
	"multi_bind":                         handleMultiBind,
	"local_addr_enum":                    handleLocalAddrEnum,
	"peer_addr_enum":                     handlePeerAddrEnum,
	"bindx_add_remove":                   handleBindxAddRemove,
	"primary_addr_management":            handlePrimaryAddrManagement,
	"peer_primary_addr_request":          handlePeerPrimaryAddrRequest,
	"peeloff_assoc":                      handlePeelOffAssoc,
	"assoc_id_listing":                   handleAssocIDListing,
	"assoc_status_opt_info":              handleAssocStatus,
	"stream_reconfig_reset":              handleStreamReset,
	"stream_reconfig_add_streams":        handleStreamAddStreams,
	"negative_connect_error":             handleNegativeConnectError,
	"unordered_delivery":                 handleUnorderedDelivery,
}

func (r *runner) runFeature(ctx context.Context, sessionID string, feature catalogFeature) (*featureState, error) {
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
	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
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
	conn, err := dialContract(contract)
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

func handleBindxAddRemove(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, peer, extra, err := openBoundFeatureSocket(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(extra) > 0 {
		if err := conn.BindAddrs(extra); err != nil {
			return nil, err
		}
		if err := conn.UnbindAddrs(extra); err != nil {
			return nil, err
		}
		if err := conn.BindAddrs(extra); err != nil {
			return nil, err
		}
	}
	if err := sendContractMessagesToPeer(conn, peer, contract.ClientSendMessages); err != nil {
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

	peerAddrs, err := conn.PeerAddrs()
	if err != nil {
		return nil, err
	}
	if len(peerAddrs) == 0 {
		return nil, fmt.Errorf("no peer addresses available for primary-address management")
	}
	if err := conn.SetPrimaryAddr(&peerAddrs[len(peerAddrs)-1]); err != nil {
		return nil, err
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	target := peerAddrs[len(peerAddrs)-1]
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetPrimaryAddr succeeded for %s", target.String()),
		ReportText:   fmt.Sprintf("client requested peer address %s as the primary destination", target.String()),
	}, nil
}

func handlePeerPrimaryAddrRequest(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddrs, err := conn.LocalAddrs()
	if err != nil {
		return nil, err
	}
	if len(localAddrs) == 0 {
		return nil, fmt.Errorf("no local addresses available for peer primary-address request")
	}
	if err := conn.SetPeerPrimaryAddr(&localAddrs[0]); err != nil {
		return nil, err
	}
	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("SetPeerPrimaryAddr succeeded for %s", localAddrs[0].String()),
		ReportText:   fmt.Sprintf("client requested peer primary address change to local address %s", localAddrs[0].String()),
	}, nil
}

func handlePeelOffAssoc(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peeled, err := conn.PeelOff(0)
	if err != nil {
		return nil, err
	}
	defer peeled.Close()

	if err := sendContractMessages(peeled, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "PeelOff(0) succeeded and the peeled association sent the probe payload",
		ReportText:   "client peeled the association onto a dedicated socket and sent the probe payload there",
	}, nil
}

func handleAssocIDListing(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	ids, err := conn.AssocIDs()
	if err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("enumerated %d association id(s)", len(ids)),
		ReportText:   fmt.Sprintf("association ids: %s", renderAssocIDs(ids)),
	}, nil
}

func handleAssocStatus(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := sendContractMessages(conn, contract.ClientSendMessages); err != nil {
		return nil, err
	}
	status, err := conn.AssocStatus(0)
	if err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("association state=%d in_streams=%d out_streams=%d primary=%s", status.State, status.InStreams, status.OutStreams, status.PrimaryAddr.String()),
		ReportText:   fmt.Sprintf("association status state=%d in_streams=%d out_streams=%d primary=%s", status.State, status.InStreams, status.OutStreams, status.PrimaryAddr.String()),
	}, nil
}

func handleStreamReset(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.EnableStreamReset(net.SCTPStreamResetIncoming | net.SCTPStreamResetOutgoing); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	if err := conn.ResetStreams(net.SCTPStreamResetOutgoing, []uint16{contract.ServerSendMessages[0].Stream}); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: fmt.Sprintf("stream reset request succeeded for stream=%d", contract.ServerSendMessages[0].Stream),
		ReportText:   fmt.Sprintf("client requested SCTP stream reset for stream=%d", contract.ServerSendMessages[0].Stream),
	}, nil
}

func handleStreamAddStreams(ctx context.Context, _ *runner, contract *scenarioContract) (*completionPayload, error) {
	conn, err := dialContract(contract)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.EnableStreamReset(net.SCTPStreamResetIncoming | net.SCTPStreamResetOutgoing); err != nil {
		return nil, err
	}
	if _, err := runTriggerAndRead(conn, contract); err != nil {
		return nil, err
	}
	if err := conn.AddStreams(1, 1); err != nil {
		return nil, err
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "AddStreams(1,1) succeeded",
		ReportText:   "client requested one additional inbound stream and one additional outbound stream",
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
			Flags:  net.SCTPUnordered,
		}
		if _, err := conn.WriteToSCTP([]byte(msg.Payload), nil, info); err != nil {
			return nil, err
		}
	}
	return &completionPayload{
		EvidenceKind: "runtime",
		EvidenceText: "sent the probe payload with SCTPSndInfo.Flags set to net.SCTPUnordered",
		ReportText:   "client attempted unordered delivery using net.SCTPUnordered",
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

func sendContractMessagesToPeer(conn *net.SCTPConn, peer *net.SCTPAddr, messages []messageSpec) error {
	if peer == nil {
		return fmt.Errorf("no peer address available")
	}
	for _, msg := range messages {
		info := &net.SCTPSndInfo{
			Stream: msg.Stream,
			PPID:   msg.PPID,
		}
		if _, err := conn.WriteToSCTP([]byte(msg.Payload), peer, info); err != nil {
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
	ids := make([]string, 0, len(supportedFeatureHandlers))
	for id := range supportedFeatureHandlers {
		ids = append(ids, id)
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
