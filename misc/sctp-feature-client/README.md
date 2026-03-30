# Go SCTP Feature Client

This directory contains a Go client for the FreeBSD SCTP feature server in
`/home/olivier/Projects/sctp/sctp-conformance`.

The client:

- fetches the live feature catalog from the server
- creates a session
- executes the current SCTP conformance catalog with the in-tree Go SCTP API
- leaves only unknown future server feature ids to the generic `unsupported`
  fallback

## Build

Run from the `go-sctp` repository root:

```bash
GOROOT=$(pwd) ./bin/go build ./misc/sctp-feature-client/go
```

## Run

```bash
GOROOT=$(pwd) ./bin/go run ./misc/sctp-feature-client/go --base-url http://free.metatao.net:18080
```

Optional flags:

- `--agent-name`
- `--environment-name`
- `--features bind_listen_connect,nodelay`
- `--include-manual-setup`
- `--list-scenarios`

Features whose server contract declares `manual_setup_required=true` are skipped
by default. To run them, either:

- select them explicitly with `--features`
- or opt into all of them with `--include-manual-setup`

To print the Go-side feature mapping without contacting the server:

```bash
GOROOT=$(pwd) ./bin/go run ./misc/sctp-feature-client/go --list-scenarios
```

That output is keyed by `feature_id`, so it can be matched directly against the
dashboard and server API while keeping the FreeBSD server client-agnostic.

## Contract Lifecycle

The Go client does not hardcode per-feature SCTP payloads or peer addresses.

For each feature:

1. it fetches the server catalog with `GET /v1/features`
2. it creates a session with `POST /v1/sessions`
3. it calls `POST /v1/sessions/{sessionId}/features/{featureId}/start`
4. it reads the returned `contract`
5. the selected handler uses that contract to dial the SCTP endpoint and execute the scenario

In code, `runFeature()` reads `started.Contract`, and handlers such as
`handleBasicSend()` consume fields like `contract.ClientSendMessages`.

That is why multiple dashboard features can share one Go handler: the handler is
generic, while the feature-specific payloads and addresses come from the
FreeBSD server contract.

## Current Support

Implemented now:

- socket create
- basic send scenarios
- `SCTP_NODELAY`
- `SCTP_INITMSG`
- `SCTP_RTOINFO`
- `SCTP_DELAYED_SACK`
- `SCTP_MAX_BURST`
- `SCTP_DEFAULT_SNDINFO`
- `SCTP_RECVRCVINFO`
- large-message reassembly
- `SCTP_MAXSEG` fragmentation control
- `SCTP_RECVNXTINFO`
- `SCTP_AUTOCLOSE`
- notification scenarios
- typed notification parsing in the feature client for address-change and partial-delivery events
- multihome connect
- bindx add/remove on a pre-connected client socket
- local and peer address enumeration
- primary-address management
- peer primary-address request
- association peeloff
- association id listing
- association status
- stream reset enable/request
- stream add-stream reconfiguration
- invalid-target error path
- unordered delivery attempt via `SCTPSndInfo.Flags`

Manual-setup scenarios currently exposed by the server and skipped by default include:

- PR-SCTP loss-based checks
- AUTH and ASCONF scenarios that depend on host sysctls
- peer-address-change notifications that need a real path-state transition
- partial-delivery notifications that need host/socket tuning so large inbound messages trigger partial delivery

## Validation Notes

- Local validation runs with:
  - `GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP' -count=1`
  - `GO111MODULE=off GOROOT=$(pwd) ./bin/go test ./misc/sctp-feature-client/go -count=1`
- Full end-to-end validation against the FreeBSD reference server still requires
  a Linux host with real SCTP reachability to `free.metatao.net`.
