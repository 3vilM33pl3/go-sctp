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

## Current Support

Implemented now:

- socket create
- basic send scenarios
- `SCTP_NODELAY`
- `SCTP_INITMSG`
- `SCTP_RTOINFO`
- `SCTP_DEFAULT_SNDINFO`
- `SCTP_RECVRCVINFO`
- `SCTP_RECVNXTINFO`
- `SCTP_AUTOCLOSE`
- notification scenarios
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

## Validation Notes

- Local validation runs with:
  - `GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP' -count=1`
  - `GO111MODULE=off GOROOT=$(pwd) ./bin/go test ./misc/sctp-feature-client/go -count=1`
- Full end-to-end validation against the FreeBSD reference server still requires
  a Linux host with real SCTP reachability to `free.metatao.net`.
