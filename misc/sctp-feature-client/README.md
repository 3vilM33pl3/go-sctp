# Go SCTP Feature Client

This directory contains a Go client for the FreeBSD SCTP feature server in
`/home/olivier/Projects/sctp/sctp-conformance`.

The client:

- fetches the live feature catalog from the server
- creates a session
- executes the currently supported scenarios with the in-tree Go SCTP API
- explicitly marks unsupported features with evidence text

## Build

Run from the `go-sctp-linux` repository root:

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
- notification scenarios
- multihome connect
- local and peer address enumeration
- invalid-target error path
- unordered delivery attempt via `SCTPSndInfo.Flags`

Explicitly unsupported now:

- `SCTP_RTOINFO`
- default sndinfo socket options
- `SCTP_RECVNXTINFO`
- `SCTP_AUTOCLOSE`
- bindx add/remove
- primary-address management
- peeloff
- assoc status / assoc-id listing
- stream reconfiguration
