# SCTP Interop Harness

This directory contains a Linux SCTP interoperability harness between:

- Go (`net` package with in-tree SCTP support)
- C++ (`lksctp` userspace API)

## Layout

- `cpp/`: C++ server and client binaries
- `go/`: Go server and client programs
- `harness/run_matrix.sh`: matrix runner for:
  - `Go server <- Go client`
  - `Go server <- C++ client`
  - `C++ server <- Go client`
  - `C++ server <- C++ client`
  - `Go multihome server <- Go multihome client`
  - `Go multihome failover path <- Go multihome client`
  - `C++ multihome server <- C++ multihome client`

## Prerequisites

- Linux kernel with SCTP support (`modprobe sctp`)
- `libsctp-dev` (or distro equivalent)
- `cmake`, `g++`
- Built Go tree in this repo (`./src/make.bash`)

## Run

```bash
./misc/sctp-interop/harness/run_matrix.sh
```

Optional environment overrides:

- `PORT_GO_SERVER` (default `19000`)
- `PORT_CPP_SERVER` (default `19001`)
- `PORT_GO_MULTI_SERVER` (default `19002`)
- `GO_MULTI_HOSTS` (default `127.0.0.1,127.0.0.2`)
- `PORT_GO_MULTI_FAILOVER_SERVER` (default `19004`)
- `PORT_CPP_MULTI_SERVER` (default `19003`)
- `CPP_MULTI_HOSTS` (default `127.0.0.1,127.0.0.2`)
