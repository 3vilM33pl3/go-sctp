# SCTP Interop Harness

This directory contains a Linux SCTP interoperability harness between:

- Go (`net` package with in-tree SCTP support)
- C++ (`lksctp` userspace API)

## Layout

- `cpp/`: C++ server and client binaries
- `go/`: Go server and client programs
- `harness/run_matrix.sh`: matrix runner (`Go server <- C++ client`, `C++ server <- Go client`)

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
