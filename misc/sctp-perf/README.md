# SCTP Performance Matrix (Go, C++, Rust)

This directory contains a cross-language SCTP performance harness for:

- Go runtime SCTP (`misc/sctp-perf/go`)
- C++ SCTP (`misc/sctp-perf/cpp`)
- Rust SCTP stdlib branch (`misc/sctp-perf/rust`)

Each implementation supports the same two benchmark modes:

- `rtt`: ping-pong message round-trip benchmark
- `throughput`: unidirectional send benchmark with server-side sink and summary reply

## Matrix

The harness executes the full ordered matrix for each mode:

- `go server <- go client`
- `go server <- cpp client`
- `go server <- rust client`
- `cpp server <- go client`
- `cpp server <- cpp client`
- `cpp server <- rust client`
- `rust server <- go client`
- `rust server <- cpp client`
- `rust server <- rust client`

## Run

```bash
cd /home/olivier/Projects/sctp/go-sctp-linux
./misc/sctp-perf/harness/run_perf_matrix.sh
```

Main outputs:

- CSV: `artifacts/sctp-perf/perf_matrix_<timestamp>.csv`
- Summary: `artifacts/sctp-perf/perf_matrix_<timestamp>-summary.md`
- Logs: `artifacts/sctp-perf/logs_<timestamp>/`

## Important prerequisites

- Linux with SCTP enabled (`modprobe sctp`)
- `cmake`, `g++`
- Go tree built in this repo (`./src/make.bash`)
- Rust SCTP stage1 compiler from sibling repo (`/home/olivier/Projects/sctp/rust-sctp`)

If Rust lives elsewhere, override:

```bash
RUST_STAGE1=/path/to/rust-sctp/build/x86_64-unknown-linux-gnu/stage1 \
./misc/sctp-perf/harness/run_perf_matrix.sh
```

## Tunables

- `BASE_PORT` (default `19100`)
- `SERVER_HOST` (default `127.0.0.1`)
- `RTT_ITERS` (default `200`)
- `RTT_SIZE` (default `256`)
- `THROUGHPUT_ITERS` (default `2000`)
- `THROUGHPUT_SIZE` (default `1200`)
- `PERF_DATA_DIR` (default `artifacts/sctp-perf`)
