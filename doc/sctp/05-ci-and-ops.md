# CI and Operations

## Building

The tree tracks Go master (`go1.28-devel`), whose `cmd/dist` requires a
bootstrap toolchain of at least Go 1.26:

```bash
go install golang.org/dl/go1.27.1@latest && ~/go/bin/go1.27.1 download
export GOROOT_BOOTSTRAP=$HOME/sdk/go1.27.1
cd src && ./make.bash
```

`./bin/go version` must report a `devel` version: `cmd/api` only reads
`api/next` on development versions, and the API registration lives there.

## Pipeline

1. `./src/make.bash`
2. `go test net -run 'SCTP|Sctp' -count=1` (and `-race`)
3. cross-GOOS `go build std` + `go vet net` matrix (see 04-test-strategy.md)
4. `go test cmd/api -run Check -check && go test cmd/relnote -check`
5. `./misc/sctp-interop/harness/run_matrix.sh`
6. `./src/run.bash` (nightly or on demand): the complete Go test suite.

## Runner requirements

- Kernel SCTP (`modprobe sctp` on Linux, `kldload sctp` on FreeBSD).
- For the interop matrix: `cmake`, `g++`, `linux-libc-dev` (or
  `libsctp-dev`/`lksctp-tools`).
- `TMPDIR` must not lie below a stray `.git` directory: the Go tests build
  throwaway modules under `TMPDIR`, and VCS stamping then runs `git status`
  in that repository. A `.git` in `/data/tmp` made `cmd/go`, `cmd/compile`
  and `cmd/cgo` script tests fail with "error obtaining VCS status" on one
  runner; point `TMPDIR` elsewhere or set `GOFLAGS=-buildvcs=false`.

## Operational notes

- Linux and FreeBSD/amd64 are the supported platforms; every other GOOS
  compiles with stubs that return `errors.ErrUnsupported`.
- `SetPeerPrimaryAddr` needs ASCONF enabled on Linux (`net.sctp.addip_enable`)
  and returns `EPERM` otherwise; the tests skip that step.
- Keep interop ports configurable with `PORT_GO_SERVER` / `PORT_CPP_SERVER`.
