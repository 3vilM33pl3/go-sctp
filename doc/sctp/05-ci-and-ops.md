# CI and Operations

## Recommended CI Topology

- Authoritative SCTP jobs: self-hosted Linux runner
- Optional hosted jobs: non-SCTP unit and lint checks

## Runner Requirements

- Kernel SCTP module available (`modprobe sctp`)
- Packages:
  - `libsctp-dev`
  - `lksctp-tools`
  - `cmake`
  - `g++`

## Standard Build Pipeline

```bash
cd src
./make.bash
cd ..
GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP|TestParseNetworkSCTP|TestResolveSCTPAddrUnknownNetwork' -count=1
./misc/sctp-interop/harness/run_matrix.sh
```

## Operational Notes

- v1 is Linux-first; non-Linux behavior is stubbed as unsupported.
- Keep interop ports configurable with env vars in CI:
  - `PORT_GO_SERVER`
  - `PORT_CPP_SERVER`
