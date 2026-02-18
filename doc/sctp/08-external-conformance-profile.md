# External SCTP Conformance Profile

This profile defines how to evaluate this Go runtime SCTP implementation against
external (non-project) SCTP validation tools and standards references.

It is intentionally split into:
- protocol conformance (wire behavior),
- socket API conformance (RFC 6458 style),
- interoperability conformance (independent implementations),
- extension conformance (optional features).

## 1) Scope and Claims

This profile supports evidence for:
- Core SCTP behavior per `RFC 9260` on Linux.
- SCTP sockets API behavior per `RFC 6458` (where exercised).
- Multihoming/failover behavior (`RFC 9260`, `RFC 5061` surface areas used here).
- PR-SCTP/interleaving behavior only if extension suites are enabled.

This profile does **not** claim formal IETF certification. There is no single
official IETF "SCTP conformance suite" that fully certifies all SCTP RFCs.

## 2) External Test Assets

Use these external tools/suites:

1. `lksctp-tools` (userspace SCTP tools and functional tests)
2. SCTP Conformance Test Suite Project (`networktest`, SourceForge)
3. `packetdrill` (scripted stack-level packet tests)
4. PR-SCTP packetdrill tests (`PR_SCTP_Testsuite`)
5. `TSCTP` (basic cross-stack SCTP functional/interoperability checks)

## 3) Test Matrix

| Layer | Standard Focus | Tool | Required |
|---|---|---|---|
| Baseline kernel/userspace SCTP availability | Linux SCTP stack readiness | `checksctp`, `sctp_test`, `sctp_darn` | Yes |
| Runtime SCTP API behavior | RFC 6458 mapping + Go API surface | Go `net` SCTP tests + C API spot checks | Yes |
| Wire-level protocol behavior | RFC 9260 core chunks/states/error handling | `packetdrill`, `networktest` | Yes |
| Interop behavior | Independent endpoint compatibility | Existing Go/C++ matrix + `TSCTP` | Yes |
| Extensions: PR-SCTP, interleaving | RFC 3758, RFC 8260, related | `PR_SCTP_Testsuite` | Optional but recommended |

## 4) Environment

Linux host requirements:
- SCTP kernel module enabled (`modprobe sctp`).
- Build chain: `gcc`, `cmake`, `make`, `git`.
- Existing project requirements from `05-ci-and-ops.md`.

Install common external tools (Debian/Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y lksctp-tools lksctp-tools-dev cmake gcc g++ make git
```

## 5) Execution Profile

Run all commands from:

```bash
cd /home/olivier/Projects/sctp/go-sctp-linux
```

### Phase A: Project Baseline (already in-repo)

```bash
cd src
./make.bash
cd ..
GOROOT=$(pwd) ./bin/go test net -run '^TestSCTP|TestParseNetworkSCTP|TestResolveSCTP' -count=1 -v
./misc/sctp-interop/harness/run_matrix.sh
```

Pass gate:
- `go test` SCTP tests pass (or explicitly skip only when kernel SCTP absent).
- Interop harness prints `interop matrix PASSED`.

### Phase B: External Baseline with `lksctp-tools`

```bash
checksctp
sctp_test -H 127.0.0.1 -P 10010 -l &
sleep 1
sctp_test -H 127.0.0.1 -P 10011 -h 127.0.0.1 -p 10010 -s -c 1
pkill -f "sctp_test -H 127.0.0.1 -P 10010 -l" || true
```

Pass gate:
- `checksctp` indicates SCTP support.
- `sctp_test` server/client exchange succeeds without crashes.

### Phase C: External Protocol Conformance (`networktest`)

Use SourceForge SCTP conformance suite:
- Download/build `networktest` SCTP suite.
- Execute packet-level tests for:
  - core SCTP state/chunk handling,
  - auth/reconfig tests as available.

Pass gate:
- No critical failures in core SCTP test categories.
- Any skipped/unsupported tests documented with reason.

### Phase D: Scripted Wire Checks (`packetdrill`)

Build/install `packetdrill` and run SCTP-focused scripts:
- handshake/state transitions,
- ABORT/error cause handling,
- retransmission/ack behavior,
- path/failover scenarios (where scripts exist).

Pass gate:
- All selected SCTP scripts pass on target kernel/runtime combination.

### Phase E: Extension Conformance (`PR_SCTP_Testsuite`) [Recommended]

Run packetdrill scripts from `PR_SCTP_Testsuite` for:
- PR-SCTP negotiation and behavior (`RFC 3758`),
- interleaving/scheduler-related cases (`RFC 8260`) if enabled.

Pass gate:
- All extension tests relevant to enabled features pass.
- If a feature is intentionally not enabled, mark as "out of scope".

### Phase F: Independent Functional Tool (`TSCTP`)

Run TSCTP server/client exchange as an additional external IUT check.

Pass gate:
- Clean association setup, data transfer, teardown across tested address sets.

## 6) RFC Coverage Map

| RFC | Topic | Evidence Source |
|---|---|---|
| `RFC 9260` | Core SCTP protocol | Phase A + C + D |
| `RFC 6458` | SCTP sockets API mapping | Phase A + B (+ targeted API checks) |
| `RFC 5061` | Dynamic address reconfiguration | Phase A multihome/failover + C |
| `RFC 3758` | Partial reliability | Phase E |
| `RFC 8260` | Interleaving/schedulers | Phase E |

## 7) Output Artifacts (for validation/release evidence)

Store under:

```text
artifacts/external-conformance/
```

Recommended files:
- `env.txt` (kernel version, distro, tool versions)
- `phase-a-go-tests.log`
- `phase-a-interop.log`
- `phase-b-lksctp-tools.log`
- `phase-c-networktest.log`
- `phase-d-packetdrill.log`
- `phase-e-pr-sctp.log`
- `phase-f-tsctp.log`
- `summary.md` (pass/fail and deviations)

## 8) Decision Rule for "Standards-Conformant Enough" Claim

Allow "standards-conformant on tested profile" only when:
- Phase A, B, D pass.
- Phase C has no untriaged critical failures.
- Any skipped tests are explicitly scoped with rationale.
- Extension claims (`PR-SCTP`, interleaving) are made only if Phase E passes.

## 9) Known Limits

- External suites vary in age and maintenance status.
- Some suites target earlier RFC baselines (`RFC 4960` era) and need result interpretation against newer `RFC 9260`.
- Kernel behavior and userspace API behavior can differ by distro/kernel patch level.

## 10) Sources

- RFC 9260: https://www.rfc-editor.org/rfc/rfc9260
- RFC 6458: https://datatracker.ietf.org/doc/html/rfc6458
- RFC 5061: https://www.rfc-editor.org/rfc/rfc5061
- RFC 3758: https://www.rfc-editor.org/rfc/rfc3758
- RFC 8260: https://datatracker.ietf.org/doc/html/rfc8260
- SCTP Conformance Test Suite (networktest): https://networktest.sourceforge.net/
- lksctp-tools: https://github.com/sctp/lksctp-tools
- packetdrill: https://github.com/google/packetdrill
- PR_SCTP_Testsuite: https://nplab.github.io/PR_SCTP_Testsuite/
- TSCTP: https://www.nntb.no/~dreibh/tsctp/
