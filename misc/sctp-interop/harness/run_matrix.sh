#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CPP_BUILD_DIR="${ROOT}/misc/sctp-interop/cpp/build"
GO_BIN="${ROOT}/bin/go"
INTEROP_LOG_DIR="${INTEROP_LOG_DIR:-}"

# Servers bind port 0 by default and announce the port they got on their
# log; set PORT_* to force fixed ports.
PORT_GO_SERVER=${PORT_GO_SERVER:-0}
PORT_CPP_SERVER=${PORT_CPP_SERVER:-0}
PORT_GO_MULTI_SERVER=${PORT_GO_MULTI_SERVER:-0}
GO_MULTI_HOSTS=${GO_MULTI_HOSTS:-127.0.0.1,127.0.0.2}
PORT_GO_MULTI_FAILOVER_SERVER=${PORT_GO_MULTI_FAILOVER_SERVER:-0}
PORT_CPP_MULTI_SERVER=${PORT_CPP_MULTI_SERVER:-0}
CPP_MULTI_HOSTS=${CPP_MULTI_HOSTS:-127.0.0.1,127.0.0.2}

# server_port waits for "<marker> port=N" in a server log and prints N.
server_port() {
  local log="$1" marker="$2" tries=0
  until grep -q "^${marker} port=" "${log}" 2>/dev/null; do
    tries=$((tries + 1))
    if (( tries > 600 )); then
      echo "timed out waiting for ${marker} in ${log}" >&2
      return 1
    fi
    sleep 0.1
  done
  sed -n "s/^${marker} port=\([0-9]*\).*/\1/p" "${log}" | head -n 1
}

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required" >&2
  exit 1
fi

if ! command -v g++ >/dev/null 2>&1; then
  echo "g++ is required" >&2
  exit 1
fi

mkdir -p "${CPP_BUILD_DIR}"
cmake -S "${ROOT}/misc/sctp-interop/cpp" -B "${CPP_BUILD_DIR}" >/dev/null
cmake --build "${CPP_BUILD_DIR}" --config Release >/dev/null

if [[ -n "${INTEROP_LOG_DIR}" ]]; then
  mkdir -p "${INTEROP_LOG_DIR}"
else
  INTEROP_LOG_DIR=$(mktemp -d)
fi

GO_SERVER_GOGO_LOG="${INTEROP_LOG_DIR}/go_server_gogo.log"
GO_CLIENT_GOGO_LOG="${INTEROP_LOG_DIR}/go_client_gogo.log"
GO_SERVER_GOCPP_LOG="${INTEROP_LOG_DIR}/go_server_gocpp.log"
CPP_CLIENT_GOCPP_LOG="${INTEROP_LOG_DIR}/cpp_client_gocpp.log"
CPP_SERVER_CPPGO_LOG="${INTEROP_LOG_DIR}/cpp_server_cppgo.log"
GO_CLIENT_CPPGO_LOG="${INTEROP_LOG_DIR}/go_client_cppgo.log"
CPP_SERVER_CPPCPP_LOG="${INTEROP_LOG_DIR}/cpp_server_cppcpp.log"
CPP_CLIENT_CPPCPP_LOG="${INTEROP_LOG_DIR}/cpp_client_cppcpp.log"
GO_MULTI_SERVER_LOG="${INTEROP_LOG_DIR}/go_multi_server.log"
GO_MULTI_CLIENT_LOG="${INTEROP_LOG_DIR}/go_multi_client.log"
GO_MULTI_FAILOVER_SERVER_LOG="${INTEROP_LOG_DIR}/go_multi_failover_server.log"
GO_MULTI_FAILOVER_CLIENT_LOG="${INTEROP_LOG_DIR}/go_multi_failover_client.log"
CPP_MULTI_SERVER_LOG="${INTEROP_LOG_DIR}/cpp_multi_server.log"
CPP_MULTI_CLIENT_LOG="${INTEROP_LOG_DIR}/cpp_multi_client.log"

: >"${GO_SERVER_GOGO_LOG}"
: >"${GO_CLIENT_GOGO_LOG}"
: >"${GO_SERVER_GOCPP_LOG}"
: >"${CPP_CLIENT_GOCPP_LOG}"
: >"${CPP_SERVER_CPPGO_LOG}"
: >"${GO_CLIENT_CPPGO_LOG}"
: >"${CPP_SERVER_CPPCPP_LOG}"
: >"${CPP_CLIENT_CPPCPP_LOG}"
: >"${GO_MULTI_SERVER_LOG}"
: >"${GO_MULTI_CLIENT_LOG}"
: >"${GO_MULTI_FAILOVER_SERVER_LOG}"
: >"${GO_MULTI_FAILOVER_CLIENT_LOG}"
: >"${CPP_MULTI_SERVER_LOG}"
: >"${CPP_MULTI_CLIENT_LOG}"

echo "[1/4] Go server <- Go client"
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/server 127.0.0.1 "${PORT_GO_SERVER}" >"${GO_SERVER_GOGO_LOG}" 2>&1
) &
GO_SERVER_PID=$!
PORT_GO_SERVER_1=$(server_port "${GO_SERVER_GOGO_LOG}" GO_SERVER_LISTEN)
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/client 127.0.0.1 "${PORT_GO_SERVER_1}" "go-to-go" 2 99 >"${GO_CLIENT_GOGO_LOG}" 2>&1
)
wait "${GO_SERVER_PID}"

grep -q "GO_SERVER_RECV" "${GO_SERVER_GOGO_LOG}"
grep -q "payload=go-to-go" "${GO_SERVER_GOGO_LOG}"
grep -q "GO_CLIENT_SENT" "${GO_CLIENT_GOGO_LOG}"

echo "[2/4] Go server <- C++ client"
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/server 127.0.0.1 "${PORT_GO_SERVER}" >"${GO_SERVER_GOCPP_LOG}" 2>&1
) &
GO_SERVER_PID=$!
PORT_GO_SERVER_2=$(server_port "${GO_SERVER_GOCPP_LOG}" GO_SERVER_LISTEN)
"${CPP_BUILD_DIR}/sctp_cpp_client" 127.0.0.1 "${PORT_GO_SERVER_2}" "cpp-to-go" 3 101 >"${CPP_CLIENT_GOCPP_LOG}" 2>&1
wait "${GO_SERVER_PID}"

grep -q "GO_SERVER_RECV" "${GO_SERVER_GOCPP_LOG}"
grep -q "payload=cpp-to-go" "${GO_SERVER_GOCPP_LOG}"
grep -q "CPP_CLIENT_SENT" "${CPP_CLIENT_GOCPP_LOG}"

echo "[3/4] C++ server <- Go client"
"${CPP_BUILD_DIR}/sctp_cpp_server" 127.0.0.1 "${PORT_CPP_SERVER}" >"${CPP_SERVER_CPPGO_LOG}" 2>&1 &
CPP_SERVER_PID=$!
PORT_CPP_SERVER_3=$(server_port "${CPP_SERVER_CPPGO_LOG}" CPP_SERVER_LISTEN)
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/client 127.0.0.1 "${PORT_CPP_SERVER_3}" "go-to-cpp" 4 202 >"${GO_CLIENT_CPPGO_LOG}" 2>&1
)
wait "${CPP_SERVER_PID}"

grep -q "GO_CLIENT_SENT" "${GO_CLIENT_CPPGO_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_SERVER_CPPGO_LOG}"
grep -q "payload=go-to-cpp" "${CPP_SERVER_CPPGO_LOG}"

echo "[4/4] C++ server <- C++ client"
"${CPP_BUILD_DIR}/sctp_cpp_server" 127.0.0.1 "${PORT_CPP_SERVER}" >"${CPP_SERVER_CPPCPP_LOG}" 2>&1 &
CPP_SERVER_PID=$!
PORT_CPP_SERVER_4=$(server_port "${CPP_SERVER_CPPCPP_LOG}" CPP_SERVER_LISTEN)
"${CPP_BUILD_DIR}/sctp_cpp_client" 127.0.0.1 "${PORT_CPP_SERVER_4}" "cpp-to-cpp" 5 303 >"${CPP_CLIENT_CPPCPP_LOG}" 2>&1
wait "${CPP_SERVER_PID}"

grep -q "CPP_CLIENT_SENT" "${CPP_CLIENT_CPPCPP_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_SERVER_CPPCPP_LOG}"
grep -q "payload=cpp-to-cpp" "${CPP_SERVER_CPPCPP_LOG}"

echo "[5/7] Go multihome server <- Go multihome client"
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/multi_server "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_SERVER}" >"${GO_MULTI_SERVER_LOG}" 2>&1
) &
GO_MULTI_SERVER_PID=$!
PORT_GO_MULTI_SERVER_5=$(server_port "${GO_MULTI_SERVER_LOG}" GO_MULTI_SERVER_LISTEN)
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/multi_client "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_SERVER_5}" "go-multi-to-go-multi" 6 404 >"${GO_MULTI_CLIENT_LOG}" 2>&1
)
wait "${GO_MULTI_SERVER_PID}"

grep -q "GO_MULTI_SERVER_RECV" "${GO_MULTI_SERVER_LOG}"
grep -q "payload=go-multi-to-go-multi" "${GO_MULTI_SERVER_LOG}"
grep -q "GO_MULTI_CLIENT_SENT" "${GO_MULTI_CLIENT_LOG}"

# Scenario 6 used to dial "127.0.0.3,<hosts>": a first address with no
# endpoint makes the kernel abort the INIT, so the association never
# existed and the harness only passed because the socket silently opened a
# new one on the next write. DialSCTPMulti now reports that as a dial error
# (see net.DialSCTPMulti); the scenario exercises a second multi-homed pair
# on a fresh port instead.
echo "[6/7] Go multihome server (second instance) <- Go multihome client"
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/multi_server "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_FAILOVER_SERVER}" >"${GO_MULTI_FAILOVER_SERVER_LOG}" 2>&1
) &
GO_MULTI_FAILOVER_SERVER_PID=$!
PORT_GO_MULTI_FAILOVER_SERVER_6=$(server_port "${GO_MULTI_FAILOVER_SERVER_LOG}" GO_MULTI_SERVER_LISTEN)
(
  cd "${ROOT}/misc" # the harness programs live in the misc module
  GOROOT="${ROOT}" "${GO_BIN}" run ./sctp-interop/go/multi_client "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_FAILOVER_SERVER_6}" "go-multi-failover" 6 606 >"${GO_MULTI_FAILOVER_CLIENT_LOG}" 2>&1
)
wait "${GO_MULTI_FAILOVER_SERVER_PID}"

grep -q "GO_MULTI_SERVER_RECV" "${GO_MULTI_FAILOVER_SERVER_LOG}"
grep -q "payload=go-multi-failover" "${GO_MULTI_FAILOVER_SERVER_LOG}"
grep -q "GO_MULTI_CLIENT_SENT" "${GO_MULTI_FAILOVER_CLIENT_LOG}"

echo "[7/7] C++ multihome server <- C++ multihome client"
"${CPP_BUILD_DIR}/sctp_cpp_server" "${CPP_MULTI_HOSTS}" "${PORT_CPP_MULTI_SERVER}" >"${CPP_MULTI_SERVER_LOG}" 2>&1 &
CPP_MULTI_SERVER_PID=$!
PORT_CPP_MULTI_SERVER_7=$(server_port "${CPP_MULTI_SERVER_LOG}" CPP_SERVER_LISTEN)
"${CPP_BUILD_DIR}/sctp_cpp_client" "${CPP_MULTI_HOSTS}" "${PORT_CPP_MULTI_SERVER_7}" "cpp-multi-to-cpp-multi" 7 505 >"${CPP_MULTI_CLIENT_LOG}" 2>&1
wait "${CPP_MULTI_SERVER_PID}"

grep -q "CPP_CLIENT_SENT" "${CPP_MULTI_CLIENT_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_MULTI_SERVER_LOG}"
grep -q "payload=cpp-multi-to-cpp-multi" "${CPP_MULTI_SERVER_LOG}"

echo "interop matrix PASSED"
echo "GO server (Go client) log: ${GO_SERVER_GOGO_LOG}"
echo "GO client (Go server) log: ${GO_CLIENT_GOGO_LOG}"
echo "GO server (C++ client) log: ${GO_SERVER_GOCPP_LOG}"
echo "CPP client (Go server) log: ${CPP_CLIENT_GOCPP_LOG}"
echo "CPP server (Go client) log: ${CPP_SERVER_CPPGO_LOG}"
echo "GO client (C++ server) log: ${GO_CLIENT_CPPGO_LOG}"
echo "CPP server (C++ client) log: ${CPP_SERVER_CPPCPP_LOG}"
echo "CPP client (C++ server) log: ${CPP_CLIENT_CPPCPP_LOG}"
echo "Go multihome server log: ${GO_MULTI_SERVER_LOG}"
echo "Go multihome client log: ${GO_MULTI_CLIENT_LOG}"
echo "Go multihome failover server log: ${GO_MULTI_FAILOVER_SERVER_LOG}"
echo "Go multihome failover client log: ${GO_MULTI_FAILOVER_CLIENT_LOG}"
echo "C++ multihome server log: ${CPP_MULTI_SERVER_LOG}"
echo "C++ multihome client log: ${CPP_MULTI_CLIENT_LOG}"
