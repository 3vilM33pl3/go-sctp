#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CPP_BUILD_DIR="${ROOT}/misc/sctp-interop/cpp/build"
GO_BIN="${ROOT}/bin/go"
INTEROP_LOG_DIR="${INTEROP_LOG_DIR:-}"

PORT_GO_SERVER=${PORT_GO_SERVER:-19000}
PORT_CPP_SERVER=${PORT_CPP_SERVER:-19001}
PORT_GO_MULTI_SERVER=${PORT_GO_MULTI_SERVER:-19002}
GO_MULTI_HOSTS=${GO_MULTI_HOSTS:-127.0.0.1,127.0.0.2}
PORT_GO_MULTI_FAILOVER_SERVER=${PORT_GO_MULTI_FAILOVER_SERVER:-19004}
PORT_CPP_MULTI_SERVER=${PORT_CPP_MULTI_SERVER:-19003}
CPP_MULTI_HOSTS=${CPP_MULTI_HOSTS:-127.0.0.1,127.0.0.2}

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
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/server.go 127.0.0.1 "${PORT_GO_SERVER}" >"${GO_SERVER_GOGO_LOG}" 2>&1
) &
GO_SERVER_PID=$!
sleep 1
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/client.go 127.0.0.1 "${PORT_GO_SERVER}" "go-to-go" 2 99 >"${GO_CLIENT_GOGO_LOG}" 2>&1
)
wait "${GO_SERVER_PID}"

grep -q "GO_SERVER_RECV" "${GO_SERVER_GOGO_LOG}"
grep -q "payload=go-to-go" "${GO_SERVER_GOGO_LOG}"
grep -q "GO_CLIENT_SENT" "${GO_CLIENT_GOGO_LOG}"

echo "[2/4] Go server <- C++ client"
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/server.go 127.0.0.1 "${PORT_GO_SERVER}" >"${GO_SERVER_GOCPP_LOG}" 2>&1
) &
GO_SERVER_PID=$!
sleep 1
"${CPP_BUILD_DIR}/sctp_cpp_client" 127.0.0.1 "${PORT_GO_SERVER}" "cpp-to-go" 3 101 >"${CPP_CLIENT_GOCPP_LOG}" 2>&1
wait "${GO_SERVER_PID}"

grep -q "GO_SERVER_RECV" "${GO_SERVER_GOCPP_LOG}"
grep -q "payload=cpp-to-go" "${GO_SERVER_GOCPP_LOG}"
grep -q "CPP_CLIENT_SENT" "${CPP_CLIENT_GOCPP_LOG}"

echo "[3/4] C++ server <- Go client"
"${CPP_BUILD_DIR}/sctp_cpp_server" 127.0.0.1 "${PORT_CPP_SERVER}" >"${CPP_SERVER_CPPGO_LOG}" 2>&1 &
CPP_SERVER_PID=$!
sleep 1
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/client.go 127.0.0.1 "${PORT_CPP_SERVER}" "go-to-cpp" 4 202 >"${GO_CLIENT_CPPGO_LOG}" 2>&1
)
wait "${CPP_SERVER_PID}"

grep -q "GO_CLIENT_SENT" "${GO_CLIENT_CPPGO_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_SERVER_CPPGO_LOG}"
grep -q "payload=go-to-cpp" "${CPP_SERVER_CPPGO_LOG}"

echo "[4/4] C++ server <- C++ client"
"${CPP_BUILD_DIR}/sctp_cpp_server" 127.0.0.1 "${PORT_CPP_SERVER}" >"${CPP_SERVER_CPPCPP_LOG}" 2>&1 &
CPP_SERVER_PID=$!
sleep 1
"${CPP_BUILD_DIR}/sctp_cpp_client" 127.0.0.1 "${PORT_CPP_SERVER}" "cpp-to-cpp" 5 303 >"${CPP_CLIENT_CPPCPP_LOG}" 2>&1
wait "${CPP_SERVER_PID}"

grep -q "CPP_CLIENT_SENT" "${CPP_CLIENT_CPPCPP_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_SERVER_CPPCPP_LOG}"
grep -q "payload=cpp-to-cpp" "${CPP_SERVER_CPPCPP_LOG}"

echo "[5/7] Go multihome server <- Go multihome client"
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/multi_server.go "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_SERVER}" >"${GO_MULTI_SERVER_LOG}" 2>&1
) &
GO_MULTI_SERVER_PID=$!
sleep 1
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/multi_client.go "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_SERVER}" "go-multi-to-go-multi" 6 404 >"${GO_MULTI_CLIENT_LOG}" 2>&1
)
wait "${GO_MULTI_SERVER_PID}"

grep -q "GO_MULTI_SERVER_RECV" "${GO_MULTI_SERVER_LOG}"
grep -q "payload=go-multi-to-go-multi" "${GO_MULTI_SERVER_LOG}"
grep -q "GO_MULTI_CLIENT_SENT" "${GO_MULTI_CLIENT_LOG}"

echo "[6/7] Go multihome failover path <- Go multihome client"
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/multi_server.go "${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_FAILOVER_SERVER}" >"${GO_MULTI_FAILOVER_SERVER_LOG}" 2>&1
) &
GO_MULTI_FAILOVER_SERVER_PID=$!
sleep 1
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/multi_client.go "127.0.0.3,${GO_MULTI_HOSTS}" "${PORT_GO_MULTI_FAILOVER_SERVER}" "go-multi-failover" 6 606 >"${GO_MULTI_FAILOVER_CLIENT_LOG}" 2>&1
)
wait "${GO_MULTI_FAILOVER_SERVER_PID}"

grep -q "GO_MULTI_SERVER_RECV" "${GO_MULTI_FAILOVER_SERVER_LOG}"
grep -q "payload=go-multi-failover" "${GO_MULTI_FAILOVER_SERVER_LOG}"
grep -q "GO_MULTI_CLIENT_SENT" "${GO_MULTI_FAILOVER_CLIENT_LOG}"

echo "[7/7] C++ multihome server <- C++ multihome client"
"${CPP_BUILD_DIR}/sctp_cpp_server" "${CPP_MULTI_HOSTS}" "${PORT_CPP_MULTI_SERVER}" >"${CPP_MULTI_SERVER_LOG}" 2>&1 &
CPP_MULTI_SERVER_PID=$!
sleep 1
"${CPP_BUILD_DIR}/sctp_cpp_client" "${CPP_MULTI_HOSTS}" "${PORT_CPP_MULTI_SERVER}" "cpp-multi-to-cpp-multi" 7 505 >"${CPP_MULTI_CLIENT_LOG}" 2>&1
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
