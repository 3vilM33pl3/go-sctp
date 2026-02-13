#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CPP_BUILD_DIR="${ROOT}/misc/sctp-interop/cpp/build"
GO_BIN="${ROOT}/bin/go"
INTEROP_LOG_DIR="${INTEROP_LOG_DIR:-}"

PORT_GO_SERVER=${PORT_GO_SERVER:-19000}
PORT_CPP_SERVER=${PORT_CPP_SERVER:-19001}

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
  GO_SERVER_LOG="${INTEROP_LOG_DIR}/go_server.log"
  CPP_CLIENT_LOG="${INTEROP_LOG_DIR}/cpp_client.log"
  CPP_SERVER_LOG="${INTEROP_LOG_DIR}/cpp_server.log"
  GO_CLIENT_LOG="${INTEROP_LOG_DIR}/go_client.log"
  : >"${GO_SERVER_LOG}"
  : >"${CPP_CLIENT_LOG}"
  : >"${CPP_SERVER_LOG}"
  : >"${GO_CLIENT_LOG}"
else
  GO_SERVER_LOG=$(mktemp)
  CPP_CLIENT_LOG=$(mktemp)
  CPP_SERVER_LOG=$(mktemp)
  GO_CLIENT_LOG=$(mktemp)
fi

echo "[1/2] Go server <- C++ client"
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/server.go 127.0.0.1 "${PORT_GO_SERVER}" >"${GO_SERVER_LOG}" 2>&1
) &
GO_SERVER_PID=$!
sleep 1
"${CPP_BUILD_DIR}/sctp_cpp_client" 127.0.0.1 "${PORT_GO_SERVER}" "cpp-to-go" 3 101 >"${CPP_CLIENT_LOG}" 2>&1
wait "${GO_SERVER_PID}"

grep -q "GO_SERVER_RECV" "${GO_SERVER_LOG}"
grep -q "payload=cpp-to-go" "${GO_SERVER_LOG}"
grep -q "CPP_CLIENT_SENT" "${CPP_CLIENT_LOG}"

echo "[2/2] C++ server <- Go client"
"${CPP_BUILD_DIR}/sctp_cpp_server" 127.0.0.1 "${PORT_CPP_SERVER}" >"${CPP_SERVER_LOG}" 2>&1 &
CPP_SERVER_PID=$!
sleep 1
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" run ./misc/sctp-interop/go/client.go 127.0.0.1 "${PORT_CPP_SERVER}" "go-to-cpp" 4 202 >"${GO_CLIENT_LOG}" 2>&1
)
wait "${CPP_SERVER_PID}"

grep -q "GO_CLIENT_SENT" "${GO_CLIENT_LOG}"
grep -q "CPP_SERVER_RECV" "${CPP_SERVER_LOG}"
grep -q "payload=go-to-cpp" "${CPP_SERVER_LOG}"

echo "interop matrix PASSED"
echo "GO server log: ${GO_SERVER_LOG}"
echo "CPP client log: ${CPP_CLIENT_LOG}"
echo "CPP server log: ${CPP_SERVER_LOG}"
echo "GO client log: ${GO_CLIENT_LOG}"
