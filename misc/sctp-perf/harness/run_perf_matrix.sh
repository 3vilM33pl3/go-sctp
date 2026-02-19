#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT}/misc/sctp-perf/harness/common.sh"

PERF_DIR="${ROOT}/misc/sctp-perf"
BUILD_DIR="${PERF_DIR}/build"
GO_BUILD_DIR="${BUILD_DIR}/go"
CPP_BUILD_DIR="${BUILD_DIR}/cpp"
RUST_BUILD_DIR="${BUILD_DIR}/rust"

GO_BIN="${GO_BIN:-${ROOT}/bin/go}"
RUST_STAGE1="${RUST_STAGE1:-/home/olivier/Projects/sctp/rust-sctp/build/x86_64-unknown-linux-gnu/stage1}"
RUSTC="${RUSTC:-${RUST_STAGE1}/bin/rustc}"
RUST_SYSROOT="${RUST_SYSROOT:-${RUST_STAGE1}}"

SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
BASE_PORT="${BASE_PORT:-19100}"
RTT_ITERS="${RTT_ITERS:-200}"
RTT_SIZE="${RTT_SIZE:-256}"
THROUGHPUT_ITERS="${THROUGHPUT_ITERS:-2000}"
THROUGHPUT_SIZE="${THROUGHPUT_SIZE:-1200}"

DATE_TAG="$(date +%F-%H%M%S)"
PERF_DATA_DIR="${PERF_DATA_DIR:-${ROOT}/artifacts/sctp-perf}"
LOG_DIR="${PERF_DATA_DIR}/logs_${DATE_TAG}"
CSV_PATH="${PERF_DATA_DIR}/perf_matrix_${DATE_TAG}.csv"
SUMMARY_PATH="${PERF_DATA_DIR}/perf_matrix_${DATE_TAG}-summary.md"

mkdir -p "${PERF_DATA_DIR}" "${LOG_DIR}" "${GO_BUILD_DIR}" "${CPP_BUILD_DIR}" "${RUST_BUILD_DIR}"

require_cmd cmake
require_cmd g++

if [[ ! -x "${GO_BIN}" ]]; then
  echo "error: go toolchain not found at ${GO_BIN}" >&2
  echo "hint: build this tree first with ./src/make.bash" >&2
  exit 1
fi
if [[ ! -x "${RUSTC}" ]]; then
  echo "error: rustc not found at ${RUSTC}" >&2
  echo "hint: set RUSTC or RUST_STAGE1 to your rust-sctp stage1 toolchain" >&2
  exit 1
fi

echo "building Go perf binaries..."
(
  cd "${ROOT}"
  GOROOT="${ROOT}" "${GO_BIN}" build -trimpath -o "${GO_BUILD_DIR}/perf_server" ./misc/sctp-perf/go/perf_server.go
  GOROOT="${ROOT}" "${GO_BIN}" build -trimpath -o "${GO_BUILD_DIR}/perf_client" ./misc/sctp-perf/go/perf_client.go
)

echo "building C++ perf binaries..."
cmake -S "${PERF_DIR}/cpp" -B "${CPP_BUILD_DIR}" >/dev/null
cmake --build "${CPP_BUILD_DIR}" --config Release >/dev/null

echo "building Rust perf binaries..."
"${RUSTC}" --edition=2021 -O --sysroot "${RUST_SYSROOT}" \
  "${PERF_DIR}/rust/src/bin/perf_server.rs" -o "${RUST_BUILD_DIR}/perf_server"
"${RUSTC}" --edition=2021 -O --sysroot "${RUST_SYSROOT}" \
  "${PERF_DIR}/rust/src/bin/perf_client.rs" -o "${RUST_BUILD_DIR}/perf_client"

server_bin() {
  case "$1" in
    go) echo "${GO_BUILD_DIR}/perf_server" ;;
    cpp) echo "${CPP_BUILD_DIR}/sctp_perf_server" ;;
    rust) echo "${RUST_BUILD_DIR}/perf_server" ;;
    *) echo "unknown language: $1" >&2; exit 1 ;;
  esac
}

client_bin() {
  case "$1" in
    go) echo "${GO_BUILD_DIR}/perf_client" ;;
    cpp) echo "${CPP_BUILD_DIR}/sctp_perf_client" ;;
    rust) echo "${RUST_BUILD_DIR}/perf_client" ;;
    *) echo "unknown language: $1" >&2; exit 1 ;;
  esac
}

run_case() {
  local mode="$1"
  local server_lang="$2"
  local client_lang="$3"
  local iterations="$4"
  local size="$5"
  local port="$6"

  local server_log="${LOG_DIR}/${mode}_${server_lang}_server_for_${client_lang}.log"
  local client_log="${LOG_DIR}/${mode}_${client_lang}_client_to_${server_lang}.log"
  local server
  local client
  server="$(server_bin "${server_lang}")"
  client="$(client_bin "${client_lang}")"

  "${server}" "${SERVER_HOST}" "${port}" "${mode}" "${iterations}" "${size}" >"${server_log}" 2>&1 &
  local server_pid=$!
  sleep 1

  set +e
  "${client}" "${SERVER_HOST}" "${port}" "${mode}" "${iterations}" "${size}" >"${client_log}" 2>&1
  local client_rc=$?
  set -e
  if [[ ${client_rc} -ne 0 ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    echo "error: client failed for mode=${mode} server=${server_lang} client=${client_lang}" >&2
    echo "server log: ${server_log}" >&2
    echo "client log: ${client_log}" >&2
    exit 1
  fi

  set +e
  wait "${server_pid}"
  local server_rc=$?
  set -e
  if [[ ${server_rc} -ne 0 ]]; then
    echo "error: server failed for mode=${mode} server=${server_lang} client=${client_lang}" >&2
    echo "server log: ${server_log}" >&2
    echo "client log: ${client_log}" >&2
    exit 1
  fi

  local result_line
  result_line="$(grep "PERF_CLIENT_RESULT" "${client_log}" | tail -n 1 || true)"
  if [[ -z "${result_line}" ]]; then
    echo "error: missing PERF_CLIENT_RESULT in ${client_log}" >&2
    exit 1
  fi

  local elapsed
  local rtt
  local throughput
  elapsed="$(kv_get "${result_line}" "elapsed_s")"
  rtt="$(kv_get "${result_line}" "rtt_us_avg")"
  throughput="$(kv_get "${result_line}" "throughput_mbps")"

  echo "${mode},${server_lang},${client_lang},${iterations},${size},${elapsed},${rtt},${throughput}" >>"${CSV_PATH}"
  echo "ok mode=${mode} server=${server_lang} client=${client_lang} elapsed_s=${elapsed} rtt_us_avg=${rtt} throughput_mbps=${throughput}"
}

echo "mode,server_lang,client_lang,iterations,payload_size,elapsed_s,rtt_us_avg,throughput_mbps" >"${CSV_PATH}"

langs=(go cpp rust)
port="${BASE_PORT}"

echo "running RTT matrix..."
for server_lang in "${langs[@]}"; do
  for client_lang in "${langs[@]}"; do
    run_case "rtt" "${server_lang}" "${client_lang}" "${RTT_ITERS}" "${RTT_SIZE}" "${port}"
    port=$((port + 1))
  done
done

echo "running throughput matrix..."
for server_lang in "${langs[@]}"; do
  for client_lang in "${langs[@]}"; do
    run_case "throughput" "${server_lang}" "${client_lang}" "${THROUGHPUT_ITERS}" "${THROUGHPUT_SIZE}" "${port}"
    port=$((port + 1))
  done
done

stats_line="$(awk -F, '
  NR == 1 { next }
  {
    total += 1
    if ($1 == "rtt") {
      rtt_n += 1
      rtt_sum += $7
      if (rtt_min == 0 || $7 < rtt_min) rtt_min = $7
      if ($7 > rtt_max) rtt_max = $7
    }
    if ($1 == "throughput") {
      th_n += 1
      th_sum += $8
      if ($8 > th_max) {
        th_max = $8
        th_best_server = $2
        th_best_client = $3
      }
    }
  }
  END {
    rtt_mean = (rtt_n > 0) ? rtt_sum / rtt_n : 0
    th_mean = (th_n > 0) ? th_sum / th_n : 0
    printf "total=%d rtt_mean=%.3f rtt_min=%.3f rtt_max=%.3f th_mean=%.3f th_max=%.3f th_best_server=%s th_best_client=%s",
      total, rtt_mean, rtt_min, rtt_max, th_mean, th_max, th_best_server, th_best_client
  }
' "${CSV_PATH}")"

total_cases="$(kv_get "${stats_line}" "total")"
rtt_mean="$(kv_get "${stats_line}" "rtt_mean")"
rtt_min="$(kv_get "${stats_line}" "rtt_min")"
rtt_max="$(kv_get "${stats_line}" "rtt_max")"
th_mean="$(kv_get "${stats_line}" "th_mean")"
th_max="$(kv_get "${stats_line}" "th_max")"
th_best_server="$(kv_get "${stats_line}" "th_best_server")"
th_best_client="$(kv_get "${stats_line}" "th_best_client")"

{
  echo "# SCTP Performance Matrix Summary (${DATE_TAG})"
  echo
  echo "- Total cases: ${total_cases}"
  echo "- RTT mean: ${rtt_mean} us"
  echo "- RTT min/max: ${rtt_min} us / ${rtt_max} us"
  echo "- Throughput mean: ${th_mean} Mbps"
  echo "- Best throughput: ${th_max} Mbps (server=${th_best_server}, client=${th_best_client})"
  echo
  echo "## Matrix Results"
  echo
  echo "| mode | server | client | iterations | payload_size | elapsed_s | rtt_us_avg | throughput_mbps |"
  echo "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"
  awk -F, 'NR > 1 { printf("| %s | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8) }' "${CSV_PATH}"
  echo
  echo "## Environment"
  echo
  echo "- Kernel: $(uname -srmo)"
  echo "- Distro: $(lsb_release -ds 2>/dev/null || awk -F= '/^PRETTY_NAME=/{gsub(/\"/,\"\",$2); print $2}' /etc/os-release)"
  echo "- Go: $(${GO_BIN} version)"
  echo "- C++: $(g++ --version | head -n 1)"
  echo "- Rust: $(${RUSTC} --version)"
  if git -C "${ROOT}" rev-parse HEAD >/dev/null 2>&1; then
    echo "- Repository revision: \`$(git -C "${ROOT}" rev-parse HEAD)\`"
  fi
} >"${SUMMARY_PATH}"

echo "wrote:"
echo "  ${CSV_PATH}"
echo "  ${SUMMARY_PATH}"
echo "  ${LOG_DIR}"
