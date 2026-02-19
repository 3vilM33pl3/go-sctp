#!/usr/bin/env bash

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

kv_get() {
  local line="$1"
  local key="$2"
  local part=""
  for part in $line; do
    if [[ "$part" == "${key}="* ]]; then
      echo "${part#*=}"
      return 0
    fi
  done
  return 1
}
