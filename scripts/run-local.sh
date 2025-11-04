#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELLO_ROOT="${ROOT_DIR}/servers/hello/src"

print_usage() {
  cat <<'EOF'
Usage: scripts/run-local.sh [unprotected|token-check|token-binding|all]

Runs the sample APIs directly with the local dotnet SDK, avoiding Docker.
For Approov-protected apps the script ensures a .env file exists by copying
from .env.example when necessary.
EOF
}

project_dir_for() {
  case "$1" in
    unprotected) printf '%s\n' "${HELLO_ROOT}/unprotected-server" ;;
    token-check) printf '%s\n' "${HELLO_ROOT}/approov-protected-server/token-check" ;;
    token-binding) printf '%s\n' "${HELLO_ROOT}/approov-protected-server/token-binding-check" ;;
    *) return 1 ;;
  esac
}

project_port_for() {
  case "$1" in
    unprotected) printf '8001\n' ;;
    token-check) printf '8002\n' ;;
    token-binding) printf '8003\n' ;;
    *) return 1 ;;
  esac
}

ensure_env_file() {
  local project_dir="$1"
  local env_example="${project_dir}/.env.example"
  local env_file="${project_dir}/.env"

  if [[ -f "${env_example}" && ! -f "${env_file}" ]]; then
    echo ">> Copying ${env_example##*/} to ${env_file##*/}"
    cp "${env_example}" "${env_file}"
  fi
}

run_project() {
  local key="$1"
  local project_dir
  local port

  if ! project_dir="$(project_dir_for "${key}")"; then
    echo "Unknown project key '${key}'" >&2
    exit 1
  fi

  if ! port="$(project_port_for "${key}")"; then
    echo "Unknown project key '${key}'" >&2
    exit 1
  fi

  ensure_env_file "${project_dir}"

  echo ">> Starting ${key} at http://localhost:${port}"
  (cd "${project_dir}" && exec dotnet run --urls "http://0.0.0.0:${port}")
}

run_all() {
  local pids=()
  local key
  local project_dir
  local port

  trap 'echo "Stopping services..."; for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; wait || true' INT TERM

  for key in unprotected token-check token-binding; do
    project_dir="$(project_dir_for "${key}")" || {
      echo "Unknown project key '${key}'" >&2
      exit 1
    }
    port="$(project_port_for "${key}")" || {
      echo "Unknown project key '${key}'" >&2
      exit 1
    }
    ensure_env_file "${project_dir}"
    (
      cd "${project_dir}"
      exec dotnet run --urls "http://0.0.0.0:${port}"
    ) &
    local pid=$!
    pids+=("${pid}")
    echo ">> ${key} listening on http://localhost:${port} (PID ${pid})"
  done

  echo "All services are running. Press Ctrl+C to stop."
  wait -n || true
}

main() {
  if [[ $# -ne 1 ]]; then
    print_usage
    exit 1
  fi

  case "$1" in
    unprotected|token-check|token-binding)
      run_project "$1"
      ;;
    all)
      run_all
      ;;
    -h|--help)
      print_usage
      ;;
    *)
      print_usage
      exit 1
      ;;
  esac
}

main "$@"
