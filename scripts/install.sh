#!/usr/bin/env bash
# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Replicant Linux installer.
#
# Prepares a Linux host and installs Replicant from this clone, then verifies the
# install by exercising the real pipeline (catalog -> engine -> CEF -> transport).
#
# SAFETY: this script downloads packages from your distribution's repositories,
# PyPI, and npm. That is INSTALL-TIME egress and is separate from Replicant's
# runtime rule, which is unchanged: at run time the only network egress is the
# collector the operator configures. Verification below sends synthetic data to
# 127.0.0.1 only and contacts nothing external.

# -E (errtrace) is required: without it the ERR trap below is not inherited into
# shell functions, and every step of this installer runs inside one.
set -Eeuo pipefail

readonly EX_OK=0
readonly EX_USAGE=1
readonly EX_DISTRO=2
readonly EX_PREREQ=3
readonly EX_VENV=4
readonly EX_BUILD=5
readonly EX_VERIFY=6

readonly MIN_PY_MAJOR=3
readonly MIN_PY_MINOR=11
readonly MIN_NODE_MAJOR=18

NO_WEB=0
DEV=0
ASSUME_YES=0
DRY_RUN=0

REPO_ROOT=""
PYTHON_BIN=""
PKG_MGR=""
CURRENT_STEP="startup"
# Guard every expansion with (( ${#MISSING[@]} )) first: on bash <= 4.3
# (macOS 3.2, RHEL 7) "${MISSING[@]}" on an empty array trips set -u.
MISSING=()

if [[ -t 1 && -t 2 && -z "${NO_COLOR:-}" ]]; then
  readonly C_RESET=$'\033[0m'
  readonly C_DIM=$'\033[2m'
  readonly C_RED=$'\033[31m'
  readonly C_GREEN=$'\033[32m'
  readonly C_YELLOW=$'\033[33m'
  readonly C_BOLD=$'\033[1m'
else
  readonly C_RESET="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BOLD=""
fi

step()  { CURRENT_STEP="$1"; printf '\n%s==>%s %s\n' "$C_BOLD" "$C_RESET" "$1"; }
ok()    { printf '  %s[ok]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn()  { printf '  %s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
info()  { printf '  %s%s%s\n' "$C_DIM" "$1" "$C_RESET"; }

die() {
  local code="$1"; shift
  printf '  %s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
  exit "$code"
}

on_err() {
  local line="$1" code="$2" cmd="$3"
  printf '\n%s[fail]%s installation failed during "%s"\n' "$C_RED" "$C_RESET" "$CURRENT_STEP" >&2
  printf '  line %s, exit %s: %s\n' "$line" "$code" "$cmd" >&2
  printf '  Re-run with --dry-run to inspect the planned actions without changing anything.\n' >&2
}
trap 'on_err "$LINENO" "$?" "$BASH_COMMAND"' ERR

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command, or print it under --dry-run. Always pass argv, never a string.
run_cmd() {
  if (( DRY_RUN )); then
    printf '  %swould run:%s' "$C_DIM" "$C_RESET"
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

# Run argv with the working directory scoped to $1. Later steps need this; putting
# `cd` outside run_cmd would really change directory even under --dry-run.
run_cmd_in() {
  local dir="$1"; shift
  if (( DRY_RUN )); then
    printf '  %swould run:%s (cd %s &&' "$C_DIM" "$C_RESET" "$dir"
    printf ' %q' "$@"
    printf ')\n'
    return 0
  fi
  ( cd "$dir" && "$@" )
}

usage() {
  cat <<'EOF'
Replicant Linux installer

Usage: scripts/install.sh [options]

Options:
  --no-web     CLI-only install. Skips Node/npm and the frontend build.
  --dev        Install the "dev" extra (pytest, black, ruff, mypy) instead of "web".
  --yes, -y    Non-interactive. Assume yes when asked to install missing packages.
  --dry-run    Print every action that would be taken. Changes nothing.
  --help, -h   Show this help.

Installing pulls packages from PyPI and npm. That is install-time egress and is
separate from the runtime rule that Replicant's only egress is your collector.
EOF
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --no-web)  NO_WEB=1 ;;
      --dev)     DEV=1 ;;
      --yes|-y)  ASSUME_YES=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --help|-h) usage; exit "$EX_OK" ;;
      *)
        printf 'Unknown option: %s\n\n' "$1" >&2
        usage >&2
        exit "$EX_USAGE"
        ;;
    esac
    shift
  done
}

resolve_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
  REPO_ROOT="$(cd "$script_dir/.." && pwd -P)"
}

main() {
  parse_args "$@"
  resolve_repo_root
  printf '%sReplicant installer%s\n' "$C_BOLD" "$C_RESET"
  info "repo: $REPO_ROOT"
  step "Sanity"
  run_cmd true
  ok "helpers wired"
}

main "$@"
