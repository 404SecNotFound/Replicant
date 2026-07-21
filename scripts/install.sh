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

set -euo pipefail

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
MISSING=()

usage() {
  cat <<'EOF'
Replicant Linux installer

Usage: scripts/install.sh [options]

Options:
  --no-web     CLI-only install. Skips Node/npm and the frontend build.
  --dev        Install the "dev" extra (pytest, black, ruff, mypy) instead of "web".
  --yes        Non-interactive. Assume yes when asked to install missing packages.
  --dry-run    Print every action that would be taken. Changes nothing.
  --help       Show this help.

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
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  REPO_ROOT="$(cd "$script_dir/.." && pwd -P)"
}

main() {
  parse_args "$@"
  resolve_repo_root
  printf 'Replicant installer\n'
  printf '  repo: %s\n' "$REPO_ROOT"
}

main "$@"
