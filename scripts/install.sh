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
# Same guard rule as MISSING: check [[ -n "$PKG_MGR" ]] before expanding this,
# it is deliberately empty when no usable package manager was found.
PKG_INSTALL_ARGV=()
SUDO=""
CURRENT_STEP="startup"
# Guard every expansion with (( ${#MISSING[@]} )) first: on bash <= 4.3
# (macOS 3.2, RHEL 7) "${MISSING[@]}" on an empty array trips set -u.
MISSING=()
# Temp files created during verification, removed by cleanup_tmp on any exit.
# Guard expansions: this is empty until verification actually runs.
TMP_FILES=()

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

cleanup_tmp() {
  (( ${#TMP_FILES[@]} )) && rm -f "${TMP_FILES[@]}"
  return 0
}
trap cleanup_tmp EXIT

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

preflight() {
  step "Preflight"

  local kernel
  kernel="$(uname -s)"
  if [[ "$kernel" != "Linux" ]]; then
    if (( DRY_RUN )); then
      warn "host is not Linux ($kernel); continuing because --dry-run changes nothing"
    else
      die "$EX_USAGE" \
        "this installer targets Linux, but this host is $kernel. See the README for manual setup."
    fi
  else
    ok "host is Linux ($(uname -r))"
  fi

  if [[ ! -f "$REPO_ROOT/pyproject.toml" ]] \
     || ! grep -Eq '^[[:space:]]*name[[:space:]]*=[[:space:]]*["'"'"']replicant["'"'"']' "$REPO_ROOT/pyproject.toml"; then
    die "$EX_USAGE" "$REPO_ROOT does not look like the Replicant repository (no matching pyproject.toml)."
  fi
  ok "Replicant repository found"

  if (( DEV )) && (( NO_WEB )); then
    info "--dev with --no-web: the dev extra still installs fastapi/uvicorn, but no frontend is built"
  fi
}

detect_pkg_mgr() {
  step "Package manager"

  if (( EUID == 0 )); then
    SUDO=""
    info "running as root; package installs will not use sudo"
  elif have sudo; then
    SUDO="sudo"
  else
    SUDO=""
    warn "not root and sudo is not available; packages cannot be installed automatically"
  fi

  local candidate
  for candidate in apt-get dnf yum pacman zypper; do
    if have "$candidate"; then
      PKG_MGR="$candidate"
      case "$PKG_MGR" in
        apt-get) PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} apt-get install -y) ;;
        dnf)     PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} dnf install -y) ;;
        yum)     PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} yum install -y) ;;
        pacman)  PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} pacman -S --noconfirm) ;;
        zypper)  PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} zypper install -y) ;;
      esac
      if [[ -z "$SUDO" ]] && (( EUID != 0 )); then
        PKG_MGR=""
        PKG_INSTALL_ARGV=()
        warn "found $candidate but cannot elevate; missing prerequisites will be reported only"
        return 0
      fi
      ok "detected package manager: $PKG_MGR"
      return 0
    fi
  done
  PKG_MGR=""
  warn "no supported package manager found (looked for apt-get, dnf, yum, pacman, zypper)"
  info "missing prerequisites will be reported but not installed"
}

# One distribution package name per line for a logical prerequisite, never a
# space-separated string: the caller reads these into an array so a name is never
# word-split and run_cmd keeps its argv contract.
#
# A zero-length result means the prerequisite is unmapped for this manager. Callers
# MUST treat that as a failure, not as "nothing to install" - running the package
# manager with no operands exits 0 and would report success having installed nothing.
pkg_names_for() {
  local prereq="${1:?pkg_names_for requires a prerequisite name}"
  case "$PKG_MGR:$prereq" in
    apt-get:python) printf '%s\n' python3 python3-venv python3-pip ;;
    apt-get:git)    printf '%s\n' git ;;
    apt-get:node)   printf '%s\n' nodejs npm ;;
    dnf:python|yum:python) printf '%s\n' python3 python3-pip ;;
    dnf:git|yum:git)       printf '%s\n' git ;;
    dnf:node|yum:node)     printf '%s\n' nodejs npm ;;
    pacman:python) printf '%s\n' python python-pip ;;
    pacman:git)    printf '%s\n' git ;;
    pacman:node)   printf '%s\n' nodejs npm ;;
    zypper:python) printf '%s\n' python311 python311-pip ;;
    zypper:git)    printf '%s\n' git ;;
    zypper:node)   printf '%s\n' nodejs npm ;;
    *) : ;;
  esac
}

find_python() {
  local candidate major minor
  for candidate in python3.13 python3.12 python3.11 python3; do
    have "$candidate" || continue
    major="$("$candidate" -c 'import sys; print(sys.version_info[0])' 2>/dev/null || printf '0')"
    minor="$("$candidate" -c 'import sys; print(sys.version_info[1])' 2>/dev/null || printf '0')"
    [[ "$major" =~ ^[0-9]+$ ]] || major=0
    [[ "$minor" =~ ^[0-9]+$ ]] || minor=0
    if (( major > MIN_PY_MAJOR )) || { (( major == MIN_PY_MAJOR )) && (( minor >= MIN_PY_MINOR )); }; then
      PYTHON_BIN="$candidate"
      return 0
    fi
  done
  return 1
}

python_has_venv() {
  [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1
}

node_ok() {
  have node || return 1
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || printf '0')"
  [[ "$major" =~ ^[0-9]+$ ]] && (( major >= MIN_NODE_MAJOR ))
}

check_prereqs() {
  step "Prerequisites"
  MISSING=()

  if find_python; then
    ok "Python $("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])') ($PYTHON_BIN)"
    if python_has_venv; then
      ok "Python venv module"
    else
      warn "Python venv module missing"
      MISSING+=(python)
    fi
  else
    warn "no Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} found"
    MISSING+=(python)
  fi

  if have git; then ok "git"; else warn "git missing"; MISSING+=(git); fi

  if (( NO_WEB )); then
    info "skipping Node/npm checks (--no-web)"
  else
    if node_ok && have npm; then
      ok "Node $(node -p 'process.versions.node') and npm"
    else
      warn "Node >= ${MIN_NODE_MAJOR} and npm required to build the web UI (use --no-web to skip)"
      MISSING+=(node)
    fi
  fi

  if (( ${#MISSING[@]} == 0 )); then
    ok "all prerequisites satisfied"
  fi
}

install_prereqs() {
  step "Install prerequisites"

  if (( ${#MISSING[@]} == 0 )); then
    ok "nothing to install"
    return 0
  fi

  if [[ -z "$PKG_MGR" ]] || (( ${#PKG_INSTALL_ARGV[@]} == 0 )); then
    printf '\n'
    warn "cannot install automatically on this system"
    info "install these yourself, then re-run: ${MISSING[*]}"
    die "$EX_DISTRO" "unsupported distribution"
  fi

  local -a packages=()
  local logical name before
  for logical in "${MISSING[@]}"; do
    before=${#packages[@]}
    while IFS= read -r name; do
      [[ -n "$name" ]] && packages+=("$name")
    done < <(pkg_names_for "$logical")
    if (( ${#packages[@]} == before )); then
      die "$EX_DISTRO" "no $PKG_MGR package mapping for '$logical'; install it manually and re-run"
    fi
  done

  printf '\n  The following packages are missing and will be installed:\n'
  printf '    %s\n' "${packages[*]}"
  printf '  Command:\n     '
  printf ' %q' "${PKG_INSTALL_ARGV[@]}" "${packages[@]}"
  printf '\n\n'

  if (( DRY_RUN )); then
    info "would prompt for confirmation before installing"
  elif (( ! ASSUME_YES )); then
    local reply=""
    # Brace group, not a bare `exec ... 2>/dev/null`: bash applies redirections
    # left to right, so a bare form prints its own "/dev/tty: Device not configured"
    # to the real stderr before 2>/dev/null can take effect. Putting 2>/dev/null on
    # a { } group suppresses that cleanly, and because { } does not fork a subshell
    # fd 3 still persists to the read below. Reordering instead would silence stderr
    # permanently for the rest of the script, including die and the ERR trap.
    if ! { exec 3< /dev/tty; } 2>/dev/null; then
      die "$EX_PREREQ" "no terminal available to confirm; re-run with --yes to install non-interactively"
    fi
    read -r -p "  Proceed? [y/N] " reply <&3 || reply=""
    exec 3<&-
    case "$reply" in
      [yY]|[yY][eE][sS]) ;;
      *) die "$EX_PREREQ" "declined; install the packages above and re-run" ;;
    esac
  fi

  if [[ "$PKG_MGR" == "apt-get" ]]; then
    run_cmd ${SUDO:+"$SUDO"} apt-get update
  fi
  run_cmd "${PKG_INSTALL_ARGV[@]}" "${packages[@]}"

  if (( DRY_RUN )); then
    info "would re-check prerequisites after installing"
    return 0
  fi

  # Re-run the full check, not just find_python: the usual reason "python" is in
  # MISSING is an absent python3-venv while python3 itself was already fine, so
  # re-probing find_python alone would prove nothing about what was missing.
  check_prereqs
  if (( ${#MISSING[@]} != 0 )); then
    die "$EX_PREREQ" "still missing after install: ${MISSING[*]}"
  fi
  ok "prerequisites installed"
}

setup_venv() {
  step "Virtual environment"
  local venv="$REPO_ROOT/.venv"

  if [[ -d "$venv" ]]; then
    ok "reusing existing .venv"
  else
    run_cmd "$PYTHON_BIN" -m venv "$venv" || die "$EX_VENV" "could not create $venv"
    ok "created .venv with $PYTHON_BIN"
  fi

  if (( ! DRY_RUN )) && [[ ! -x "$venv/bin/python" ]]; then
    die "$EX_VENV" "$venv/bin/python is missing; the venv is not usable"
  fi

  run_cmd "$venv/bin/python" -m pip install --quiet --upgrade pip \
    || die "$EX_VENV" "could not upgrade pip inside the venv"
  ok "pip up to date"
}

pip_install() {
  step "Install Replicant"
  local venv="$REPO_ROOT/.venv" extra="web"
  (( DEV )) && extra="dev"

  # Braces are required here. Without them the expansion reads as array-index
  # syntax to static analysis (SC1087), even though bash expands it correctly
  # for a scalar. A comment line must not begin with the linter's own name or
  # it is parsed as a directive.
  run_cmd "$venv/bin/python" -m pip install --quiet -e "${REPO_ROOT}[$extra]" \
    || die "$EX_VENV" "pip install -e .[$extra] failed"
  ok "installed Replicant with the '$extra' extra"

  if (( ! DRY_RUN )) && [[ ! -x "$venv/bin/replicant" ]]; then
    die "$EX_VENV" "the 'replicant' console script was not installed"
  fi
}

build_frontend() {
  step "Web UI"

  if (( NO_WEB )); then
    info "skipped (--no-web). 'replicant web' will serve a page explaining how to build it."
    return 0
  fi

  local webui="$REPO_ROOT/webui"
  [[ -d "$webui" ]] || die "$EX_BUILD" "$webui not found"

  # dist/ is gitignored, so a fresh clone never carries a build.
  if [[ -f "$webui/package-lock.json" ]]; then
    run_cmd_in "$webui" npm ci || die "$EX_BUILD" "npm ci failed"
  else
    run_cmd_in "$webui" npm install || die "$EX_BUILD" "npm install failed"
  fi
  run_cmd_in "$webui" npm run build || die "$EX_BUILD" "npm run build failed"

  if (( ! DRY_RUN )) && [[ ! -f "$webui/dist/index.html" ]]; then
    die "$EX_BUILD" "build finished but $webui/dist/index.html is missing"
  fi
  ok "frontend built"
}

verify_install() {
  step "Verify"
  local venv="$REPO_ROOT/.venv"
  local bin="$venv/bin/replicant"
  local py="$venv/bin/python"

  if (( DRY_RUN )); then
    info "would run: $bin list"
    info "would run: $bin run REP-001 --no-send --to-file <tmp>, requiring a CEF:0| first line"
    info "would run: a loopback UDP send to 127.0.0.1, requiring datagrams to arrive"
    return 0
  fi

  "$bin" list >/dev/null 2>&1 || die "$EX_VERIFY" "'replicant list' failed"
  ok "catalog loads"

  local tmp_log
  tmp_log="$(mktemp -t replicant-verify.XXXXXX)"
  TMP_FILES+=("$tmp_log")
  "$bin" run REP-001 --intensity low --to-file "$tmp_log" --no-send >/dev/null 2>&1 \
    || die "$EX_VERIFY" "'replicant run --no-send' failed"
  head -n 1 "$tmp_log" | grep -q '^CEF:0|' \
    || die "$EX_VERIFY" "output does not start with CEF:0| (got: $(head -c 40 "$tmp_log"))"
  ok "CEF written ($(wc -l < "$tmp_log" | tr -d ' ') lines)"

  local listener_out port count listener_pid i
  listener_out="$(mktemp -t replicant-listener.XXXXXX)"
  TMP_FILES+=("$listener_out")

  "$py" -c '
import socket, sys
out = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
with open(out, "w") as fh:
    fh.write("PORT %d\n" % sock.getsockname()[1])
sock.settimeout(20.0)
count = 0
try:
    while True:
        sock.recvfrom(65535)
        count += 1
        sock.settimeout(2.0)
except OSError:
    pass
finally:
    sock.close()
with open(out, "a") as fh:
    fh.write("COUNT %d\n" % count)
' "$listener_out" &
  listener_pid=$!

  port=""
  for _ in $(seq 1 50); do
    port="$(awk "/^PORT /{print \$2; exit}" "$listener_out" 2>/dev/null || true)"
    [[ -n "$port" ]] && break
    sleep 0.1
  done
  if [[ -z "$port" ]]; then
    kill "$listener_pid" 2>/dev/null || true
    die "$EX_VERIFY" "loopback listener did not start"
  fi

  # Low intensity and a short duration deliberately: this path goes through the
  # emitter and is subject to the events-per-second cap, so a heavier technique
  # would make the installer look like it had hung.
  if ! "$bin" run REP-001 --intensity low --duration 2m \
       --host 127.0.0.1 --port "$port" --transport udp >/dev/null 2>&1; then
    kill "$listener_pid" 2>/dev/null || true
    die "$EX_VERIFY" "loopback send failed"
  fi

  wait "$listener_pid" 2>/dev/null || true
  count="$(awk "/^COUNT /{print \$2; exit}" "$listener_out" 2>/dev/null || printf '0')"
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  (( count > 0 )) || die "$EX_VERIFY" "no datagrams arrived on the loopback listener"
  ok "loopback transport delivered $count events"
}

report() {
  step "Done"
  local extra="web"
  if (( DEV )); then extra="dev"; fi
  printf '\n  Replicant is installed in %s/.venv (extra: %s).\n\n' "$REPO_ROOT" "$extra"
  printf '  Activate it:      source .venv/bin/activate\n'
  printf '  Interactive menu: replicant menu\n'
  if (( NO_WEB )); then
    printf '  Web UI:           not built (--no-web). Build with: cd webui && npm install && npm run build\n'
  else
    printf '  Web UI:           replicant web\n'
  fi
  printf '  Headless run:     replicant run REP-001 --to-file ./out/test.log --no-send\n\n'
  printf '  %sReminder:%s at run time Replicant only sends to the collector you configure.\n' \
    "$C_BOLD" "$C_RESET"
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
  preflight
  detect_pkg_mgr
  check_prereqs
  install_prereqs
  setup_venv
  pip_install
  build_frontend
  verify_install
  report
}

main "$@"
