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

# Bash-only script (arrays, [[, local). Fail clearly under `sh` instead of
# limping into whatever `set -E` does on a shell that does not support it.
[ -n "${BASH_VERSION:-}" ] || { echo "run this with bash: bash scripts/install.sh" >&2; exit 1; }

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

# Fallback only. The real value is WEB_DEFAULT_PORT in replicant/config/settings.py
# and is read from the installed package at report time, so this is used solely if
# that import fails. Printing a port the tool does not serve on is worse than
# printing nothing, so the two must not drift.
readonly WEB_PORT_FALLBACK=9787
WEB_PORT="$WEB_PORT_FALLBACK"

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
# PID of the loopback listener started by verify_install. Global (not local to
# verify_install) so cleanup_tmp can reap it if the script exits before that
# function's own wait does, e.g. on SIGTERM.
LISTENER_PID=""
# Same reasoning for the web check's server.
WEB_PID=""

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
  # Written as explicit ifs rather than `A && B || true`. shellcheck flags that
  # form (SC2015) because the `|| true` also fires when A is false, so the two
  # cases are indistinguishable to a reader. Here the intent really is "skip
  # quietly", which is exactly why it should be spelled out: a future edit that
  # relied on the `|| true` catching only B's failure would be wrong.
  if [[ -n "$LISTENER_PID" ]]; then
    kill "$LISTENER_PID" 2>/dev/null || true
  fi
  # The web check's server has to be reaped here, not by a RETURN trap in the
  # function: every failure path there calls die, which exits, and exit does not
  # fire RETURN. Leaving a listener bound after a failed install is the kind of
  # mess that gets blamed on the next thing to touch that port.
  if [[ -n "$WEB_PID" ]]; then
    kill "$WEB_PID" 2>/dev/null || true
  fi
  if (( ${#TMP_FILES[@]} )); then
    rm -f "${TMP_FILES[@]}"
  fi
  return 0
}
trap cleanup_tmp EXIT INT TERM

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

# Run a verification command with stdout suppressed, surfacing stderr on failure.
# Always runs in $REPO_ROOT: verification invokes `replicant run`, which writes a
# manifest to the relative path manifests/, and callers must not scatter that
# into whatever directory the operator happened to be in.
# Allocate a tracked temp file, or fail. Callers MUST check the return value.
#
# Every caller assigns into a variable that is later used as a redirect target.
# An empty value there is not a benign default: `2>""` fails to open, so the
# command is never executed, and in a subshell that failure does not propagate
# the way it appears to. See verify_cmd below for what that cost us.
new_tmp_file() {
  local prefix="${1:?new_tmp_file requires a prefix}" path
  path="$(mktemp -t "$prefix.XXXXXX")" || return 1
  [[ -n "$path" ]] || return 1
  TMP_FILES+=("$path")
  printf '%s\n' "$path"
}

verify_cmd() {
  local what="$1"; shift
  local err
  # Fail closed when no temp file can be created.
  #
  # This previously read `err="$(mktemp ...)"` with no check. When mktemp failed
  # (read-only or full /tmp, or a hardened container), err was empty, the
  # redirect `2>"$err"` could not open, the command NEVER RAN, and this function
  # returned 0 anyway. The installer then printed a green [ok] for verification
  # it had not performed, which is the single worst thing a verification step can
  # do. Reproduced with a control: /bin/false took the success path.
  if ! err="$(new_tmp_file replicant-verify-err)"; then
    warn "$what could not be verified: no writable temporary file available"
    return 1
  fi
  if ! ( cd "$REPO_ROOT" && "$@" ) >/dev/null 2>"$err"; then
    warn "$what failed; last output:"
    tail -n 5 "$err" >&2 || true
    return 1
  fi
  return 0
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
    warn "running this whole installer as root; .venv, node_modules, dist/, and manifests/ inside this clone will end up root-owned, which an unprivileged 'replicant' run cannot write to afterward. Prefer running this script unprivileged; only the package-manager install needs sudo."
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
        # --no-install-recommends / install_weak_deps=False are not tidiness. Without
        # them apt pulls the full recommended closure: an observed Ubuntu 22.04 run
        # dragged in tilix, libgtk-3, ubuntu-mono and humanity-icon-theme, i.e. a GUI
        # terminal emulator and a desktop icon theme, onto a headless host. Replicant's
        # audience runs this on servers next to a SIEM.
        apt-get) PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y --no-install-recommends) ;;
        dnf)     PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} dnf install -y --setopt=install_weak_deps=False) ;;
        yum)     PKG_INSTALL_ARGV=(${SUDO:+"$SUDO"} yum install -y --setopt=install_weak_deps=False) ;;
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

# --- Resolving prerequisites against what this host actually offers -----------
#
# pkg_names_for above installs a distribution's DEFAULT python3 and nodejs. On
# several current LTS releases that is below Replicant's minimum: Ubuntu 22.04
# ships Python 3.10 and Node 12, Debian 11 ships 3.9, RHEL/Rocky/Alma 8 and 9
# ship 3.6/3.9 and Node 16. The original flow took sudo consent, installed those
# anyway, re-checked, and only then died with "still missing after install",
# having changed the operator's system for no benefit.
#
# The functions below invert that order: ask the package manager what it would
# actually install BEFORE asking for sudo, and refuse up front when nothing on
# offer can meet the minimum. Every query here is read-only and mutates nothing.

# Print the version the package manager would install, or nothing when the
# package is not offered here.
pkg_candidate_version() {
  local pkg="${1:?pkg_candidate_version requires a package name}"
  case "$PKG_MGR" in
    apt-get)
      { apt-cache policy "$pkg" 2>/dev/null || true; } |
        awk '/Candidate:/ { if ($2 != "(none)") print $2; exit }'
      ;;
    dnf|yum)
      # dnf exits non-zero for an unknown package, and pipefail would propagate
      # that out of the substitution, so absorb it here rather than at each call.
      { "$PKG_MGR" -q info --available "$pkg" 2>/dev/null || true; } |
        awk '/^Version/ { print $3; exit }'
      ;;
    *) : ;;
  esac
}

# Debian policy and RPM both order pre-releases below the final release using a
# leading "~", so "~rc" is the reliable marker. This matters concretely: Ubuntu
# 22.04's python3.11 is 3.11.0~rc1 and was never updated, so it satisfies a
# numeric ">= 3.11" test while putting the operator on a release-candidate
# interpreter. Refuse it rather than installing it silently.
#
# Keying on "~" alone is deliberate: Debian 12's python3 is "3.11.2-1+b1", a
# binNMU of a normal release, and must NOT be treated as a pre-release.
version_is_prerelease() {
  case "${1:-}" in
    *~rc*|*~alpha*|*~beta*|*~pre*|*~dev*) return 0 ;;
    *) return 1 ;;
  esac
}

# Compare a distribution version string ("3.11.2-1+b1", "3.9.18") against the
# minimum. Only the leading major.minor is significant.
version_meets_py_min() {
  local v="${1:-}" major minor
  major="${v%%.*}"
  v="${v#*.}"
  minor="${v%%[!0-9]*}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > MIN_PY_MAJOR )) && return 0
  (( major == MIN_PY_MAJOR && minor >= MIN_PY_MINOR )) && return 0
  return 1
}

# Newest qualifying series first.
#
# Prints nothing when nothing on offer qualifies, and still returns 0. Two
# reasons this signals by output rather than exit status: the caller already
# detects "no packages were added", and a `return 1` out of the process
# substitution below would trip the ERR trap and print a spurious "installation
# failed" banner ahead of the real, specific refusal message.
#
# Every diagnostic here MUST go to stderr. Stdout is the package list the caller
# reads, so a stray warn on stdout is consumed as a package name.
resolve_python_packages() {
  local series ver
  case "$PKG_MGR" in
    apt-get|dnf|yum) ;;
    # pacman and zypper are not probed here; zypper's static mapping is already
    # version-qualified (python311) and pacman tracks current Python. Keep them.
    *) pkg_names_for python; return 0 ;;
  esac

  for series in 3.13 3.12 3.11; do
    ver="$(pkg_candidate_version "python$series")"
    [[ -n "$ver" ]] || continue
    if version_is_prerelease "$ver"; then
      warn "python$series is offered here only as a pre-release ($ver); not installing it" >&2
      continue
    fi
    case "$PKG_MGR" in
      # Debian and Ubuntu split ensurepip into pythonX.Y-venv. Without it the
      # very next step, `python -m venv`, fails.
      apt-get) printf '%s\n' "python$series" "python$series-venv" ;;
      *)       printf '%s\n' "python$series" "python$series-pip" ;;
    esac
    return 0
  done

  # No versioned series on offer. The unversioned default is correct on
  # distributions that already ship a new enough interpreter (Debian 12, Fedora).
  ver="$(pkg_candidate_version python3)"
  if [[ -n "$ver" ]] && ! version_is_prerelease "$ver" && version_meets_py_min "$ver"; then
    pkg_names_for python
  fi
  return 0
}

# Node is only needed for the web UI, so --no-web makes this moot. Same output
# contract as resolve_python_packages: empty stdout means "cannot satisfy".
resolve_node_packages() {
  local ver major
  case "$PKG_MGR" in
    apt-get|dnf|yum) ;;
    *) pkg_names_for node; return 0 ;;
  esac
  ver="$(pkg_candidate_version nodejs)"
  major="${ver%%.*}"
  if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= MIN_NODE_MAJOR )); then
    printf '%s\n' nodejs npm
  fi
  return 0
}

resolve_packages_for() {
  case "${1:?resolve_packages_for requires a prerequisite name}" in
    python) resolve_python_packages ;;
    node)   resolve_node_packages ;;
    *)      pkg_names_for "$1" ;;
  esac
}

# Called instead of installing, when the host cannot be brought up to minimum.
# Prints what is wrong and what the operator can do, then exits WITHOUT having
# touched the system. This is the whole point of resolving before consenting.
refuse_unsatisfiable() {
  local logical="${1:?}"
  printf '\n'
  warn "this system cannot reach the required $logical version from its own repositories"
  case "$logical" in
    python)
      info "Replicant needs Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR}. Options:"
      case "$PKG_MGR" in
        apt-get)
          info "  - Ubuntu 22.04: add the deadsnakes PPA, then re-run"
          info "      sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt-get update"
          info "  - or upgrade to a release that ships >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} (Ubuntu 24.04, Debian 12)"
          ;;
        dnf|yum)
          info "  - RHEL/Rocky/Alma 8 and 9 offer a versioned package:"
          info "      sudo dnf install python3.11 python3.11-pip"
          info "    then re-run this installer"
          ;;
        *)
          info "  - install Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} using your distribution's method, then re-run"
          ;;
      esac
      ;;
    node)
      info "Replicant needs Node >= ${MIN_NODE_MAJOR} to build the web UI. Options:"
      info "  - re-run with --no-web to install the CLI only and skip Node entirely"
      case "$PKG_MGR" in
        dnf|yum) info "  - or enable a newer module stream: sudo dnf module enable nodejs:20" ;;
        apt-get) info "  - or install Node >= ${MIN_NODE_MAJOR} from NodeSource (https://github.com/nodesource/distributions)" ;;
      esac
      ;;
  esac
  printf '\n'
  die "$EX_PREREQ" "refusing to install packages that would not satisfy '$logical'; nothing was changed"
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

  # git is not actually invoked anywhere below; the repo is necessarily already
  # cloned to have gotten this far. A missing git only warns and never adds to
  # MISSING, so it never forces an automatic sudo install on its own.
  if have git; then ok "git"; else warn "git missing (not required by this installer)"; fi

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
    if (( DRY_RUN )); then
      warn "--dry-run: continuing without a package manager; the plan below assumes these prerequisites end up present"
      return 0
    fi
    die "$EX_DISTRO" "unsupported distribution"
  fi

  # Refresh the index BEFORE resolving, not after consenting. apt-cache reports
  # nothing at all against a stale or empty list directory, which would make the
  # resolver below refuse a host that can in fact satisfy the requirement. This
  # only rewrites /var/lib/apt/lists and installs nothing; the consent prompt
  # still gates every actual package change.
  if [[ "$PKG_MGR" == "apt-get" ]]; then
    info "refreshing package index first, so the check below sees what is really available (installs nothing)"
    run_cmd ${SUDO:+"$SUDO"} env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update \
      || die "$EX_PREREQ" "apt-get update failed"
    if (( DRY_RUN )); then
      warn "--dry-run skipped the index refresh, so the availability check below may be inconclusive"
    fi
  fi

  local -a packages=()
  local logical name before
  for logical in "${MISSING[@]}"; do
    before=${#packages[@]}
    while IFS= read -r name; do
      [[ -n "$name" ]] && packages+=("$name")
    done < <(resolve_packages_for "$logical")
    if (( ${#packages[@]} == before )); then
      if (( DRY_RUN )); then
        warn "nothing $PKG_MGR offers can satisfy '$logical' on this host; install it manually"
        continue
      fi
      # Refuse here, before the consent prompt and before any sudo. Installing a
      # package set already known to be insufficient is what produced the old
      # "still missing after install" dead end.
      refuse_unsatisfiable "$logical"
    fi
  done

  if (( ${#packages[@]} == 0 )); then
    warn "no installable packages after mapping; nothing to install automatically"
    return 0
  fi

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

  run_cmd "${PKG_INSTALL_ARGV[@]}" "${packages[@]}" \
    || die "$EX_PREREQ" "package installation failed"

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

    if (( ! DRY_RUN )) && [[ -x "$venv/bin/python" ]]; then
      local vmajor vminor
      vmajor="$("$venv/bin/python" -c 'import sys; print(sys.version_info[0])' 2>/dev/null || printf '0')"
      vminor="$("$venv/bin/python" -c 'import sys; print(sys.version_info[1])' 2>/dev/null || printf '0')"
      [[ "$vmajor" =~ ^[0-9]+$ ]] || vmajor=0
      [[ "$vminor" =~ ^[0-9]+$ ]] || vminor=0
      if (( vmajor < MIN_PY_MAJOR )) || { (( vmajor == MIN_PY_MAJOR )) && (( vminor < MIN_PY_MINOR )); }; then
        die "$EX_VENV" "existing .venv uses Python ${vmajor}.${vminor}, below ${MIN_PY_MAJOR}.${MIN_PY_MINOR}; remove it and re-run: rm -rf $venv"
      fi
    fi
  else
    run_cmd "$PYTHON_BIN" -m venv "$venv" || die "$EX_VENV" "could not create $venv"
    if (( DRY_RUN )); then
      info "would create .venv with $PYTHON_BIN"
    else
      ok "created .venv with $PYTHON_BIN"
    fi
  fi

  if (( ! DRY_RUN )) && [[ ! -x "$venv/bin/python" ]]; then
    die "$EX_VENV" "$venv/bin/python is missing; the venv is not usable; remove it and re-run: rm -rf $venv"
  fi

  run_cmd "$venv/bin/python" -m pip install --quiet --upgrade pip \
    || die "$EX_VENV" "could not upgrade pip inside the venv"
  if (( DRY_RUN )); then
    info "would upgrade pip in the venv"
  else
    ok "pip up to date"
  fi
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
  if (( DRY_RUN )); then
    info "would install Replicant with the '$extra' extra"
  else
    ok "installed Replicant with the '$extra' extra"
  fi

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

  # Vite writes into the Python package (webui/vite.config.ts), so the built UI
  # ships in a wheel instead of being stranded outside it.
  local dist="$REPO_ROOT/replicant/webui_dist"
  if (( ! DRY_RUN )) && [[ ! -f "$dist/index.html" ]]; then
    die "$EX_BUILD" "build finished but $dist/index.html is missing"
  fi
  if (( DRY_RUN )); then
    info "would build frontend"
  else
    ok "frontend built"
  fi
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
    if (( ! NO_WEB )); then
      info "would run: 'replicant web' on an ephemeral loopback port, requiring /api/health 200 and /api/catalog 401"
    fi
    return 0
  fi

  verify_cmd "'replicant list'" "$bin" list || die "$EX_VERIFY" "'replicant list' failed"
  ok "catalog loads"

  # Guarded, and not only for tidiness: an unguarded assignment here fires the
  # ERR trap twice, because set -E propagates it into the command-substitution
  # subshell as well as the outer assignment. That printed six lines of failure
  # banner where the design specifies three.
  local tmp_log
  tmp_log="$(new_tmp_file replicant-verify)" \
    || die "$EX_VERIFY" "could not create a temporary file for verification output"
  verify_cmd "'replicant run --no-send'" "$bin" run REP-001 --intensity low --to-file "$tmp_log" --no-send \
    || die "$EX_VERIFY" "'replicant run --no-send' failed"
  head -n 1 "$tmp_log" | grep -q '^CEF:0|' \
    || die "$EX_VERIFY" "output does not start with CEF:0| (got: $(head -c 40 "$tmp_log"))"
  ok "CEF written ($(wc -l < "$tmp_log" | tr -d ' ') lines)"

  local listener_out port count
  listener_out="$(new_tmp_file replicant-listener)" \
    || die "$EX_VERIFY" "could not create a temporary file for the loopback listener"

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
  LISTENER_PID=$!

  port=""
  for _ in $(seq 1 50); do
    port="$(awk '/^PORT /{print $2; exit}' "$listener_out" 2>/dev/null || true)"
    [[ -n "$port" ]] && break
    sleep 0.1
  done
  if [[ -z "$port" ]]; then
    kill "$LISTENER_PID" 2>/dev/null || true
    die "$EX_VERIFY" "loopback listener did not start"
  fi

  # Default plan, no --duration override: REP-001 low has interval_s 300, so a
  # short window such as 2m would truncate the plan down to a single callback at
  # t=0 and prove nothing. The default plan (duration_min 240) fires about 49
  # events, which is a far stronger delivery signal.
  #
  # --pace burst is what keeps it fast, and it has to be explicit. A live send
  # now defaults to reproducing the plan's own timeline, and REP-001 low spans
  # 238 minutes, so an installer that leaves the pace unstated hangs for four
  # hours verifying a socket. What this step proves is that datagrams reach a
  # listener; the shape they arrive in is not the claim, so burst is both the
  # fast answer and the correct one.
  if ! verify_cmd "loopback send" "$bin" run REP-001 --intensity low --pace burst \
       --host 127.0.0.1 --port "$port" --transport udp; then
    kill "$LISTENER_PID" 2>/dev/null || true
    die "$EX_VERIFY" "loopback send failed"
  fi

  wait "$LISTENER_PID" 2>/dev/null || true
  LISTENER_PID=""
  count="$(awk '/^COUNT /{print $2; exit}' "$listener_out" 2>/dev/null || printf '0')"
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  (( count > 0 )) || die "$EX_VERIFY" "no datagrams arrived on the loopback listener"
  if (( count == 1 )); then
    ok "loopback transport delivered 1 event"
  else
    ok "loopback transport delivered $count events"
  fi

  verify_web "$py" "$bin"
}

# Start the web server for real and prove three things the build check cannot:
# that it binds, that it serves the built frontend, and that the API refuses an
# unauthenticated request. Verifying that the built index.html exists only proves
# a file was written; it says nothing about whether the server starts.
verify_web() {
  local py="$1" bin="$2"

  if (( NO_WEB )); then
    info "skipping web check (--no-web)"
    return 0
  fi

  local port
  port="$("$py" -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
' 2>/dev/null || true)"
  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    warn "could not allocate a port for the web check; skipping"
    return 0
  fi

  local web_out
  web_out="$(new_tmp_file replicant-web)" \
    || die "$EX_VERIFY" "could not create a temporary file for the web check"

  "$bin" web --host 127.0.0.1 --port "$port" --no-browser >"$web_out" 2>&1 &
  WEB_PID=$!

  local result
  result="$("$py" -c '
import sys, time, urllib.error, urllib.request

port = sys.argv[1]
base = "http://127.0.0.1:%s" % port


def status(path):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


for _ in range(80):
    try:
        if status("/api/health") == 200:
            break
    except OSError:
        time.sleep(0.25)
else:
    print("NOSTART")
    raise SystemExit(0)

# An unauthenticated API call must be refused. If this ever returns 200 the
# install has produced a server anyone on the host can drive.
print("AUTH_OPEN" if status("/api/catalog") != 401 else "OK")
' "$port" 2>/dev/null || printf 'ERROR')"

  kill "$WEB_PID" 2>/dev/null || true
  wait "$WEB_PID" 2>/dev/null || true
  WEB_PID=""

  case "$result" in
    OK)
      ok "web server starts, serves, and requires a token"
      ;;
    NOSTART)
      die "$EX_VERIFY" "web server did not answer on 127.0.0.1:$port (see $web_out)"
      ;;
    AUTH_OPEN)
      die "$EX_VERIFY" "web API answered an unauthenticated request; refusing to call this a good install"
      ;;
    *)
      die "$EX_VERIFY" "web check could not run (see $web_out)"
      ;;
  esac
}

report() {
  step "Done"
  local extra="web"
  if (( DEV )); then extra="dev"; fi

  if (( DRY_RUN )); then
    printf '\n  This was a dry run: the plan above was printed and nothing was installed.\n'
    printf '  Re-run without --dry-run to install Replicant into %s/.venv (extra: %s).\n\n' \
      "$REPO_ROOT" "$extra"
    return 0
  fi

  # Ask the installed package what port it actually defaults to rather than
  # repeating the number here. `|| true` because a summary line is not worth
  # aborting a successful install over; the fallback stands if this fails.
  local reported_port
  reported_port="$("$REPO_ROOT/.venv/bin/python" -c \
    'from replicant.config.settings import WEB_DEFAULT_PORT; print(WEB_DEFAULT_PORT)' \
    2>/dev/null || true)"
  if [[ "$reported_port" =~ ^[0-9]+$ ]]; then
    WEB_PORT="$reported_port"
  fi

  printf '\n  Replicant is installed in %s/.venv (extra: %s).\n\n' "$REPO_ROOT" "$extra"
  printf '  Activate it:      source %s/.venv/bin/activate\n' "$REPO_ROOT"
  printf '  Interactive menu: replicant menu\n'
  if (( NO_WEB )); then
    printf '  Web UI:           not built (--no-web). Build with: cd webui && npm install && npm run build\n'
  else
    printf '  Web UI:           replicant web            (http://127.0.0.1:%s/)\n' "$WEB_PORT"
    printf '  Reach it remotely: replicant web --host 0.0.0.0 --no-browser\n'
    printf '                    then open http://<this-host>:%s/ and use the token printed on start.\n' \
      "$WEB_PORT"
    printf '                    The token persists in ~/.config/replicant/web-token.\n'
    printf '                    The embedded terminal tab is off by default on a non-loopback bind.\n'
    printf '  Run as a service: see %s/scripts/replicant-web.service\n' "$REPO_ROOT"
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
