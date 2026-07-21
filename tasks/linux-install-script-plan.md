# Linux Install Script Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `scripts/install.sh`, which takes a fresh Linux box from a `git clone` to a verified working Replicant install, asking before it touches the system and proving the pipeline works before it exits 0.

**Architecture:** One self-contained `bash` script of small single-purpose functions. `main()` calls them in order; every task adds one function and wires it into `main()`, so the script runs after every task. A `--dry-run` flag prints intended actions without performing them, which is both an operator feature and the only way to exercise the logic on the macOS development host.

**Tech Stack:** bash 4+, coreutils, the host package manager (apt-get/dnf/yum/pacman/zypper), Python >= 3.11 with `venv`, Node >= 18 with npm. Verification uses the freshly created `.venv` interpreter, never `nc`/`socat`.

Spec: `docs/linux-install-script-design.md`. Branch: `feature/linux-install-script` (off `main` at `b03c577`).

---

## Testing approach (read before Task 1)

This is a shell script with no Python surface. There is no pytest task in this plan and **the suite count does not change**. Adding a subprocess test that shells out to the installer from macOS would assert nothing real.

Each task is verified by running the script and diffing observed output against expected output:

- `bash -n scripts/install.sh` catches syntax errors.
- `shellcheck scripts/install.sh` if available (`brew install shellcheck`); treat as advisory if absent.
- `./scripts/install.sh --dry-run` walks the full decision path without mutating anything.

**Known limitation, stated honestly:** distribution package names and the `sudo` path cannot be validated from macOS. Those are confirmed by a real run on Linux by the operator. Do not claim they are tested.

Preflight deliberately **allows `--dry-run` on non-Linux** (warning instead of hard failure) so the logic is walkable here. A real run on non-Linux still refuses.

---

## File structure

- `scripts/install.sh` (new) - the entire installer. Single file by design; splitting into sourced fragments would break the "one script on a fresh box" premise.
- `README.md` (modify) - add a Linux install section under Quick start.

---

## Task 1: Skeleton, exit codes, flags, repo root

**Files:**
- Create: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --help`
Expected: FAIL, `no such file or directory`.

- [ ] **Step 2: Create the script**

```bash
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
```

- [ ] **Step 3: Make it executable**

```bash
chmod +x scripts/install.sh
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --help`
Expected: PASS, usage text, exit 0.

Run: `./scripts/install.sh --bogus; echo "exit=$?"`
Expected: `Unknown option: --bogus`, usage on stderr, `exit=1`.

Run: `./scripts/install.sh --dry-run`
Expected: prints `Replicant installer` and the absolute repo path.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): script skeleton with flags and repo-root resolution"
```

---

## Task 2: Output helpers, error trap, dry-run command runner

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'would run'`
Expected: FAIL, `0` (no runner exists yet).

- [ ] **Step 2: Add helpers after the globals block, before `usage()`**

```bash
if [[ -t 1 ]]; then
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
  printf '\n%s[fail]%s installation failed during "%s" (line %s)\n' \
    "$C_RED" "$C_RESET" "$CURRENT_STEP" "$1" >&2
  printf '  Re-run with --dry-run to inspect the planned actions without changing anything.\n' >&2
}
trap 'on_err "$LINENO"' ERR

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command, or print it under --dry-run. Always pass argv, never a string.
run_cmd() {
  if (( DRY_RUN )); then
    printf '  %swould run:%s %s\n' "$C_DIM" "$C_RESET" "$*"
    return 0
  fi
  "$@"
}
```

- [ ] **Step 3: Exercise the runner from `main()`**

Replace the body of `main()` with:

```bash
main() {
  parse_args "$@"
  resolve_repo_root
  printf '%sReplicant installer%s\n' "$C_BOLD" "$C_RESET"
  info "repo: $REPO_ROOT"
  step "Sanity"
  run_cmd true
  ok "helpers wired"
}
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'would run'`
Expected: PASS, `1`.

Run: `./scripts/install.sh 2>&1 | grep -c '\[ok\] helpers wired'`
Expected: `1`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): output helpers, error trap, dry-run command runner"
```

---

## Task 3: Preflight (OS and repo sanity)

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'not Linux'`
Expected: FAIL, `0`. (On macOS. On Linux this check reports the kernel instead.)

- [ ] **Step 2: Add `preflight()` after `run_cmd()`**

```bash
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

  if [[ ! -f "$REPO_ROOT/pyproject.toml" ]] || ! grep -q '^name = "replicant"' "$REPO_ROOT/pyproject.toml"; then
    die "$EX_USAGE" "$REPO_ROOT does not look like the Replicant repository (no matching pyproject.toml)."
  fi
  ok "Replicant repository found"

  if (( DEV )) && (( NO_WEB )); then
    info "--dev with --no-web: the dev extra still installs fastapi/uvicorn, but no frontend is built"
  fi
}
```

- [ ] **Step 3: Call it from `main()`**

Replace the `step "Sanity"` / `run_cmd true` / `ok "helpers wired"` lines with:

```bash
  preflight
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'not Linux'`
Expected: PASS, `1` on macOS.

Run: `./scripts/install.sh; echo "exit=$?"`
Expected on macOS: `[fail] this installer targets Linux...`, `exit=1`.

Run: `cd /tmp && "$OLDPWD/scripts/install.sh" --dry-run 2>&1 | grep -c 'Replicant repository found'; cd - >/dev/null`
Expected: `1` (repo root resolves from the script path, not the working directory).

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): preflight OS and repository checks"
```

---

## Task 4: Package manager detection

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'package manager'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `preflight()`**

```bash
detect_pkg_mgr() {
  step "Package manager"
  local candidate
  for candidate in apt-get dnf yum pacman zypper; do
    if have "$candidate"; then
      PKG_MGR="$candidate"
      ok "detected package manager: $PKG_MGR"
      return 0
    fi
  done
  PKG_MGR=""
  warn "no supported package manager found (looked for apt-get, dnf, yum, pacman, zypper)"
  info "missing prerequisites will be reported but not installed"
}

# Distribution package names for a logical prerequisite.
pkg_names_for() {
  case "$PKG_MGR:$1" in
    apt-get:python) printf 'python3 python3-venv python3-pip' ;;
    apt-get:git)    printf 'git' ;;
    apt-get:node)   printf 'nodejs npm' ;;
    dnf:python|yum:python) printf 'python3 python3-pip' ;;
    dnf:git|yum:git)       printf 'git' ;;
    dnf:node|yum:node)     printf 'nodejs npm' ;;
    pacman:python) printf 'python python-pip' ;;
    pacman:git)    printf 'git' ;;
    pacman:node)   printf 'nodejs npm' ;;
    zypper:python) printf 'python311 python311-pip' ;;
    zypper:git)    printf 'git' ;;
    zypper:node)   printf 'nodejs npm' ;;
    *) printf '' ;;
  esac
}

# argv of the install command for this package manager.
pkg_install_argv() {
  case "$PKG_MGR" in
    apt-get) printf 'sudo apt-get install -y' ;;
    dnf)     printf 'sudo dnf install -y' ;;
    yum)     printf 'sudo yum install -y' ;;
    pacman)  printf 'sudo pacman -S --noconfirm' ;;
    zypper)  printf 'sudo zypper install -y' ;;
    *)       printf '' ;;
  esac
}
```

- [ ] **Step 3: Call it from `main()`, after `preflight`**

```bash
  detect_pkg_mgr
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'package manager'`
Expected: PASS, `1`. On macOS the line is the `no supported package manager found` warning; on Debian it is `detected package manager: apt-get`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): package manager detection and package name mapping"
```

---

## Task 5: Prerequisite checks

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'Python'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `pkg_install_argv()`**

```bash
find_python() {
  local candidate major minor
  for candidate in python3.13 python3.12 python3.11 python3; do
    have "$candidate" || continue
    major="$("$candidate" -c 'import sys; print(sys.version_info[0])' 2>/dev/null || printf '0')"
    minor="$("$candidate" -c 'import sys; print(sys.version_info[1])' 2>/dev/null || printf '0')"
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
```

- [ ] **Step 3: Call it from `main()`, after `detect_pkg_mgr`**

```bash
  check_prereqs
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -E '\[ok\] (Python|git)'`
Expected: PASS, lines for the detected Python version and git.

Run: `./scripts/install.sh --dry-run --no-web 2>&1 | grep -c 'skipping Node/npm'`
Expected: `1`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): prerequisite detection for python, venv, git, node"
```

---

## Task 6: Install missing prerequisites with consent

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'nothing to install'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `check_prereqs()`**

```bash
install_prereqs() {
  step "Install prerequisites"

  if (( ${#MISSING[@]} == 0 )); then
    ok "nothing to install"
    return 0
  fi

  local packages="" logical
  for logical in "${MISSING[@]}"; do
    packages+="$(pkg_names_for "$logical") "
  done
  packages="${packages% }"

  if [[ -z "$PKG_MGR" || -z "$packages" ]]; then
    printf '\n'
    warn "cannot install automatically on this system"
    info "install these yourself, then re-run: ${MISSING[*]}"
    die "$EX_DISTRO" "unsupported distribution"
  fi

  local install_argv
  install_argv="$(pkg_install_argv)"
  printf '\n  The following packages are missing and will be installed:\n'
  printf '    %s\n' "$packages"
  printf '  Command:\n'
  printf '    %s %s\n\n' "$install_argv" "$packages"

  if (( ! ASSUME_YES )); then
    local reply
    read -r -p "  Proceed? [y/N] " reply || reply=""
    case "$reply" in
      [yY]|[yY][eE][sS]) ;;
      *) die "$EX_PREREQ" "declined; install the packages above and re-run" ;;
    esac
  fi

  if [[ "$PKG_MGR" == "apt-get" ]]; then
    run_cmd sudo apt-get update
  fi
  # shellcheck disable=SC2086
  run_cmd $install_argv $packages

  MISSING=()
  if ! find_python; then
    die "$EX_PREREQ" "Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} still not found after install"
  fi
  ok "prerequisites installed"
}
```

Note on the `shellcheck disable`: `$install_argv` and `$packages` must word-split here, which is exactly what SC2086 warns about. The values are built from the fixed tables in Task 4 and never from user input.

- [ ] **Step 3: Call it from `main()`, after `check_prereqs`**

```bash
  install_prereqs
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run --no-web 2>&1 | grep -c 'nothing to install'`
Expected: PASS, `1` on a machine that already has Python and git.

To exercise the missing branch without a Linux host, temporarily raise the bar:

```bash
sed -i.bak 's/^readonly MIN_NODE_MAJOR=18/readonly MIN_NODE_MAJOR=999/' scripts/install.sh
./scripts/install.sh --dry-run 2>&1 | tail -20
mv scripts/install.sh.bak scripts/install.sh
```
Expected: the missing-package summary and, with no package manager on macOS, `[fail] unsupported distribution` with exit 2. Confirm `scripts/install.sh` is restored afterwards with `git diff --stat`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): consent-gated installation of missing prerequisites"
```

---

## Task 7: Virtualenv and package install

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'pip install'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `install_prereqs()`**

```bash
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

  run_cmd "$venv/bin/python" -m pip install --quiet -e "$REPO_ROOT[$extra]" \
    || die "$EX_VENV" "pip install -e .[$extra] failed"
  ok "installed Replicant with the '$extra' extra"

  if (( ! DRY_RUN )) && [[ ! -x "$venv/bin/replicant" ]]; then
    die "$EX_VENV" "the 'replicant' console script was not installed"
  fi
}
```

- [ ] **Step 3: Call both from `main()`, after `install_prereqs`**

```bash
  setup_venv
  pip_install
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'pip install'`
Expected: PASS, at least `1`.

Run: `./scripts/install.sh --dry-run --dev 2>&1 | grep -o '\[dev\]'`
Expected: `[dev]` (the extra switches with the flag).

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): venv creation and editable package install"
```

---

## Task 8: Frontend build

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'npm run build'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `pip_install()`**

```bash
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
    ( cd "$webui" && run_cmd npm ci ) || die "$EX_BUILD" "npm ci failed"
  else
    ( cd "$webui" && run_cmd npm install ) || die "$EX_BUILD" "npm install failed"
  fi
  ( cd "$webui" && run_cmd npm run build ) || die "$EX_BUILD" "npm run build failed"

  if (( ! DRY_RUN )) && [[ ! -f "$webui/dist/index.html" ]]; then
    die "$EX_BUILD" "build finished but $webui/dist/index.html is missing"
  fi
  ok "frontend built"
}
```

- [ ] **Step 3: Call it from `main()`, after `pip_install`**

```bash
  build_frontend
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'npm run build'`
Expected: PASS, `1`.

Run: `./scripts/install.sh --dry-run --no-web 2>&1 | grep -c 'skipped (--no-web)'`
Expected: `1`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): frontend build with dist assertion"
```

---

## Task 9: Verification

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Write the failing check**

Run: `./scripts/install.sh --dry-run 2>&1 | grep -c 'Verify'`
Expected: FAIL, `0`.

- [ ] **Step 2: Add after `build_frontend()`**

```bash
verify_install() {
  step "Verify"
  local venv="$REPO_ROOT/.venv"
  local bin="$venv/bin/replicant"
  local py="$venv/bin/python"

  if (( DRY_RUN )); then
    info "would run: $bin list"
    info "would run: $bin run REP-001 --no-send --to-file <tmp> and require a CEF:0| first line"
    info "would run: a loopback UDP send to 127.0.0.1 and require datagrams to arrive"
    return 0
  fi

  # 1. catalog
  "$bin" list >/dev/null 2>&1 || die "$EX_VERIFY" "'replicant list' failed"
  ok "catalog loads"

  # 2. render to file, no network
  local tmp_log
  tmp_log="$(mktemp -t replicant-verify.XXXXXX)"
  trap 'rm -f "$tmp_log" "${listener_out:-}"' RETURN
  "$bin" run REP-001 --intensity low --to-file "$tmp_log" --no-send >/dev/null 2>&1 \
    || die "$EX_VERIFY" "'replicant run --no-send' failed"
  head -n 1 "$tmp_log" | grep -q '^CEF:0|' \
    || die "$EX_VERIFY" "output does not start with CEF:0| (got: $(head -c 40 "$tmp_log"))"
  ok "CEF written ($(wc -l < "$tmp_log" | tr -d ' ') lines)"

  # 3. real loopback transport
  local listener_out port count
  listener_out="$(mktemp -t replicant-listener.XXXXXX)"
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
  local listener_pid=$!

  port=""
  local i
  for i in $(seq 1 50); do
    port="$(awk '/^PORT /{print $2; exit}' "$listener_out" 2>/dev/null || true)"
    [[ -n "$port" ]] && break
    sleep 0.1
  done
  [[ -n "$port" ]] || { kill "$listener_pid" 2>/dev/null || true; die "$EX_VERIFY" "listener did not start"; }

  # Low intensity and a short duration: this path goes through the emitter and is
  # subject to the eps cap, so a heavier technique would look like a hang.
  "$bin" run REP-001 --intensity low --duration 2m \
      --host 127.0.0.1 --port "$port" --transport udp >/dev/null 2>&1 \
    || { kill "$listener_pid" 2>/dev/null || true; die "$EX_VERIFY" "loopback send failed"; }

  wait "$listener_pid" 2>/dev/null || true
  count="$(awk '/^COUNT /{print $2; exit}' "$listener_out" 2>/dev/null || printf '0')"
  (( count > 0 )) || die "$EX_VERIFY" "no datagrams arrived on the loopback listener"
  ok "loopback transport delivered $count events"
}
```

- [ ] **Step 3: Call it from `main()`, after `build_frontend`**

```bash
  verify_install
```

- [ ] **Step 4: Verify**

Run: `bash -n scripts/install.sh && ./scripts/install.sh --dry-run 2>&1 | grep -c 'would run:.*loopback'`
Expected: PASS, `1`.

The real verification body cannot run on macOS because preflight refuses a non-dry run. Exercise the underlying commands directly against the existing venv to prove the assertions hold:

```bash
./.venv/bin/replicant list >/dev/null && echo "list ok"
T=$(mktemp); ./.venv/bin/replicant run REP-001 --intensity low --to-file "$T" --no-send >/dev/null \
  && head -n1 "$T" | grep -q '^CEF:0|' && echo "cef ok"; rm -f "$T"
```
Expected: `list ok` then `cef ok`.

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): post-install verification including loopback transport"
```

---

## Task 10: Final report, README, and the gate

**Files:**
- Modify: `scripts/install.sh`, `README.md`

- [ ] **Step 1: Add `report()` after `verify_install()`**

```bash
report() {
  step "Done"
  local extra="web"
  (( DEV )) && extra="dev"
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
```

- [ ] **Step 2: Call it from `main()`, after `verify_install`**

```bash
  report
```

- [ ] **Step 3: Add the README section**

In `README.md`, immediately after the `## Quick start` code block that ends with `./.venv/bin/pip install -e ".[dev]"`, insert:

````markdown
### Linux one-shot install

On a fresh Linux box, `scripts/install.sh` does the whole setup and then verifies it:

```bash
git clone https://github.com/404SecNotFound/Replicant.git
cd Replicant
./scripts/install.sh
```

It checks prerequisites first and, if any are missing, prints exactly what it will install and asks before touching the system. It then creates `.venv`, installs Replicant, builds the web UI, and proves the install works by loading the catalog, rendering CEF to a file, and sending a run over loopback UDP.

Flags: `--no-web` (CLI only), `--dev` (dev extra), `--yes` (non-interactive), `--dry-run` (show every action, change nothing).

Installing pulls packages from your distribution, PyPI, and npm. That is install-time egress and is separate from the runtime rule that Replicant's only network egress is the collector you configure.
````

- [ ] **Step 4: Run the gate**

```bash
bash -n scripts/install.sh
shellcheck scripts/install.sh || echo "(shellcheck unavailable or advisory)"
./scripts/install.sh --dry-run
./scripts/install.sh --dry-run --no-web
./scripts/install.sh --dry-run --dev
./.venv/bin/pytest -q -p no:warnings >/dev/null 2>&1; echo "pytest exit=$?"
```
Expected: `bash -n` silent; the three dry runs each reach `==> Done` with no `[fail]`; `pytest exit=0` and the count unchanged from `main` (this task adds no Python).

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh README.md
git commit -m "feat(install): completion report and README install section"
```

---

## Task 11: Review and open the PR

- [ ] **Step 1: Whole-implementation review**

Use superpowers:requesting-code-review against `main..HEAD`. Focus the reviewer on: word-splitting and quoting bugs, the `trap ... RETURN` cleanup in `verify_install`, listener/PID handling if the send fails, idempotence on re-run, and whether any path can leave a half-built install without a non-zero exit.

- [ ] **Step 2: Fix findings, re-run the Task 10 gate.**

- [ ] **Step 3: Push and open the PR (only when the operator asks)**

```bash
git push -u origin feature/linux-install-script
gh pr create -R 404SecNotFound/Replicant --base main --head feature/linux-install-script \
  --title "Linux install script" --body-file docs/linux-install-script-design.md
```

- [ ] **Step 4: Operator validation on a real Linux host**

The plan cannot close this itself. Distribution package names, the `sudo` path, and the non-dry verification run are unproven until executed on Linux. Ask the operator to run `./scripts/install.sh` on a fresh box and report the outcome.

---

## Self-review notes (author checklist, done)

- **Spec coverage:** goal (T1-T10), in-repo shape (T7 editable install), consent-gated prereqs (T6), verification incl. loopback (T9), flags `--no-web`/`--dev`/`--yes`/`--dry-run`/`--help` (T1, exercised T5/T7/T8/T10), exit codes 0-6 (T1 constants, used T3/T6/T7/T8/T9), safety note (T1 header, T10 README), error trap (T2), testing approach (preamble, T10 gate), non-goals untouched. Every spec section maps to a task.
- **Placeholder scan:** none. Every step carries the literal code or command to run.
- **Type consistency:** `MISSING` is set by `check_prereqs` (T5) and consumed by `install_prereqs` (T6); `PYTHON_BIN` set by `find_python` (T5) and used by `setup_venv` (T7); `PKG_MGR` set by `detect_pkg_mgr` (T4) and read by `pkg_names_for`/`pkg_install_argv` (T4) and `install_prereqs` (T6); `REPO_ROOT` set in T1 and used throughout; `run_cmd`/`die`/`ok`/`warn`/`info`/`step`/`have` defined once in T2 and used unchanged after. `main()` gains exactly one call per task, in order.
- **Known gap, deliberate:** no pytest task. The suite count must be identical to `main` after this branch; if it changed, something Python was touched that should not have been.
