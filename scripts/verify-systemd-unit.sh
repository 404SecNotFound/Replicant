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
# Assertions for scripts/replicant-web.service, run INSIDE a container that has a
# real systemd as PID 1 and the unit already enabled.
#
# `systemd-analyze verify` only parses the unit. It cannot tell you that the
# sandboxing directives still let the token be written, that Restart=on-failure
# actually recovers the service, that the token stays out of the journal, or that
# the thing serves once it is up. Those need systemd to really run it.
#
# Driven by .github/workflows/ci.yml (job: systemd-unit), which also documents how
# to reproduce the container locally.
#
# Comparisons go through `expect` rather than `A && B || C`: shellcheck flags that
# form (SC2015) because C also runs when A is false, and scripts/install.sh already
# settled on spelling these out.
set -uo pipefail

FAILED=0

pass() { printf 'PASS  %s\n' "$1"; }

fail() {
  printf 'FAIL  %s\n' "$1"
  if [[ -n "${2:-}" ]]; then
    printf '      %s\n' "$2"
  fi
  FAILED=1
}

# expect <label> <actual> <expected> [detail-on-failure]
expect() {
  if [[ "$2" == "$3" ]]; then
    pass "$1"
  else
    fail "$1" "got '$2', expected '$3'${4:+ | $4}"
  fi
}

PORT="${REPLICANT_WEB_PORT:-9787}"
UNIT=replicant-web
CFG=/opt/replicant/.config/replicant

probe() {
python3 - "$1" <<'PY'
import sys, urllib.error, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
        print(response.status)
except urllib.error.HTTPError as exc:
    print(exc.code)
except Exception as exc:  # noqa: BLE001 - any transport failure is a non-answer
    print("ERR %s" % exc)
PY
}

# 1. systemd's own parser accepts it, with no warnings.
if out="$(systemd-analyze verify "/etc/systemd/system/$UNIT.service" 2>&1)"; then
  expect "systemd-analyze verify is silent" "${out:-}" ""
else
  fail "systemd-analyze verify rejected the unit" "$out"
fi

# 2. The service reached running.
expect "unit is active" "$(systemctl is-active "$UNIT" 2>&1)" "active" \
  "$(systemctl status "$UNIT" --no-pager -l 2>&1 | tail -5)"

# 3. Not running as root. /proc rather than ps, which a minimal image lacks.
main_pid="$(systemctl show -p MainPID --value "$UNIT")"
if [[ "$main_pid" =~ ^[0-9]+$ ]] && (( main_pid > 0 )); then
  expect "runs as the service user, not root" \
    "$(stat -c '%U' "/proc/$main_pid" 2>/dev/null)" "replicant"
else
  fail "no MainPID" "unit did not reach a running state"
fi

# 4/5. It serves, and it refuses an unauthenticated call. A unit that brought up an
# open server would otherwise look identical to a working one.
expect "/api/health answers 200" "$(probe "http://127.0.0.1:$PORT/api/health")" "200"
expect "/api/catalog refuses an unauthenticated request" \
  "$(probe "http://127.0.0.1:$PORT/api/catalog")" "401"

# 6. The token was written despite ProtectHome=read-only and ProtectSystem=full.
# This is the pairing that breaks if the unit ever moves config back under the
# service user's home directory.
if [[ -f "$CFG/web-token" ]]; then
  expect "token written 0600 under the sandbox" "$(stat -c '%a' "$CFG/web-token")" "600"
  expect "config dir is 0700" "$(stat -c '%a' "$CFG")" "700"
else
  fail "no token file at $CFG/web-token" "$(systemctl status "$UNIT" --no-pager -l 2>&1 | tail -5)"
fi

# 7. The token is NOT in the journal. Under systemd, stdout IS the journal, so a
# banner that prints the token writes it in cleartext to a file readable by root
# and the systemd-journal group, giving away what the 0600 file protects.
token="$(cat "$CFG/web-token" 2>/dev/null || echo)"
if [[ -n "$token" ]]; then
  if journalctl -u "$UNIT" --no-pager -o cat 2>/dev/null | grep -qF "$token"; then
    fail "token appears in the journal" "the startup banner must not print it off a tty"
  else
    pass "token is absent from the journal"
  fi
fi

# 8. Terminal tab off by default, because ExecStart binds 0.0.0.0.
if [[ -n "$token" ]]; then
  term="$(python3 - "$PORT" "$token" <<'PY'
import json, sys, urllib.request
request = urllib.request.Request("http://127.0.0.1:%s/api/config" % sys.argv[1])
request.add_header("Authorization", "Bearer %s" % sys.argv[2])
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        print(json.load(response)["terminal_enabled"])
except Exception as exc:  # noqa: BLE001
    print("ERR %s" % exc)
PY
)"
  expect "terminal tab disabled on the 0.0.0.0 bind" "$term" "False"
fi

# 9. Restart=on-failure really recovers it. Wait for the condition that matters,
# serving again, not merely a changed MainPID: systemd sets that as soon as it
# forks, and RestartSec=5s puts the socket several seconds behind it. Asserting on
# the PID alone reported the unit broken when it was still starting.
before="$(systemctl show -p MainPID --value "$UNIT")"
kill -9 "$before" 2>/dev/null
now=""
recovered=0
for _ in $(seq 1 60); do
  sleep 0.5
  now="$(systemctl show -p MainPID --value "$UNIT")"
  if [[ ! "$now" =~ ^[0-9]+$ ]] || (( now == 0 )) || [[ "$now" == "$before" ]]; then
    continue
  fi
  if [[ "$(probe "http://127.0.0.1:$PORT/api/health")" == "200" ]]; then
    recovered=1
    break
  fi
done
if (( recovered )); then
  pass "Restart=on-failure recovered it and it serves again ($before -> $now)"
else
  fail "did not recover after SIGKILL within 30s" \
    "$(systemctl status "$UNIT" --no-pager -l 2>&1 | tail -10)"
fi

# 10. The token survives the restart, which is the point of persisting it.
expect "token survived the restart" "$(cat "$CFG/web-token" 2>/dev/null || echo)" "$token"

printf '\n'
if (( FAILED )); then
  printf 'RESULT: FAILURES PRESENT\n'
  exit 1
fi
printf 'RESULT: ALL CHECKS PASSED\n'
