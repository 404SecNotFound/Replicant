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
"""Unattended scripts must say which delivery shape they want.

The defect this guards, and it was shipped and caught in CI rather than
reasoned about: sending to a collector now defaults to reproducing the plan's
own timeline, and REP-001 at low intensity spans 238 minutes. The installer's
loopback verification runs exactly that command to prove a socket works, so it
stopped being a smoke test and became a four hour wait. Two CI jobs sat on it
until they were cancelled.

An operator gets a printed projection and a prompt. A script gets neither, so a
script that sends has to name its pace. Burst is almost always the right answer
there: what these commands prove is that datagrams arrive, not the shape they
arrive in.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Files that run without anyone watching. Documentation is deliberately out of
# scope: a human running a README example sees the projection and can stop it.
UNATTENDED = sorted((REPO / "scripts").glob("*.sh")) + sorted(
    (REPO / ".github" / "workflows").glob("*.yml")
)


def _joined_commands(text: str) -> list[str]:
    """Lines with shell backslash-continuations folded into one.

    Without this the check reads the halves of a wrapped command separately and
    a flag on the first line looks absent from the second, which is exactly how
    the installer's own invocation is written.
    """

    return text.replace("\\\n", " ").splitlines()


def _live_sends_without_a_pace(text: str) -> list[str]:
    found = []
    for line in _joined_commands(text):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "run REP-" not in stripped:
            continue
        if "--host" not in stripped and "--profile" not in stripped:
            continue  # not a live send
        if "--no-send" in stripped:
            continue  # renders only, never reaches a collector
        if "--pace" not in stripped:
            found.append(" ".join(stripped.split()))
    return found


def test_the_check_catches_a_live_send_with_no_pace() -> None:
    """The installer's command as it was shipped, and as CI found it."""

    shipped = (
        '  if ! verify_cmd "loopback send" "$bin" run REP-001 --intensity low \\\n'
        '       --host 127.0.0.1 --port "$port" --transport udp; then\n'
    )

    assert _live_sends_without_a_pace(shipped)


def test_the_check_accepts_a_live_send_that_names_its_pace() -> None:
    fixed = (
        '  if ! verify_cmd "loopback send" "$bin" run REP-001 --intensity low --pace burst \\\n'
        '       --host 127.0.0.1 --port "$port" --transport udp; then\n'
    )

    assert _live_sends_without_a_pace(fixed) == []


def test_the_check_ignores_a_render_that_never_sends() -> None:
    """--no-send has no collector to pace against, so demanding a pace there
    would be a rule with nothing behind it."""

    dry = 'run REP-001 --intensity low --to-file "$tmp_log" --no-send\n'

    assert _live_sends_without_a_pace(dry) == []


def test_no_shipped_script_sends_without_naming_a_pace() -> None:
    offenders: list[str] = []
    for path in UNATTENDED:
        for command in _live_sends_without_a_pace(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(REPO)}: {command}")

    assert not offenders, (
        "these run unattended and send to a collector without naming a pace, so they "
        "inherit the plan's own timeline and can run for hours:\n  " + "\n  ".join(offenders)
    )
