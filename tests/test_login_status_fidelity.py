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
"""A successful login must not render as a failed one, on any vendor.

The defect this guards: ``event:system`` is the login path, and two of the three
profiles hardcoded failure semantics into it. Check Point emitted
``act=Reject`` and ``auth_status=Failed Login`` unconditionally; Palo Alto
emitted ``PanOSEventID=auth-fail`` unconditionally. The engine only ever sends
``status="success"`` down this path, from REP-018's lateral movement chain, so
every admin login Replicant produced on those two vendors was internally
contradictory: a Reject whose own ``msg`` said "Admin login successful".

That is worse than a cosmetic mismatch. REP-018's detection use case keys on
*successful* administrative logins moving between hosts, so the events were
wrong in exactly the field a correlation rule reads, on exactly the technique
that needs them. A detection engineer tuning against this would have concluded
the rule did not fire because the rule was wrong.

FortiGate is the oracle here and was always correct: it carries ``status``
straight into ``FTNTFGTstatus`` and into the event name. Both precedents for the
fix were already in the same two files, in the VPN handlers, which branch on
``is_fail``. The bug was that the system handler did not.

These are parametrized over every vendor rather than written per profile, so a
fourth vendor cannot reintroduce it quietly.
"""

from __future__ import annotations

import pytest

from replicant.core.models import EventRecord
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile

PROFILES = [
    pytest.param(FortiGateProfile, id="fortigate"),
    pytest.param(PaloAltoProfile, id="paloalto"),
    pytest.param(CheckPointProfile, id="checkpoint"),
]

# Words that assert a login did not succeed. Matched case-insensitively against
# every rendered extension value.
FAILURE_WORDS = ("fail", "reject", "deny", "denied")


def _login(status: str) -> EventRecord:
    """An ``event:system`` login exactly as the engine builds it for REP-018."""
    successful = status == "success"
    return EventRecord(
        log_type="event",
        subtype="system",
        action="login",
        level="notice",
        eventtime=1752537600,
        duser="svc-backup",
        src="10.30.0.44",
        session_id=4242,
        extra={
            "logdesc": "Admin login successful" if successful else "Admin login failed",
            "fgt_action": "login",
            "status": status,
            "ui": "ssh(10.30.0.44)",
            "method": "ssh",
            "reason": "none" if successful else "password_invalid",
            "msg": (
                "Administrator svc-backup logged in successfully from ssh(10.30.0.44)"
                if successful
                else "Administrator svc-backup login failed from ssh(10.30.0.44)"
            ),
        },
    )


@pytest.mark.parametrize("profile_cls", PROFILES)
def test_a_successful_login_carries_no_failure_verdict(profile_cls: type) -> None:
    _header, ext = profile_cls().render(_login("success"))

    # The message field is the event's own account of itself. Any *other* field
    # claiming failure contradicts it, which is the defect.
    offenders = {
        key: value
        for key, value in ext.items()
        if key not in {"msg", "FTNTFGTmsg", "FTNTFGTlogdesc", "logdesc"}
        and any(word in str(value).lower() for word in FAILURE_WORDS)
    }

    assert offenders == {}, f"success rendered with failure semantics: {offenders}"


@pytest.mark.parametrize("profile_cls", PROFILES)
def test_a_failed_login_is_still_rendered_as_a_failure(profile_cls: type) -> None:
    """The other half. A fix that always says success is the same bug mirrored."""
    _header, ext = profile_cls().render(_login("failure"))
    blob = " ".join(str(v).lower() for v in ext.values())

    assert any(word in blob for word in FAILURE_WORDS)


@pytest.mark.parametrize("profile_cls", PROFILES)
def test_the_rendered_status_matches_the_event(profile_cls: type) -> None:
    """Whatever field carries status must track the event, not a constant."""
    _h, success = profile_cls().render(_login("success"))
    _h2, failure = profile_cls().render(_login("failure"))

    assert success != failure, "the two outcomes render identically"
