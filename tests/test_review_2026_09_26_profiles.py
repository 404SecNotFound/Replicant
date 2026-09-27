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
"""Both verdicts of the admin login path, on the fields a rule keys on.

CLAUDE.md: "a golden-line test that covers one verdict of a two-verdict field is
not a test of that field." The golden line for ``event:system`` is a failed
login on every vendor, and the engine only ever produces successful ones
(REP-018), so each of these was wrong on the only case that ships.
"""

from __future__ import annotations

from replicant.core.models import EventRecord, load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import ScenarioEngine


def _login(status: str, level: str) -> EventRecord:
    successful = status == "success"
    return EventRecord(
        log_type="event",
        subtype="system",
        action="login",
        level=level,
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
            "msg": "Administrator svc-backup login",
        },
    )


def test_fortigate_success_and_failure_carry_different_signature_ids() -> None:
    """Success rendered 32002, which the reference defines as 'login failed'."""

    profile = FortiGateProfile()
    ok_header, ok_ext = profile.render(_login("success", "notice"))
    bad_header, bad_ext = profile.render(_login("failed", "alert"))

    assert bad_header.signature_id == "32002"
    assert bad_ext["FTNTFGTlogid"] == "0100032002"
    assert bad_header.name == "event:system login failed"

    assert ok_header.signature_id == "32001"
    assert ok_ext["FTNTFGTlogid"] == "0100032001"
    assert ok_header.name == "event:system login success"
    assert ok_header.signature_id != bad_header.signature_id
    assert ok_header.name != bad_header.name


def test_every_rep018_login_renders_the_success_signature_on_fortigate() -> None:
    catalog = load_catalog(TECHNIQUE_CATALOG)
    plan = ScenarioEngine().plan(catalog.by_id("REP-018"), "medium", EntityModel.build(), 1337)
    profile = FortiGateProfile()
    logins = [e for e in plan.events if e.log_type == "event" and e.subtype == "system"]
    assert logins
    assert {profile.render(e)[0].signature_id for e in logins} == {"32001"}


def test_checkpoint_successful_system_login_is_unknown_without_cp_severity() -> None:
    """Reference 2.2-2.3: successful auth is Unknown, cp_severity only on failures.

    Success rendered 'Low' with cp_severity=Low, so every REP-018 login looked like
    a low-severity finding to a rule reading severity.
    """

    header, ext = CheckPointProfile().render(_login("success", "notice"))
    assert header.severity == "Unknown"
    assert "cp_severity" not in ext
    assert ext["act"] == "Accept"


def test_checkpoint_failed_system_login_keeps_its_level_severity() -> None:
    """The other verdict, which the golden line covers: unchanged."""

    header, ext = CheckPointProfile().render(_login("failed", "alert"))
    assert header.severity == "High"
    assert ext["cp_severity"] == "High"
    assert ext["act"] == "Reject"
