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
"""PAN-OS profile behavior: severity mapping, guards, optional GeoIP field."""

from __future__ import annotations

import pytest

from replicant.core.models import EventRecord
from replicant.profiles.paloalto import PaloAltoProfile


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("emergency", 10),
        ("critical", 9),
        ("alert", 8),
        ("error", 6),
        ("warning", 5),
        ("notice", 3),
        ("information", 2),
        ("debug", 1),
    ],
)
def test_severity_not_reversed(level: str, severity: int) -> None:
    assert PaloAltoProfile().severity(level) == severity


def test_unknown_level_raises() -> None:
    with pytest.raises(ValueError):
        PaloAltoProfile().severity("bogus")


def test_unsupported_log_type_raises() -> None:
    event = EventRecord(
        log_type="utm",
        subtype="app-ctrl",
        action="block",
        level="warning",
        eventtime=1,
    )
    with pytest.raises(ValueError):
        PaloAltoProfile().render(event)


def _vpn_tunnel_up(extra_overrides: dict[str, str] | None = None) -> EventRecord:
    extra = {
        "logdesc": "SSL VPN tunnel up",
        "fgt_action": "tunnel-up",
        "remip": "203.0.113.60",
        "tunneltype": "ssl-tunnel",
        "tunnelid": "1846277",
        "group": "vpn-users",
        "reason": "login-success",
        "msg": "SSL tunnel established",
    }
    if extra_overrides:
        extra.update(extra_overrides)
    return EventRecord(
        log_type="event",
        subtype="vpn",
        action="tunnel-up",
        level="notice",
        eventtime=1752662122,
        duser="jsmith",
        src="203.0.113.60",
        extra=extra,
    )


def test_globalprotect_emits_source_region_when_srccountry_present() -> None:
    _, ext = PaloAltoProfile().render(_vpn_tunnel_up({"srccountry": "Wadiya"}))
    assert ext["cs4Label"] == "Source Region"
    assert ext["cs4"] == "Wadiya"


def test_globalprotect_omits_source_region_when_absent() -> None:
    _, ext = PaloAltoProfile().render(_vpn_tunnel_up())
    assert "cs4" not in ext


def test_proto_number_maps_to_name() -> None:
    _, ext = PaloAltoProfile().render(
        EventRecord(
            log_type="traffic",
            subtype="forward",
            action="accept",
            level="notice",
            eventtime=1,
            src="10.0.0.1",
            spt=1234,
            dst="203.0.113.1",
            dpt=443,
            proto=6,
            session_id=1,
            out_bytes=1,
            in_bytes=1,
            extra={
                "policyid": "1",
                "service": "HTTPS",
                "app": "HTTPS",
                "trandisp": "snat",
                "duration": "1",
                "sentpkt": "1",
                "rcvdpkt": "1",
            },
        )
    )
    assert ext["proto"] == "tcp"  # IP protocol 6 -> PAN-OS string
