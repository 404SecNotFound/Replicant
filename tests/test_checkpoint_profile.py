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
"""Check Point profile behavior: string severity, ms epoch, numeric proto, guards."""

from __future__ import annotations

import pytest

from replicant.core.models import EventRecord
from replicant.profiles.checkpoint import CheckPointProfile


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("emergency", "Very-High"),
        ("critical", "Very-High"),
        ("alert", "High"),
        ("error", "High"),
        ("warning", "Medium"),
        ("notice", "Low"),
        ("notification", "Low"),
        ("information", "Low"),
        ("debug", "Low"),
    ],
)
def test_severity_is_string_not_reversed(level: str, severity: str) -> None:
    assert CheckPointProfile().severity(level) == severity


def test_unknown_level_raises() -> None:
    with pytest.raises(ValueError):
        CheckPointProfile().severity("bogus")


def test_unsupported_log_type_raises() -> None:
    event = EventRecord(
        log_type="utm",
        subtype="app-ctrl",
        action="block",
        level="warning",
        eventtime=1,
    )
    with pytest.raises(ValueError):
        CheckPointProfile().render(event)


def _traffic(dst: str, action: str = "accept") -> EventRecord:
    return EventRecord(
        log_type="traffic",
        subtype="forward",
        action=action,
        level="notice",
        eventtime=1,
        src="10.20.30.40",
        spt=1234,
        dst=dst,
        dpt=443,
        proto=6,
        session_id=1,
        out_bytes=1,
        in_bytes=1,
        extra={"policyid": "1", "service": "HTTPS", "app": "HTTPS", "trandisp": "snat"},
    )


def test_rt_is_epoch_milliseconds() -> None:
    _, ext = CheckPointProfile().render(_traffic("203.0.113.1"))
    assert ext["rt"] == "1000"  # eventtime 1 second -> 1000 ms


def test_proto_is_numeric_string() -> None:
    _, ext = CheckPointProfile().render(_traffic("203.0.113.1"))
    assert ext["proto"] == "6"  # IANA protocol number, not a name


def test_device_direction_internal_is_zero_external_is_one() -> None:
    profile = CheckPointProfile()
    _, internal = profile.render(_traffic("10.9.9.9"))
    _, external = profile.render(_traffic("203.0.113.9"))
    assert internal["deviceDirection"] == "0"
    assert external["deviceDirection"] == "1"


def test_plain_connection_has_no_cp_severity_and_unknown_header() -> None:
    header, ext = CheckPointProfile().render(_traffic("203.0.113.1"))
    assert header.severity == "Unknown"
    assert "cp_severity" not in ext


def test_firewall_product_and_action() -> None:
    header, ext = CheckPointProfile().render(_traffic("203.0.113.1", action="deny"))
    assert header.device_product == "VPN-1 & FireWall-1"
    assert header.device_version == "Check Point"
    assert ext["act"] == "Drop"


def _ips() -> EventRecord:
    return EventRecord(
        log_type="utm",
        subtype="ips",
        action="reset",
        level="alert",
        eventtime=1752661995,
        src="198.51.100.30",
        spt=443,
        dst="10.20.30.40",
        dpt=49180,
        proto=6,
        session_id=901,
        extra={
            "ips_severity": "high",
            "service": "HTTPS",
            "policyid": "7",
            "attack": "Apache.Struts.OGNL.Remote.Code.Execution",
            "attackid": "40449",
            "request": "/struts2/index.action",
            "msg": "applications3A Apache.Struts.OGNL.Remote.Code.Execution",
        },
    )


def test_ips_emits_cp_severity_and_protection_fields() -> None:
    header, ext = CheckPointProfile().render(_ips())
    assert header.device_product == "SmartDefense"
    assert header.signature_id == "IPS"
    assert header.severity == "High"
    assert ext["cp_severity"] == "High"
    assert ext["cs4Label"] == "Protection Name"
    assert ext["cs4"] == "Apache.Struts.OGNL.Remote.Code.Execution"
    assert ext["act"] == "Prevent"


def _vpn(action: str, extra: dict[str, str]) -> EventRecord:
    return EventRecord(
        log_type="event",
        subtype="vpn",
        action=action,
        level="notice" if action == "tunnel-up" else "alert",
        eventtime=1752662122,
        duser="jsmith",
        src="203.0.113.60",
        extra=extra,
    )


def test_vpn_success_has_tunnel_and_no_cp_severity() -> None:
    event = _vpn(
        "tunnel-up",
        {
            "tunneltype": "ssl-tunnel",
            "tunnelid": "1846277",
            "group": "vpn-users",
            "reason": "login-success",
            "msg": "SSL tunnel established",
        },
    )
    header, ext = CheckPointProfile().render(event)
    assert header.device_product == "Mobile Access"
    assert header.severity == "Unknown"
    assert ext["auth_status"] == "Successful Login"
    assert ext["cn1"] == "1846277"
    assert "cp_severity" not in ext


def test_vpn_fail_has_cp_severity_and_no_tunnel() -> None:
    event = _vpn(
        "ssl-login-fail",
        {
            "tunneltype": "ssl-web",
            "reason": "sslvpn_login_permission_denied",
            "msg": "SSL user failed to logged in",
        },
    )
    header, ext = CheckPointProfile().render(event)
    assert header.severity == "High"
    assert ext["cp_severity"] == "High"
    assert ext["auth_status"] == "Failed Login"
    assert "cn1" not in ext


def test_system_product_is_check_point() -> None:
    event = EventRecord(
        log_type="event",
        subtype="system",
        action="login",
        level="alert",
        eventtime=1752662165,
        duser="admin",
        src="10.20.30.9",
        extra={
            "status": "failed",
            "method": "https",
            "reason": "name_invalid",
            "msg": "Administrator admin login failed",
        },
    )
    header, ext = CheckPointProfile().render(event)
    assert header.device_product == "Check Point"
    assert ext["administrator"] == "admin"
    assert ext["operation"] == "Log In"
