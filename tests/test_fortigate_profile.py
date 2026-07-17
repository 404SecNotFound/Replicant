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
"""FortiGate profile behavior: severity mapping, signature-id derivation, guards."""

from __future__ import annotations

import pytest

from replicant.core.models import EventRecord
from replicant.profiles.fortigate import FortiGateDevice, FortiGateProfile


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("emergency", 8),
        ("alert", 7),
        ("critical", 6),
        ("error", 5),
        ("warning", 4),
        ("notice", 3),
        ("notification", 3),
        ("information", 2),
        ("debug", 1),
    ],
)
def test_severity_is_reversed_fortios_level(level: str, severity: int) -> None:
    assert FortiGateProfile().severity(level) == severity


def test_severity_case_insensitive() -> None:
    assert FortiGateProfile().severity("NOTICE") == 3


def test_unknown_level_raises() -> None:
    with pytest.raises(ValueError):
        FortiGateProfile().severity("bogus")


def _dns_event() -> EventRecord:
    return EventRecord(
        log_type="dns",
        subtype="dns-query",
        action="pass",
        level="notice",
        eventtime=1752662041,
        src="10.20.30.40",
        spt=54621,
        dst="10.20.0.53",
        dpt=53,
        proto=17,
        session_id=13355,
        extra={
            "policyid": "7",
            "xid": "42311",
            "qname": "abc.example.net",
            "qtype": "TXT",
            "qtypeval": "16",
        },
    )


def test_signature_id_is_last_five_of_logid() -> None:
    header, ext = FortiGateProfile().render(_dns_event())
    assert ext["FTNTFGTlogid"] == "1501054803"
    assert header.signature_id == "54803"


def test_product_string_is_lowercase_g() -> None:
    header, _ = FortiGateProfile().render(_dns_event())
    assert header.device_vendor == "Fortinet"
    assert header.device_product == "Fortigate"


def test_default_interface_used_when_absent() -> None:
    _, ext = FortiGateProfile().render(_dns_event())
    assert ext["deviceInboundInterface"] == "port2"


def test_byte_key_is_switchable() -> None:
    device = FortiGateDevice(byte_key_out="FTNTFGTsentbyte", byte_key_in="FTNTFGTrcvdbyte")
    event = EventRecord(
        log_type="traffic",
        subtype="forward",
        action="accept",
        level="notice",
        eventtime=1,
        src="10.0.0.1",
        spt=1,
        dst="203.0.113.1",
        dpt=443,
        proto=6,
        session_id=1,
        out_bytes=100,
        in_bytes=200,
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
    _, ext = FortiGateProfile(device).render(event)
    assert "FTNTFGTsentbyte" in ext and "out" not in ext
    assert ext["FTNTFGTsentbyte"] == "100"


def test_unsupported_log_type_raises() -> None:
    event = EventRecord(
        log_type="utm",
        subtype="app-ctrl",
        action="block",
        level="warning",
        eventtime=1,
    )
    with pytest.raises(ValueError):
        FortiGateProfile().render(event)


def test_missing_required_field_raises() -> None:
    event = EventRecord(
        log_type="dns",
        subtype="dns-query",
        action="pass",
        level="notice",
        eventtime=1,
        # no src / session_id -> required for dns template
        extra={
            "policyid": "7",
            "xid": "1",
            "qname": "a.example.net",
            "qtype": "A",
            "qtypeval": "1",
        },
    )
    with pytest.raises(ValueError):
        FortiGateProfile().render(event)
