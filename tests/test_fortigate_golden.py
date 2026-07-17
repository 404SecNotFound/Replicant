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
"""Byte-for-byte golden tests against docs/fortigate-cef-reference.md.

The reference document is the oracle. This test extracts the seven constructed
sample lines from section 3 of the reference, strips the transport-added syslog
prefix, and asserts the FortiGate profile + CEF serializer reproduce each CEF
payload exactly. Reading the lines from the file (rather than transcribing them)
removes transcription drift: if the reference changes, this test tracks it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from replicant.cef.serializer import to_cef
from replicant.core.models import EventRecord
from replicant.profiles.fortigate import FortiGateProfile

REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "fortigate-cef-reference.md"

# Matches only the seven section-3 golden lines: a numeric syslog PRI, then a
# FortiGate CEF payload. The section-1.4 template lines start with literal
# "<PRI>" (no digits) and the escaping examples have no prefix, so neither match.
_GOLDEN_LINE = re.compile(r"^<\d+>.* (CEF:0\|Fortinet\|Fortigate\|.*)$")


def _golden_payloads() -> list[str]:
    payloads: list[str] = []
    for line in REFERENCE.read_text(encoding="utf-8").splitlines():
        match = _GOLDEN_LINE.match(line)
        if match:
            payloads.append(match.group(1))
    return payloads


def _events() -> list[tuple[str, EventRecord]]:
    """The seven events, in the same order the lines appear in the reference."""

    return [
        (
            "traffic:forward accept",
            EventRecord(
                log_type="traffic",
                subtype="forward",
                action="accept",
                level="notice",
                eventtime=1752661924,
                src="10.20.30.40",
                spt=51544,
                dst="203.0.113.25",
                dpt=443,
                proto=6,
                session_id=48213,
                out_bytes=8421,
                in_bytes=61325,
                extra={
                    "policyid": "7",
                    "service": "HTTPS",
                    "app": "HTTPS",
                    "trandisp": "snat",
                    "duration": "122",
                    "sentpkt": "64",
                    "rcvdpkt": "58",
                },
            ),
        ),
        (
            "traffic:forward deny",
            EventRecord(
                log_type="traffic",
                subtype="forward",
                action="deny",
                level="warning",
                eventtime=1752661927,
                src="10.20.30.55",
                spt=44992,
                dst="198.51.100.77",
                dpt=3389,
                proto=6,
                session_id=48260,
                out_bytes=0,
                in_bytes=0,
                extra={
                    "policyid": "0",
                    "service": "RDP",
                    "policytype": "policy",
                    "sentpkt": "1",
                    "rcvdpkt": "0",
                },
            ),
        ),
        (
            "utm:ips signature reset",
            EventRecord(
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
                    "eventtype": "signature",
                    "ips_severity": "high",
                    "service": "HTTPS",
                    "policyid": "7",
                    "attack": "Apache.Struts.OGNL.Remote.Code.Execution",
                    "attackid": "40449",
                    "hostname": "10.20.30.40",
                    "request": "/struts2/index.action",
                    "direction": "incoming",
                    "profile": "default",
                    "cnt": "1",
                    "msg": "applications3A Apache.Struts.OGNL.Remote.Code.Execution",
                },
            ),
        ),
        (
            "dns:dns-query pass",
            EventRecord(
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
                    "profile": "default",
                    "xid": "42311",
                    "qname": "updates.example.net",
                    "qtype": "A",
                    "qtypeval": "1",
                    "qclass": "IN",
                },
            ),
        ),
        (
            "event:vpn ssl-login (success)",
            EventRecord(
                log_type="event",
                subtype="vpn",
                action="tunnel-up",
                level="notice",
                eventtime=1752662122,
                duser="jsmith",
                src="203.0.113.60",
                extra={
                    "logdesc": "SSL VPN tunnel up",
                    "fgt_action": "tunnel-up",
                    "remip": "203.0.113.60",
                    "tunneltype": "ssl-tunnel",
                    "tunnelid": "1846277",
                    "group": "vpn-users",
                    "reason": "login-success",
                    "msg": "SSL tunnel established",
                },
            ),
        ),
        (
            "event:vpn ssl-login-fail",
            EventRecord(
                log_type="event",
                subtype="vpn",
                action="ssl-login-fail",
                level="alert",
                eventtime=1752662140,
                duser="jsmith",
                src="198.51.100.200",
                extra={
                    "logdesc": "SSL VPN login fail",
                    "fgt_action": "ssl-login-fail",
                    "remip": "198.51.100.200",
                    "tunneltype": "ssl-web",
                    "reason": "sslvpn_login_permission_denied",
                    "msg": "SSL user failed to logged in",
                },
            ),
        ),
        (
            "event:system login failed",
            EventRecord(
                log_type="event",
                subtype="system",
                action="login",
                level="alert",
                eventtime=1752662165,
                duser="admin",
                src="10.20.30.9",
                extra={
                    "logdesc": "Admin login failed",
                    "fgt_action": "login",
                    "status": "failed",
                    "ui": "https(10.20.30.9)",
                    "method": "https",
                    "reason": "name_invalid",
                    "msg": (
                        "Administrator admin login failed from https(10.20.30.9) "
                        "because of invalid user name"
                    ),
                },
            ),
        ),
    ]


def test_reference_has_seven_golden_lines() -> None:
    assert len(_golden_payloads()) == 7


def test_event_fixture_count_matches_reference() -> None:
    assert len(_events()) == len(_golden_payloads())


@pytest.mark.parametrize("index", range(7))
def test_golden_line_byte_for_byte(index: int) -> None:
    profile = FortiGateProfile()
    label, event = _events()[index]
    expected = _golden_payloads()[index]
    header, extension = profile.render(event)
    produced = to_cef(header, extension)
    assert produced == expected, f"{label} mismatch"
