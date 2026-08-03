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
"""A collector reachable only over IPv6 must be usable.

F-10 of the 2026-08 security review. Every socket in the transport was created
with a hardcoded ``socket.AF_INET``, so an IPv6 collector address failed at
``connect`` with an unhelpful error and there was no way to reach one at all.
Dual-stack SIEM deployments are ordinary, and an operator whose collector has
only a v6 address had no route through the tool.

The family now comes from ``getaddrinfo``, which resolves a literal or a name to
whichever family it actually has, so nothing has to be configured and IPv4 keeps
behaving exactly as it did.

Safety rule 1 is unchanged: the only peer is still the configured collector, and
resolution asks about that host and no other.
"""

from __future__ import annotations

import socket

import pytest

from replicant.core.models import CollectorProfile
from replicant.transport.syslog import SyslogEmitter, probe_collector

pytestmark = pytest.mark.skipif(not socket.has_ipv6, reason="host has no IPv6 support at all")


def _v6_available() -> bool:
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        probe.bind(("::1", 0))
    except OSError:
        return False
    finally:
        probe.close()
    return True


needs_v6_loopback = pytest.mark.skipif(not _v6_available(), reason="no IPv6 loopback on this host")


@needs_v6_loopback
def test_a_udp_datagram_reaches_an_ipv6_collector() -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    listener.bind(("::1", 0))
    listener.settimeout(3.0)
    port = int(listener.getsockname()[1])
    try:
        profile = CollectorProfile(name="t", host="::1", port=port, transport="udp")
        with SyslogEmitter(profile) as emitter:
            emitter.send("CEF:0|x|y|z|1|n|3|", level="notice")
        data, _ = listener.recvfrom(65535)
    finally:
        listener.close()

    assert b"CEF:0" in data


@needs_v6_loopback
def test_a_tcp_stream_connects_over_ipv6() -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    try:
        profile = CollectorProfile(name="t", host="::1", port=port, transport="tcp")
        with SyslogEmitter(profile) as emitter:
            emitter.send("CEF:0|x|y|z|1|n|3|", level="notice")
        accepted, _ = listener.accept()
        accepted.settimeout(3.0)
        received = accepted.recv(65535)
        accepted.close()
    finally:
        listener.close()

    assert b"CEF:0" in received


@needs_v6_loopback
def test_the_connect_probe_reports_an_ipv6_path() -> None:
    """The verdict has to describe a v6 path, not fail resolving it."""
    listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    listener.bind(("::1", 0))
    port = int(listener.getsockname()[1])
    try:
        report = probe_collector(
            CollectorProfile(name="t", host="::1", port=port, transport="udp"),
            payload="<13>probe",
        )
    finally:
        listener.close()

    assert report.verdict == "sent_unconfirmed"
    assert report.source is not None


def test_ipv4_is_unchanged() -> None:
    """The regression that matters most: v6 support must cost v4 nothing."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(3.0)
    port = int(listener.getsockname()[1])
    try:
        profile = CollectorProfile(name="t", host="127.0.0.1", port=port, transport="udp")
        with SyslogEmitter(profile) as emitter:
            emitter.send("CEF:0|x|y|z|1|n|3|", level="notice")
        data, _ = listener.recvfrom(65535)
    finally:
        listener.close()

    assert b"CEF:0" in data
