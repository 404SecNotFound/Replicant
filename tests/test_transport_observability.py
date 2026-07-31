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
"""What the transport reports about its own sends.

Written against a real loopback socket rather than a mock, because the claim
under test is about what the socket layer does and a mock would only assert that
the code calls the method it was written to call.

Motivating failure: a live run reported 921 events per second sent while the
collector received nothing. Every assertion here is something that would have
narrowed that down.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from replicant.core.models import CollectorProfile
from replicant.obs import log as obs_log
from replicant.transport.syslog import UDP_SAFE_PAYLOAD, SyslogEmitter


@pytest.fixture(autouse=True)
def fresh_buffer() -> Iterator[None]:
    obs_log.reset_for_tests()
    obs_log.install(capacity=200, level="debug")
    yield
    obs_log.reset_for_tests()


@pytest.fixture()
def receiver() -> Iterator[socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    yield sock
    sock.close()


def _profile(port: int) -> CollectorProfile:
    return CollectorProfile(host="127.0.0.1", port=port, transport="udp")


def _messages() -> list[str]:
    return [entry.message for entry in obs_log.snapshot()]


def test_send_returns_the_byte_count_and_counts_it(receiver: socket.socket) -> None:
    emitter = SyslogEmitter(_profile(receiver.getsockname()[1]))

    size = emitter.send("CEF:0|Fortinet|Fortigate|7.4.1|00013|test|3|src=192.0.2.1")

    delivered, _ = receiver.recvfrom(65535)
    assert size == len(delivered)
    assert emitter.stats.sends == 1
    assert emitter.stats.bytes == size
    assert emitter.stats.errors == 0
    emitter.close()


def test_an_oversize_datagram_is_counted_and_warned_once(receiver: socket.socket) -> None:
    emitter = SyslogEmitter(_profile(receiver.getsockname()[1]))
    payload = "CEF:0|Fortinet|Fortigate|7.4.1|00013|big|3|msg=" + ("x" * 2000)

    for _ in range(3):
        emitter.send(payload)
        receiver.recvfrom(65535)

    assert emitter.stats.oversize == 3
    warnings = [m for m in _messages() if "non-fragmenting limit" in m]
    # Counted every time, reported once. 36000 identical warnings would bury the
    # buffer that has to hold the rest of the run.
    assert len(warnings) == 1
    assert str(UDP_SAFE_PAYLOAD) in warnings[0]
    emitter.close()


def test_a_datagram_at_the_limit_does_not_warn(receiver: socket.socket) -> None:
    emitter = SyslogEmitter(_profile(receiver.getsockname()[1]))
    # Frame adds a PRI, timestamp and hostname, so build the payload to land the
    # framed datagram exactly on the limit rather than guessing at the payload.
    overhead = len(emitter.frame("", "notice"))
    emitter.send("y" * (UDP_SAFE_PAYLOAD - overhead))
    receiver.recvfrom(65535)

    assert emitter.stats.oversize == 0
    assert [m for m in _messages() if "non-fragmenting limit" in m] == []
    emitter.close()


def test_a_failed_send_is_counted_reported_and_re_raised() -> None:
    emitter = SyslogEmitter(_profile(9))
    emitter.connect()
    assert emitter._sock is not None
    emitter._sock.close()  # any send now raises OSError

    with pytest.raises(OSError):
        emitter.send("CEF:0|Fortinet|Fortigate|7.4.1|00013|x|3|")

    assert emitter.stats.errors == 1
    assert emitter.stats.sends == 0
    assert any("send failed" in m for m in _messages())


def test_connect_records_the_destination(receiver: socket.socket) -> None:
    port = receiver.getsockname()[1]
    emitter = SyslogEmitter(_profile(port))
    emitter.connect()

    assert any(f"127.0.0.1:{port}" in m and "udp" in m for m in _messages())
    emitter.close()


def test_close_reports_the_totals(receiver: socket.socket) -> None:
    emitter = SyslogEmitter(_profile(receiver.getsockname()[1]))
    emitter.send("CEF:0|Fortinet|Fortigate|7.4.1|00013|x|3|")
    receiver.recvfrom(65535)
    emitter.close()

    assert any("socket closed: 1 sends" in m for m in _messages())


def test_udp_open_states_that_delivery_is_unconfirmed(receiver: socket.socket) -> None:
    """The operator reading this log must not read 'sent' as 'delivered'."""

    emitter = SyslogEmitter(_profile(receiver.getsockname()[1]))
    emitter.connect()

    assert any("delivery is unconfirmed" in m for m in _messages())
    emitter.close()
