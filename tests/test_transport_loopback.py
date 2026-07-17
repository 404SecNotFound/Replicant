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
"""Loopback transport tests.

A tiny in-test UDP and TCP receiver confirms lines arrive intact. Runs in CI with
no external collector (blueprint s17).
"""

from __future__ import annotations

import socket
import threading
from datetime import datetime
from pathlib import Path

from replicant.core.models import CollectorProfile
from replicant.transport.filesink import FileSink
from replicant.transport.syslog import SyslogEmitter

PAYLOAD = "CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward accept|3|src=10.20.30.40 dpt=443"


def test_udp_loopback_line_arrives_intact() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5.0)
    port = receiver.getsockname()[1]
    profile = CollectorProfile(name="loopback", host="127.0.0.1", port=port, transport="udp")
    try:
        with SyslogEmitter(profile) as emitter:
            assert emitter.send_test(PAYLOAD) is True
        data, _ = receiver.recvfrom(65535)
    finally:
        receiver.close()
    line = data.decode("utf-8")
    assert PAYLOAD in line
    assert line.startswith("<189>")  # local7.notice = 23*8 + 5


def test_tcp_loopback_line_arrives_intact() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received: list[bytes] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            received.append(conn.recv(65535))

    thread = threading.Thread(target=serve)
    thread.start()

    profile = CollectorProfile(name="loopback", host="127.0.0.1", port=port, transport="tcp")
    try:
        with SyslogEmitter(profile) as emitter:
            assert emitter.send_test(PAYLOAD) is True
        thread.join(timeout=5.0)
    finally:
        server.close()

    assert received, "TCP receiver got no data"
    line = received[0].decode("utf-8")
    assert PAYLOAD in line
    assert line.endswith("\n")  # TCP newline framing


def test_tcp_connection_refused_is_fail_closed() -> None:
    # Grab a port, then close the listener so nothing is listening.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    profile = CollectorProfile(name="dead", host="127.0.0.1", port=port, transport="tcp")
    emitter = SyslogEmitter(profile)
    assert emitter.send_test(PAYLOAD) is False


def test_frame_rfc3164_format() -> None:
    profile = CollectorProfile(name="f", host="127.0.0.1", port=514, transport="udp")
    emitter = SyslogEmitter(profile, hostname="FGT-LAB-01")
    framed = emitter.frame(PAYLOAD, level="notice", now=datetime(2026, 7, 16, 10, 32, 4)).decode()
    assert framed == f"<189>Jul 16 10:32:04 FGT-LAB-01 {PAYLOAD}"


def test_frame_pads_single_digit_day() -> None:
    profile = CollectorProfile(name="f", host="127.0.0.1", port=514, transport="udp")
    emitter = SyslogEmitter(profile, hostname="H")
    framed = emitter.frame("X", level="warning", now=datetime(2026, 7, 6, 1, 2, 3)).decode()
    assert framed == "<188>Jul  6 01:02:03 H X"  # warning = 23*8 + 4, space-padded day


def test_filesink_writes_payload_without_prefix(tmp_path: Path) -> None:
    target = tmp_path / "out.log"
    with FileSink(target) as sink:
        sink.write(PAYLOAD)
        sink.write(PAYLOAD)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines == [PAYLOAD, PAYLOAD]
    assert not target.read_text(encoding="utf-8").startswith("<")
