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
"""Both ends of the path get logged, not just the far one.

A destination on its own never looks wrong. A live lab session was lost to a
collector configured as ``10.20.0.125`` when the collector was ``10.0.20.125``,
two transposed octets. Replicant logged the destination on every run and it read
as entirely ordinary. It only became obvious beside the source address.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from replicant.core.models import CollectorProfile
from replicant.obs import log as obs_log
from replicant.transport.syslog import (
    SyslogEmitter,
    describe_path,
    local_source_for,
    route_for,
    route_interface_for,
)

# Real shape, taken from a Linux host: default route first, then the on-link /24.
# Addresses are hex words in host byte order, which is what the parser reads.
ROUTE_TABLE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ens33\t00000000\t0114000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
ens33\t0014000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""


@pytest.fixture(autouse=True)
def fresh_buffer() -> Iterator[None]:
    obs_log.reset_for_tests()
    obs_log.install(capacity=100, level="debug")
    yield
    obs_log.reset_for_tests()


@pytest.fixture()
def routes(tmp_path: Path) -> Path:
    table = tmp_path / "route"
    table.write_text(ROUTE_TABLE, encoding="ascii")
    return table


class TestRouteInterface:
    def test_picks_the_on_link_route_over_the_default(self, routes: Path) -> None:
        assert route_interface_for("10.0.20.125", routes) == "ens33"

    def test_falls_back_to_the_default_route(self, routes: Path) -> None:
        """The transposed address in the lab. It matches only the default route."""

        assert route_interface_for("10.20.0.125", routes) == "ens33"

    def test_longest_prefix_wins(self, routes: Path) -> None:
        assert route_interface_for("172.17.0.9", routes) == "docker0"

    def test_a_missing_table_is_not_an_error(self, tmp_path: Path) -> None:
        """Absent on macOS. A diagnostic that raises is worse than a quiet one."""

        assert route_interface_for("10.0.20.125", tmp_path / "absent") is None

    def test_a_malformed_address_is_not_an_error(self, routes: Path) -> None:
        assert route_interface_for("not-an-ip", routes) is None


class TestLocalSource:
    def test_reports_the_address_the_kernel_would_send_from(self) -> None:
        source = local_source_for("127.0.0.1", 514)

        assert source is not None
        assert source[0] == "127.0.0.1"

    def test_sends_nothing(self) -> None:
        """Safety rule 1. A UDP connect performs a route lookup and no I/O."""

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(0.3)
        try:
            local_source_for("127.0.0.1", listener.getsockname()[1])
            with pytest.raises((TimeoutError, OSError)):
                listener.recvfrom(65535)
        finally:
            listener.close()


class TestDescribePath:
    def test_names_both_ends(self) -> None:
        described = describe_path("127.0.0.1", 514)

        assert described.startswith("127.0.0.1 -> 127.0.0.1:514")

    def test_the_connect_log_carries_the_source_address(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        try:
            emitter = SyslogEmitter(CollectorProfile(host="127.0.0.1", port=port, transport="udp"))
            emitter.connect()
            emitter.close()
        finally:
            listener.close()

        connect_lines = [
            entry.message
            for entry in obs_log.snapshot()
            if "connecting to collector" in entry.message
        ]
        assert len(connect_lines) == 1
        # Both ends, so a destination on the wrong subnet is visible without a
        # packet capture.
        assert "->" in connect_lines[0]
        assert f"127.0.0.1:{port}" in connect_lines[0]
        assert "over udp" in connect_lines[0]


class TestRouteGateway:
    def test_a_directly_connected_destination_has_no_gateway(self, routes: Path) -> None:
        route = route_for("10.0.20.125", routes)

        assert route is not None
        assert route.interface == "ens33"
        assert route.gateway is None
        assert route.is_direct

    def test_a_routed_destination_names_the_gateway(self, routes: Path) -> None:
        """The lab's transposed address. It leaves via the router."""

        route = route_for("10.20.0.125", routes)

        assert route is not None
        assert route.gateway == "10.0.20.1"
        assert not route.is_direct

    def test_an_unroutable_address_returns_none(self, tmp_path: Path) -> None:
        assert route_for("10.0.20.125", tmp_path / "absent") is None


class TestOffSubnetWarning:
    def _emitter(self, host: str, port: int) -> SyslogEmitter:
        return SyslogEmitter(CollectorProfile(host=host, port=port, transport="udp"))

    def test_a_direct_collector_produces_no_warning(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        try:
            emitter = self._emitter("127.0.0.1", listener.getsockname()[1])
            emitter.connect()
            emitter.close()
        finally:
            listener.close()

        warnings = [e.message for e in obs_log.snapshot() if e.level == "warning"]
        assert [w for w in warnings if "segment" in w] == []

    def test_a_routed_collector_warns_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from replicant.transport import syslog as syslog_mod

        monkeypatch.setattr(
            syslog_mod,
            "route_for",
            lambda host, table=None: syslog_mod.Route(interface="ens33", gateway="10.0.20.1"),
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        try:
            emitter = self._emitter("127.0.0.1", listener.getsockname()[1])
            for _ in range(3):
                emitter.connect()
                emitter.send("CEF:0|x|y|z|1|n|3|")
                listener.recvfrom(65535)
        finally:
            listener.close()
            emitter.close()

        warnings = [e.message for e in obs_log.snapshot() if e.level == "warning"]
        segment = [w for w in warnings if "segment" in w]
        # Once per emitter. A legitimate routed collector costs one line per run.
        assert len(segment) == 1
        assert "gateway 10.0.20.1" in segment[0]
        assert "ens33" in segment[0]
        # It must say why 0 errors is not reassurance, which is the trap.
        assert "0 errors" in segment[0]

    def test_the_warning_never_refuses_the_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A collector on another subnet is an ordinary, correct deployment."""

        from replicant.transport import syslog as syslog_mod

        monkeypatch.setattr(
            syslog_mod,
            "route_for",
            lambda host, table=None: syslog_mod.Route(interface="ens33", gateway="10.0.20.1"),
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        try:
            emitter = self._emitter("127.0.0.1", listener.getsockname()[1])
            sent = emitter.send("CEF:0|x|y|z|1|n|3|")
            delivered, _ = listener.recvfrom(65535)
        finally:
            listener.close()
            emitter.close()

        assert sent == len(delivered)


def test_loopback_is_direct_even_though_it_is_absent_from_the_route_table(
    routes: Path,
) -> None:
    """Caught by CI, not locally: /proc/net/route is the MAIN table only.

    Loopback routes live in the kernel's `local` table, so 127.0.0.1 matches only
    the default route and reads as going via the gateway. macOS has no
    /proc/net/route at all, so this passed on the development machine and failed
    on Linux, which is exactly the class of bug the containerised CI jobs exist
    to catch.
    """

    route = route_for("127.0.0.1", routes)

    assert route is not None
    assert route.is_direct
    assert route.interface == "lo"
