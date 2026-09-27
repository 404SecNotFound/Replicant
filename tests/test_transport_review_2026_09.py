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
"""Transport defects from the 2026-09-26 send-path review.

Each group names the measured failure it guards. Safety rule 1: every socket
here talks only to an in-process loopback listener this test owns, and the
routing tests read fixture files rather than the host's own table.
"""

from __future__ import annotations

import re
import socket
import threading
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from replicant.cef.serializer import to_cef
from replicant.config.settings import Settings
from replicant.core.models import CefHeader, CollectorProfile
from replicant.transport import syslog as syslog_mod
from replicant.transport.syslog import (
    UDP6_SAFE_PAYLOAD,
    UDP_MAX_PAYLOAD,
    OversizeDatagramError,
    SyslogEmitter,
    route_for,
    validate_syslog_hostname,
)

UDP = CollectorProfile(name="t", host="127.0.0.1", port=514, transport="udp")
DUBAI = timezone(timedelta(hours=4))

# -- 3. header timestamp zone and RFC 5424 ------------------------------------


def test_the_rfc3164_header_is_utc_by_default_not_host_local() -> None:
    """Measured: a Dubai host stamped the header in local time with no zone, so a
    collector reading it as UTC saw every event four hours in the future."""

    emitter = SyslogEmitter(UDP, hostname="H")
    # 10:00 in Dubai is 06:00 UTC.
    framed = emitter.frame("X", now=datetime(2026, 9, 26, 10, 0, 0, tzinfo=DUBAI)).decode()

    assert framed == "<189>Sep 26 06:00:00 H X"


def test_the_live_header_tracks_utc_whatever_the_host_zone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end on the no-argument path the emit loop actually uses."""

    import time as time_mod

    monkeypatch.setenv("TZ", "Asia/Dubai")
    time_mod.tzset()
    try:
        framed = SyslogEmitter(UDP, hostname="H").frame("X").decode()
    finally:
        monkeypatch.delenv("TZ")
        time_mod.tzset()
    header = re.match(r"<\d+>(\w{3} [ \d]\d \d\d:\d\d:\d\d) H X", framed)
    assert header is not None, framed
    now = datetime.now(UTC)
    stamped = datetime.strptime(f"{now.year} {header.group(1)}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=UTC
    )
    assert abs((stamped - now).total_seconds()) < 120, framed


def test_local_header_time_is_still_available_on_request() -> None:
    emitter = SyslogEmitter(UDP, hostname="H", header_timezone="local")
    aware = datetime(2026, 9, 26, 6, 0, 0, tzinfo=UTC)
    local = aware.astimezone()

    framed = emitter.frame("X", now=aware).decode()

    assert framed.startswith(f"<189>Sep {local.day:2d} {local.strftime('%H:%M:%S')} H ")


def test_rfc5424_carries_an_explicit_offset() -> None:
    emitter = SyslogEmitter(UDP, hostname="FGT-LAB-01", syslog_format="rfc5424")
    framed = emitter.frame(
        "CEF:0|a|b|c|1|n|3|k=v", now=datetime(2026, 9, 26, 10, 0, 0, tzinfo=DUBAI)
    ).decode()

    assert framed == "<189>1 2026-09-26T06:00:00.000Z FGT-LAB-01 - - - - CEF:0|a|b|c|1|n|3|k=v"


def test_rfc5424_local_zone_writes_the_local_offset_not_z() -> None:
    emitter = SyslogEmitter(UDP, hostname="H", syslog_format="rfc5424", header_timezone="local")
    framed = emitter.frame("X", now=datetime(2026, 9, 26, 6, 0, 0, tzinfo=UTC)).decode()

    stamp = framed.split(" ")[1]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(Z|[+-]\d\d:\d\d)", stamp)
    assert datetime.fromisoformat(stamp.replace("Z", "+00:00")) == datetime(
        2026, 9, 26, 6, 0, 0, tzinfo=UTC
    )


def test_the_run_manifest_records_the_envelope(tmp_path: Path) -> None:
    from replicant.core.models import RunRequest, load_catalog
    from replicant.core.orchestrator import Orchestrator
    from replicant.resources import TECHNIQUE_CATALOG

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(2.0)
    try:
        settings = Settings(manifest_dir=str(tmp_path), syslog_format="rfc5424")
        orch = Orchestrator(load_catalog(TECHNIQUE_CATALOG), settings)
        result = orch.run(
            RunRequest(
                technique_id="REP-001",
                intensity="low",
                collector=CollectorProfile(
                    host="127.0.0.1", port=listener.getsockname()[1], transport="udp"
                ),
                pace="burst",
            )
        )
        datagram, _ = listener.recvfrom(65535)
    finally:
        listener.close()

    assert result.manifest.syslog_format == "rfc5424"
    assert result.manifest.syslog_timezone == "utc"
    assert datagram.decode().split(" ")[0].endswith(">1")


# -- 9. route lookup for names and IPv6 -----------------------------------------

_ZERO = "0" * 32
# /proc/net/ipv6_route rows: dest plen src src_plen next_hop metric refcnt use flags iface.
IPV6_ROUTE = "".join(
    " ".join(fields) + "\n"
    for fields in (
        # 2001:db8::/64 on-link
        (
            "20010db8" + "0" * 24,
            "40",
            _ZERO,
            "00",
            _ZERO,
            "00000100",
            "1",
            "0",
            "00000001",
            "ens33",
        ),
        # default via fe80::1
        (
            _ZERO,
            "00",
            _ZERO,
            "00",
            "fe80" + "0" * 27 + "1",
            "00000400",
            "2",
            "0",
            "00000003",
            "ens33",
        ),
        # fd00::/8 unreachable (RTF_REJECT), listed against lo
        ("fd" + "0" * 30, "08", _ZERO, "00", _ZERO, "ffffffff", "1", "0", "00200200", "lo"),
    )
)


@pytest.fixture()
def v6_routes(tmp_path: Path) -> Path:
    path = tmp_path / "ipv6_route"
    path.write_text(IPV6_ROUTE, encoding="ascii")
    return path


def test_an_on_link_ipv6_destination_is_direct(v6_routes: Path) -> None:
    route = route_for("2001:db8::1", ipv6_table=v6_routes)

    assert route is not None
    assert route.interface == "ens33"
    assert route.is_direct


def test_an_off_link_ipv6_destination_names_its_next_hop(v6_routes: Path) -> None:
    route = route_for("2001:db8:1::5", ipv6_table=v6_routes)

    assert route is not None
    assert route.gateway == "fe80::1"
    assert not route.is_direct


def test_a_reject_route_is_not_reported_as_direct_via_lo(v6_routes: Path) -> None:
    route = route_for("fd00::5", ipv6_table=v6_routes)

    # Falls through to the default route rather than claiming on-link via lo.
    assert route is not None
    assert route.interface == "ens33"
    assert route.gateway == "fe80::1"


def test_ipv6_loopback_is_direct(v6_routes: Path) -> None:
    route = route_for("::1", ipv6_table=v6_routes)

    assert route is not None and route.is_direct and route.interface == "lo"


def test_no_ipv6_table_is_none_not_an_error(tmp_path: Path) -> None:
    assert route_for("2001:db8::1", ipv6_table=tmp_path / "absent") is None


def test_the_off_segment_check_resolves_a_name_before_looking_up_the_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured: route_for('localhost') and every DNS name returned None, so the
    gateway warning never ran for a collector configured by name."""

    seen: list[str] = []

    def fake_route(dest: str, *_a: object, **_k: object) -> syslog_mod.Route | None:
        seen.append(dest)
        return syslog_mod.Route(interface="ens33", gateway="10.0.20.1")

    monkeypatch.setattr(syslog_mod, "route_for", fake_route)
    emitter = SyslogEmitter(CollectorProfile(host="localhost", port=514, transport="udp"))
    emitter._warn_if_off_subnet()

    assert seen and all(re.fullmatch(r"[0-9a-f:.]+", dest) for dest in seen), seen
    assert emitter._warned_off_subnet


def test_the_path_line_shows_the_address_a_name_resolved_to() -> None:
    line = syslog_mod.describe_path("localhost", 514)

    assert "localhost (" in line or "-> localhost:" in line
    assert "via lo" in line and "direct" in line, line


# -- 10. reconnect on a dropped stream ------------------------------------------


class ClosingListener:
    """TCP listener that accepts, reads ``close_after`` lines, then closes.

    Every later connection is read to EOF. Collects every line it received.
    """

    def __init__(self, close_after: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.close_after = close_after
        self.lines: list[bytes] = []
        self.connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(5.0)
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn:
                buffer = b""
                conn.settimeout(3.0)
                while True:
                    if self.connections == 1 and len(self.lines) >= self.close_after:
                        # Abortive close so the sender sees RST, not a clean FIN
                        # that a following write could still succeed against.
                        conn.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"
                        )
                        break
                    try:
                        chunk = conn.recv(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        self.lines.append(line)

    def close(self) -> None:
        self.sock.close()


def _send_until_failure_then_more(emitter: SyslogEmitter, total: int) -> None:
    import time

    for index in range(total):
        emitter.send(f"CEF:0|a|b|c|1|n|3|seq={index}")
        time.sleep(0.02)


def test_a_dropped_tcp_collector_is_reconnected_and_the_failed_record_resent() -> None:
    listener = ClosingListener(close_after=5)
    waits: list[float] = []
    emitter = SyslogEmitter(
        CollectorProfile(host="127.0.0.1", port=listener.port, transport="tcp"),
        hostname="H",
        sleep=waits.append,
    )
    try:
        _send_until_failure_then_more(emitter, 20)
        stats = emitter.stats
        emitter.close()
        import time

        time.sleep(0.3)
    finally:
        listener.close()

    assert stats.reconnects >= 1
    assert stats.resent == stats.reconnects
    assert waits[: stats.reconnects] == [0.5] * stats.reconnects
    assert listener.connections >= 2
    received = {int(line.rsplit(b"seq=", 1)[1]) for line in listener.lines}
    # The last record always arrives: the run continued past the drop. Records
    # the kernel had buffered when the peer reset may not (stated limitation).
    assert 19 in received
    assert stats.sends == 20


def test_a_collector_that_stays_down_ends_the_run_after_bounded_attempts() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    waits: list[float] = []
    emitter = SyslogEmitter(
        CollectorProfile(host="127.0.0.1", port=port, transport="tcp"),
        hostname="H",
        sleep=waits.append,
    )
    emitter.connect()
    conn, _ = listener.accept()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    conn.close()
    listener.close()  # nothing to reconnect to

    with pytest.raises(OSError):
        for index in range(50):
            emitter.send(f"CEF:0|a|b|c|1|n|3|seq={index}")
            import time

            time.sleep(0.01)

    assert waits == [0.5, 1.0, 2.0]
    assert emitter.stats.reconnects == 0
    emitter.close()


def test_udp_is_never_retried() -> None:
    """A UDP send error is not a dropped connection, and resending would double it."""

    waits: list[float] = []
    emitter = SyslogEmitter(UDP, hostname="H", sleep=waits.append)

    class Broken:
        def sendto(self, *_a: object) -> int:
            raise OSError("boom")

        def close(self) -> None:
            pass

    emitter._sock = Broken()  # type: ignore[assignment]
    with pytest.raises(OSError, match="boom"):
        emitter.send("X")
    assert waits == []


# -- 12. hostname validation and header newlines ---------------------------------


@pytest.mark.parametrize(
    "bad", ["FGT LAB", "FGT\nLAB", "FGT\rLAB", "", "-lead", "x" * 256, "tab\there", "é"]
)
def test_a_header_unsafe_hostname_is_refused_at_the_settings_boundary(bad: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(hostname=bad)
    with pytest.raises(ValueError):
        validate_syslog_hostname(bad)


@pytest.mark.parametrize("good", ["FGT-LAB-01", "pa.lab.example", "fw_01", "2001:db8::1"])
def test_ordinary_hostnames_are_accepted(good: str) -> None:
    assert Settings(hostname=good).hostname == good


def test_a_newline_in_a_header_value_cannot_split_the_record() -> None:
    header = CefHeader(
        device_vendor="Fortinet",
        device_product="Forti\ngate",
        device_version="7.2\r\n",
        signature_id="00013",
        name="bad\rname",
        severity=5,
    )

    line = to_cef(header, {"msg": "a\nb"})

    assert "\n" not in line and "\r" not in line
    assert line.startswith("CEF:0|Fortinet|Forti gate|7.2 |00013|bad name|5|")
    assert line.endswith("msg=a\\nb")


def test_the_frame_is_one_line() -> None:
    emitter = SyslogEmitter(UDP, hostname="FGT-LAB-01")
    header = CefHeader(
        device_vendor="V\nX",
        device_product="P",
        device_version="1",
        signature_id="1",
        name="n",
        severity=1,
    )
    framed = emitter.frame(to_cef(header, {"k": "v"}), now=datetime(2026, 1, 1)).decode()

    assert "\n" not in framed


# -- 14. family-correct UDP sizes ------------------------------------------------


def test_the_ipv6_fragmentation_threshold_is_1452(monkeypatch: pytest.MonkeyPatch) -> None:
    emitter = SyslogEmitter(UDP, hostname="H")
    emitter._family = socket.AF_INET6

    assert emitter._udp_limits()[0] == UDP6_SAFE_PAYLOAD == 1452


def test_a_datagram_no_udp_can_carry_is_refused_by_record_not_by_traceback() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    try:
        emitter = SyslogEmitter(
            CollectorProfile(host="127.0.0.1", port=receiver.getsockname()[1], transport="udp"),
            hostname="H",
        )
        emitter.send("small")
        with pytest.raises(OversizeDatagramError) as caught:
            emitter.send("y" * (UDP_MAX_PAYLOAD + 10))
        emitter.close()
    finally:
        receiver.close()

    message = str(caught.value)
    assert "record 2" in message
    assert "tcp" in message
    assert emitter.stats.errors == 1
