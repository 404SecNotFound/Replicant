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
"""Syslog transport.

UDP and TCP senders behind one interface (blueprint s8). RFC 3164 framing by
default, matching FortiGate's on-wire format: ``<PRI>Mmm dd HH:MM:SS HOST
<cef-payload>`` with no tag. The CEF payload is supplied by the caller; this
module adds only the syslog envelope.

Safety rule 1: the only socket peer is the configured collector. A ``SyslogEmitter``
is bound to exactly one :class:`CollectorProfile` and never opens any other target.
"""

from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import TracebackType

from replicant.core.models import CollectorProfile
from replicant.obs.log import get_logger, verbose

_log = get_logger("transport")

# Ethernet MTU 1500, minus 20 bytes of IPv4 header and 8 of UDP. A datagram above
# this fragments, and fragments are dropped by more middleboxes and collectors
# than most people expect. TCP does not care, so the check is UDP-only.
UDP_SAFE_PAYLOAD = 1472

# FortiOS level name -> syslog numeric severity (RFC 3164). PRI = facility*8 + sev.
_LEVEL_TO_SYSLOG_SEVERITY: dict[str, int] = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "notification": 5,
    "information": 6,
    "debug": 7,
}


PROC_NET_ROUTE = Path("/proc/net/route")


def local_source_for(host: str, port: int) -> tuple[str, int] | None:
    """The local address the kernel would use to reach ``host``.

    ``connect`` on a UDP socket **sends nothing**. It performs the route lookup
    and binds a local address, which is the whole point here and is what keeps
    this compatible with safety rule 1: no datagram leaves, and the only address
    involved is the collector the operator configured.

    Returns None when the route lookup fails, since a diagnostic that raises is
    worse than one that stays quiet.
    """

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((host, port))
            name = probe.getsockname()
            return (str(name[0]), int(name[1]))
        finally:
            probe.close()
    except OSError:
        return None


@dataclass(frozen=True)
class Route:
    """How the kernel would reach a destination.

    ``gateway`` is None when the destination is directly connected, which is the
    distinction that matters: a datagram to a directly-connected host goes over
    the local segment, while anything else is handed to a router and its fate is
    out of this machine's hands.
    """

    interface: str
    gateway: str | None

    @property
    def is_direct(self) -> bool:
        return self.gateway is None


def _hex_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<L", value))


def route_for(dest: str, route_table: Path = PROC_NET_ROUTE) -> Route | None:
    """Longest-prefix match from the kernel's own table. Linux only, best effort."""

    try:
        target = struct.unpack("<L", socket.inet_aton(dest))[0]
    except OSError:
        return None

    best: tuple[int, Route] | None = None
    try:
        with route_table.open(encoding="ascii") as handle:
            for index, row in enumerate(handle):
                if index == 0:  # header
                    continue
                fields = row.split()
                if len(fields) < 8:
                    continue
                try:
                    network = int(fields[1], 16)
                    gateway = int(fields[2], 16)
                    mask = int(fields[7], 16)
                except ValueError:
                    continue
                if (target & mask) == network:
                    bits = bin(mask).count("1")
                    if best is None or bits > best[0]:
                        best = (
                            bits,
                            Route(
                                interface=fields[0],
                                gateway=_hex_to_ip(gateway) if gateway else None,
                            ),
                        )
    except OSError:
        return None
    return best[1] if best else None


def route_interface_for(dest: str, route_table: Path = PROC_NET_ROUTE) -> str | None:
    """The interface the kernel would send to ``dest`` on. Linux only, best effort.

    Reads the kernel routing table directly rather than shelling out to ``ip``,
    which keeps this dependency-free and safe to call from a library. Addresses in
    ``/proc/net/route`` are hex words in host byte order, so they compare directly
    against ``inet_aton`` unpacked little-endian. [Unverified] on a big-endian
    host, where the two would disagree; the failure mode is a missing interface
    name in one log line, not a wrong one, because a mismatch simply finds no route.

    Returns None on any other platform, which is why every caller treats the
    interface as optional.
    """

    try:
        target = struct.unpack("<L", socket.inet_aton(dest))[0]
    except OSError:
        return None

    best: tuple[int, str] | None = None
    try:
        with route_table.open(encoding="ascii") as handle:
            for index, row in enumerate(handle):
                if index == 0:  # header
                    continue
                fields = row.split()
                if len(fields) < 8:
                    continue
                try:
                    network = int(fields[1], 16)
                    mask = int(fields[7], 16)
                except ValueError:
                    continue
                if (target & mask) == network:
                    # Longest prefix wins, exactly as the kernel decides it, so a
                    # specific route beats the default route rather than racing it.
                    bits = bin(mask).count("1")
                    if best is None or bits > best[0]:
                        best = (bits, fields[0])
    except OSError:
        return None
    return best[1] if best else None


def describe_path(host: str, port: int) -> str:
    """One line naming both ends of the path, plus the interface when known.

    Exists because a destination on its own never looks wrong. A live lab session
    was lost to a collector configured as ``10.20.0.125`` when the collector was
    ``10.0.20.125``: two transposed octets. Replicant logged the destination on
    every run and it read as perfectly ordinary. It only became obvious beside the
    source address, which a packet capture showed and this did not.
    """

    source = local_source_for(host, port)
    if source is None:
        return f"{host}:{port} (no route)"
    route = route_for(host)
    if route is None:
        return f"{source[0]} -> {host}:{port}"
    # "direct" vs "via <gateway>" is the distinction that would have caught the
    # transposed address: the correct collector was directly connected, the
    # mistyped one was handed to a router.
    hop = "direct" if route.is_direct else f"gateway {route.gateway}"
    return f"{source[0]} -> {host}:{port} via {route.interface} ({hop})"


@dataclass
class SendStats:
    """What actually happened on the socket, as opposed to what was attempted.

    ``sends`` counts datagrams handed to the kernel, which for UDP is the only
    thing this process can honestly claim. ``oversize`` is the interesting one
    during a live test: it counts payloads that will fragment, which is a common
    reason a collector receives the small connect-test line and none of the real
    ones.
    """

    sends: int = 0
    bytes: int = 0
    errors: int = 0
    oversize: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "sends": self.sends,
            "bytes": self.bytes,
            "errors": self.errors,
            "oversize": self.oversize,
        }


class SyslogEmitter:
    """Frames CEF payloads into RFC 3164 syslog and sends them to one collector."""

    def __init__(
        self,
        profile: CollectorProfile,
        hostname: str = "FGT-LAB-01",
        connect_timeout: float = 5.0,
    ) -> None:
        self.profile = profile
        self.hostname = hostname
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self.stats = SendStats()
        # Warn once per emitter, not once per datagram. A run that fragments
        # fragments every line, and 36000 identical warnings buries the buffer.
        self._warned_oversize = False
        self._warned_off_subnet = False

    # -- lifecycle -------------------------------------------------------------

    def connect(self) -> None:
        if self._sock is not None:
            return
        _log.info(
            "connecting to collector %s over %s",
            describe_path(self.profile.host, self.profile.port),
            self.profile.transport,
        )
        self._warn_if_off_subnet()
        if self.profile.transport == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Says nothing about reachability. Recorded because an operator
            # reading the log needs to know that this line is not evidence of a
            # working path: UDP has no connect, no handshake and no ack.
            _log.debug(
                "udp socket open; no handshake exists, so delivery is unconfirmed "
                "until something on the collector side counts it"
            )
        elif self.profile.transport == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((self.profile.host, self.profile.port))
            self._sock = sock
        elif self.profile.transport == "tls":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            self._sock = self._tls_context().wrap_socket(
                sock, server_hostname=self.profile.host if self.profile.tls_verify else None
            )
            self._sock.connect((self.profile.host, self.profile.port))
        else:  # pragma: no cover - Transport literal forbids other values
            raise ValueError(f"unsupported transport: {self.profile.transport}")

    def _warn_if_off_subnet(self) -> None:
        """Say so when the collector is not on this host's segment.

        A warning, never a refusal. A SIEM collector on another subnet is an
        ordinary, correct deployment, and rejecting it would break more setups
        than it saved. But it is also what a mistyped address looks like, and
        three separate transpositions of one lab address (``10.20.0.125`` and
        ``10.20.0.127`` for a collector at ``10.0.20.125``) each cost hours,
        because a routed destination fails exactly like a correct one: the
        datagram leaves, the kernel reports success, and nothing comes back.

        Once per emitter, so a legitimate routed collector costs one line per run
        rather than one per datagram.
        """

        if self._warned_off_subnet:
            return
        route = route_for(self.profile.host)
        if route is None or route.is_direct:
            return
        self._warned_off_subnet = True
        source = local_source_for(self.profile.host, self.profile.port)
        origin = source[0] if source else "this host"
        _log.warning(
            "collector %s is NOT on this host's segment (%s). Datagrams leave via "
            "gateway %s on %s, and a router silently discarding them looks identical "
            "to success here: UDP has no acknowledgement, so sends will report 0 errors "
            "either way. If the collector should be local, check the address.",
            self.profile.host,
            origin,
            route.gateway,
            route.interface,
        )

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self.profile.tls_cafile)
        if not self.profile.tls_verify:
            # Lab collectors commonly present a self-signed certificate.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
            _log.info(
                "collector socket closed: %d sends, %d bytes, %d errors, %d oversize",
                self.stats.sends,
                self.stats.bytes,
                self.stats.errors,
                self.stats.oversize,
            )

    def __enter__(self) -> SyslogEmitter:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- framing / sending -----------------------------------------------------

    def pri(self, level: str) -> int:
        severity = _LEVEL_TO_SYSLOG_SEVERITY.get(level.lower(), 5)
        return self.profile.facility * 8 + severity

    def frame(self, payload: str, level: str = "notice", now: datetime | None = None) -> bytes:
        stamp = now or datetime.now()
        timestamp = f"{stamp.strftime('%b')} {stamp.day:2d} {stamp.strftime('%H:%M:%S')}"
        return f"<{self.pri(level)}>{timestamp} {self.hostname} {payload}".encode()

    def send(self, payload: str, level: str = "notice") -> int:
        """Send one framed line. Returns the byte count handed to the socket.

        The return value and the counters exist because "sent" was previously the
        strongest claim available, and for UDP it is a weak one: ``sendto``
        reports that the kernel accepted the datagram, not that anything received
        it. Recording the size is what makes the fragmentation case visible.
        """

        self.connect()
        assert self._sock is not None
        data = self.frame(payload, level)
        size = len(data)

        if self.profile.transport == "udp" and size > UDP_SAFE_PAYLOAD:
            self.stats.oversize += 1
            if not self._warned_oversize:
                self._warned_oversize = True
                _log.warning(
                    "datagram is %d bytes, above the %d-byte non-fragmenting limit. "
                    "IP will fragment it, and collectors and middleboxes drop fragments. "
                    "This is a common reason a short connect test arrives and full CEF "
                    "lines do not. Consider tcp transport for lines this long.",
                    size,
                    UDP_SAFE_PAYLOAD,
                )

        try:
            if self.profile.transport == "udp":
                self._sock.sendto(data, (self.profile.host, self.profile.port))
            else:
                self._sock.sendall(data + b"\n")
        except OSError as exc:
            # Counted and reported, then re-raised. Swallowing it here would turn
            # a broken run into a silent one, which is the failure this whole
            # module exists to stop.
            self.stats.errors += 1
            _log.warning(
                "send failed after %d ok: %s (%s)", self.stats.sends, exc, type(exc).__name__
            )
            raise

        self.stats.sends += 1
        self.stats.bytes += size
        verbose(_log, "sent %d bytes level=%s", size, level)
        return size

    def send_test(self, payload: str) -> bool:
        """Send one line; return transport success.

        TCP/TLS report whether the socket connected; UDP cannot confirm receipt,
        so success means the datagram was handed to the stack (blueprint s8).
        """

        try:
            self.send(payload, level="notice")
            return True
        except OSError:
            self.close()
            return False
