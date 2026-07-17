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
from datetime import datetime
from types import TracebackType

from replicant.core.models import CollectorProfile

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

    # -- lifecycle -------------------------------------------------------------

    def connect(self) -> None:
        if self._sock is not None:
            return
        if self.profile.transport == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

    def send(self, payload: str, level: str = "notice") -> None:
        self.connect()
        assert self._sock is not None
        data = self.frame(payload, level)
        if self.profile.transport == "udp":
            self._sock.sendto(data, (self.profile.host, self.profile.port))
        else:
            self._sock.sendall(data + b"\n")

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
