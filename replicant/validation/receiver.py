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
"""Minimal loopback-only syslog receiver for Tier 1 validation."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Literal


class LocalSyslogReceiver:
    """Capture UDP or newline-framed TCP syslog records on 127.0.0.1 only."""

    def __init__(self, path: str | Path, transport: Literal["udp", "tcp"] = "udp") -> None:
        self.path = Path(path)
        self.transport = transport
        socket_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        self._socket = socket.socket(socket.AF_INET, socket_type)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.2)
        if transport == "tcp":
            self._socket.listen(1)
        self.port = int(self._socket.getsockname()[1])
        self._records: list[str] = []
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, name="replicant-ingest", daemon=True)

    @property
    def records(self) -> list[str]:
        with self._condition:
            return list(self._records)

    def __enter__(self) -> LocalSyslogReceiver:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _append(self, line: str) -> None:
        text = line.rstrip("\r\n")
        if not text:
            return
        with self._condition:
            self._records.append(text)
            self._condition.notify_all()

    def _serve(self) -> None:
        try:
            if self.transport == "udp":
                self._serve_udp()
            else:
                self._serve_tcp()
        except OSError as exc:
            if not self._stop.is_set():
                self._error = exc
        finally:
            with self._condition:
                self._condition.notify_all()

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                payload, _ = self._socket.recvfrom(1_048_576)
            except TimeoutError:
                continue
            self._append(payload.decode("utf-8"))

    def _serve_tcp(self) -> None:
        connection: socket.socket | None = None
        while not self._stop.is_set() and connection is None:
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
        if connection is None:
            return
        buffer = b""
        with connection:
            connection.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    chunk = connection.recv(1_048_576)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._append(line.decode("utf-8"))
            if buffer:
                self._append(buffer.decode("utf-8"))

    def wait_for_count(self, expected: int, timeout: float = 5.0) -> bool:
        """Wait until at least ``expected`` records arrive, then report the outcome."""

        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self._records) < expected and self._error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
        if self._error is not None:
            raise OSError(f"local syslog receiver failed: {self._error}") from self._error
        return len(self.records) >= expected

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        if self._thread.ident is not None:
            self._thread.join(timeout=2.0)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        text = "\n".join(self.records)
        self.path.write_text(text + ("\n" if text else ""), encoding="utf-8")
