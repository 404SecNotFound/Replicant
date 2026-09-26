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
"""Minimal loopback-only syslog receiver for Tier 1 validation.

Robustness rules this receiver follows, each one a defect it used to have:

* A datagram or line that is not valid UTF-8 is decoded with replacement
  characters and kept. It used to raise ``UnicodeDecodeError`` inside the
  receive thread, which only caught ``OSError``, so one bad datagram killed the
  thread silently and every later record was lost: the verdict then read
  ``fail_no_events`` for a run that had delivered everything.
* Any exception in the receive thread is recorded and re-raised by
  ``wait_for_count``, so the verdict surfaces the receiver failure instead of
  reporting absent telemetry.
* TCP mode accepts every connection until shutdown, bounded by
  ``MAX_TCP_CONNECTIONS`` concurrent readers. It used to accept exactly one, so a
  sender that reconnected lost everything after the first connection closed.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Literal

#: Concurrent TCP connections served at once. A loopback validation run opens
#: one; the bound only stops a misbehaving local client exhausting threads.
MAX_TCP_CONNECTIONS = 16

_POLL_S = 0.2


class LocalSyslogReceiver:
    """Capture UDP or newline-framed TCP syslog records on 127.0.0.1 only."""

    def __init__(self, path: str | Path, transport: Literal["udp", "tcp"] = "udp") -> None:
        self.path = Path(path)
        self.transport = transport
        socket_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        self._socket = socket.socket(socket.AF_INET, socket_type)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(_POLL_S)
        if transport == "tcp":
            self._socket.listen(MAX_TCP_CONNECTIONS)
        self.port = int(self._socket.getsockname()[1])
        self._records: list[str] = []
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._readers: list[threading.Thread] = []
        self._slots = threading.BoundedSemaphore(MAX_TCP_CONNECTIONS)
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

    def _append(self, raw: bytes) -> None:
        # errors="replace": the receiver's job is to count and keep what arrived.
        # A byte sequence that is not UTF-8 is a finding about the sender, which
        # the evaluator can report, not a reason to stop receiving.
        text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not text:
            return
        with self._condition:
            self._records.append(text)
            self._condition.notify_all()

    def _fail(self, exc: BaseException) -> None:
        with self._condition:
            if self._error is None and not self._stop.is_set():
                self._error = exc
            self._condition.notify_all()

    def _serve(self) -> None:
        # Exception, not OSError: anything that ends this thread ends reception,
        # and a thread that dies without recording why makes the verdict lie.
        try:
            if self.transport == "udp":
                self._serve_udp()
            else:
                self._serve_tcp()
        except Exception as exc:  # noqa: BLE001 - surfaced through wait_for_count
            self._fail(exc)
        finally:
            with self._condition:
                self._condition.notify_all()

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                payload, _ = self._socket.recvfrom(1_048_576)
            except TimeoutError:
                continue
            self._append(payload)

    def _serve_tcp(self) -> None:
        while not self._stop.is_set():
            if not self._slots.acquire(timeout=_POLL_S):
                continue
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                self._slots.release()
                continue
            except BaseException:
                self._slots.release()
                raise
            reader = threading.Thread(
                target=self._read_connection,
                args=(connection,),
                name="replicant-ingest-conn",
                daemon=True,
            )
            self._readers = [thread for thread in self._readers if thread.is_alive()]
            self._readers.append(reader)
            reader.start()

    def _read_connection(self, connection: socket.socket) -> None:
        try:
            buffer = b""
            with connection:
                connection.settimeout(_POLL_S)
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
                        self._append(line)
                if buffer:
                    self._append(buffer)
        except Exception as exc:  # noqa: BLE001 - surfaced through wait_for_count
            self._fail(exc)
        finally:
            self._slots.release()

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
            raise OSError(f"local syslog receiver failed: {self._error!r}") from self._error
        return len(self.records) >= expected

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        if self._thread.ident is not None:
            self._thread.join(timeout=2.0)
        for reader in list(self._readers):
            reader.join(timeout=2.0)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        text = "\n".join(self.records)
        self.path.write_text(text + ("\n" if text else ""), encoding="utf-8")
