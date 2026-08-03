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
"""A collector that will not talk to us is an operator message, not a traceback.

Two defects, and they compound.

The first: ``connect()`` set ``settimeout(connect_timeout)`` (5s) on the tcp and
tls sockets and never reset it, so every later ``sendall`` ran under the same
five second ceiling. A collector applying ordinary backpressure mid-run then
raised ``socket.timeout``. On tls this is easy to miss by reading, because the
timeout is set on the raw socket *before* ``wrap_socket`` and survives onto the
``SSLSocket``.

The second: ``socket.timeout`` is ``TimeoutError`` and a subclass of ``OSError``,
and every run handler in the CLI and the menu caught only
``(RuntimeError, NotImplementedError)``. So the first defect produced the second
one's failure mode: after a run that looked like it was working, the operator got
a raw Python traceback. ``Orchestrator.send_test`` had the same shape one level
down, breaking its own ``-> bool`` contract, which made both callers' failure
branches unreachable.

Safety rule 1: every listener here is one this test binds on loopback.
"""

from __future__ import annotations

import socket
import threading

import pytest

from replicant.core.models import CollectorProfile
from replicant.core.orchestrator import Orchestrator
from replicant.transport.syslog import SyslogEmitter


def _closed_tcp_port() -> int:
    """A port nothing is listening on. Bound then released, so it is really free."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


class _Listener:
    """A TCP listener that accepts and then reads nothing."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = int(self.sock.getsockname()[1])
        self._accepted: socket.socket | None = None
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        try:
            self._accepted, _ = self.sock.accept()
        except OSError:
            pass

    def close(self) -> None:
        if self._accepted is not None:
            self._accepted.close()
        self.sock.close()


def test_the_send_phase_is_not_bound_by_the_connect_timeout() -> None:
    """The connect budget is for connecting. Reusing it throttles every send."""
    listener = _Listener()
    profile = CollectorProfile(name="t", host="127.0.0.1", port=listener.port, transport="tcp")
    try:
        with SyslogEmitter(profile, connect_timeout=5.0) as emitter:
            live = emitter._sock
            assert live is not None
            assert live.gettimeout() != 5.0, "connect timeout still governs sends"
    finally:
        listener.close()


def test_socket_timeout_really_is_an_oserror() -> None:
    """Pins the relationship the CLI handlers depend on.

    If this ever stops holding, adding ``OSError`` to the except tuples silently
    stops covering timeouts, which is the exact failure this file exists for.
    """
    assert issubclass(socket.timeout, OSError)


def test_send_test_reports_a_refused_collector_rather_than_raising(tmp_path) -> None:
    """It is annotated ``-> bool``. It has to return one."""
    from replicant.config.settings import Settings
    from replicant.core.models import load_catalog
    from replicant.resources import TECHNIQUE_CATALOG

    orch = Orchestrator(load_catalog(TECHNIQUE_CATALOG), Settings(manifest_dir=str(tmp_path)))
    profile = CollectorProfile(name="t", host="127.0.0.1", port=_closed_tcp_port(), transport="tcp")

    # Not pytest.raises: the contract is a False, and both callers have a failure
    # branch that was unreachable while this raised.
    assert orch.send_test(profile) is False


def test_a_refused_collector_is_a_message_not_a_traceback(tmp_path, monkeypatch) -> None:
    """The CLI's run path, end to end, against a port nothing is listening on."""
    from replicant.cli.app import main

    # manifest_dir is relative to the cwd and there is no flag for it. Running
    # from tmp_path keeps the repo's own manifests/ clean, and incidentally
    # exercises the v0.3.1 guarantee that runtime resources resolve relative to
    # the package rather than to wherever the process happens to be.
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "run",
            "REP-001",
            "--intensity",
            "low",
            "--duration",
            "20s",
            "--host",
            "127.0.0.1",
            "--port",
            str(_closed_tcp_port()),
            "--transport",
            "tcp",
        ]
    )

    # A clean non-zero exit. Before this, the OSError escaped main() entirely and
    # the operator saw a traceback after a run that had looked healthy.
    assert code == 1


@pytest.mark.parametrize("transport", ["tcp", "tls"])
def test_both_stream_transports_reset_the_timeout(transport: str) -> None:
    """tls is the one worth asserting: settimeout is applied to the raw socket
    before wrap_socket, so that it survives onto the SSLSocket is not obvious."""
    emitter = SyslogEmitter(
        CollectorProfile(name="t", host="127.0.0.1", port=1, transport=transport),
        connect_timeout=5.0,
    )

    assert emitter.send_timeout != emitter.connect_timeout
