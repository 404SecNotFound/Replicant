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
"""The terminal bridge must bound what one browser can cost the host.

F-05 of the 2026-08 security review, the remainder after PR #43 landed frame
validation and a bounded output queue. Two things were left.

**Session limits.** Every accepted websocket spawned a ``replicant menu``
process and nothing counted them, so a page that reconnects in a loop, or a
handful of tabs, multiplies real processes against one host. It also defeats the
events-per-second cap, which is per-process (F-08).

**Termination could hang the whole server.** ``_terminate`` sent SIGTERM and
then called ``os.waitpid(pid, 0)`` — blocking, on the asyncio event loop. A
child that ignores SIGTERM therefore froze not just that tab but every request
the server was serving, with no escalation to SIGKILL and no timeout. That is a
denial of service reachable by the terminal's own child process.

The rule adopted for this review applies here too: each of these was run against
the unfixed code and observed to fail.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time

import pytest

pytest.importorskip("fastapi")

from replicant.web import pty_bridge  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX pty only")


class TestSessionLimits:
    def test_there_is_a_global_session_cap(self) -> None:
        assert pty_bridge.MAX_TERMINAL_SESSIONS >= 1

    def test_there_is_a_per_client_session_cap(self) -> None:
        assert pty_bridge.MAX_SESSIONS_PER_CLIENT >= 1
        assert pty_bridge.MAX_SESSIONS_PER_CLIENT <= pty_bridge.MAX_TERMINAL_SESSIONS

    def test_a_client_is_refused_once_it_holds_its_share(self) -> None:
        registry = pty_bridge.SessionRegistry(global_cap=4, per_client_cap=2)

        assert registry.acquire("10.0.0.9") is None
        assert registry.acquire("10.0.0.9") is None
        refusal = registry.acquire("10.0.0.9")

        assert refusal is not None
        assert "session" in refusal.lower()

    def test_one_client_cannot_exhaust_the_host(self) -> None:
        """The per-client cap is what stops one browser taking every slot."""
        registry = pty_bridge.SessionRegistry(global_cap=4, per_client_cap=2)
        for _ in range(2):
            registry.acquire("10.0.0.9")

        # A different operator still gets in.
        assert registry.acquire("10.0.0.10") is None

    def test_the_global_cap_holds_across_clients(self) -> None:
        registry = pty_bridge.SessionRegistry(global_cap=2, per_client_cap=2)
        assert registry.acquire("a") is None
        assert registry.acquire("b") is None

        assert registry.acquire("c") is not None

    def test_releasing_frees_the_slot(self) -> None:
        """Otherwise the cap becomes a one-way ratchet to a dead terminal."""
        registry = pty_bridge.SessionRegistry(global_cap=1, per_client_cap=1)
        registry.acquire("a")
        assert registry.acquire("a") is not None

        registry.release("a")

        assert registry.acquire("a") is None

    def test_release_of_an_unknown_client_is_not_an_error(self) -> None:
        """`finally` blocks run on paths that never acquired."""
        registry = pty_bridge.SessionRegistry(global_cap=1, per_client_cap=1)
        registry.release("never-seen")

        assert registry.acquire("a") is None


class TestTermination:
    def test_a_child_ignoring_sigterm_is_killed_and_does_not_block(self) -> None:
        """The defect: SIGTERM then a blocking waitpid, on the event loop.

        The child here traps SIGTERM and keeps running, which is the exact case
        that used to freeze the server. The assertion is on both outcomes: the
        process must actually die, and the call must return in about the grace
        period rather than hanging.
        """
        pid, master_fd = pty_bridge._spawn_command(
            [
                sys.executable,
                "-c",
                "import signal,time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "print('ready', flush=True)\n"
                "time.sleep(300)\n",
            ]
        )
        # Let the child install its handler before signalling it.
        time.sleep(1.0)

        started = time.monotonic()
        asyncio.run(pty_bridge.terminate(pid, master_fd, grace=1.0, kill_grace=2.0))
        elapsed = time.monotonic() - started

        assert elapsed < 10.0, f"termination took {elapsed:.1f}s; it used to hang forever"
        with pytest.raises(OSError):
            os.kill(pid, 0)

    def test_a_cooperative_child_is_reaped_without_waiting_for_the_grace(self) -> None:
        """SIGKILL escalation must not become the normal path."""
        pid, master_fd = pty_bridge._spawn_command(
            [sys.executable, "-c", "import time; time.sleep(300)"]
        )
        time.sleep(0.3)

        started = time.monotonic()
        asyncio.run(pty_bridge.terminate(pid, master_fd, grace=5.0, kill_grace=2.0))
        elapsed = time.monotonic() - started

        assert elapsed < 4.0, "a SIGTERM-respecting child waited out the grace period"

    def test_terminating_an_already_dead_child_is_quiet(self) -> None:
        pid, master_fd = pty_bridge._spawn_command([sys.executable, "-c", "pass"])
        time.sleep(0.5)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

        asyncio.run(pty_bridge.terminate(pid, master_fd, grace=0.5, kill_grace=0.5))

    def test_terminate_never_calls_blocking_waitpid(self) -> None:
        """A regression guard on the shape, not just the timing.

        Timing tests pass on a fast machine even when the blocking call is back.
        This pins that the source no longer contains the blocking form.
        """
        import inspect

        source = inspect.getsource(pty_bridge)

        assert "os.waitpid(pid, 0)" not in source, "blocking waitpid is back on the event loop"
        assert "WNOHANG" in source
        assert "SIGKILL" in source
        assert signal.SIGKILL is not None
