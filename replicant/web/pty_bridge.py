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
"""Pseudo-terminal bridge.

Spawns ``replicant menu`` in a PTY and bridges its I/O to a websocket, so the real
Rich TUI runs inside an xterm.js terminal in the browser. This is how the web UI
"switches into the terminal": it is the same interactive menu, not a re-creation.

Control frames from the client are JSON: ``{"t": "i", "d": "<keystrokes>"}`` for
input and ``{"t": "r", "cols": N, "rows": M}`` for resize. Terminal output flows
back as raw text frames. POSIX only (uses ``pty``); the server guards this.
"""

from __future__ import annotations

import asyncio
import codecs
import fcntl
import json
import os
import pty
import signal
import struct
import sys
import termios
import time

from starlette.websockets import WebSocket, WebSocketDisconnect

from replicant.obs.log import get_logger

_log = get_logger("terminal")

_CHILD_ARGV = [sys.executable, "-m", "replicant.cli.app", "menu"]


def utf8_stream_decoder() -> codecs.IncrementalDecoder:
    """A decoder that carries a partial multi-byte sequence across PTY reads.

    ``os.read`` returns whatever bytes are available, so a chunk boundary can
    land in the middle of a UTF-8 sequence. Decoding each chunk on its own with
    ``errors="replace"`` turns those split bytes into U+FFFD permanently, which
    showed up as corrupted box-drawing characters in the menu's table borders
    once the catalog grew large enough to straddle a read boundary. An
    incremental decoder holds the incomplete tail until the rest arrives.
    """

    return codecs.getincrementaldecoder("utf-8")("replace")


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def _spawn_command(argv: list[str]) -> tuple[int, int]:
    """Fork ``argv`` onto a new PTY. Returns (pid, master_fd).

    Split out from :func:`_spawn` so the termination path can be tested against a
    child that deliberately ignores SIGTERM, which is the case that used to hang
    the event loop and which no test could reach while the argv was hardcoded.
    """

    pid, master_fd = pty.fork()
    if pid == 0:  # child
        _enable_cr_to_nl(0)  # so the xterm Enter key (CR) terminates line prompts
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env.setdefault("COLUMNS", "100")
        env.setdefault("LINES", "30")
        try:
            os.execve(argv[0], argv, env)
        except Exception:  # pragma: no cover - exec failure path
            os._exit(127)
    return pid, master_fd


def _spawn() -> tuple[int, int]:
    """Fork a child running the Rich menu attached to a new PTY. Returns (pid, fd)."""

    return _spawn_command(list(_CHILD_ARGV))


def _enable_cr_to_nl(fd: int) -> None:
    """Ensure the terminal maps carriage return to newline on input (ICRNL).

    xterm.js sends CR (\\r) for the Enter key. Without ICRNL the canonical line
    discipline never sees a line terminator, so Rich prompts appear to ignore Enter.
    """

    try:
        attrs = termios.tcgetattr(fd)
    except termios.error:  # pragma: no cover - not a tty
        return
    attrs[0] |= termios.ICRNL  # iflag
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


#: Terminal sessions this host will run at once, across every client.
#:
#: Each session is a real ``replicant menu`` process. Without a cap, a page that
#: reconnects in a loop, or a handful of tabs, multiplies processes against one
#: host. It also multiplies the events-per-second cap, which is per-process, so
#: this bounds F-08 as well even before that gets its own answer.
MAX_TERMINAL_SESSIONS = 4
#: And what any single client may hold of that, so one browser cannot take every
#: slot and lock the operator out of their own tool from another machine.
MAX_SESSIONS_PER_CLIENT = 2

#: How long a child gets to honour SIGTERM before SIGKILL.
TERMINATE_GRACE_S = 3.0
#: And how long to wait for the corpse after SIGKILL before giving up. Bounded
#: because the one thing this must never do is block the event loop.
KILL_GRACE_S = 2.0

#: One websocket frame. Anything larger is a client that is not the Replicant UI.
MAX_FRAME_BYTES = 64 * 1024
#: One paste. Well above a human keystroke burst, far below a memory problem.
MAX_INPUT_CHARS = 8 * 1024
#: Terminal dimensions. `struct.pack` on an unbounded int raises, and a browser
#: never legitimately reports either of these outside the range.
MAX_DIMENSION = 1000
#: And the floor. The xterm fit addon measures its container, so a tab that has
#: not been laid out yet, or a hidden pane, makes it compute 1 column and send it.
#: The bound accepted that, the PTY was duly resized to one column, and every
#: prompt after it wrapped one character per line. The banner printed before the
#: resize stayed readable, which is what made it look like a rendering fault
#: rather than a resize the server had agreed to.
#:
#: Floored here rather than in the client. The client is the thing that was
#: wrong, and a bound that only holds when the client is correct is not a bound.
MIN_DIMENSION = 20
#: Backlog of PTY output. A browser that stops reading must not grow this without
#: limit; past the bound the oldest chunk is dropped, which corrupts scrollback
#: rather than exhausting the host.
MAX_OUTPUT_CHUNKS = 2048


def _bounded(value: object, fallback: int) -> int | None:
    """A terminal dimension, or None when the frame is not usable."""

    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if MIN_DIMENSION <= value <= MAX_DIMENSION else None


def _write_all(fd: int, payload: bytes) -> None:
    """Write every byte, tolerating the short writes a nonblocking fd can return.

    ``os.write`` on a nonblocking master fd may accept only part of a buffer, and
    the discarded remainder used to vanish silently: a long paste arrived at the
    shell truncated.
    """

    view = memoryview(payload)
    while view:
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            return  # the reader is behind; dropping is better than blocking the loop
        if written <= 0:
            return
        view = view[written:]


class SessionRegistry:
    """Counts live terminal sessions, globally and per client.

    Deliberately a plain dict with no lock. Every caller is a coroutine on one
    asyncio event loop, so acquire and release never interleave; adding a lock
    would suggest a concurrency that does not exist here.
    """

    def __init__(self, global_cap: int, per_client_cap: int) -> None:
        self.global_cap = global_cap
        self.per_client_cap = per_client_cap
        self._per_client: dict[str, int] = {}

    @property
    def total(self) -> int:
        return sum(self._per_client.values())

    def acquire(self, client: str) -> str | None:
        """Take a slot. Returns None on success, or a reason to show the operator.

        A refusal is a sentence the terminal can print, not a bare bool: a tab
        that simply fails to open is the kind of thing that gets reported as "the
        web UI is broken".
        """

        if self.total >= self.global_cap:
            return (
                f"This host is already running {self.total} terminal sessions, which is "
                f"the limit ({self.global_cap}). Close one and try again."
            )
        held = self._per_client.get(client, 0)
        if held >= self.per_client_cap:
            return (
                f"You already have {held} terminal sessions open, which is the limit "
                f"per client ({self.per_client_cap}). Close one and try again."
            )
        self._per_client[client] = held + 1
        return None

    def release(self, client: str) -> None:
        """Give a slot back. Safe to call for a client that never acquired one,
        because the caller's ``finally`` runs on paths that were refused."""

        held = self._per_client.get(client)
        if held is None:
            return
        if held <= 1:
            del self._per_client[client]
        else:
            self._per_client[client] = held - 1


#: Process-wide, because the cap is about what this host will run.
_REGISTRY = SessionRegistry(MAX_TERMINAL_SESSIONS, MAX_SESSIONS_PER_CLIENT)


async def _reap(pid: int, timeout: float) -> bool:
    """Poll for the child with WNOHANG until ``timeout``. Never blocks the loop."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            done, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True  # already reaped
        if done == pid:
            return True
        await asyncio.sleep(0.05)
    return False


async def terminate(
    pid: int,
    master_fd: int,
    *,
    grace: float = TERMINATE_GRACE_S,
    kill_grace: float = KILL_GRACE_S,
) -> None:
    """End the child, escalating to SIGKILL, without ever blocking the loop.

    The defect this replaces: SIGTERM followed by a blocking ``os.waitpid`` with
    no WNOHANG, called directly on the asyncio event loop. A child that ignores SIGTERM froze
    every request the server was serving, not just its own tab, with no
    escalation and no timeout. The terminal's own child process could therefore
    deny service to the whole web UI.

    Giving up after ``kill_grace`` leaves a zombie. That is the right trade: a
    zombie costs one process table entry, and the alternative is the hang this
    exists to remove.
    """

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    if not await _reap(pid, grace):
        _log.warning("terminal child %d ignored SIGTERM after %.1fs; killing", pid, grace)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if not await _reap(pid, kill_grace):  # pragma: no cover - needs an unkillable child
            _log.warning("terminal child %d did not exit after SIGKILL; leaving it", pid)

    try:
        os.close(master_fd)
    except OSError:
        pass


async def bridge_terminal(websocket: WebSocket) -> None:
    """Run one terminal session for an accepted websocket until either side ends."""

    client = websocket.client.host if websocket.client else "unknown"
    refusal = _REGISTRY.acquire(client)
    if refusal is not None:
        _log.warning("terminal session refused for %s: %s", client, refusal)
        try:
            await websocket.send_text(f"\r\n{refusal}\r\n")
        finally:
            await websocket.close(code=1013)  # try again later
        return

    try:
        await _bridge_session(websocket)
    finally:
        _REGISTRY.release(client)


async def _bridge_session(websocket: WebSocket) -> None:
    loop = asyncio.get_running_loop()
    pid, master_fd = _spawn()
    _set_winsize(master_fd, 30, 100)
    os.set_blocking(master_fd, False)

    out_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=MAX_OUTPUT_CHUNKS)
    closing = asyncio.Event()

    def on_readable() -> None:
        try:
            data = os.read(master_fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:  # child exited / PTY closed
            loop.remove_reader(master_fd)
            closing.set()
            return
        try:
            out_queue.put_nowait(data)
        except asyncio.QueueFull:
            # A browser that has stopped reading must not be able to grow this
            # without limit. Drop the oldest chunk: scrollback is damaged, the
            # host is not.
            try:
                out_queue.get_nowait()
                out_queue.put_nowait(data)
            except (asyncio.QueueEmpty, asyncio.QueueFull):  # pragma: no cover
                pass

    loop.add_reader(master_fd, on_readable)

    async def pump_output() -> None:
        # One decoder for the whole connection, so a multi-byte character split
        # across two reads is reassembled rather than replaced.
        decoder = utf8_stream_decoder()
        while not closing.is_set() or not out_queue.empty():
            try:
                data = await asyncio.wait_for(out_queue.get(), timeout=0.25)
            except TimeoutError:
                continue
            text = decoder.decode(data)
            if not text:  # chunk ended mid-sequence; wait for the remainder
                continue
            try:
                await websocket.send_text(text)
            except Exception:  # pragma: no cover - client vanished mid-send
                closing.set()
                return

    async def pump_input() -> None:
        while not closing.is_set():
            try:
                message = await websocket.receive_text()
            except WebSocketDisconnect:
                closing.set()
                return
            except Exception:  # pragma: no cover
                closing.set()
                return
            # Every frame is validated before anything is read out of it. The
            # previous code assumed decoded JSON was an object, so a valid scalar
            # or array -- `1`, or `[]` -- raised at `.get()`, ended this task, and
            # left the parent waiting on `closing` forever while the PTY and the
            # child process stayed alive. One malformed frame stranded a session.
            if len(message) > MAX_FRAME_BYTES:
                continue
            try:
                control = json.loads(message)
            except json.JSONDecodeError:
                continue
            if not isinstance(control, dict):
                continue
            kind = control.get("t")
            if kind == "i":
                payload = control.get("d")
                if not isinstance(payload, str) or len(payload) > MAX_INPUT_CHARS:
                    continue
                # xterm sends CR for Enter; normalize to LF so the canonical line
                # discipline always sees a line terminator for Rich's prompts.
                data = payload.replace("\r\n", "\n").replace("\r", "\n")
                try:
                    _write_all(master_fd, data.encode("utf-8"))
                except OSError:
                    closing.set()
                    return
            elif kind == "r":
                rows = _bounded(control.get("rows"), 30)
                cols = _bounded(control.get("cols"), 100)
                if rows is None or cols is None:
                    continue
                _set_winsize(master_fd, rows, cols)

    output_task = asyncio.create_task(pump_output())
    input_task = asyncio.create_task(pump_input())
    try:
        # Whichever ends first ends the session. Waiting only on `closing` meant a
        # pump that died on its own -- a malformed frame, a vanished client --
        # left the parent waiting forever with the child still running.
        await asyncio.wait(
            [asyncio.ensure_future(closing.wait()), output_task, input_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for task in (output_task, input_task):
            task.cancel()
        try:
            loop.remove_reader(master_fd)
        except (ValueError, OSError):
            pass
        await terminate(pid, master_fd)
        try:
            await websocket.close()
        except Exception:  # pragma: no cover
            pass
