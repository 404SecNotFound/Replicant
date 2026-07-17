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
import fcntl
import json
import os
import pty
import signal
import struct
import sys
import termios

from starlette.websockets import WebSocket, WebSocketDisconnect

_CHILD_ARGV = [sys.executable, "-m", "replicant.cli.app", "menu"]


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def _spawn() -> tuple[int, int]:
    """Fork a child running the Rich menu attached to a new PTY. Returns (pid, fd)."""

    pid, master_fd = pty.fork()
    if pid == 0:  # child: become the TUI
        _enable_cr_to_nl(0)  # so the xterm Enter key (CR) terminates line prompts
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env.setdefault("COLUMNS", "100")
        env.setdefault("LINES", "30")
        try:
            os.execve(sys.executable, _CHILD_ARGV, env)
        except Exception:  # pragma: no cover - exec failure path
            os._exit(127)
    return pid, master_fd


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


async def bridge_terminal(websocket: WebSocket) -> None:
    """Run one terminal session for an accepted websocket until either side ends."""

    loop = asyncio.get_running_loop()
    pid, master_fd = _spawn()
    _set_winsize(master_fd, 30, 100)
    os.set_blocking(master_fd, False)

    out_queue: asyncio.Queue[bytes] = asyncio.Queue()
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
        out_queue.put_nowait(data)

    loop.add_reader(master_fd, on_readable)

    async def pump_output() -> None:
        while not closing.is_set() or not out_queue.empty():
            try:
                data = await asyncio.wait_for(out_queue.get(), timeout=0.25)
            except TimeoutError:
                continue
            try:
                await websocket.send_text(data.decode("utf-8", "replace"))
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
            try:
                control = json.loads(message)
            except json.JSONDecodeError:
                continue
            kind = control.get("t")
            if kind == "i":
                # xterm sends CR for Enter; normalize to LF so the canonical line
                # discipline always sees a line terminator for Rich's prompts.
                data = control.get("d", "").replace("\r\n", "\n").replace("\r", "\n")
                os.write(master_fd, data.encode("utf-8"))
            elif kind == "r":
                _set_winsize(master_fd, int(control.get("rows", 30)), int(control.get("cols", 100)))

    output_task = asyncio.create_task(pump_output())
    input_task = asyncio.create_task(pump_input())
    try:
        await closing.wait()
    finally:
        for task in (output_task, input_task):
            task.cancel()
        try:
            loop.remove_reader(master_fd)
        except (ValueError, OSError):
            pass
        _terminate(pid, master_fd)
        try:
            await websocket.close()
        except Exception:  # pragma: no cover
            pass


def _terminate(pid: int, master_fd: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    try:
        os.close(master_fd)
    except OSError:
        pass
