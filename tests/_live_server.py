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
"""A real uvicorn server on a loopback ephemeral port, for tests that need one.

Two of the 2026-09-26 findings do not exist under ``TestClient``: request bodies
arriving in pieces over a socket, and uvicorn rewriting the client address from
``X-Forwarded-For``. Both were reproduced against a live server, so their guards
run against one too, built with the same ``uvicorn_config`` that ``serve`` uses.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import uvicorn

from replicant.web.server import uvicorn_config


@contextmanager
def live_server(app: Any, config: uvicorn.Config | None = None) -> Iterator[int]:
    """Serve ``app`` on 127.0.0.1 and yield the port. Stops on exit."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    server = uvicorn.Server(config or uvicorn_config(app))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def read_status(conn: socket.socket, timeout: float) -> int | None:
    """The status code of the first response on ``conn``, or None on timeout."""

    conn.settimeout(timeout)
    data = b""
    try:
        while b"\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    except (TimeoutError, OSError):
        return None
    if not data.startswith(b"HTTP/"):
        return None
    return int(data.split(b" ", 2)[1])
