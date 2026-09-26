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
"""2026-09-26 M-02: request bodies were read in full before the token check.

Reproduced against a live server: an unauthenticated 400 MB POST to /api/runs
grew the process to about 1.3 GB RSS before it answered 401, because FastAPI
buffers and parses a body before it resolves dependencies, and nothing capped
its size. These run against a real uvicorn over a socket, because the defect is
about bytes arriving on a connection, which ``TestClient`` does not model.

Positive controls, each observed red against the unfixed code: without
``BodyLimitMiddleware`` the declared-length case times out waiting for a server
that is still reading, and the chunked case answers 422 after buffering the
whole megabyte; without ``_authenticate_before_body`` the unauthenticated
chunked case also answers only after the body is read.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.guards import MAX_BODY_BYTES  # noqa: E402
from replicant.web.server import create_app  # noqa: E402
from tests._live_server import live_server, read_status  # noqa: E402

TOKEN = "body-limit-token"
CATALOG = load_catalog(TECHNIQUE_CATALOG)


def _app(tmp_path: Path) -> object:
    return create_app(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")), token=TOKEN)


def _request_head(port: int, extra: str) -> bytes:
    return (
        f"POST /api/runs HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        f"Content-Type: application/json\r\n{extra}\r\n"
    ).encode("ascii")


def test_the_cap_is_well_above_the_largest_legitimate_body() -> None:
    # A RunBody with every field and a collector is a few hundred bytes.
    assert MAX_BODY_BYTES >= 16 * 1024


def test_a_declared_oversized_body_is_refused_before_it_is_read(tmp_path: Path) -> None:
    with live_server(_app(tmp_path)) as port:
        conn = socket.create_connection(("127.0.0.1", port))
        try:
            conn.sendall(_request_head(port, f"Content-Length: {400 * 1024 * 1024}\r\n"))
            conn.sendall(b"x" * 4096)  # a token start, nowhere near 400 MB
            started = time.monotonic()
            status = read_status(conn, timeout=5.0)
        finally:
            conn.close()
    assert status == 413
    assert time.monotonic() - started < 5.0


def _send_chunked(conn: socket.socket, total: int, chunk: int = 16 * 1024) -> None:
    sent = 0
    try:
        while sent < total:
            piece = b"{" * min(chunk, total - sent)
            conn.sendall(f"{len(piece):x}\r\n".encode("ascii") + piece + b"\r\n")
            sent += len(piece)
        conn.sendall(b"0\r\n\r\n")
    except OSError:
        pass  # the server is allowed to hang up on us once it has refused


def test_an_oversized_chunked_body_is_refused_while_it_streams(tmp_path: Path) -> None:
    """No Content-Length to check, so the bytes are counted as they arrive."""

    with live_server(_app(tmp_path)) as port:
        conn = socket.create_connection(("127.0.0.1", port))
        try:
            conn.sendall(
                _request_head(
                    port,
                    f"Transfer-Encoding: chunked\r\nX-Replicant-Token: {TOKEN}\r\n",
                )
            )
            _send_chunked(conn, 1024 * 1024)
            status = read_status(conn, timeout=10.0)
        finally:
            conn.close()
    assert status == 413


def test_an_unauthenticated_write_is_refused_without_reading_its_body(tmp_path: Path) -> None:
    """The body is never read for a caller with no credential: the 401 arrives
    while the client is still holding almost all of it."""

    with live_server(_app(tmp_path)) as port:
        conn = socket.create_connection(("127.0.0.1", port))
        try:
            conn.sendall(_request_head(port, "Transfer-Encoding: chunked\r\n"))
            conn.sendall(b"10\r\n" + b"{" * 16 + b"\r\n")  # 16 bytes, then silence
            status = read_status(conn, timeout=5.0)
        finally:
            conn.close()
    assert status == 401


def test_an_ordinary_body_is_unaffected(tmp_path: Path) -> None:
    with live_server(_app(tmp_path)) as port:
        body = b'{"technique_id": "REP-001", "no_send": true}'
        conn = socket.create_connection(("127.0.0.1", port))
        try:
            conn.sendall(
                _request_head(
                    port,
                    f"Content-Length: {len(body)}\r\nX-Replicant-Token: {TOKEN}\r\n",
                )
                + body
            )
            # /api/plan would be cheaper, but /api/runs is the route the review
            # reproduced against, so it is the one shown to still work.
            status = read_status(conn, timeout=30.0)
        finally:
            conn.close()
    assert status == 200
