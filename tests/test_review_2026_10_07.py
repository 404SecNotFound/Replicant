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
"""Security findings of the 2026-10-07 review. Decision record:
``docs/security-review-2026-10-07.md``.

Every guard here was run against the unfixed code first and observed to fail,
per the standing rule. The controls are named in each docstring.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.confine import ConfinementError, confined_output_path  # noqa: E402
from replicant.config.settings import Settings, parse_duration  # noqa: E402
from replicant.core.models import RunRequest, load_catalog  # noqa: E402
from replicant.obs import log as obs_log  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.pty_bridge import MAX_FRAME_BYTES  # noqa: E402
from replicant.web.server import SESSION_COOKIE, create_app, uvicorn_config  # noqa: E402

TOKEN = "review-token-2026-10-07"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(TECHNIQUE_CATALOG)


def _client(tmp_path: Path, **kwargs: Any) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN, **kwargs)
    return TestClient(app, base_url="http://localhost")


# -- N-01: the duration parser must be linear ------------------------------------

# Forty digits and a bad tail. The previous pattern, (?:\d+\s*[smhd]?\s*)+, has a
# nested quantifier whose every optional part matches empty, so a non-matching
# tail backtracks through 2^N splits of the digit run: 1.2 s at 24 digits, 5 s at
# 26, roughly a day at 40. Control: restore that pattern and this test hangs.
_HOSTILE = "1" * 40 + "x"
_BUDGET_S = 1.0


def _timed(fn: Any, *args: Any) -> float:
    started = time.perf_counter()
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 - the outcome is asserted by the caller
        pass
    return time.perf_counter() - started


class TestDurationParserIsLinear:
    def test_a_hostile_duration_is_refused_within_budget(self) -> None:
        with pytest.raises(ValueError, match="cannot parse duration"):
            parse_duration(_HOSTILE)
        assert _timed(parse_duration, _HOSTILE) < _BUDGET_S

    def test_the_run_request_boundary_is_also_linear(self) -> None:
        with pytest.raises(ValueError):
            RunRequest(technique_id="REP-001", duration=_HOSTILE)
        elapsed = _timed(lambda: RunRequest(technique_id="REP-001", duration=_HOSTILE))
        assert elapsed < _BUDGET_S

    @pytest.mark.parametrize(
        ("text", "seconds"),
        [
            ("1" * 40, int("1" * 40)),  # a long but valid digit run still parses
            ("1h 30m", 5400),
            ("1 h", 3600),
            ("2d1h", 176400),
        ],
    )
    def test_well_formed_durations_are_unchanged(self, text: str, seconds: int) -> None:
        assert parse_duration(text) == seconds

    @pytest.mark.parametrize("text", ["10x", "1h garbage", "-1h", "1.5h", "", "   ", "h", "1hh"])
    def test_malformed_durations_still_raise(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_duration(text)


# -- N-02: a malformed duration from the web is a 422, not a 500 ----------------


@pytest.mark.parametrize("route", ["/api/plan", "/api/runs"])
def test_a_malformed_web_duration_is_a_validation_error(tmp_path: Path, route: str) -> None:
    """RunBody.duration had no validator, so pydantic raised inside the handler
    and FastAPI answered 500 with a traceback on stderr. Control: drop the
    validator from RunBody."""
    client = _client(tmp_path)
    started = time.perf_counter()
    response = client.post(
        route,
        headers=HEADERS,
        json={"technique_id": "REP-001", "duration": _HOSTILE, "no_send": True},
    )
    assert response.status_code == 422, response.text
    assert "duration" in response.text
    assert time.perf_counter() - started < _BUDGET_S


# -- N-03: an over-long output name is a refusal, not an OSError ------------------


def test_an_overlong_output_name_is_a_confinement_error(tmp_path: Path) -> None:
    """``Path.resolve`` raises ENAMETOOLONG past NAME_MAX, which escaped the
    helper and became a 500 from the API and a traceback in the menu prompt.
    Control: remove the OSError handling in ``confined_output_path``."""
    with pytest.raises(ConfinementError):
        confined_output_path("a" * 300 + ".log", str(tmp_path / "manifests"))


def test_an_overlong_output_name_from_the_web_is_a_400(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/plan",
        headers=HEADERS,
        json={"technique_id": "REP-001", "to_file": "a" * 300 + ".log", "no_send": True},
    )
    assert response.status_code == 400, response.text


# -- N-04: the session id is a credential and never reaches a log ---------------


def test_the_terminal_cap_key_does_not_carry_the_session_id(tmp_path: Path) -> None:
    """The per-client key was ``session:<cookie value>`` and the bridge logs the
    key when it refuses a session, so the 12 hour bearer credential reached the
    log ring, ``/api/logs``, the SSE log stream and the journal. The key only
    has to be stable per session, so it is a digest now. Control: build the key
    from the raw cookie value."""
    client = _client(tmp_path)
    client.get("/", params={"token": TOKEN})
    keys: list[str] = []

    async def fake_bridge(websocket: Any, client_key: str | None = None) -> None:
        keys.append(client_key or "")
        await websocket.send_text("ok")
        await websocket.receive_text()

    sid = client.cookies[SESSION_COOKIE]
    with patch("replicant.web.server.bridge_terminal", fake_bridge):
        for _ in range(2):
            with client.websocket_connect(
                "/ws/terminal",
                headers={
                    "host": "localhost",
                    "origin": "http://localhost",
                    "cookie": f"{SESSION_COOKIE}={sid}",
                },
            ) as ws:
                assert ws.receive_text() == "ok"
                ws.send_text("bye")

    assert len(keys) == 2 and keys[0] == keys[1]  # still stable per session
    assert keys[0].startswith("session:")
    assert sid not in keys[0]
    assert sid[:12] not in keys[0]


def test_a_session_shaped_value_is_redacted_on_write() -> None:
    """Defence in depth for N-04: should any path log the cookie value itself,
    the ring masks it the way it masks the launch token. Control: remove the
    ``session:`` pattern from ``obs.log``."""
    sid = secrets.token_urlsafe(32)
    obs_log.get_logger("web").warning("terminal session refused for session:%s: cap", sid)

    stored = obs_log.snapshot()[-1].message
    assert sid not in stored
    assert "<redacted>" in stored


# -- N-05: the terminal frame bound is enforced before the frame is buffered -----


def test_the_websocket_frame_bound_is_applied_by_the_server() -> None:
    """``MAX_FRAME_BYTES`` was checked after receipt, by which point uvicorn had
    already buffered up to its 16 MiB default. The same reasoning as the body
    cap: a bound applied after the read is not a bound. Control: drop
    ``ws_max_size`` from ``uvicorn_config``."""
    config = uvicorn_config(object())
    assert config.ws_max_size == MAX_FRAME_BYTES
