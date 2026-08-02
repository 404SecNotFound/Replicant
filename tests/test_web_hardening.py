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
"""P1 findings from the 2026-08 review: headers, no-auth policy, file output."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.server import AccessPolicy, create_app  # noqa: E402

CATALOG = load_catalog(TECHNIQUE_CATALOG)
HEADERS = {"x-replicant-token": "t", "host": "localhost"}


def _client(tmp_path: Path, policy: AccessPolicy | None = None) -> TestClient:
    app = create_app(
        CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")), token="t", policy=policy
    )
    return TestClient(app, base_url="http://localhost")


# -- F-03: a policy behind the Markdown fix ----------------------------------


def test_a_content_security_policy_is_sent(tmp_path: Path) -> None:
    """Second line of defence for the Docs tab. Raw HTML is escaped before it can
    become markup; this means a regression there is not an execution primitive."""

    csp = _client(tmp_path).get("/api/health").headers.get("content-security-policy", "")

    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("style-src")[0]  # not on script-src
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp


def test_sniffing_and_referrer_are_constrained(tmp_path: Path) -> None:
    headers = _client(tmp_path).get("/api/health").headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("referrer-policy") == "no-referrer"


# -- F-06: one authentication policy, not two --------------------------------


def test_no_auth_opens_the_terminal_it_says_it_opens(tmp_path: Path) -> None:
    """The startup warning says --no-auth exposes the terminal without
    authentication. The websocket path ignored require_auth and closed every
    connection, so the warning described a state the code could not reach."""

    policy = AccessPolicy(require_auth=False)
    client = _client(tmp_path, policy)

    with client.websocket_connect(
        "/ws/terminal", headers={"host": "localhost", "origin": "http://localhost"}
    ) as ws:
        assert ws.receive_text() is not None


def test_no_auth_still_enforces_the_browser_boundary(tmp_path: Path) -> None:
    """--no-auth drops the credential, never the Origin check. Otherwise any page
    on the machine could drive the terminal."""

    from starlette.websockets import WebSocketDisconnect

    client = _client(tmp_path, AccessPolicy(require_auth=False))

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws/terminal", headers={"host": "localhost", "origin": "http://localhost:9999"}
        ) as ws:
            ws.receive_text()


# -- F-07: the web cannot truncate arbitrary paths ---------------------------


def test_web_output_cannot_escape_its_directory(tmp_path: Path) -> None:
    """FileSink opens with mode 'w', which truncates. A stolen web token must not
    be worth more than the collector-run authority it is meant to carry."""

    victim = tmp_path / "precious.txt"
    victim.write_text("do not truncate me", encoding="utf-8")

    resp = _client(tmp_path).post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-002",
            "intensity": "low",
            "no_send": True,
            "to_file": str(victim),
        },
    )

    assert resp.status_code == 200
    assert victim.read_text(encoding="utf-8") == "do not truncate me"


def test_a_traversal_attempt_is_confined_rather_than_honoured(tmp_path: Path) -> None:
    resp = _client(tmp_path).post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-002",
            "intensity": "low",
            "no_send": True,
            "to_file": "../../../../etc/replicant-should-never-write-here",
        },
    )

    assert resp.status_code == 200
    assert not Path("/etc/replicant-should-never-write-here").exists()
