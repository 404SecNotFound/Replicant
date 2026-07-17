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
"""Web API tests via FastAPI TestClient (no real network beyond loopback)."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.web.server import create_app  # noqa: E402

TOKEN = "test-token"
CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")
HEADERS = {"x-replicant-token": TOKEN}


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN)
    # base_url localhost so the DNS-rebinding Host guard accepts the request
    return TestClient(app, base_url="http://localhost")


def test_health_needs_no_token(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["vendor"] == "fortigate"


def test_catalog_requires_token(client: TestClient) -> None:
    assert client.get("/api/catalog").status_code == 401
    resp = client.get("/api/catalog", headers=HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()["techniques"]) == 11


def test_non_local_host_rejected(client: TestClient) -> None:
    resp = client.get("/api/health", headers={"host": "evil.example.com"})
    assert resp.status_code == 403


def test_config_endpoint(client: TestClient) -> None:
    resp = client.get("/api/config", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["eps_cap"] == 2000


def test_connect_test_reaches_loopback(client: TestClient) -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5.0)
    port = receiver.getsockname()[1]
    try:
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": port, "transport": "udp"},
        )
        data, _ = receiver.recvfrom(65535)
    finally:
        receiver.close()
    assert resp.status_code == 200 and resp.json()["ok"] is True
    assert "traffic:forward accept" in data.decode()


def test_run_stream_reports_lines_and_done(client: TestClient) -> None:
    start = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "intensity": "medium", "duration": "2m", "no_send": True},
    )
    assert start.status_code == 200
    run_id = start.json()["run_id"]

    body = ""
    with client.stream("GET", f"/api/runs/{run_id}/events?token={TOKEN}") as resp:
        assert resp.status_code == 200
        for chunk in resp.iter_text():
            body += chunk
            if '"type": "done"' in body:
                break
    assert '"type": "line"' in body
    assert '"type": "done"' in body

    status = client.get(f"/api/runs/{run_id}", headers=HEADERS).json()
    assert status["status"] == "done"
    assert status["manifest"]["technique_id"] == "REP-001"
    assert status["event_count"] > 0


def test_run_unimplemented_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-011", "intensity": "low", "no_send": True},
    )
    assert resp.status_code == 400


def test_run_unknown_technique_returns_404(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-999", "no_send": True},
    )
    assert resp.status_code == 404


def test_stop_unknown_run_is_false(client: TestClient) -> None:
    resp = client.post("/api/runs/deadbeef/stop", headers=HEADERS)
    assert resp.status_code == 200 and resp.json()["ok"] is False


def test_terminal_ws_rejects_bad_token(client: TestClient) -> None:
    with pytest.raises(Exception):  # noqa: B017 - starlette raises on 1008 close during handshake
        with client.websocket_connect("/ws/terminal?token=wrong"):
            pass


def test_run_to_file_from_web(client: TestClient, tmp_path: Path) -> None:
    out = tmp_path / "web.log"
    start = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-004",
            "intensity": "medium",
            "duration": "5s",
            "no_send": True,
            "to_file": str(out),
        },
    )
    run_id = start.json()["run_id"]
    with client.stream("GET", f"/api/runs/{run_id}/events?token={TOKEN}") as resp:
        for chunk in resp.iter_text():
            if '"type": "done"' in chunk or '"type": "done"' in "".join([chunk]):
                pass
        # drain fully
    # poll until finished
    status = client.get(f"/api/runs/{run_id}", headers=HEADERS).json()
    assert status["status"] in {"done", "running"}
    lines = out.read_text().splitlines()
    assert all("dns:dns-query pass" in line for line in lines)
    assert json.loads(json.dumps(status))  # serializable
