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
"""The Logs tab's API: read the buffer, tail it, and switch mode."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.obs import log as obs_log  # noqa: E402
from replicant.web.server import create_app, sse_log_line  # noqa: E402

TOKEN = "test-token-value-1234"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)


@pytest.fixture()
def client(tmp_path: Path) -> Iterator[TestClient]:
    obs_log.reset_for_tests()
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN)
    obs_log.set_level("debug")
    obs_log.clear()
    yield TestClient(app, base_url="http://localhost")
    obs_log.reset_for_tests()


def test_index_reports_the_level_and_the_available_modes(client: TestClient) -> None:
    body = client.get("/api/logs", headers=HEADERS).json()

    assert body["levels"] == ["debug", "verbose", "info", "warning"]
    assert body["level"] in body["levels"]


def test_entries_come_back_newest_last_with_a_cursor(client: TestClient) -> None:
    obs_log.get_logger("t").info("alpha")
    obs_log.get_logger("t").warning("beta")

    body = client.get("/api/logs", headers=HEADERS).json()
    messages = [entry["message"] for entry in body["entries"]]

    assert messages[-2:] == ["alpha", "beta"]
    assert body["cursor"] == body["entries"][-1]["seq"]


def test_after_returns_only_newer_entries(client: TestClient) -> None:
    obs_log.get_logger("t").info("first")
    cursor = client.get("/api/logs", headers=HEADERS).json()["cursor"]
    obs_log.get_logger("t").info("second")

    body = client.get(f"/api/logs?after={cursor}", headers=HEADERS).json()
    assert [entry["message"] for entry in body["entries"]] == ["second"]


def test_an_empty_page_still_advances_nothing_and_keeps_the_cursor(client: TestClient) -> None:
    obs_log.get_logger("t").info("only")
    cursor = client.get("/api/logs", headers=HEADERS).json()["cursor"]

    body = client.get(f"/api/logs?after={cursor}", headers=HEADERS).json()
    assert body["entries"] == []
    assert body["cursor"] == cursor


def test_setting_the_level_changes_what_is_recorded(client: TestClient) -> None:
    assert client.put("/api/logs/level", json={"level": "warning"}, headers=HEADERS).json() == {
        "level": "warning"
    }

    obs_log.get_logger("t").info("suppressed")
    obs_log.get_logger("t").warning("kept")

    messages = [e["message"] for e in client.get("/api/logs", headers=HEADERS).json()["entries"]]
    assert "suppressed" not in messages
    assert "kept" in messages


def test_an_unknown_level_is_rejected(client: TestClient) -> None:
    response = client.put("/api/logs/level", json={"level": "chatty"}, headers=HEADERS)
    assert response.status_code == 400
    assert "chatty" in response.json()["detail"]


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/api/logs"), ("get", "/api/logs/stream"), ("put", "/api/logs/level")],
)
def test_every_log_endpoint_requires_the_token(client: TestClient, method: str, path: str) -> None:
    response = client.request(method.upper(), path, json={"level": "info"})
    assert response.status_code == 401


def test_the_token_is_not_readable_through_the_log_api(client: TestClient) -> None:
    """The buffer is served over HTTP, so it is one more sink for the secret."""

    obs_log.get_logger("web").info("banner http://127.0.0.1:9787/?token=%s", TOKEN)

    body = client.get("/api/logs", headers=HEADERS).text
    assert TOKEN not in body
    assert "<redacted>" in body


def test_a_record_serialises_as_one_server_sent_event() -> None:
    obs_log.install()
    obs_log.set_level("debug")
    obs_log.get_logger("t").info("streamed")
    entry = obs_log.snapshot()[-1]

    line = sse_log_line(entry)

    assert line.startswith("data: ")
    assert line.endswith("\n\n")
    payload = json.loads(line[len("data: ") :])
    assert payload["message"] == "streamed"
    assert payload["level"] == "info"
    assert payload["seq"] == entry.seq


def test_the_stream_carries_the_token_through_redaction() -> None:
    obs_log.install()
    obs_log.set_level("debug")
    obs_log.get_logger("web").info("token=%s", TOKEN)

    line = sse_log_line(obs_log.snapshot()[-1])
    assert TOKEN not in line


def test_a_run_with_no_destination_is_flagged_in_the_response(client: TestClient) -> None:
    """The API says where the events went, rather than leaving the client to infer it."""

    body = client.post(
        "/api/runs",
        json={"technique_id": "REP-001", "intensity": "low", "no_send": True},
        headers=HEADERS,
    ).json()

    assert body["destination"] == "none"
    assert "no destination" in body["destination_warning"].lower()


def test_a_file_run_reports_its_destination_without_a_warning(
    client: TestClient, tmp_path: Path
) -> None:
    body = client.post(
        "/api/runs",
        json={
            "technique_id": "REP-001",
            "intensity": "low",
            "no_send": True,
            "to_file": str(tmp_path / "out.log"),
        },
        headers=HEADERS,
    ).json()

    assert body["destination"] == "file"
    assert body["destination_warning"] is None
