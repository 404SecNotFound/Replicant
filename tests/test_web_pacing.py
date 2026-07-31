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
"""Pacing over the web API.

The form has to be able to say what each choice costs before the operator picks
one, which means the server has to be able to answer "how long would this take?"
without starting a run. That is what ``POST /api/plan`` is for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.server import create_app  # noqa: E402

TOKEN = "test-token"
CATALOG = load_catalog(TECHNIQUE_CATALOG)
HEADERS = {"x-replicant-token": TOKEN}


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN)
    return TestClient(app, base_url="http://localhost")


def _plan(client: TestClient, **body: object) -> dict:
    payload = {"technique_id": "REP-001", "intensity": "low", **body}
    resp = client.post("/api/plan", json=payload, headers=HEADERS)
    assert resp.status_code == 200, resp.text
    return resp.json()


# -- the preview the form needs ----------------------------------------------


def test_the_preview_needs_a_token(client: TestClient) -> None:
    assert client.post("/api/plan", json={"technique_id": "REP-001"}).status_code == 401


def test_the_preview_reports_the_plan_s_own_span(client: TestClient) -> None:
    """49 events across 238 minutes. Both figures are shown in the form, because
    the count alone does not tell an operator that the run takes four hours."""

    body = _plan(client, pace="plan")

    assert body["event_count"] == 49
    assert body["plan_span_s"] == 14_280
    assert body["projected_s"] == pytest.approx(14_280, abs=1)


def test_the_preview_prices_burst_and_plan_differently(client: TestClient) -> None:
    """The contrast is the reason the control exists. If both modes projected the
    same duration there would be nothing to choose between them."""

    burst = _plan(client, pace="burst")
    plan = _plan(client, pace="plan")

    assert burst["projected_s"] < 1.0
    assert plan["projected_s"] > 14_000
    # Burst does not change what the timestamps claim, only when they arrive. That
    # is exactly why a burst run cannot satisfy an interval-keyed rule.
    assert burst["plan_span_s"] == plan["plan_span_s"]


def test_the_preview_follows_speed(client: TestClient) -> None:
    body = _plan(client, pace="plan", speed=60)

    assert body["projected_s"] == pytest.approx(238, abs=2)
    # The event times compress with the schedule, so the span the timestamps claim
    # moves too. Reported separately so the form can say both.
    assert body["compressed_span_s"] == pytest.approx(238, abs=2)


def test_the_preview_rejects_a_speed_that_could_do_nothing(client: TestClient) -> None:
    resp = client.post(
        "/api/plan",
        json={"technique_id": "REP-001", "intensity": "low", "pace": "burst", "speed": 60},
        headers=HEADERS,
    )

    assert resp.status_code == 422


def test_the_preview_rejects_an_unknown_technique(client: TestClient) -> None:
    resp = client.post("/api/plan", json={"technique_id": "REP-999"}, headers=HEADERS)

    assert resp.status_code == 404


# -- what a started run reports ----------------------------------------------


def test_a_started_run_reports_the_pace_it_chose(client: TestClient, tmp_path: Path) -> None:
    """The server decides the pace, so the server says which one it used rather
    than the client restating a default it might have got wrong."""

    resp = client.post(
        "/api/runs",
        json={
            "technique_id": "REP-001",
            "intensity": "low",
            "no_send": True,
            "to_file": str(tmp_path / "o.log"),
        },
        headers=HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    # A file-only run bursts: there is no wall clock in a file to reproduce.
    assert body["pace"] == "burst"
    assert body["projected_s"] < 1.0


def test_a_run_that_asks_for_an_impossible_combination_is_refused(
    client: TestClient, tmp_path: Path
) -> None:
    resp = client.post(
        "/api/runs",
        json={
            "technique_id": "REP-001",
            "intensity": "low",
            "no_send": True,
            "to_file": str(tmp_path / "o.log"),
            "speed": 60,
        },
        headers=HEADERS,
    )

    # No pace named and no collector resolves to burst, which would discard the
    # speed silently. Refused rather than ignored.
    assert resp.status_code == 400
    assert "plan pacing only" in resp.json()["detail"].lower()
