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
"""Three sample lines should not cost a whole plan, every time.

Review finding #3. The sample endpoint fires whenever the operator selects a
technique in the catalog rail, and it built the entire plan to pick three lines
out of it. REP-004 at high intensity is 180,000 events and about 1.6 seconds of
pure CPU, discarded immediately.

The reviewer's suggested fix, "build three and stop", would change what the
sample shows: it is deliberately the FIRST, MIDDLE and LAST event, and the middle
of three is not the middle of the run. The sample is fully determined by
(technique, intensity, vendor) given a fixed seed, so caching preserves the
output exactly and removes the repeat cost.
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
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(TECHNIQUE_CATALOG)


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(CATALOG, Settings(manifest_dir=str(tmp_path)), token=TOKEN)
    return TestClient(app, base_url="http://localhost")


def _sample(client: TestClient, tid: str = "REP-004", intensity: str = "high") -> dict:
    resp = client.get(
        f"/api/catalog/{tid}/sample", headers=HEADERS, params={"intensity": intensity}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_repeat_request_does_not_rebuild_the_plan(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _sample(client)

    # Any further build would be a cache miss. Counting is used rather than
    # timing, which passes or fails on how busy the machine is.
    from replicant.core.orchestrator import Orchestrator

    builds = {"n": 0}
    original = Orchestrator.build_plan

    def counted(self, request):  # type: ignore[no-untyped-def]
        builds["n"] += 1
        return original(self, request)

    monkeypatch.setattr(Orchestrator, "build_plan", counted)
    second = _sample(client)

    assert builds["n"] == 0, "the plan was rebuilt for an identical sample request"
    assert second["lines"] == first["lines"]


def test_the_sample_is_still_first_middle_and_last(client: TestClient) -> None:
    """The cache must not change what a sample contains."""
    body = _sample(client, "REP-001", "low")

    assert body["lines"]
    assert len(body["lines"]) <= 3
    assert all(line.startswith("CEF:0|") for line in body["lines"])


def test_a_different_intensity_is_a_different_sample(client: TestClient) -> None:
    """Intensity is part of the key, so it must not serve a stale answer."""
    low = _sample(client, "REP-004", "low")
    high = _sample(client, "REP-004", "high")

    assert low["intensity"] == "low"
    assert high["intensity"] == "high"


def test_a_different_vendor_is_a_different_sample(client: TestClient) -> None:
    fortigate = client.get(
        "/api/catalog/REP-001/sample", headers=HEADERS, params={"vendor": "fortigate"}
    ).json()
    checkpoint = client.get(
        "/api/catalog/REP-001/sample", headers=HEADERS, params={"vendor": "checkpoint"}
    ).json()

    assert fortigate["lines"] != checkpoint["lines"]
    assert "Fortinet" in fortigate["lines"][0]
    assert "Check Point" in checkpoint["lines"][0]
