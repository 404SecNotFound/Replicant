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
CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)
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
    assert len(resp.json()["techniques"]) == 24


def test_catalog_exposes_detail_fields(client: TestClient) -> None:
    techniques = client.get("/api/catalog", headers=HEADERS).json()["techniques"]
    rep001 = next(t for t in techniques if t["id"] == "REP-001")
    for key in (
        "signature_id",
        "action",
        "cef_fields_held",
        "cef_fields_varied",
        "params",
        "distributions",
        "benign_baseline",
        "references",
    ):
        assert key in rep001, f"missing detail field {key}"
    assert rep001["cef_fields_varied"]  # non-empty: drives the detail panel
    assert set(rep001["params"]) <= {"low", "medium", "high"}


def test_technique_sample_renders_lines(client: TestClient) -> None:
    resp = client.get("/api/catalog/REP-001/sample", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["vendor"] == "fortigate"
    assert data["lines"], "expected at least one rendered sample line"
    assert all(line.startswith("CEF:") for line in data["lines"])
    assert data["cef_fields_varied"]


def test_technique_sample_honors_vendor(client: TestClient) -> None:
    data = client.get(
        "/api/catalog/REP-001/sample", headers=HEADERS, params={"vendor": "paloalto"}
    ).json()
    assert data["vendor"] == "paloalto"
    assert data["lines"][0].startswith("CEF:0|Palo Alto Networks|PAN-OS")


def test_technique_sample_requires_token(client: TestClient) -> None:
    assert client.get("/api/catalog/REP-001/sample").status_code == 401


def test_technique_sample_unknown_id_404(client: TestClient) -> None:
    assert client.get("/api/catalog/REP-999/sample", headers=HEADERS).status_code == 404


def test_technique_sample_unknown_vendor_400(client: TestClient) -> None:
    resp = client.get("/api/catalog/REP-001/sample", headers=HEADERS, params={"vendor": "nope"})
    assert resp.status_code == 400


def test_non_local_host_rejected(client: TestClient) -> None:
    resp = client.get("/api/health", headers={"host": "evil.example.com"})
    assert resp.status_code == 403


def test_config_endpoint(client: TestClient) -> None:
    resp = client.get("/api/config", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["eps_cap"] == 2000


def test_config_reports_vendor_options(client: TestClient) -> None:
    data = client.get("/api/config", headers=HEADERS).json()
    assert data["vendor"] == "fortigate"
    assert data["vendors"] == ["fortigate", "paloalto", "checkpoint"]


def test_connect_test_line_reflects_vendor(client: TestClient) -> None:
    from unittest.mock import patch

    def fake_send_test(self: object, collector: object) -> bool:
        return True

    with patch("replicant.web.server.Orchestrator.send_test", fake_send_test):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": 514, "transport": "udp", "vendor": "checkpoint"},
        )
    assert resp.status_code == 200
    assert resp.json()["line"].startswith("CEF:0|Check Point|")


def test_run_with_vendor_writes_checkpoint_cef(client: TestClient, tmp_path: Path) -> None:
    out = tmp_path / "cp_web.log"
    start = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-001",
            "intensity": "low",
            "duration": "2m",
            "no_send": True,
            "to_file": str(out),
            "vendor": "checkpoint",
        },
    )
    assert start.status_code == 200
    # Web output is confined to a server-chosen directory now, so the reported
    # path is the only correct place to look for it.
    out = Path(start.json()["output_path"])
    run_id = start.json()["run_id"]
    body = ""
    with client.stream("GET", f"/api/runs/{run_id}/events?token={TOKEN}") as resp:
        for chunk in resp.iter_text():
            body += chunk
            if '"type": "done"' in body:
                break
    lines = out.read_text().splitlines()
    assert lines
    assert all(line.startswith("CEF:0|Check Point|") for line in lines)


def test_run_unknown_vendor_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "no_send": True, "vendor": "bogus"},
    )
    assert resp.status_code == 400


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


def test_connect_test_passes_tls_options(client: TestClient) -> None:
    from unittest.mock import patch

    captured: dict[str, object] = {}

    def fake_send_test(self: object, collector: object) -> bool:
        captured["collector"] = collector
        return True

    with patch("replicant.web.server.Orchestrator.send_test", fake_send_test):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={
                "host": "127.0.0.1",
                "port": 6514,
                "transport": "tls",
                "tls_verify": False,
                "tls_cafile": "/tmp/ca.pem",
            },
        )
    assert resp.status_code == 200
    collector = captured["collector"]
    assert collector.transport == "tls"  # type: ignore[attr-defined]
    assert collector.tls_verify is False  # type: ignore[attr-defined]
    assert collector.tls_cafile == "/tmp/ca.pem"  # type: ignore[attr-defined]


def test_run_notimplemented_maps_to_400(client: TestClient) -> None:
    # All catalog techniques are implemented, so force the engine's not-implemented
    # path and assert the endpoint still maps it to a 400 (the error contract).
    from unittest.mock import patch

    with patch(
        "replicant.web.server.RunManager.start",
        side_effect=NotImplementedError("no builder"),
    ):
        resp = client.post(
            "/api/runs",
            headers=HEADERS,
            json={"technique_id": "REP-001", "intensity": "low", "no_send": True},
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
    out = Path(start.json()["output_path"])
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


def test_connect_test_rejects_out_of_range_port(client: TestClient) -> None:
    resp = client.post("/api/connect/test", headers=HEADERS, json={"host": "192.0.2.1", "port": 0})
    assert resp.status_code == 422


def test_connect_test_rejects_unknown_transport(client: TestClient) -> None:
    resp = client.post(
        "/api/connect/test", headers=HEADERS, json={"host": "192.0.2.1", "transport": "banana"}
    )
    assert resp.status_code == 422


def test_start_run_rejects_unknown_intensity(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "intensity": "ludicrous", "no_send": True},
    )
    assert resp.status_code == 422


# A non-loopback bind used to be refused outright by `_require_loopback`. That
# refusal is gone on purpose (tasks/webui-access-and-nav-spec.md): remote hosting is
# now supported, and the compensating controls live in tests/test_web_access.py.
# `is_loopback` survives as the predicate those controls key off, so it still has to
# classify correctly - it now decides whether the terminal tab defaults on and
# whether `--no-auth` needs an acknowledgement, rather than whether the server starts.


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.5.5.5"])
def test_loopback_addresses_are_recognised(host: str) -> None:
    from replicant.web.server import is_loopback

    assert is_loopback(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "10.20.0.50", "example.com"])
def test_routable_and_wildcard_addresses_are_not_loopback(host: str) -> None:
    from replicant.web.server import is_loopback

    assert not is_loopback(host)


# --- anchor selection on the web run path -----------------------------------
#
# The anchor trap: CEF eventtime is pinned to the determinism anchor while the
# syslog header is stamped at send time. On a SIEM that keys on parsed event time,
# a live send with the default fixed anchor lands outside every recent-window rule
# and nothing fires, which is indistinguishable from a broken detection. The CLI
# has had --anchor since Phase 2; the web path had no way to set it at all.


def _resolved_anchor(client: TestClient, anchor: object) -> dict:
    body = {"technique_id": "REP-001", "intensity": "low", "duration": "2m", "no_send": True}
    if anchor is not None:
        body["anchor"] = anchor
    return client.post("/api/runs", headers=HEADERS, json=body).json()


def test_run_defaults_to_the_fixed_anchor(client: TestClient) -> None:
    from replicant.config.settings import Settings

    assert _resolved_anchor(client, None)["anchor_epoch"] == Settings().anchor_epoch


def test_run_accepts_anchor_now(client: TestClient) -> None:
    import time

    resolved = _resolved_anchor(client, "now")["anchor_epoch"]

    assert abs(resolved - int(time.time())) < 120


def test_fixed_is_an_accepted_spelling_of_the_default(client: TestClient) -> None:
    # The form offers "now" and "fixed"; "fixed" has to mean something to the API
    # rather than falling through to parse_anchor and 400-ing.
    from replicant.config.settings import Settings

    assert _resolved_anchor(client, "fixed")["anchor_epoch"] == Settings().anchor_epoch


def test_run_accepts_an_explicit_epoch(client: TestClient) -> None:
    assert _resolved_anchor(client, "1700000000")["anchor_epoch"] == 1700000000


def test_run_accepts_an_iso_timestamp(client: TestClient) -> None:
    # 1784073600 == 2026-07-15T00:00:00Z. Check with:
    #   date -u -d @1784073600   (GNU)   /   date -u -r 1784073600   (BSD)
    assert _resolved_anchor(client, "2026-07-15T00:00:00Z")["anchor_epoch"] == 1784073600


def test_run_rejects_an_unparseable_anchor(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "no_send": True, "anchor": "last tuesday"},
    )

    assert resp.status_code == 400
    assert "anchor" in resp.json()["detail"]


def test_a_live_send_with_a_stale_anchor_is_flagged_in_the_response(client: TestClient) -> None:
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-001",
            "intensity": "low",
            "duration": "2m",
            "no_send": False,
            "collector": {"host": "127.0.0.1", "port": 9, "transport": "udp"},
            "anchor": "fixed",
        },
    )

    assert resp.status_code == 200
    assert "anchor" in (resp.json()["anchor_warning"] or "").lower()


def test_a_file_only_run_is_not_warned_about_its_anchor(client: TestClient) -> None:
    # Writing a fixed-anchor artifact to a file is the correct use of the default,
    # so warning there would train the operator to ignore the warning.
    assert _resolved_anchor(client, "fixed")["anchor_warning"] is None


def test_start_run_while_one_active_returns_409(client: TestClient, monkeypatch) -> None:
    from replicant.web import runner as runner_mod

    def busy(self, request, settings=None, total=None):  # type: ignore[no-untyped-def]
        raise runner_mod.RunInProgressError("run-abc")

    monkeypatch.setattr(runner_mod.RunManager, "start", busy)
    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "intensity": "low", "no_send": True},
    )
    assert resp.status_code == 409
    assert "in progress" in resp.json()["detail"]
