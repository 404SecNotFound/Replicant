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
"""Web-layer findings of the 2026-09-26 review. Decision record:
``docs/security-review-2026-09-26.md``.

Every guard here was run against the unfixed code and observed to fail before
the fix was restored; the record names the control used for each. The request
body cap (M-02) lives in ``test_web_body_limits.py`` because it needs a real
socket.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.cli.app import build_parser  # noqa: E402
from replicant.config.settings import Settings, config_dir  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.transport.syslog import PathReport  # noqa: E402
from replicant.web import guards, pty_bridge  # noqa: E402
from replicant.web.guards import (  # noqa: E402
    CA_REFUSAL,
    CAFileRefused,
    CollectorPolicy,
    StreamLimiter,
    TokenBucket,
    confined_cafile,
    parse_collector_rule,
    prune_evidence,
)
from replicant.web.runner import RunInProgressError, RunManager  # noqa: E402
from replicant.web.server import (  # noqa: E402
    CONNECT_FAILED_SUMMARY,
    CONNECT_TEST_BURST,
    SESSION_COOKIE,
    AccessPolicy,
    create_app,
    uvicorn_config,
)

TOKEN = "review-token"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(TECHNIQUE_CATALOG)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _client(tmp_path: Path, **kwargs: Any) -> TestClient:
    policy = kwargs.pop("policy", None)
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN, policy=policy, **kwargs)
    return TestClient(app, base_url="http://localhost")


def _stub_report(collector: Any, verdict: str = "sent_unconfirmed", summary: str = "stub") -> Any:
    return PathReport(
        host=collector.host,
        port=collector.port,
        transport=collector.transport,
        verdict=verdict,
        summary=summary,
        proves="stub",
        does_not_prove="stub",
    )


# -- H-01: validation is one at a time, and its evidence is bounded -----------


def test_a_second_validation_is_refused_while_one_runs(tmp_path: Path) -> None:
    """Twelve concurrent REP-004 high validations OOM-killed the server.

    Control: with begin_validation removed from the endpoint, the second call
    blocks behind nothing, runs, and answers 200.
    """
    client = _client(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    real_validate = __import__(
        "replicant.core.orchestrator", fromlist=["Orchestrator"]
    ).Orchestrator.validate

    def slow_validate(self: Any, *args: Any, **kwargs: Any) -> Any:
        entered.set()
        release.wait(10)
        return real_validate(self, *args, **kwargs)

    body = {"technique_id": "REP-011", "tier": "plan", "intensity": "low"}
    results: list[int] = []
    with patch("replicant.core.orchestrator.Orchestrator.validate", slow_validate):
        first = threading.Thread(
            target=lambda: results.append(
                client.post("/api/validate", headers=HEADERS, json=body).status_code
            )
        )
        first.start()
        assert entered.wait(10)
        second = client.post("/api/validate", headers=HEADERS, json=body)
        release.set()
        first.join(30)

    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "validation_in_progress"
    assert results == [200]
    # And the slot is released afterwards.
    assert client.post("/api/validate", headers=HEADERS, json=body).status_code == 200


def test_a_run_and_a_validation_exclude_each_other() -> None:
    """Decision: they share the host, so peak memory is the larger, not the sum."""
    manager = RunManager(CATALOG, Settings())
    manager.begin_validation()
    with pytest.raises(guards_validation_error()):
        manager.reserve("REP-001", "fortigate")
    manager.end_validation()

    manager.reserve("REP-001", "fortigate")
    with pytest.raises(RunInProgressError):
        manager.begin_validation()


def guards_validation_error() -> type[Exception]:
    from replicant.web.runner import ValidationInProgressError

    return ValidationInProgressError


def test_a_validation_is_refused_over_http_while_a_run_is_reserved(tmp_path: Path) -> None:
    client = _client(tmp_path)
    reserved = client.post(
        "/api/run-admissions",
        headers=HEADERS,
        json={"technique_id": "REP-001", "admission_id": str(uuid.uuid4())},
    )
    assert reserved.status_code == 200

    resp = client.post(
        "/api/validate", headers=HEADERS, json={"technique_id": "REP-011", "tier": "plan"}
    )

    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "run_in_progress"


def _pack(root: Path, run_id: str) -> None:
    (root / run_id).mkdir(parents=True)
    (root / run_id / "manifest.json").write_text("{}", encoding="utf-8")
    (root / f"{run_id}.zip").write_bytes(b"PK")


def _rid(n: int) -> str:
    return f"RUN-20260926T0000{n:02d}Z-{n:06x}"


def test_evidence_retention_keeps_the_newest_packs(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    for n in range(5):
        _pack(root, _rid(n))

    removed = prune_evidence(root, keep=2)

    assert removed == [_rid(0), _rid(1), _rid(2)]
    assert sorted(p.name for p in root.iterdir()) == sorted(
        [_rid(3), f"{_rid(3)}.zip", _rid(4), f"{_rid(4)}.zip"]
    )


def test_evidence_retention_only_considers_run_ids(tmp_path: Path) -> None:
    """Named to sort BEFORE every run id, so it would be pruned first if it were
    a candidate. Control: drop the _RUN_ID match."""
    root = tmp_path / "evidence"
    for n in range(3):
        _pack(root, _rid(n))
    (root / "00-notes.txt").write_text("keep me", encoding="utf-8")
    (root / "RUN-not-a-run-id").mkdir()

    prune_evidence(root, keep=1)

    assert (root / "00-notes.txt").exists()
    assert (root / "RUN-not-a-run-id").is_dir()


def test_evidence_retention_never_follows_a_symlink(tmp_path: Path) -> None:
    """A planted RUN-* link, oldest by name, pointing at data outside the root.

    Held at two layers: links are skipped as candidates, and ``shutil.rmtree``
    refuses a symlinked directory. Removing the skip alone stays green because of
    the second. The recorded control removes the skip and resolves the path
    before deleting (the regression a "tidy up the paths" change would make),
    and the outside data is deleted.
    """
    root = tmp_path / "evidence"
    for n in range(3):
        _pack(root, _rid(n))
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "data").write_text("keep me", encoding="utf-8")
    link = root / "RUN-20250101T000000Z-aaaaaa"
    link.symlink_to(outside, target_is_directory=True)

    prune_evidence(root, keep=1)

    assert link.is_symlink()
    assert (outside / "data").read_text(encoding="utf-8") == "keep me"


def test_the_web_server_prunes_evidence_after_each_validation(tmp_path: Path) -> None:
    """Control: without the prune call three validations leave three packs."""
    client = _client(tmp_path, evidence_keep=2)
    body = {"technique_id": "REP-011", "tier": "plan", "intensity": "low"}
    ids = []
    for _ in range(3):
        resp = client.post("/api/validate", headers=HEADERS, json=body)
        assert resp.status_code == 200
        ids.append(resp.json()["run_id"])
        time.sleep(1.05)  # run ids sort by their UTC second

    root = tmp_path / "manifests" / "evidence"
    assert not (root / ids[0]).exists()
    assert not (root / f"{ids[0]}.zip").exists()
    assert (root / ids[2]).is_dir() and (root / f"{ids[2]}.zip").is_file()


def test_evidence_keep_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _client(tmp_path, evidence_keep=0)


# -- L-07: an abandoned reservation expires -----------------------------------


def test_an_abandoned_reservation_stops_holding_the_lock() -> None:
    """POST /api/run-admissions and then nothing used to 409 every run forever.

    Control: with _expire_admissions_locked a no-op the second reserve raises
    RunInProgressError at any clock value.
    """
    clock = FakeClock()
    manager = RunManager(CATALOG, Settings(), clock=clock)
    first = manager.reserve("REP-001", "fortigate")

    clock.now += 30
    with pytest.raises(RunInProgressError):
        manager.reserve("REP-002", "fortigate")

    clock.now += manager.admission_ttl_s
    second = manager.reserve("REP-002", "fortigate")

    assert first.status == "error"
    assert second.status == "reserved"
    assert manager.active() is second


def test_an_expired_reservation_cannot_be_claimed() -> None:
    from replicant.web.runner import RunAdmissionError

    clock = FakeClock()
    manager = RunManager(CATALOG, Settings(), clock=clock)
    handle = manager.reserve("REP-001", "fortigate")
    clock.now += manager.admission_ttl_s + 1

    with pytest.raises(RunAdmissionError):
        manager.claim(handle.admission_id, "REP-001", "fortigate")


def test_a_stalled_admitting_run_also_expires() -> None:
    clock = FakeClock()
    manager = RunManager(CATALOG, Settings(), clock=clock)
    handle = manager.reserve("REP-001", "fortigate")
    manager.claim(handle.admission_id, "REP-001", "fortigate")
    clock.now += manager.admission_ttl_s + 1

    assert manager.active() is None


def test_a_prompt_start_is_unaffected_by_expiry() -> None:
    clock = FakeClock()
    manager = RunManager(CATALOG, Settings(), clock=clock)
    handle = manager.reserve("REP-001", "fortigate")
    clock.now += manager.admission_ttl_s - 1
    claimed = manager.claim(handle.admission_id, "REP-001", "fortigate")

    assert claimed.status == "admitting"


def test_an_abandoned_reservation_expires_over_http(tmp_path: Path) -> None:
    clock = FakeClock()
    client = _client(tmp_path, clock=clock)
    reserve = {"technique_id": "REP-001", "admission_id": str(uuid.uuid4())}
    assert client.post("/api/run-admissions", headers=HEADERS, json=reserve).status_code == 200
    run = {"technique_id": "REP-001", "intensity": "low", "duration": "2m", "no_send": True}
    assert client.post("/api/runs", headers=HEADERS, json=run).status_code == 409

    clock.now += 61

    assert client.post("/api/runs", headers=HEADERS, json=run).status_code == 200


# -- M-04: the terminal default follows reachability, not the bind alone ------


def test_terminal_is_off_behind_a_proxy_on_a_loopback_bind() -> None:
    """Control: AccessPolicy.for_bind deciding from is_loopback(host) alone."""
    assert not AccessPolicy.for_bind("127.0.0.1", ["replicant.lab"]).terminal_enabled


def test_terminal_stays_on_when_the_allowed_host_is_itself_loopback() -> None:
    assert AccessPolicy.for_bind("127.0.0.1", ["localhost", "::1"]).terminal_enabled


def test_enable_terminal_still_turns_it_on_behind_a_proxy() -> None:
    assert AccessPolicy.for_bind(
        "127.0.0.1", ["replicant.lab"], enable_terminal=True
    ).terminal_enabled


def test_terminal_is_off_when_collectors_are_restricted() -> None:
    """The menu is a separate process the web allow list does not govern."""
    assert not AccessPolicy.for_bind("127.0.0.1", collector_restricted=True).terminal_enabled


def test_proxied_terminal_websocket_is_refused(tmp_path: Path) -> None:
    """The reproduced case: loopback bind, --allowed-host, allowed Host and Origin."""
    client = _client(tmp_path, policy=AccessPolicy.for_bind("127.0.0.1", ["replicant.lab"]))

    with pytest.raises(Exception):  # noqa: B017 - starlette raises on a handshake close
        with client.websocket_connect(
            f"/ws/terminal?token={TOKEN}",
            headers={"host": "replicant.lab", "origin": "http://replicant.lab"},
        ):
            pass


# -- M-05: connect tests are metered and destinations can be restricted ------


def test_connect_tests_are_rate_limited(tmp_path: Path) -> None:
    """Measured at 311 probes a second. Control: drop _charge_connect_test."""
    client = _client(tmp_path)
    body = {"host": "127.0.0.1", "port": 9, "transport": "udp"}
    with patch("replicant.web.server.probe_collector", lambda c, payload: _stub_report(c)):
        codes = [
            client.post("/api/connect/test", headers=HEADERS, json=body).status_code
            for _ in range(CONNECT_TEST_BURST + 1)
        ]

    assert codes[:CONNECT_TEST_BURST] == [200] * CONNECT_TEST_BURST
    assert codes[-1] == 429


def test_the_connect_allowance_refills() -> None:
    clock = FakeClock()
    bucket = TokenBucket(2, 60.0, clock=clock)
    assert bucket.take() == 0.0 and bucket.take() == 0.0
    assert bucket.take() > 0
    clock.now += 30
    assert bucket.take() == 0.0


def test_the_rate_limit_is_per_session(tmp_path: Path) -> None:
    client = _client(tmp_path)
    body = {"host": "127.0.0.1", "port": 9, "transport": "udp"}
    with patch("replicant.web.server.probe_collector", lambda c, payload: _stub_report(c)):
        for _ in range(CONNECT_TEST_BURST):
            client.post("/api/connect/test", headers=HEADERS, json=body)
        assert client.post("/api/connect/test", headers=HEADERS, json=body).status_code == 429
        # A browser session is its own bucket.
        client.get("/", params={"token": TOKEN})
        assert client.cookies.get(SESSION_COOKIE)
        resp = client.post("/api/connect/test", headers={"origin": "http://localhost"}, json=body)
    assert resp.status_code == 200


def test_a_connect_failure_returns_a_generic_summary(tmp_path: Path) -> None:
    """The verdict survives; the exception text does not. Control: the old
    endpoint returned the report unchanged."""
    client = _client(tmp_path)
    leaky = "FileNotFoundError: [Errno 2] No such file or directory: '/etc/shadow-ish'"
    with patch(
        "replicant.web.server.probe_collector",
        lambda c, payload: _stub_report(c, verdict="failed", summary=leaky),
    ):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": 9, "transport": "tcp"},
        )
    report = resp.json()["report"]
    assert report["verdict"] == "failed"
    assert report["summary"] == CONNECT_FAILED_SUMMARY
    assert "Errno" not in resp.text


def test_a_refused_summary_carries_no_exception_text(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with patch(
        "replicant.web.server.probe_collector",
        lambda c, payload: _stub_report(
            c, verdict="refused", summary="ConnectionRefusedError: [Errno 111] refused"
        ),
    ):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": 9, "transport": "tcp"},
        )
    assert resp.json()["report"]["verdict"] == "refused"
    assert "Errno" not in resp.text


@pytest.mark.parametrize(
    "text,host,port,allowed",
    [
        ("10.0.20.0/24:514", "10.0.20.7", 514, True),
        ("10.0.20.0/24:514", "10.0.20.7", 515, False),
        ("10.0.20.0/24:514", "10.0.21.7", 514, False),
        ("10.0.20.0/24", "10.0.20.7", 6514, True),
        ("192.0.2.10", "192.0.2.10", 514, True),
        ("[2001:db8::/32]:6514", "2001:db8::5", 6514, True),
        ("[2001:db8::/32]:6514", "2001:db8::5", 514, False),
        ("2001:db8::/32", "2001:db8::5", 514, True),
        ("10.0.20.0/24", "collector.lab", 514, False),  # names never match
    ],
)
def test_collector_rules(text: str, host: str, port: int, allowed: bool) -> None:
    assert CollectorPolicy((parse_collector_rule(text),)).permits(host, port) is allowed


@pytest.mark.parametrize("bad", ["10.0.20.0/33", "banana", "10.0.0.0/8:0", "[::1", "1.2.3.4:x"])
def test_a_bad_collector_rule_refuses_startup(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_collector_rule(bad)


def test_an_empty_allow_list_permits_everything() -> None:
    assert CollectorPolicy().permits("203.0.113.9", 514)


def test_the_allow_list_is_enforced_on_connect_tests_and_runs(tmp_path: Path) -> None:
    """Control: without _check_destination both calls reach the probe/run."""
    policy = CollectorPolicy.parse(["10.0.20.0/24:514"])
    client = _client(tmp_path, collector_policy=policy)
    probed: list[Any] = []

    def probe(c: Any, payload: str) -> Any:
        probed.append(c)
        return _stub_report(c)

    with patch("replicant.web.server.probe_collector", probe):
        denied = client.post(
            "/api/connect/test", headers=HEADERS, json={"host": "10.0.30.1", "port": 22}
        )
        allowed = client.post(
            "/api/connect/test", headers=HEADERS, json={"host": "10.0.20.5", "port": 514}
        )
    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert [c.host for c in probed] == ["10.0.20.5"]

    run = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-001",
            "collector": {"host": "10.0.30.1", "port": 22, "transport": "tcp"},
        },
    )
    assert run.status_code == 403
    # And the refusal released the single-run lock rather than holding it.
    assert client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None


def test_a_no_send_run_is_not_held_to_the_allow_list(tmp_path: Path) -> None:
    policy = CollectorPolicy.parse(["10.0.20.0/24:514"])
    client = _client(tmp_path, collector_policy=policy)
    resp = client.post(
        "/api/plan",
        headers=HEADERS,
        json={
            "technique_id": "REP-001",
            "no_send": True,
            "collector": {"host": "10.0.30.1", "port": 22},
        },
    )
    assert resp.status_code == 200


# -- L-06: a web-supplied CA file is a name inside <config>/ca ----------------


def test_an_arbitrary_cafile_path_is_refused_with_a_generic_error(tmp_path: Path) -> None:
    """Control: the old endpoint passed any path to ssl and echoed the error."""
    client = _client(tmp_path)
    secret = tmp_path / "secret.key"
    secret.write_text("x", encoding="utf-8")
    replies = []
    for value in (str(secret), "/nonexistent/ca.pem", "/etc", "../secret.key"):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": 6514, "transport": "tls", "tls_cafile": value},
        )
        replies.append((resp.status_code, resp.json()["detail"]))

    assert all(code == 400 for code, _ in replies)
    assert {detail for _, detail in replies} == {CA_REFUSAL}


def test_a_cafile_is_refused_on_runs_too(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post(
        "/api/plan",
        headers=HEADERS,
        json={
            "technique_id": "REP-001",
            "collector": {
                "host": "127.0.0.1",
                "port": 6514,
                "transport": "tls",
                "tls_cafile": "/etc/passwd",
            },
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == CA_REFUSAL


def test_a_cafile_in_the_ca_dir_resolves(tmp_path: Path) -> None:
    root = tmp_path / "ca"
    root.mkdir()
    (root / "lab.pem").write_text("x", encoding="utf-8")
    assert confined_cafile("lab.pem", root) == str(root / "lab.pem")
    assert confined_cafile(None, root) is None
    assert confined_cafile("  ", root) is None


def test_a_symlinked_cafile_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "ca"
    root.mkdir()
    (tmp_path / "outside.pem").write_text("x", encoding="utf-8")
    (root / "lab.pem").symlink_to(tmp_path / "outside.pem")
    (root / "sub").mkdir()
    for value in ("lab.pem", "sub", "sub/x.pem", ".."):
        with pytest.raises(CAFileRefused):
            confined_cafile(value, root)


def test_the_ca_dir_is_under_the_config_dir(tmp_path: Path) -> None:
    client = _client(tmp_path)
    ca = config_dir() / "ca"
    ca.mkdir(parents=True)
    (ca / "lab.pem").write_text("x", encoding="utf-8")
    seen: list[Any] = []

    def probe(c: Any, payload: str) -> Any:
        seen.append(c.tls_cafile)
        return _stub_report(c, verdict="handshake_ok")

    with patch("replicant.web.server.probe_collector", probe):
        resp = client.post(
            "/api/connect/test",
            headers=HEADERS,
            json={"host": "127.0.0.1", "port": 6514, "transport": "tls", "tls_cafile": "lab.pem"},
        )
    assert resp.status_code == 200
    assert seen == [str(ca / "lab.pem")]


# -- L-08: a non-ASCII credential is a 401, not a 500 -------------------------


@pytest.mark.parametrize("route", ["/api/health", "/api/catalog", "/"])
def test_a_non_ascii_token_does_not_break_every_route(tmp_path: Path, route: str) -> None:
    """compare_digest(str, str) raises TypeError on non-ASCII, and the cookie
    middleware authenticates every request. Control: revert to comparing str."""
    client = _client(tmp_path)
    resp = client.get(route, params={"token": "tést"})

    assert resp.status_code in {200, 303, 401}
    assert resp.status_code != 500


def test_a_non_ascii_header_token_is_a_401(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.get("/api/catalog", headers={"authorization": "Bearer café".encode()})
    assert resp.status_code == 401


def test_a_non_ascii_launch_token_still_authenticates(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    client = TestClient(create_app(CATALOG, settings, token="tést"), base_url="http://localhost")
    assert client.get("/api/catalog", params={"token": "tést"}).status_code == 200


# -- M-03 (web half): the terminal child gets a minimal environment ------------


def test_the_terminal_child_environment_is_minimal() -> None:
    """Control: the old _spawn_command copied os.environ wholesale."""
    parent = {
        "PATH": "/usr/bin",
        "HOME": "/home/op",
        "LANG": "en_GB.UTF-8",
        "LC_ALL": "C.UTF-8",
        "REPLICANT_CONFIG_DIR": "/cfg",
        "AWS_SECRET_ACCESS_KEY": "hunter2",
        "HTTPS_PROXY": "http://user:pass@proxy:3128",
        "REPLICANT_SOMETHING_ELSE": "x",
        "REPLICANT_WEB_CONFINED": "0",
    }
    env = pty_bridge.child_environment(parent)

    assert env["REPLICANT_WEB_CONFINED"] == "1"
    assert env["TERM"] == "xterm-256color"
    assert env["REPLICANT_CONFIG_DIR"] == "/cfg"
    assert env["LC_ALL"] == "C.UTF-8"
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "HTTPS_PROXY" not in env
    assert "REPLICANT_SOMETHING_ELSE" not in env
    assert set(env) <= (
        pty_bridge.CHILD_ENV_ALLOW
        | {"TERM", "COLUMNS", "LINES", "REPLICANT_WEB_CONFINED", "LC_ALL"}
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX pty only")
def test_the_spawned_child_really_receives_the_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through pty.fork and execve, not only the pure function."""
    monkeypatch.setenv("REVIEW_CANARY_SECRET", "canary-value")
    import sys

    pid, fd = pty_bridge._spawn_command(
        [
            sys.executable,
            "-c",
            "import os;print('CANARY=' + os.environ.get('REVIEW_CANARY_SECRET', 'absent'));"
            "print('CONFINED=' + os.environ.get('REPLICANT_WEB_CONFINED', 'absent'))",
        ]
    )
    out = b""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and b"CONFINED=" not in out:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    os.waitpid(pid, 0)
    os.close(fd)
    text = out.decode()
    assert "CANARY=absent" in text
    assert "CONFINED=1" in text


# -- L-09: the per-client terminal cap cannot be dodged ------------------------


def test_the_terminal_cap_is_keyed_on_the_session_not_the_peer(tmp_path: Path) -> None:
    """X-Forwarded-For used to choose the key. Control: key on websocket.client."""
    client = _client(tmp_path)
    client.get("/", params={"token": TOKEN})
    keys: list[str] = []

    async def fake_bridge(websocket: Any, client_key: str | None = None) -> None:
        keys.append(client_key or "")
        await websocket.send_text("ok")
        await websocket.receive_text()

    sid = client.cookies[SESSION_COOKIE]
    with patch("replicant.web.server.bridge_terminal", fake_bridge):
        for forwarded in ("10.0.0.1", "10.0.0.2"):
            with client.websocket_connect(
                "/ws/terminal",
                headers={
                    "host": "localhost",
                    "origin": "http://localhost",
                    "cookie": f"{SESSION_COOKIE}={sid}",
                    "x-forwarded-for": forwarded,
                },
            ) as ws:
                assert ws.receive_text() == "ok"
                ws.send_text("bye")

    assert len(keys) == 2 and keys[0] == keys[1]
    assert keys[0].startswith("session:")


def test_forwarded_headers_are_untrusted_by_default() -> None:
    """uvicorn trusts 127.0.0.1 unless told otherwise. Control: the old serve()
    built uvicorn.Config without proxy settings."""
    config = uvicorn_config(object())
    assert config.proxy_headers is False
    assert config.forwarded_allow_ips == []


def test_forwarded_headers_are_trusted_only_from_a_named_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert uvicorn_config(object()).forwarded_allow_ips == []
    config = uvicorn_config(object(), ["10.0.0.5"])
    assert config.proxy_headers is True
    assert config.forwarded_allow_ips == ["10.0.0.5"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX only")
def test_a_spoofed_forwarded_for_does_not_change_the_client_on_a_live_server(
    tmp_path: Path,
) -> None:
    import http.client

    from tests._live_server import live_server

    async def app(scope: Any, receive: Any, send: Any) -> None:
        # Raw ASGI: reports the client address uvicorn put in the scope.
        client = scope.get("client") or ("", 0)
        body = str(client[0]).encode("ascii")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    with live_server(app) as port:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/who", headers={"X-Forwarded-For": "203.0.113.77"})
        seen = conn.getresponse().read().decode()
        conn.close()
    assert "203.0.113.77" not in seen
    assert "127.0.0.1" in seen


# -- SSE: live streams are capped ---------------------------------------------


def test_the_stream_limiter_refuses_past_its_cap_and_frees_on_release() -> None:
    limiter = StreamLimiter(2)
    a, b = limiter.acquire(), limiter.acquire()
    assert a is not None and b is not None
    assert limiter.acquire() is None
    a.release()
    a.release()  # idempotent
    assert limiter.live == 1
    assert limiter.acquire() is not None


def test_a_dropped_slot_is_released_by_collection() -> None:
    limiter = StreamLimiter(1)
    slot = limiter.acquire()
    assert slot is not None
    del slot
    assert limiter.live == 0


def _open_stream(port: int, path: str) -> tuple[Any, int | None]:
    """Open an SSE request on a raw socket and return it with its status."""
    import socket

    from tests._live_server import read_status

    conn = socket.create_connection(("127.0.0.1", port))
    conn.sendall(
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        f"X-Replicant-Token: {TOKEN}\r\n\r\n".encode("ascii")
    )
    return conn, read_status(conn, timeout=5.0)


def test_streams_past_the_cap_are_refused_and_freed_on_disconnect(tmp_path: Path) -> None:
    """Run and log streams share one cap, and a closed tab gives its slot back.

    Log streams never end on their own, which is what makes them the right thing
    to hold open here. A live server, because ``TestClient`` buffers a streamed
    body before returning. Control: without _stream_slot the third stream and
    the run stream both open with 200.
    """
    from tests._live_server import live_server

    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN, max_streams=2)
    client = TestClient(app, base_url="http://localhost")
    run_id = client.post(
        "/api/runs",
        headers=HEADERS,
        json={"technique_id": "REP-001", "intensity": "low", "duration": "2m", "no_send": True},
    ).json()["run_id"]

    with live_server(app) as port:
        first, s1 = _open_stream(port, "/api/logs/stream")
        second, s2 = _open_stream(port, "/api/logs/stream")
        third, s3 = _open_stream(port, "/api/logs/stream")
        run, s4 = _open_stream(port, f"/api/runs/{run_id}/events")
        assert (s1, s2, s3, s4) == (200, 200, 429, 429)
        for conn in (first, third, run):
            conn.close()

        # The disconnect is noticed on the stream's next poll (0.4s).
        reopened: int | None = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            conn, reopened = _open_stream(port, "/api/logs/stream")
            conn.close()
            if reopened == 200:
                break
            time.sleep(0.2)
        second.close()
    assert reopened == 200


# -- CLI flags -----------------------------------------------------------------


def test_new_web_flags_default_to_the_current_behaviour() -> None:
    args = build_parser().parse_args(["web"])
    assert args.collector_allow == []
    assert args.evidence_keep == guards.DEFAULT_EVIDENCE_KEEP
    assert args.forwarded_allow_ips == []


def test_new_web_flags_are_repeatable() -> None:
    args = build_parser().parse_args(
        [
            "web",
            "--collector-allow",
            "10.0.20.0/24:514",
            "--collector-allow",
            "[2001:db8::/32]:6514",
            "--forwarded-allow-ips",
            "10.0.0.5",
            "--evidence-keep",
            "5",
        ]
    )
    assert args.collector_allow == ["10.0.20.0/24:514", "[2001:db8::/32]:6514"]
    assert args.forwarded_allow_ips == ["10.0.0.5"]
    assert args.evidence_keep == 5


def test_the_web_command_passes_the_new_flags_to_serve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from replicant.cli.app import main

    seen: dict[str, Any] = {}
    monkeypatch.setattr("replicant.web.server.serve", lambda *a, **k: seen.update(k))
    main(
        [
            "web",
            "--no-browser",
            "--collector-allow",
            "10.0.20.0/24:514",
            "--evidence-keep",
            "3",
            "--forwarded-allow-ips",
            "10.0.0.5",
        ]
    )
    assert seen["collector_allow"] == ["10.0.20.0/24:514"]
    assert seen["evidence_keep"] == 3
    assert seen["forwarded_allow_ips"] == ["10.0.0.5"]


def test_a_bad_collector_allow_is_an_operator_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from replicant.cli.app import main

    code = main(["web", "--no-browser", "--collector-allow", "banana"])
    assert code == 1
    assert "--collector-allow" in capsys.readouterr().err
