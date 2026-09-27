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
"""CLI and Rich menu defects from the 2026-09-26 send-path review.

Safety rule 1: the only sockets are loopback listeners owned by these tests, or
a loopback port bound and released so nothing is listening on it.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from rich.console import Console

from replicant.cli import menu as menu_mod
from replicant.cli.app import main
from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.core.pacing import future_skew_warning, max_future_skew, send_offsets
from replicant.obs import log as obs_log
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
COLLECTOR = CollectorProfile(name="lab", host="127.0.0.1", port=5514, transport="udp")


def _closed_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _answers(monkeypatch: pytest.MonkeyPatch, prompts: list[str], confirms: list[bool]) -> None:
    remaining_prompts = list(prompts)
    remaining_confirms = list(confirms)
    monkeypatch.setattr(
        "replicant.cli.menu.Prompt.ask", staticmethod(lambda *a, **k: remaining_prompts.pop(0))
    )
    monkeypatch.setattr(
        "replicant.cli.menu.Confirm.ask", staticmethod(lambda *a, **k: remaining_confirms.pop(0))
    )


@pytest.fixture(autouse=True)
def _fresh_stderr_handler() -> None:
    obs_log.uninstall_stderr()
    yield
    obs_log.uninstall_stderr()


# -- 4. burst sends of future-dated events are named -------------------------


def test_the_future_skew_of_a_burst_run_is_its_plan_span() -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir="unused"))
    now = int(time.time())
    plan = orch.build_plan(RunRequest(technique_id="REP-001", intensity="low", anchor_epoch=now))
    offsets = send_offsets(plan.events, pace="burst", interval=1 / 2000)

    skew = max_future_skew(plan.events, offsets, now)

    assert skew > 14_000  # a four hour beacon delivered in a fraction of a second
    assert future_skew_warning(skew, pace="burst") is not None
    assert "--pace plan" in (future_skew_warning(skew, pace="burst") or "")


def test_plan_pacing_from_now_is_never_future_dated() -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir="unused"))
    now = int(time.time())
    plan = orch.build_plan(RunRequest(technique_id="REP-001", intensity="low", anchor_epoch=now))
    offsets = send_offsets(plan.events, pace="plan", interval=1 / 2000)

    assert max_future_skew(plan.events, offsets, now) <= 0.0
    assert future_skew_warning(0.0, pace="plan") is None


def test_a_burst_send_anchored_now_warns_on_stderr_and_in_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    monkeypatch.chdir(tmp_path)
    try:
        code = main(
            [
                "run",
                "REP-001",
                "--intensity",
                "low",
                "--anchor",
                "now",
                "--pace",
                "burst",
                "--host",
                "127.0.0.1",
                "--port",
                str(listener.getsockname()[1]),
            ]
        )
    finally:
        listener.close()

    assert code == 0
    err = capsys.readouterr().err
    assert "in the future" in err and "--pace plan" in err
    manifest = json.loads(next((tmp_path / "manifests").glob("REP-001-*.json")).read_text())
    assert any("in the future" in note for note in manifest["notes"])


def test_a_plan_send_anchored_now_records_no_future_note(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    preview = orch.preview_pacing(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            collector=COLLECTOR,
            anchor_epoch=int(time.time()),
            pace="plan",
        ),
        sending=True,
    )

    assert preview.future_warning is None


# -- 5. the menu can set the event-time anchor ---------------------------------


def test_the_menu_asks_for_the_anchor_and_now_means_now(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured: menu live sends carried event times about 438 days old."""

    _answers(monkeypatch, ["low", "", "plan", "1", "now"], [False])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert request.anchor_epoch is not None
    assert abs(request.anchor_epoch - time.time()) < 120


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("default", Settings().anchor_epoch),
        ("1752537600", 1752537600),
        ("2026-01-01T00:00:00Z", 1767225600),
    ],
)
def test_the_menu_anchor_takes_the_cli_forms(
    monkeypatch: pytest.MonkeyPatch, answer: str, expected: int
) -> None:
    _answers(monkeypatch, ["low", "", "plan", "1", answer], [False])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert request.anchor_epoch == expected


def test_a_bad_anchor_is_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    _answers(monkeypatch, ["low", "", "plan", "1", "yesterday", "now"], [False])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert request.anchor_epoch is not None


# -- 6. invalid menu input re-prompts instead of a traceback ----------------------


def test_a_nonsense_duration_is_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    console = Console(record=True, width=120)
    _answers(monkeypatch, ["low", "banana", "30s", "plan", "1", "now"], [False])

    request = menu_mod._params_flow(console, "REP-001", 1337, COLLECTOR)

    assert request.duration == "30s"
    assert "not a duration" in console.export_text()


@pytest.mark.parametrize("bad", ["inf", "nan", "-3", "0", "1e9", "fast"])
def test_a_nonsense_speed_is_asked_again(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    _answers(monkeypatch, ["low", "", "plan", bad, "60", "now"], [False])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert request.speed == 60.0


def test_a_model_refusal_reasks_rather_than_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    """The final word is the request model; its refusal must not end the menu."""

    calls = {"n": 0}
    real = menu_mod.RunRequest

    def flaky(**kwargs: object) -> RunRequest:
        calls["n"] += 1
        if calls["n"] == 1:
            return real(**{**kwargs, "seed": -1})  # type: ignore[arg-type]
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(menu_mod, "RunRequest", flaky)
    _answers(monkeypatch, ["low", "", "plan", "1", "now"] * 2, [False, False])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert calls["n"] == 2 and request.seed == 1337


# -- 7. the connect test uses the probe and its exit code means something --------


def test_connect_test_to_a_closed_udp_port_is_a_refusal_and_exits_nonzero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Measured: 'test log sent', exit 0."""

    code = main(["connect", "--host", "127.0.0.1", "--port", str(_closed_udp_port()), "--test"])

    out = capsys.readouterr()
    assert code != 0
    text = out.out + out.err
    assert "refused" in text
    assert "does not prove" in text
    assert "test log sent" not in text
    assert "verified" not in text.lower()


def test_connect_test_to_a_live_udp_listener_says_what_it_cannot_prove(
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    try:
        code = main(
            ["connect", "--host", "127.0.0.1", "--port", str(listener.getsockname()[1]), "--test"]
        )
    finally:
        listener.close()

    out = capsys.readouterr().out
    assert code == 0
    assert "sent_unconfirmed" in out
    assert "does not prove" in out
    assert "path: 127.0.0.1 -> 127.0.0.1" in out
    assert "verified" not in out.lower()


def test_the_menu_connect_flow_uses_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    console = Console(record=True, width=160)
    port = _closed_udp_port()
    monkeypatch.setattr(menu_mod, "load_profiles", lambda: {})
    _answers(monkeypatch, ["127.0.0.1", "udp"], [False, False])
    monkeypatch.setattr("replicant.cli.menu.IntPrompt.ask", staticmethod(lambda *a, **k: port))
    orch = Orchestrator(CATALOG, Settings(manifest_dir="unused"))

    kept = menu_mod._connect_flow(orch, console)

    text = console.export_text()
    assert kept is None  # refused, and the operator declined to keep it
    assert "refused" in text and "does not prove" in text
    assert "test log sent" not in text


# -- 8. the path line is printed before sending ------------------------------------


def test_a_cli_run_prints_the_source_to_destination_path_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    monkeypatch.chdir(tmp_path)
    try:
        code = main(
            ["run", "REP-002", "--intensity", "low", "--pace", "burst"]
            + ["--host", "127.0.0.1", "--port", str(port)]
        )
    finally:
        listener.close()

    assert code == 0
    err = capsys.readouterr().err
    assert f"path: 127.0.0.1 -> 127.0.0.1:{port} via lo (direct, on-link) over udp" in err


def test_the_gateway_warning_reaches_stderr_through_a_real_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """It used to arrive only via Python's lastResort, which any other handler
    anywhere in the process silently disables."""

    import logging

    from replicant.transport import syslog as syslog_mod

    monkeypatch.setattr(
        syslog_mod,
        "route_for",
        lambda *_a, **_k: syslog_mod.Route(interface="ens33", gateway="10.0.20.1"),
    )
    # Any handler at all on the root logger disables lastResort.
    monkeypatch.setattr(logging, "lastResort", None)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    monkeypatch.chdir(tmp_path)
    try:
        main(
            ["run", "REP-002", "--intensity", "low", "--pace", "burst"]
            + ["--host", "127.0.0.1", "--port", str(listener.getsockname()[1])]
        )
    finally:
        listener.close()

    err = capsys.readouterr().err
    assert "NOT on this host's segment" in err
    assert "gateway 10.0.20.1" in err


def test_a_file_only_run_prints_no_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    main(["run", "REP-002", "--intensity", "low", "--to-file", "x.log", "--no-send"])

    assert "path:" not in capsys.readouterr().err


# -- 11. SIGTERM finalizes the manifest ---------------------------------------------


def _sigterm_run(tmp_path: Path, argv: list[str], glob: str) -> tuple[int, dict[str, object]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    env = {**os.environ, "REPLICANT_CONFIG_DIR": str(tmp_path / "cfg")}
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "replicant.cli.app", *argv]
            + ["--host", "127.0.0.1", "--port", str(listener.getsockname()[1])],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listener.settimeout(60)
        listener.recvfrom(65535)  # the run is emitting
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=60)
    finally:
        listener.close()
    manifest = json.loads(next((tmp_path / "manifests").glob(glob)).read_text())
    return proc.returncode, manifest


def test_sigterm_during_a_run_leaves_a_stopped_manifest(tmp_path: Path) -> None:
    """Measured: status=running and ended_at null, identical to a crash."""

    code, manifest = _sigterm_run(
        tmp_path, ["run", "REP-001", "--intensity", "low", "--anchor", "now"], "REP-001-*.json"
    )

    assert manifest["status"] == "stopped"
    assert manifest["ended_at"] is not None
    assert manifest["partial"] is True
    assert code == 128 + signal.SIGTERM


def test_sigterm_during_a_scenario_leaves_a_stopped_manifest(tmp_path: Path) -> None:
    code, manifest = _sigterm_run(
        tmp_path, ["scenario", "run", "SCEN-001", "--anchor", "now"], "SCEN-001-*.json"
    )

    assert manifest["status"] == "stopped"
    assert manifest["ended_at"] is not None
    assert code == 128 + signal.SIGTERM


def test_the_previous_sigterm_handler_is_restored() -> None:
    from replicant.core.lifecycle import stop_on_sigterm

    class Target:
        stopped = False

        def stop(self) -> None:
            Target.stopped = True

    caught: list[int] = []

    def sentinel(signum: int, _frame: object) -> None:
        caught.append(signum)

    # A sentinel rather than the default action, so a regression fails this
    # test instead of killing the test process.
    original = signal.signal(signal.SIGTERM, sentinel)
    try:
        with stop_on_sigterm(Target()) as state:
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.05)
        assert state.received and Target.stopped
        assert caught == []
        assert signal.getsignal(signal.SIGTERM) is sentinel
    finally:
        signal.signal(signal.SIGTERM, original)


# -- 13. web-terminal confinement ------------------------------------------------------


@pytest.fixture()
def confined(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPLICANT_WEB_CONFINED", "1")


def test_confined_output_keeps_only_the_basename(tmp_path: Path, confined: None) -> None:
    from replicant.config.confine import confined_output_path

    manifests = tmp_path / "work" / "manifests"
    path = confined_output_path("/etc/../../home/x/evil.log", str(manifests))

    assert path == str((tmp_path / "work" / "out" / "evil.log").resolve())


@pytest.mark.parametrize("inside", [False, True], ids=["escaping", "inside-root"])
def test_confined_output_refuses_a_planted_symlink(
    tmp_path: Path, confined: None, inside: bool
) -> None:
    """Both shapes. A link out of the directory is also caught by containment;
    a link to another file inside it is caught only by the symlink check, and
    FileSink would still follow it and truncate whatever it names."""

    from replicant.config.confine import ConfinementError, confined_output_path

    out = tmp_path / "out"
    out.mkdir()
    target = (out / "manifest-like.json") if inside else (tmp_path / "victim")
    (out / "link.log").symlink_to(target)

    with pytest.raises(ConfinementError):
        confined_output_path("link.log", str(tmp_path / "manifests"))


def test_the_menu_confines_the_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, confined: None
) -> None:
    _answers(monkeypatch, ["low", "", "/tmp/elsewhere/x.log", "default"], [True])
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))

    request = menu_mod._params_flow(
        Console(quiet=True), "REP-001", 1337, COLLECTOR, settings=settings
    )

    assert request.to_file == str((tmp_path / "out" / "x.log").resolve())


def test_an_unconfined_menu_keeps_the_path_as_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REPLICANT_WEB_CONFINED", raising=False)
    _answers(monkeypatch, ["low", "", "/tmp/elsewhere/x.log", "default"], [True])

    request = menu_mod._params_flow(Console(quiet=True), "REP-001", 1337, COLLECTOR)

    assert request.to_file == "/tmp/elsewhere/x.log"


def test_a_confined_tls_cafile_must_live_in_the_config_ca_dir(
    isolate_config_dir: Path, monkeypatch: pytest.MonkeyPatch, confined: None
) -> None:
    ca_dir = isolate_config_dir / "ca"
    ca_dir.mkdir()
    (ca_dir / "lab.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    console = Console(record=True, width=160)
    # host, transport, cafile (refused /etc/passwd), cafile (accepted by basename)
    _answers(monkeypatch, ["10.0.0.5", "tls", "/etc/passwd", "/anything/lab.pem"], [True])
    monkeypatch.setattr("replicant.cli.menu.IntPrompt.ask", staticmethod(lambda *a, **k: 6514))
    monkeypatch.setattr(menu_mod, "load_profiles", lambda: {})

    profile = menu_mod._connection_wizard(console)

    assert profile is not None
    assert profile.tls_cafile == str((ca_dir / "lab.pem").resolve())
    assert "not found" in console.export_text()


def test_a_confined_menu_never_saves_a_profile(
    isolate_config_dir: Path, monkeypatch: pytest.MonkeyPatch, confined: None
) -> None:
    console = Console(record=True, width=200)
    # Only the transport prompt remains; no "Save as a named profile?" is asked,
    # so the confirm script is empty and asking it would fail this test.
    _answers(monkeypatch, ["10.0.0.5", "udp"], [])
    monkeypatch.setattr("replicant.cli.menu.IntPrompt.ask", staticmethod(lambda *a, **k: 514))
    monkeypatch.setattr(menu_mod, "load_profiles", lambda: {})

    profile = menu_mod._connection_wizard(console)

    assert profile is not None
    assert not (isolate_config_dir / "profiles.yaml").exists()
    assert "saving collector profiles is disabled" in console.export_text()


# -- 12. a header-unsafe hostname in config is refused at the CLI boundary --------


def test_a_bad_hostname_in_config_is_a_message_not_a_traceback(
    isolate_config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (isolate_config_dir / "config.yaml").write_text('hostname: "FGT\\nLAB"\n', encoding="utf-8")

    code = main(["list"])

    assert code == 1
    assert "settings refused" in capsys.readouterr().err
