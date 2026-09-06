# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Crash-safe, write-ahead run manifest guarantees."""

from __future__ import annotations

import errno
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from threading import Barrier

import pytest

from replicant.audit import manifest as manifest_mod
from replicant.config.settings import Settings
from replicant.core import orchestrator as orchestrator_mod
from replicant.core.models import (
    CollectorProfile,
    RunManifest,
    RunRequest,
    ScenarioRunRequest,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator, _ManifestCheckpoint, run_record_of
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.transport.syslog import SendStats

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)


def _json_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.json"))


def test_manifest_exists_before_first_emit_and_is_finalized_in_place(
    tmp_path: Path, monkeypatch
) -> None:
    """The audit record must predate output, not merely survive handled errors."""

    manifest_dir = tmp_path / "manifests"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(manifest_dir)))
    original_emit = orch._emit
    seen: dict[str, object] = {}

    def inspect_then_emit(*args, **kwargs):
        paths = _json_files(manifest_dir)
        assert len(paths) == 1
        seen.update(json.loads(paths[0].read_text(encoding="utf-8")))
        return original_emit(*args, **kwargs)

    monkeypatch.setattr(orch, "_emit", inspect_then_emit)
    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            duration="2m",
            pace="burst",
            no_send=True,
        )
    )

    assert seen["status"] == "running"
    assert seen["event_count"] == 0
    assert seen["planned_event_count"] == result.event_count
    assert seen["ended_at"] is None
    assert seen["partial"] is True
    assert result.manifest.status == "done"
    assert result.manifest.event_count == result.manifest.planned_event_count
    assert result.manifest.partial is False
    assert result.manifest.ended_at is not None
    assert _json_files(manifest_dir) == [result.manifest_path]


def test_partial_failure_finalizes_exact_progress_in_same_manifest(
    tmp_path: Path, monkeypatch
) -> None:
    manifest_dir = tmp_path / "manifests"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(manifest_dir)))

    def fail_after_two(events, **kwargs):
        checkpoint = kwargs["on_checkpoint"]
        checkpoint(1, len(events))
        checkpoint(2, len(events))
        raise OSError("collector disappeared")

    monkeypatch.setattr(orch, "_emit", fail_after_two)
    with pytest.raises(OSError, match="collector disappeared"):
        orch.run(
            RunRequest(
                technique_id="REP-002",
                intensity="low",
                pace="burst",
                no_send=True,
            )
        )

    paths = _json_files(manifest_dir)
    assert len(paths) == 1
    written = json.loads(paths[0].read_text(encoding="utf-8"))
    assert written["status"] == "error"
    assert written["event_count"] == 2
    assert written["planned_event_count"] > 2
    assert written["partial"] is True
    assert written["ended_at"] is not None


def test_rendered_count_survives_first_socket_failure_and_matches_file_mirror(
    tmp_path: Path, monkeypatch
) -> None:
    """Destination failure must not erase a line already rendered and mirrored."""

    class FailingEmitter:
        def __init__(self, *_args, **_kwargs) -> None:
            self.stats = SendStats()

        def connect(self) -> None:
            pass

        def send(self, _line: str, *, level: str) -> int:
            self.stats.errors += 1
            raise OSError("collector rejected first line")

        def close(self) -> None:
            pass

    output = tmp_path / "events.log"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    monkeypatch.setattr(orchestrator_mod, "SyslogEmitter", FailingEmitter)
    monkeypatch.setattr(orchestrator_mod, "sending_lock", lambda: nullcontext())

    with pytest.raises(OSError, match="collector rejected first line") as caught:
        orch.run(
            RunRequest(
                technique_id="REP-001",
                intensity="low",
                to_file=str(output),
                collector=CollectorProfile(host="127.0.0.1", port=5514),
                pace="burst",
            )
        )

    record = run_record_of(caught.value)
    assert record is not None
    assert record["event_count"] == record["manifest"]["event_count"] == 1
    assert record["manifest"]["send_stats"] == {
        "sends": 0,
        "bytes": 0,
        "errors": 1,
        "oversize": 0,
    }
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


def test_run_preflight_manifest_failure_prevents_output(tmp_path: Path, monkeypatch) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    emitted = False

    def fail_write(*_args, **_kwargs):
        raise OSError("manifest disk unavailable")

    def emit(*_args, **_kwargs):
        nonlocal emitted
        emitted = True
        return 0, False

    monkeypatch.setattr("replicant.core.orchestrator.write_manifest", fail_write)
    monkeypatch.setattr(orch, "_emit", emit)
    with pytest.raises(OSError, match="manifest disk unavailable"):
        orch.run(RunRequest(technique_id="REP-001", pace="burst", no_send=True))
    assert emitted is False


def test_finalization_failure_surfaces_with_the_preflight_record(
    tmp_path: Path, monkeypatch
) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    monkeypatch.setattr(orch, "_emit", lambda *_args, **_kwargs: (2, False))

    def fail_update(*_args, **_kwargs):
        raise OSError("final manifest fsync failed")

    monkeypatch.setattr(orchestrator_mod, "update_manifest", fail_update)
    with pytest.raises(OSError, match="final manifest fsync failed") as caught:
        orch.run(RunRequest(technique_id="REP-002", pace="burst", no_send=True))

    record = run_record_of(caught.value)
    assert record is not None
    assert Path(record["manifest_path"]).is_file()
    assert record["manifest"]["status"] == "running"
    assert record["manifest"]["event_count"] == record["durable_event_count"] == 0
    assert record["event_count"] == 2


def test_finalization_failure_does_not_mask_the_original_emit_error(
    tmp_path: Path, monkeypatch
) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    def fail_emit(*_args, **_kwargs):
        raise ConnectionError("collector failed")

    def fail_update(*_args, **_kwargs):
        raise OSError("final manifest fsync failed")

    monkeypatch.setattr(orch, "_emit", fail_emit)
    monkeypatch.setattr(orchestrator_mod, "update_manifest", fail_update)
    with pytest.raises(ConnectionError, match="collector failed") as caught:
        orch.run(RunRequest(technique_id="REP-002", pace="burst", no_send=True))

    assert any("final manifest fsync failed" in note for note in caught.value.__notes__)
    record = run_record_of(caught.value)
    assert record is not None
    assert record["manifest"]["status"] == "running"
    assert Path(record["manifest_path"]).is_file()


def test_scenario_manifest_is_write_ahead_and_preflight_is_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    manifest_dir = tmp_path / "manifests"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(manifest_dir)))
    original_emit = orch._emit
    seen: dict[str, object] = {}

    def inspect_then_emit(*args, **kwargs):
        paths = _json_files(manifest_dir)
        assert len(paths) == 1
        seen.update(json.loads(paths[0].read_text(encoding="utf-8")))
        return original_emit(*args, **kwargs)

    monkeypatch.setattr(orch, "_emit", inspect_then_emit)
    result = orch.run_scenario(
        ScenarioRunRequest(
            scenario_id="SCEN-003",
            duration="10m",
            pace="burst",
            no_send=True,
        ),
        SCENARIOS,
    )
    assert seen["status"] == "running"
    assert seen["total_event_count"] == 0
    assert seen["planned_event_count"] == result.event_count
    assert result.manifest.status == "done"
    assert result.manifest.total_event_count == result.manifest.planned_event_count
    assert _json_files(manifest_dir) == [result.manifest_path]

    blocked = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "blocked")))
    emitted = False

    def fail_write(*_args, **_kwargs):
        raise OSError("manifest disk unavailable")

    def emit(*_args, **_kwargs):
        nonlocal emitted
        emitted = True
        return 0, False

    monkeypatch.setattr("replicant.core.orchestrator.write_scenario_manifest", fail_write)
    monkeypatch.setattr(blocked, "_emit", emit)
    with pytest.raises(OSError, match="manifest disk unavailable"):
        blocked.run_scenario(
            ScenarioRunRequest(scenario_id="SCEN-003", duration="10m", no_send=True),
            SCENARIOS,
        )
    assert emitted is False


def test_partial_scenario_failure_records_exact_progress(tmp_path: Path, monkeypatch) -> None:
    manifest_dir = tmp_path / "manifests"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(manifest_dir)))

    def fail_after_two(events, **kwargs):
        checkpoint = kwargs["on_checkpoint"]
        checkpoint(1, len(events))
        checkpoint(2, len(events))
        raise OSError("scenario collector disappeared")

    monkeypatch.setattr(orch, "_emit", fail_after_two)
    with pytest.raises(OSError, match="scenario collector disappeared"):
        orch.run_scenario(
            ScenarioRunRequest(
                scenario_id="SCEN-003",
                duration="10m",
                pace="burst",
                no_send=True,
            ),
            SCENARIOS,
        )

    written = json.loads(_json_files(manifest_dir)[0].read_text(encoding="utf-8"))
    assert written["status"] == "error"
    assert written["total_event_count"] == 2
    assert written["planned_event_count"] > 2
    assert written["partial"] is True


def test_dirty_progress_is_durable_before_a_long_plan_wait(tmp_path: Path, monkeypatch) -> None:
    """A sparse plan must not leave its last event dirty for the whole gap."""

    manifest_dir = tmp_path / "manifests"
    observed_during_wait: list[int] = []

    class Emitter:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def connect(self) -> None:
            pass

        def send(self, line: str, *, level: str) -> int:
            return len(line)

        def close(self) -> None:
            pass

    class InspectingStop:
        def clear(self) -> None:
            pass

        def is_set(self) -> bool:
            return False

        def wait(self, timeout: float) -> bool:
            assert timeout > 1.0
            [path] = _json_files(manifest_dir)
            observed_during_wait.append(
                int(json.loads(path.read_text(encoding="utf-8"))["event_count"])
            )
            return True

    monkeypatch.setattr(orchestrator_mod, "SyslogEmitter", Emitter)
    monkeypatch.setattr(orchestrator_mod, "sending_lock", lambda: nullcontext())
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(manifest_dir)))
    orch._stop = InspectingStop()  # type: ignore[assignment]

    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            collector=CollectorProfile(host="127.0.0.1", port=5514),
            pace="plan",
        )
    )

    assert result.stopped is True
    assert observed_during_wait == [1]


def test_durable_temp_is_removed_when_file_fsync_fails(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "manifest.json"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError(errno.EIO, "simulated disk failure")

    monkeypatch.setattr(manifest_mod.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated disk failure"):
        manifest_mod._atomic_replace(target, "{}\n")
    assert target.exists() is False
    assert not any(path.suffix == ".tmp" for path in tmp_path.iterdir())


def test_atomic_create_never_overwrites_a_collision(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    target.write_text("original\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        manifest_mod._atomic_create(target, "replacement\n")
    assert target.read_text(encoding="utf-8") == "original\n"
    assert not any(path.suffix == ".tmp" for path in tmp_path.iterdir())


def test_concurrent_atomic_creators_cannot_overwrite_each_other(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    gate = Barrier(2)

    def publish(payload: str) -> str:
        gate.wait()
        try:
            manifest_mod._atomic_create(target, payload)
        except FileExistsError:
            return "collision"
        return "published"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(publish, ["first\n", "second\n"]))

    assert sorted(outcomes) == ["collision", "published"]
    assert target.read_text(encoding="utf-8") in {"first\n", "second\n"}
    assert not any(path.suffix == ".tmp" for path in tmp_path.iterdir())


def test_fresh_directory_chain_is_durable_before_manifest_publication(
    tmp_path: Path, monkeypatch
) -> None:
    """Each newly created directory entry is flushed before the final link."""

    target = tmp_path / "new" / "nested" / "manifest.json"
    flushed: list[Path] = []
    real_fsync_directory = manifest_mod._fsync_directory

    def record_fsync(directory: Path) -> None:
        flushed.append(directory)
        real_fsync_directory(directory)

    monkeypatch.setattr(manifest_mod, "_fsync_directory", record_fsync)
    manifest_mod._atomic_create(target, "{}\n")

    assert flushed == [tmp_path, tmp_path / "new", target.parent]
    assert target.read_text(encoding="utf-8") == "{}\n"


def test_existing_manifest_directory_entry_is_assured_at_run_preflight(
    tmp_path: Path, monkeypatch
) -> None:
    """A just-created directory is made durable before the first publication."""

    directory = tmp_path / "manifests"
    directory.mkdir()
    flushed: list[Path] = []
    real_fsync_directory = manifest_mod._fsync_directory

    def record_fsync(path: Path) -> None:
        flushed.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(manifest_mod, "_fsync_directory", record_fsync)
    path = manifest_mod._write_unique(directory, "run", "{}\n")

    assert flushed == [*reversed(directory.parents), directory]
    assert path.read_text(encoding="utf-8") == "{}\n"


def test_retry_reassures_a_component_left_by_a_failed_parent_fsync(
    tmp_path: Path, monkeypatch
) -> None:
    """A failed mkdir flush cannot be skipped merely because retry sees the dir."""

    directory = tmp_path / "new" / "nested"
    flushed: list[Path] = []
    failed = False
    real_fsync_directory = manifest_mod._fsync_directory

    def fail_once(path: Path) -> None:
        nonlocal failed
        flushed.append(path)
        if path == tmp_path and not failed:
            failed = True
            raise OSError(errno.EIO, "simulated parent fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(manifest_mod, "_fsync_directory", fail_once)
    with pytest.raises(OSError, match="simulated parent fsync failure"):
        manifest_mod._write_unique(directory, "run", "{}\n")
    assert (tmp_path / "new").is_dir()
    assert directory.exists() is False

    flushed.clear()
    path = manifest_mod._write_unique(directory, "run", "{}\n")

    under_test_root = [
        candidate
        for candidate in flushed
        if candidate == tmp_path or candidate.is_relative_to(tmp_path)
    ]
    assert under_test_root == [tmp_path, tmp_path / "new", directory]
    assert path.read_text(encoding="utf-8") == "{}\n"


def test_unsupported_directory_fsync_fails_preflight_without_publication(
    tmp_path: Path, monkeypatch
) -> None:
    real_fsync = os.fsync

    def reject_directories(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "directory fsync unsupported")
        real_fsync(descriptor)

    monkeypatch.setattr(manifest_mod.os, "fsync", reject_directories)
    manifest_dir = tmp_path / "manifests"

    with pytest.raises(
        OSError,
        match="manifest durability requires directory fsync",
    ):
        manifest_mod._write_unique(manifest_dir, "run", "{}\n")

    assert not list(manifest_dir.glob("*.json"))
    assert not list(manifest_dir.glob("*.tmp"))


def test_platform_without_directory_fsync_fails_preflight(tmp_path: Path, monkeypatch) -> None:
    class PlatformWithoutDirectoryFsync:
        name = "nt"

    monkeypatch.setattr(manifest_mod, "os", PlatformWithoutDirectoryFsync())
    manifest_dir = tmp_path / "manifests"

    with pytest.raises(
        OSError,
        match="manifest durability requires directory fsync",
    ) as caught:
        manifest_mod._write_unique(manifest_dir, "run", "{}\n")

    assert caught.value.errno == getattr(
        errno,
        "ENOTSUP",
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    )
    assert not list(manifest_dir.glob("*.json"))
    assert not list(manifest_dir.glob("*.tmp"))


def test_progress_checkpoints_are_coalesced_to_about_once_per_second(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = RunManifest(
        replicant_version="test",
        technique_id="REP-001",
        technique_name="test",
        ndr_uc="UC-001",
        intensity="low",
        seed=1,
        params={},
        entities={},
        target="dry-run",
        transport="none",
        event_count=0,
        planned_event_count=10,
        started_at="2026-09-06T00:00:00+04:00",
        anchor_epoch=1,
        status="running",
    )
    writes: list[int] = []
    moments = iter([10.2, 10.9, 11.0, 11.1, 11.5])

    def capture(current, _path):
        writes.append(current.event_count)

    monkeypatch.setattr(orchestrator_mod, "update_manifest", capture)
    monkeypatch.setattr(orchestrator_mod.time, "monotonic", lambda: next(moments))
    checkpoint = _ManifestCheckpoint(manifest, tmp_path / "manifest.json", "event_count", 10)
    checkpoint.last_write = 10.0

    checkpoint.observe(1, 10)
    checkpoint.observe(2, 10)
    checkpoint.observe(3, 10)
    checkpoint.observe(4, 10)

    assert writes == [3]
    assert checkpoint.count == 4
