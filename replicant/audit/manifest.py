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
"""Run manifest and human summary (safety rule 5, blueprint s4).

Every run writes a manifest recording seed, technique, params, entities, target,
event count, and start/end time in UTC+04:00 so an analyst can line telemetry up
with detections.
"""

from __future__ import annotations

import errno
import json
import os
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from replicant.core.models import RunManifest, ScenarioManifest

DUBAI_TZ = timezone(timedelta(hours=4))  # UTC+04:00 (Dubai)


def new_run_id(now: datetime | None = None) -> str:
    """A stable per-run identifier: ``RUN-<UTC stamp>Z-<6 hex>``.

    UTC rather than the catalog timezone, because a run id is an absolute handle
    an operator greps across manifests and (with --mark-run) inside a SIEM, and a
    local-time stamp reads differently depending on who is looking. Sortable by
    construction; the hex suffix separates two runs started in the same second.
    """

    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S")
    return f"RUN-{stamp}Z-{uuid.uuid4().hex[:6]}"


def now_dubai_iso() -> str:
    return datetime.now(DUBAI_TZ).isoformat(timespec="seconds")


def _stamp_for_filename() -> str:
    return datetime.now(DUBAI_TZ).strftime("%Y%m%dT%H%M%S")


def _json_payload(manifest: RunManifest | ScenarioManifest) -> str:
    return json.dumps(manifest.model_dump(), indent=2, sort_keys=False) + "\n"


_UNSUPPORTED_DIRECTORY_FSYNC = {
    errno.EINVAL,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


def _fsync_directory(directory: Path) -> None:
    """Persist directory-entry changes or fail before claiming durability.

    File ``fsync`` makes the JSON durable, but an atomic rename can still be lost
    across a power failure unless its parent directory is flushed too. A platform
    or filesystem that rejects directory ``fsync`` cannot provide the audit
    contract, so surface that capability failure rather than silently sending
    after an unauditable preflight.
    """

    unsupported_errno = getattr(
        errno,
        "ENOTSUP",
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    )

    def unsupported() -> OSError:
        return OSError(
            unsupported_errno,
            "manifest durability requires directory fsync, which this "
            "platform or filesystem does not support",
            str(directory),
        )

    # Python exposes no directory-handle flush primitive on Windows. File fsync
    # and atomic replace are insufficient because their directory entries can
    # still disappear across a power loss, so the durable preflight must refuse.
    if os.name == "nt":  # pragma: no cover - platform-specific branch
        raise unsupported()

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        if exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC:
            raise unsupported() from exc
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC:
                raise unsupported() from exc
            raise
    finally:
        os.close(descriptor)


def _ensure_durable_directory(
    directory: Path,
    *,
    assure_existing_entry: bool = False,
) -> None:
    """Create a directory chain and persist every newly visible component.

    Flushing a manifest directory persists entries *inside* it, but cannot make
    the directory's own entry durable in its parent. Build missing components
    from the top down and flush each parent before any manifest is published.
    The parent flush is also performed when another process wins the mkdir race,
    because this writer cannot assume the competing creator made that entry
    durable on its behalf.
    """

    if directory.is_dir():
        # The initial manifest publication cannot tell a long-established
        # directory chain from one a competing process created a moment ago.
        # Assure every ancestor entry once at preflight when requested;
        # checkpoint replacements leave this off, avoiding those fsyncs on every
        # interval.
        if assure_existing_entry and directory.parent != directory:
            _ensure_durable_directory(
                directory.parent,
                assure_existing_entry=True,
            )
            _fsync_directory(directory.parent)
        return
    parent = directory.parent
    if parent == directory:
        # A missing filesystem root cannot be created by this process. Let mkdir
        # raise the platform's useful error rather than recursing forever.
        directory.mkdir()
        return
    _ensure_durable_directory(
        parent,
        assure_existing_entry=assure_existing_entry,
    )
    try:
        directory.mkdir()
    except FileExistsError:
        if not directory.is_dir():
            raise
    _fsync_directory(parent)


def _durable_temp(path: Path, payload: str) -> Path:
    """Write and fsync a same-directory temporary file for atomic publication."""

    _ensure_durable_directory(path.parent)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return temporary


def _atomic_replace(path: Path, payload: str) -> None:
    """Durably publish complete JSON at ``path`` with a same-directory replace."""

    temporary = _durable_temp(path, payload)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        # A failed write/replace must not accumulate temp files. After a successful
        # os.replace the source no longer exists, so this is a no-op.
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _atomic_create(path: Path, payload: str) -> None:
    """Publish complete JSON without ever overwriting an existing manifest.

    Linking the already-fsynced temp file gives exclusive-create semantics: the
    final name appears atomically and ``FileExistsError`` wins a collision race,
    while readers can never observe a placeholder or partial JSON document.
    """

    temporary = _durable_temp(path, payload)
    linked = False
    try:
        os.link(temporary, path)
        linked = True
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        if linked:
            _fsync_directory(path.parent)


def _write_unique(directory: Path, prefix: str, payload: str) -> Path:
    """Atomically write ``payload`` to a unique manifest path.

    The timestamp has second precision, so two same-id, same-seed runs in one
    second would otherwise resolve to one path and the second would overwrite the
    first, destroying a run's audit record (safety rule 5). A random token makes
    the name unique. The complete, fsynced payload is atomically published from a
    same-directory temp file, so a crash cannot expose a half-written JSON record.
    """
    _ensure_durable_directory(directory, assure_existing_entry=True)
    stamp = _stamp_for_filename()
    for _ in range(8):
        token = uuid.uuid4().hex[:8]
        path = directory / f"{prefix}-{stamp}-{token}.json"
        try:
            _atomic_create(path, payload)
        except FileExistsError:
            continue
        return path
    raise RuntimeError(f"could not allocate a unique manifest path in {directory}")


def write_manifest(manifest: RunManifest, out_dir: str | Path) -> Path:
    payload = _json_payload(manifest)
    # The run id makes the file findable from the id an operator has in hand (the
    # web 409, the CLI summary, a marked CEF line). It stays after the technique
    # and seed so a directory listing is still grouped and chronological, and it
    # already contains a timestamp and a hex suffix, so it is unique on its own;
    # _write_unique's token guards only the astronomically unlikely collision, or
    # an older manifest with no run id at all.
    suffix = manifest.run_id or "RUN-none"
    prefix = f"{manifest.technique_id}-seed{manifest.seed}-{suffix}"
    return _write_unique(Path(out_dir), prefix, payload)


def update_manifest(manifest: RunManifest | ScenarioManifest, path: str | Path) -> Path:
    """Atomically and durably replace an established write-ahead manifest."""

    resolved = Path(path)
    _atomic_replace(resolved, _json_payload(manifest))
    return resolved


def human_summary(manifest: RunManifest, manifest_path: Path) -> str:
    lines = [
        "Replicant run complete.",
        f"  run id      : {manifest.run_id}",
        f"  technique   : {manifest.technique_id}  {manifest.technique_name}",
        f"  ndr_uc      : {manifest.ndr_uc}",
        f"  intensity   : {manifest.intensity}",
        f"  seed        : {manifest.seed}",
        f"  target      : {manifest.target} ({manifest.transport})",
        f"  events      : {manifest.event_count}",
        f"  started     : {manifest.started_at}",
        f"  ended       : {manifest.ended_at}",
        f"  manifest    : {manifest_path}",
    ]
    if manifest.warmup_note:
        lines.append(f"  warm-up     : {manifest.warmup_note}")
    return "\n".join(lines)


def write_scenario_manifest(manifest: ScenarioManifest, out_dir: str | Path) -> Path:
    payload = _json_payload(manifest)
    prefix = f"{manifest.scenario_id}-seed{manifest.seed}"
    return _write_unique(Path(out_dir), prefix, payload)


def write_advisory(text: str, manifest_path: Path) -> Path:
    """Write the advisory next to its manifest with the paired name."""
    path = manifest_path.parent / f"{manifest_path.stem}.advisory.md"
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path


def write_validation_card(text: str, manifest_path: Path) -> Path:
    """Write the single-technique validation card next to its manifest."""
    path = manifest_path.parent / f"{manifest_path.stem}.card.md"
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path
