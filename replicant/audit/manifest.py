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

import json
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


def _write_unique(directory: Path, prefix: str, payload: str) -> Path:
    """Write ``payload`` to ``{prefix}-{stamp}-{token}.json`` under ``directory``.

    The timestamp has second precision, so two same-id, same-seed runs in one
    second would otherwise resolve to one path and the second would overwrite the
    first, destroying a run's audit record (safety rule 5). A random token makes
    the name unique, and exclusive creation (``open("x")``) guarantees two writers
    never resolve to the same file even under a race; on the astronomically
    unlikely collision it retries with a fresh token.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stamp = _stamp_for_filename()
    for _ in range(8):
        token = uuid.uuid4().hex[:8]
        path = directory / f"{prefix}-{stamp}-{token}.json"
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(payload)
            return path
        except FileExistsError:
            continue
    raise RuntimeError(f"could not allocate a unique manifest path in {directory}")


def write_manifest(manifest: RunManifest, out_dir: str | Path) -> Path:
    payload = json.dumps(manifest.model_dump(), indent=2, sort_keys=False) + "\n"
    # The run id makes the file findable from the id an operator has in hand (the
    # web 409, the CLI summary, a marked CEF line). It stays after the technique
    # and seed so a directory listing is still grouped and chronological, and it
    # already contains a timestamp and a hex suffix, so it is unique on its own;
    # _write_unique's token guards only the astronomically unlikely collision, or
    # an older manifest with no run id at all.
    suffix = manifest.run_id or "RUN-none"
    prefix = f"{manifest.technique_id}-seed{manifest.seed}-{suffix}"
    return _write_unique(Path(out_dir), prefix, payload)


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
    payload = json.dumps(manifest.model_dump(), indent=2, sort_keys=False) + "\n"
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
