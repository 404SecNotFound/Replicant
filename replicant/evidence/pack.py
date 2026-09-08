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
"""Write bounded, portable evidence directories from observed validation runs."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import yaml

from replicant.core.models import EventRecord, RunManifest, RunRequest, Technique
from replicant.evidence.mapping import build_mapping
from replicant.profiles.base import VendorProfile
from replicant.validation.contract import ValidationContract
from replicant.validation.verdict import ValidationResult

MAX_EVIDENCE_EVENTS = 10_000


def plan_bytes(events: list[EventRecord]) -> bytes:
    """Stable canonical bytes used to prove replay identity."""

    lines = [
        json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        for event in events
    ]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def _sample_indices(total: int, limit: int = MAX_EVIDENCE_EVENTS) -> list[int]:
    if total <= limit:
        return list(range(total))
    first_count = limit // 3
    middle_count = limit // 3
    last_count = limit - first_count - middle_count
    middle_start = max(first_count, total // 2 - middle_count // 2)
    last_start = total - last_count
    return [
        *range(first_count),
        *range(middle_start, middle_start + middle_count),
        *range(last_start, total),
    ]


def _report(
    manifest: RunManifest,
    contract: ValidationContract,
    result: ValidationResult,
    sampled: int,
) -> str:
    original = result.observed_events
    if manifest.send_stats is None:
        opening = (
            "No collector was configured for this validation run. The evidence below records "
            "a locally rendered plan only and does not claim delivery or a detection alert."
        )
    else:
        opening = (
            f"This validation observed {result.observed_events} run-tagged records on the "
            "configured local receiver path. That proves delivery and parseability on this path "
            "only; it does not prove that a SIEM rule fired."
        )
    truncation = (
        f"Telemetry is a bounded first/middle/last sample of {sampled} from {original} observed "
        f"records; {original - sampled} records are omitted."
        if sampled < original
        else f"Telemetry contains all {sampled} observed records."
    )
    return (
        "# Replicant validation evidence\n\n"
        f"{opening}\n\n"
        f"- Run: `{manifest.run_id}`\n"
        f"- Technique: `{contract.technique_id}` {contract.technique_name}\n"
        f"- Tier: `{result.tier}`\n"
        f"- Verdict: `{result.verdict.value}`\n"
        f"- Expected records: {result.expected_events}\n"
        f"- Observed records: {result.observed_events}\n\n"
        f"{truncation}\n\n"
        f"What this tier proves: {result.proves}\n\n"
        f"What this tier does not prove: {result.does_not_prove}\n"
    )


def write_evidence_pack(
    root: str | Path,
    *,
    manifest: RunManifest,
    contract: ValidationContract,
    result: ValidationResult,
    events: list[EventRecord],
    cef_lines: list[str],
    replay_events: list[EventRecord] | None = None,
    request: RunRequest,
    technique: Technique,
    profile: VendorProfile,
) -> ValidationResult:
    """Write the required evidence files and a downloadable ZIP archive."""

    evidence_root = Path(root)
    directory = evidence_root / manifest.run_id
    directory.mkdir(parents=True, exist_ok=False)
    archive = evidence_root / f"{manifest.run_id}.zip"
    indices = _sample_indices(min(len(events), len(cef_lines)))
    sampled_events = [events[index] for index in indices]
    sampled_cef = [cef_lines[index] for index in indices]
    result = result.model_copy(
        update={"evidence_path": str(directory), "evidence_archive": str(archive)}
    )

    (directory / "manifest.json").write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (directory / "contract.yaml").write_text(
        yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    (directory / "result.json").write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (directory / "telemetry.cef").write_text(
        "\n".join(sampled_cef) + ("\n" if sampled_cef else ""), encoding="utf-8"
    )
    telemetry_json: dict[str, Any] = {
        "original_count": len(events),
        "sample_count": len(sampled_events),
        "truncated": len(sampled_events) < len(events),
        "sample_strategy": "first-middle-last" if len(sampled_events) < len(events) else "all",
        "events": [event.model_dump(mode="json") for event in sampled_events],
    }
    (directory / "telemetry.json").write_text(
        json.dumps(telemetry_json, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / "mapping.md").write_text(build_mapping(technique, profile), encoding="utf-8")
    (directory / "REPORT.md").write_text(
        _report(manifest, contract, result, len(sampled_events)), encoding="utf-8"
    )
    reproducible_events = replay_events if replay_events is not None else events
    replay = {
        "schema_version": "1.0",
        "replicant_version": manifest.replicant_version,
        "technique_id": request.technique_id,
        "intensity": request.intensity,
        "seed": request.seed,
        "duration": request.duration,
        "controls": request.controls,
        "anchor_epoch": manifest.anchor_epoch,
        "param_overrides": request.param_overrides,
        "effective_params": manifest.params,
        "vendor": manifest.vendor,
        "event_count": len(reproducible_events),
        "plan_sha256": hashlib.sha256(plan_bytes(reproducible_events)).hexdigest(),
    }
    (directory / "replay.json").write_text(
        json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(directory.iterdir()):
            bundle.write(path, arcname=f"{manifest.run_id}/{path.name}")
    return result
