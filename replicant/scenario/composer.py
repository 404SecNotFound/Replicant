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
"""Deterministic, I/O-free composition of a scenario into one merged event timeline.

Reuses ``ScenarioEngine.plan`` per stage against a scenario-scoped ``EntityModel``
whose through-line pools are pinned to one synthetic victim/adversary, so the same
actor threads across stages (the cross-stage correlation key). No engine change.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

import numpy as np

from replicant.config.settings import parse_duration
from replicant.core.models import EventRecord, Scenario, Technique
from replicant.entities.model import EntityModel
from replicant.scenario.engine import ScenarioEngine

_DAY_SECONDS = 86_400
# A stage that anchors to an internal window (off-hours) needs at most one day-shift to clear
# its intended start. The bound keeps the re-plan loop finite for any future timing builder.
_MAX_ALIGN_DAYS = 2


@dataclass
class StageResult:
    index: int
    technique_id: str
    label: str | None
    ndr_uc: str
    intensity: str
    start_offset: str
    event_count: int
    tactics: list[str]
    techniques: list[str]
    # What the stage actually produced, as opposed to what was asked for. Downstream
    # consumers (advisory, manifest) report these rather than assuming the stage
    # honoured its anchor.
    start_epoch: int | None = None
    end_epoch: int | None = None
    truncated: bool = False
    has_warmup: bool = False
    aligned_days: int = 0
    top_src: str | None = None
    top_src_count: int = 0
    top_dst: str | None = None
    top_dst_count: int = 0
    top_user: str | None = None
    top_user_count: int = 0


def _dominant(values: list[str]) -> tuple[str | None, int]:
    """Most common value and its count, or (None, 0). Ties break on value for determinism."""

    if not values:
        return None, 0
    counts = Counter(values)
    top = max(sorted(counts), key=lambda value: counts[value])
    return top, counts[top]


@dataclass
class ComposedPlan:
    scenario_id: str
    seed: int
    anchor_epoch: int
    events: list[EventRecord]
    stages: list[StageResult]
    entities: dict[str, Any]
    victim: str
    adversary: str
    total_count: int = 0
    warmup_notes: list[str] = field(default_factory=list)


def _pin_entities(base: EntityModel, seed: int) -> tuple[EntityModel, str, str]:
    """Pick one victim + one adversary from the already-synthetic pools, deterministically,
    and narrow the through-line pools to them. Values come from validated pools, so the
    narrowed model stays synthetic."""
    rng = np.random.default_rng(seed)
    victim = str(rng.choice(base.internal_hosts))
    adversary = str(rng.choice(base.adversary_external))
    pinned = replace(base, internal_hosts=[victim], adversary_external=[adversary])
    return pinned, victim, adversary


def compose(
    scenario: Scenario,
    technique_by_id: Callable[[str], Technique],
    engine: ScenarioEngine,
    seed: int,
    anchor_epoch: int,
    base_entities: EntityModel,
    intensity_override: str | None = None,
) -> ComposedPlan:
    pinned, victim, adversary = _pin_entities(base_entities, seed)
    children = np.random.SeedSequence(seed).spawn(len(scenario.stages))
    tagged: list[tuple[int, int, EventRecord]] = []  # (eventtime, stage_index, event)
    stages: list[StageResult] = []
    warmups: list[str] = []
    for i, stage in enumerate(scenario.stages):
        technique = technique_by_id(stage.technique_id)
        stage_seed = int(children[i].generate_state(1)[0])
        stage_anchor = anchor_epoch + parse_duration(stage.start_offset)
        intensity = intensity_override or stage.intensity
        plan = engine.plan(
            technique,
            intensity,
            pinned,
            stage_seed,
            anchor_epoch=stage_anchor,
            param_overrides=stage.param_overrides or None,
        )
        # A technique that anchors to an internal window (REP-005 pins to 00:00-06:00 of the
        # anchor's day) would otherwise emit before the stage it is supposed to follow. Shift
        # the anchor forward whole days and re-plan with the same seed: only the window moves,
        # every other draw is identical, so the composition stays deterministic.
        aligned_days = 0
        if stage.align == "next-off-hours":
            while (
                aligned_days < _MAX_ALIGN_DAYS
                and plan.events
                and min(event.eventtime for event in plan.events) < stage_anchor
            ):
                aligned_days += 1
                plan = engine.plan(
                    technique,
                    intensity,
                    pinned,
                    stage_seed,
                    anchor_epoch=stage_anchor + aligned_days * _DAY_SECONDS,
                    param_overrides=stage.param_overrides or None,
                )
        for event in plan.events:
            tagged.append((event.eventtime, i, event))
        if plan.warmup_note:
            warmups.append(f"stage {i} ({stage.technique_id}): {plan.warmup_note}")
        times = [event.eventtime for event in plan.events]
        top_src, top_src_count = _dominant([e.src for e in plan.events if e.src])
        top_dst, top_dst_count = _dominant([e.dst for e in plan.events if e.dst])
        top_user, top_user_count = _dominant([e.duser for e in plan.events if e.duser])
        stages.append(
            StageResult(
                index=i,
                technique_id=stage.technique_id,
                label=stage.label,
                ndr_uc=technique.ndr_uc,
                intensity=intensity,
                start_offset=stage.start_offset,
                event_count=len(plan.events),
                tactics=list(technique.attack.tactics),
                techniques=list(technique.attack.techniques),
                start_epoch=min(times) if times else None,
                end_epoch=max(times) if times else None,
                truncated=plan.truncated,
                has_warmup=plan.warmup_note is not None,
                aligned_days=aligned_days,
                top_src=top_src,
                top_src_count=top_src_count,
                top_dst=top_dst,
                top_dst_count=top_dst_count,
                top_user=top_user,
                top_user_count=top_user_count,
            )
        )
    tagged.sort(key=lambda item: (item[0], item[1]))
    events = [item[2] for item in tagged]
    return ComposedPlan(
        scenario_id=scenario.id,
        seed=seed,
        anchor_epoch=anchor_epoch,
        events=events,
        stages=stages,
        entities=pinned.summary(),
        victim=victim,
        adversary=adversary,
        total_count=len(events),
        warmup_notes=warmups,
    )
