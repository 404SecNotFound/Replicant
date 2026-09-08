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
"""Hard negative controls for the four representable catalog gaps."""

from __future__ import annotations

from collections import Counter, defaultdict

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ORCHESTRATOR = Orchestrator(CATALOG, Settings())
SEEDS = (1, 7, 1337, 99_999, 424_242)


def _streams(technique_id: str, intensity: str, seed: int):
    plan = ORCHESTRATOR.build_plan(
        RunRequest(
            technique_id=technique_id,
            intensity=intensity,
            seed=seed,
            no_send=True,
        )
    )
    assert not plan.truncated
    positive = [event for event in plan.events if event.control == "positive"]
    negative = [event for event in plan.events if event.control == "negative"]
    assert positive and negative
    return positive, negative


@pytest.mark.parametrize("intensity", ("low", "medium", "high"))
@pytest.mark.parametrize("seed", SEEDS)
def test_rep002_matches_global_shape_but_reduces_per_pair_ports(intensity: str, seed: int) -> None:
    positive, negative = _streams("REP-002", intensity, seed)
    assert len(positive) == len(negative)
    assert {event.dpt for event in positive} == {event.dpt for event in negative}
    assert Counter(event.action for event in positive) == Counter(
        event.action for event in negative
    )
    assert (min(e.eventtime for e in positive), max(e.eventtime for e in positive)) == (
        min(e.eventtime for e in negative),
        max(e.eventtime for e in negative),
    )

    def per_pair(events):
        groups = defaultdict(set)
        for event in events:
            groups[(event.src, event.dst)].add(event.dpt)
        return max(map(len, groups.values()))

    assert per_pair(negative) < per_pair(positive)


@pytest.mark.parametrize("intensity", ("low", "medium", "high"))
@pytest.mark.parametrize("seed", SEEDS)
def test_rep003_matches_global_shape_but_reduces_per_source_hosts(
    intensity: str, seed: int
) -> None:
    positive, negative = _streams("REP-003", intensity, seed)
    assert len(positive) == len(negative)
    assert {event.dst for event in positive} == {event.dst for event in negative}
    assert {event.dpt for event in positive} == {event.dpt for event in negative}
    assert Counter(event.action for event in positive) == Counter(
        event.action for event in negative
    )

    def per_source(events):
        groups = defaultdict(set)
        for event in events:
            groups[(event.src, event.dpt)].add(event.dst)
        return max(map(len, groups.values()))

    assert per_source(negative) < per_source(positive)


@pytest.mark.parametrize("intensity", ("low", "medium", "high"))
@pytest.mark.parametrize("seed", SEEDS)
def test_rep010_matches_denies_but_removes_the_per_source_burst(intensity: str, seed: int) -> None:
    positive, negative = _streams("REP-010", intensity, seed)
    assert len(positive) == len(negative)
    assert Counter(event.dpt for event in positive) == Counter(event.dpt for event in negative)
    assert Counter(event.dst for event in positive) == Counter(event.dst for event in negative)
    assert {event.action for event in positive} == {event.action for event in negative} == {"deny"}
    pos_per_source = Counter(event.src for event in positive)
    neg_per_source = Counter(event.src for event in negative)
    assert max(neg_per_source.values()) < max(pos_per_source.values())
    midpoint = (
        min(e.eventtime for e in positive)
        + (max(e.eventtime for e in positive) - min(e.eventtime for e in positive)) // 2
    )
    assert sum(e.eventtime <= midpoint for e in positive) > sum(
        e.eventtime <= midpoint for e in negative
    )


@pytest.mark.parametrize("intensity", ("low", "medium", "high"))
@pytest.mark.parametrize("seed", SEEDS)
def test_rep005_current_window_matches_and_history_separates(intensity: str, seed: int) -> None:
    positive, negative = _streams("REP-005", intensity, seed)
    current_cutoff = min(
        event.eventtime for event in positive if (event.out_bytes or 0) > 1_000_000
    )
    positive_current = [event for event in positive if event.eventtime >= current_cutoff]
    negative_current = [event for event in negative if event.eventtime >= current_cutoff]
    assert len(positive_current) == len(negative_current)
    assert Counter(event.out_bytes for event in positive_current) == Counter(
        event.out_bytes for event in negative_current
    )
    assert Counter(event.in_bytes for event in positive_current) == Counter(
        event.in_bytes for event in negative_current
    )
    assert Counter(event.dst for event in positive_current) == Counter(
        event.dst for event in negative_current
    )
    assert Counter(event.dpt for event in positive_current) == Counter(
        event.dpt for event in negative_current
    )
    positive_history = [event for event in positive if event.eventtime < current_cutoff]
    negative_history = [event for event in negative if event.eventtime < current_cutoff]
    assert positive_history and negative_history
    for field in ("dpt", "dst", "action"):
        assert Counter(getattr(event, field) for event in positive_history) == Counter(
            getattr(event, field) for event in negative_history
        )
    assert Counter(event.extra["duration"] for event in positive_history) == Counter(
        event.extra["duration"] for event in negative_history
    )
    assert sum(event.out_bytes or 0 for event in positive_history) < sum(
        event.out_bytes or 0 for event in negative_history
    )
