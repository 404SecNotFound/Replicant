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
"""Bounds on the seeded distribution helpers.

These guard the two ways a param override could push a helper outside the
domain its output is defined on: jitter above 100% producing a negative
interval (backward timestamps), and a DNS label longer than the RFC 1035
63-octet limit (a name no resolver would ever emit).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.core.models import load_catalog
from replicant.entities.model import EntityModel
from replicant.scenario.distributions import high_entropy_labels, jittered_interval, make_rng
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)
ENTITIES = EntityModel.build()


def test_jittered_interval_never_goes_negative() -> None:
    rng = make_rng(1337)
    for _ in range(500):
        interval = jittered_interval(rng, 10.0, 150.0)
        assert 0.0 <= interval <= 20.0


def test_jittered_interval_negative_pct_is_no_jitter() -> None:
    rng = make_rng(1337)
    assert jittered_interval(rng, 10.0, -40.0) == pytest.approx(10.0)


def test_high_entropy_labels_respect_the_63_octet_limit() -> None:
    rng = make_rng(1337)
    labels = high_entropy_labels(rng, 50, 70, 120)
    assert len(labels) == 50
    assert all(len(label) <= 63 for label in labels)


def test_label_len_override_above_63_is_clamped_in_the_engine() -> None:
    """REP-004 joins labels under a parent; the label cap keeps qnames legal."""
    engine = ScenarioEngine()
    plan = engine.plan(
        CATALOG.by_id("REP-004"),
        "low",
        ENTITIES,
        1337,
        duration_override_s=10,
        param_overrides={"label_len": [70, 90]},
    )
    for event in plan.events:
        qname = str(event.extra["qname"])
        label = qname.split(".", 1)[0]
        assert len(label) <= 63
        assert len(qname) <= 253
