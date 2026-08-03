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
"""Every use case has to say what it is for.

The catalog described what each technique EMITS in considerable detail and never
said what running it is meant to ESTABLISH. The web UI filled that gap with a
template: "Emits synthetic <log type> telemetry that exercises <rule id>". That
sentence is true of all 24 entries, so it told an operator nothing about which
one to pick, which is the only question the screen exists to answer.

Parametrized over the whole catalog rather than spot-checked, for the reason the
duration work established: a field that is present on most entries is worse than
one present on none, because the operator learns to trust it.
"""

from __future__ import annotations

import pytest

from replicant.core.models import load_catalog
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
TECHNIQUES = [pytest.param(t, id=t.id) for t in CATALOG.techniques]


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_every_technique_states_an_objective(technique) -> None:
    assert technique.objective.strip(), f"{technique.id} has no objective"


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_the_objective_is_a_sentence_not_a_label(technique) -> None:
    """A three word stub would satisfy a presence check and help nobody."""
    assert len(technique.objective.split()) >= 8, technique.objective


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_the_objective_is_not_the_name_restated(technique) -> None:
    assert technique.objective.strip().lower() != technique.name.strip().lower()


def test_objectives_are_distinct() -> None:
    """The defect being fixed was one sentence that fitted every entry."""
    objectives = [t.objective.strip().lower() for t in CATALOG.techniques]

    assert len(set(objectives)) == len(objectives)
