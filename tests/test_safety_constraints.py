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
"""Safety-invariant constraints.

The events-per-second cap protects the operator's own collector (safety rule 4).
A non-positive cap silently disables the rate limiter in the emit loop
(``if eps_cap > 0``), so a zero or negative value is a way to turn the safeguard
off by accident. These tests pin the cap and every rate override to a positive
integer at the model boundary, which is the single choke point the CLI, menu,
web API, and scenario paths all pass through.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from replicant.config.settings import Settings
from replicant.core.models import (
    CollectorProfile,
    RunRequest,
    ScenarioRunRequest,
    load_catalog,
)
from replicant.entities.model import EntityModel
from replicant.scenario.engine import ScenarioEngine, implemented_technique_ids

CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)
ENTITIES = EntityModel.build()


@pytest.mark.parametrize("bad", [0, -1, -2000])
def test_settings_rejects_nonpositive_eps_cap(bad: int) -> None:
    with pytest.raises(ValidationError):
        Settings(eps_cap=bad)


def test_settings_accepts_positive_eps_cap() -> None:
    assert Settings(eps_cap=1).eps_cap == 1
    assert Settings().eps_cap == 2000


@pytest.mark.parametrize("bad", [0, -1, -50])
def test_run_request_rejects_nonpositive_rate_override(bad: int) -> None:
    with pytest.raises(ValidationError):
        RunRequest(technique_id="REP-001", rate_override=bad)


def test_run_request_allows_none_or_positive_rate_override() -> None:
    assert RunRequest(technique_id="REP-001").rate_override is None
    assert RunRequest(technique_id="REP-001", rate_override=10).rate_override == 10


@pytest.mark.parametrize("bad", [0, -1, -50])
def test_scenario_request_rejects_nonpositive_rate_override(bad: int) -> None:
    with pytest.raises(ValidationError):
        ScenarioRunRequest(scenario_id="SCEN-001", rate_override=bad)


def test_scenario_request_allows_none_or_positive_rate_override() -> None:
    assert ScenarioRunRequest(scenario_id="SCEN-001").rate_override is None
    assert ScenarioRunRequest(scenario_id="SCEN-001", rate_override=10).rate_override == 10


# --- Collector numeric domains -----------------------------------------------


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 99999])
def test_collector_rejects_out_of_range_port(bad_port: int) -> None:
    with pytest.raises(ValidationError):
        CollectorProfile(host="192.0.2.1", port=bad_port)


@pytest.mark.parametrize("port", [1, 514, 65535])
def test_collector_accepts_valid_port(port: int) -> None:
    assert CollectorProfile(host="192.0.2.1", port=port).port == port


@pytest.mark.parametrize("bad_facility", [-1, 24, 100])
def test_collector_rejects_out_of_range_facility(bad_facility: int) -> None:
    with pytest.raises(ValidationError):
        CollectorProfile(host="192.0.2.1", facility=bad_facility)


@pytest.mark.parametrize("facility", [0, 7, 23])
def test_collector_accepts_valid_facility(facility: int) -> None:
    assert CollectorProfile(host="192.0.2.1", facility=facility).facility == facility


# --- Universal event ceiling -------------------------------------------------
#
# Truncation to ``max_events`` is enforced inside each builder, not centrally, so
# a builder that forgets the check would emit an unbounded plan. This drives every
# implemented technique at the highest intensity and a full day of duration against
# a deliberately tiny ceiling: the ceiling, not the parameters, must bind. The
# review flagged REP-007/008/011 specifically because their counts come from
# params rather than a time loop.


@pytest.mark.parametrize("technique_id", sorted(implemented_technique_ids()))
def test_builder_never_exceeds_max_events(technique_id: str) -> None:
    engine = ScenarioEngine(max_events=10)
    plan = engine.plan(
        CATALOG.by_id(technique_id),
        "high",
        ENTITIES,
        seed=1337,
        duration_override_s=86_400,
    )
    assert len(plan.events) <= engine.max_events, (
        f"{technique_id} produced {len(plan.events)} events, "
        f"over max_events={engine.max_events}"
    )


# Safety rule 2: every entity pool must be synthetic. `_assert_synthetic` is the
# one guard between an operator config and a log line carrying a real routable
# address. The default-build test below is a positive control; without the
# rejection test beside it, a refactor that dropped or inverted the containment
# check would ship green, since the defaults are all in range.


def test_build_places_every_default_pool_inside_the_synthetic_ranges() -> None:
    """Positive control: the shipped defaults resolve, so the rejection test
    below cannot pass merely because the guard rejects everything."""
    import ipaddress

    from replicant.entities.model import _ALLOWED_RANGES

    model = EntityModel.build()
    pools = (
        model.internal_hosts
        + model.internal_targets
        + model.adversary_external
        + model.benign_external
        + [model.resolver]
    )
    for addr in pools:
        ip = ipaddress.ip_address(addr)
        assert any(ip in net for net in _ALLOWED_RANGES), f"{addr} is outside the synthetic ranges"


@pytest.mark.parametrize(
    "field,value",
    [
        ("adversary_subnet", "8.8.8.0/24"),  # a real, routable, famous address
        ("internal_subnet", "1.1.1.0/24"),
        ("target_subnet", "203.0.113.0/24 "),  # trailing space -> ValueError from ip parse
    ],
)
def test_build_refuses_a_non_synthetic_subnet(field: str, value: str) -> None:
    """The guard must reject a public range, not just document that it should."""
    from replicant.entities.model import EntityConfig

    with pytest.raises(ValueError):
        EntityModel.build(EntityConfig(**{field: value}))
