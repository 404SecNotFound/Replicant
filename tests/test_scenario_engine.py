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
"""Scenario engine tests: determinism, distribution bounds, held/varied fields."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from replicant.cef.serializer import to_cef
from replicant.core.models import EventRecord, load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.fortigate import FortiGateProfile
from replicant.scenario.distributions import shannon_entropy
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")
ENTITIES = EntityModel.build()


def _plan(technique_id: str, intensity: str, seed: int, duration_s: int | None = None):
    engine = ScenarioEngine()
    return engine.plan(
        CATALOG.by_id(technique_id),
        intensity,
        ENTITIES,
        seed,
        duration_override_s=duration_s,
    )


def _serialize(events: list[EventRecord]) -> list[str]:
    profile = FortiGateProfile()
    lines = []
    for event in events:
        header, ext = profile.render(event)
        lines.append(to_cef(header, ext))
    return lines


def test_same_seed_same_plan_rep001() -> None:
    a = _plan("REP-001", "medium", 1337, duration_s=600)
    b = _plan("REP-001", "medium", 1337, duration_s=600)
    assert _serialize(a.events) == _serialize(b.events)


def test_different_seed_differs() -> None:
    a = _plan("REP-001", "medium", 1337, duration_s=600)
    b = _plan("REP-001", "medium", 4242, duration_s=600)
    assert _serialize(a.events) != _serialize(b.events)


def test_rep001_holds_src_dst_dpt_proto() -> None:
    plan = _plan("REP-001", "medium", 1337, duration_s=1800)
    assert len(plan.events) > 5
    assert len({e.src for e in plan.events}) == 1
    assert len({e.dst for e in plan.events}) == 1
    assert len({e.dpt for e in plan.events}) == 1
    assert len({e.proto for e in plan.events}) == 1
    # session id (externalId) varies event to event
    assert len({e.session_id for e in plan.events}) == len(plan.events)


def test_rep001_bytes_within_preset_bounds() -> None:
    plan = _plan("REP-001", "medium", 1337, duration_s=1800)
    low, high = CATALOG.by_id("REP-001").params["medium"]["out_bytes"]
    for event in plan.events:
        assert event.out_bytes is not None and low <= event.out_bytes <= high


def test_rep001_interval_is_periodic_with_jitter() -> None:
    plan = _plan("REP-001", "medium", 1337, duration_s=1800)
    times = [e.eventtime for e in plan.events]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    base, jitter = 60, 0.15
    for gap in gaps:
        assert base * (1 - jitter) - 1 <= gap <= base * (1 + jitter) + 1


def test_rep002_one_src_one_dst_many_unique_ports_mostly_deny() -> None:
    plan = _plan("REP-002", "low", 1337)
    unique_ports = CATALOG.by_id("REP-002").params["low"]["unique_ports"]
    assert len(plan.events) == unique_ports
    assert len({e.src for e in plan.events}) == 1
    assert len({e.dst for e in plan.events}) == 1
    assert len({e.dpt for e in plan.events}) == unique_ports  # all destination ports unique
    deny = sum(1 for e in plan.events if e.action == "deny")
    assert deny / len(plan.events) > 0.9  # mostly deny


def test_rep004_high_entropy_qnames_high_cardinality() -> None:
    plan = _plan("REP-004", "medium", 1337, duration_s=10)  # 60 qps * 10 s = 600 queries
    assert len(plan.events) == 600
    qnames = [e.extra["qname"] for e in plan.events]
    # High unique-label cardinality under one synthetic parent domain.
    assert len(set(qnames)) == 600
    parents = {name.split(".", 1)[1] for name in qnames}
    assert len(parents) == 1
    # High Shannon entropy on the varying label (> 3.5 bits/char).
    label = qnames[0].split(".", 1)[0]
    assert shannon_entropy(label) > 3.5


def test_rep004_qtype_weighted_to_txt_null() -> None:
    plan = _plan("REP-004", "medium", 1337, duration_s=20)
    counts = Counter(e.extra["qtype"] for e in plan.events)
    assert counts["TXT"] == max(counts.values())  # TXT is the modal qtype
    assert counts["TXT"] + counts["NULL"] > counts["A"] + counts["CNAME"]


def test_rep004_holds_resolver_and_port() -> None:
    plan = _plan("REP-004", "medium", 1337, duration_s=10)
    assert {e.dst for e in plan.events} == {ENTITIES.resolver}
    assert {e.dpt for e in plan.events} == {53}
    assert {e.proto for e in plan.events} == {17}


def test_rep004_qnames_are_synthetic_parents() -> None:
    plan = _plan("REP-004", "medium", 1337, duration_s=10)
    parent = plan.events[0].extra["qname"].split(".", 1)[1]
    assert parent in set(ENTITIES.parents)
