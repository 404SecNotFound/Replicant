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

import ipaddress
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


def test_rep003_one_src_one_port_many_unique_hosts_mostly_deny() -> None:
    plan = _plan("REP-003", "low", 1337)
    preset = CATALOG.by_id("REP-003").params["low"]
    unique_hosts, port = preset["unique_hosts"], preset["port"]
    assert len(plan.events) == unique_hosts
    assert len({e.src for e in plan.events}) == 1  # one source, held
    assert {e.dpt for e in plan.events} == {port}  # one destination port, held
    assert {e.proto for e in plan.events} == {6}
    assert len({e.dst for e in plan.events}) == unique_hosts  # every dst unique
    deny = sum(1 for e in plan.events if e.action == "deny")
    assert deny / len(plan.events) > 0.9  # mostly deny


def test_rep003_deterministic_same_seed() -> None:
    a = _plan("REP-003", "low", 1337)
    b = _plan("REP-003", "low", 1337)
    assert _serialize(a.events) == _serialize(b.events)


def test_rep003_destinations_are_synthetic_internal() -> None:
    plan = _plan("REP-003", "low", 1337)
    rfc1918 = ipaddress.ip_network("10.0.0.0/8")
    for event in plan.events:
        assert event.dst is not None
        assert ipaddress.ip_address(event.dst) in rfc1918


def test_rep005_outbound_exfil_volume_shape() -> None:
    plan = _plan("REP-005", "low", 1337)
    preset = CATALOG.by_id("REP-005").params["low"]
    sessions, total_mb, dst_count = preset["sessions"], preset["total_out_mb"], preset["dst_count"]
    assert len(plan.events) == sessions
    assert len({e.src for e in plan.events}) == 1  # one source, held
    assert len({e.dpt for e in plan.events}) == 1  # one port, held
    assert len({e.dst for e in plan.events}) <= dst_count  # few destinations
    assert all(e.action == "accept" for e in plan.events)
    total_out = sum(e.out_bytes or 0 for e in plan.events)
    total_in = sum(e.in_bytes or 0 for e in plan.events)
    assert total_out >= total_mb * 1_000_000 * 0.5  # large outbound volume near target
    assert total_out / max(total_in, 1) > 20  # exfil ratio out:in > 20:1


def test_rep005_deterministic_same_seed() -> None:
    a = _plan("REP-005", "low", 1337)
    b = _plan("REP-005", "low", 1337)
    assert _serialize(a.events) == _serialize(b.events)


def test_rep005_events_weighted_off_hours() -> None:
    from datetime import datetime, timedelta, timezone

    dubai = timezone(timedelta(hours=4))
    plan = _plan("REP-005", "low", 1337)
    for event in plan.events:
        hour = datetime.fromtimestamp(event.eventtime, dubai).hour
        assert hour < 8 or hour >= 18  # outside business hours


_SYNTHETIC_RANGES = [
    ipaddress.ip_network(c)
    for c in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
]


def test_rep006_destination_fanout_shape() -> None:
    plan = _plan("REP-006", "low", 1337)
    unique_dst = CATALOG.by_id("REP-006").params["low"]["unique_dst"]
    assert len(plan.events) == unique_dst
    assert len({e.src for e in plan.events}) == 1  # one source, held
    assert len({e.dst for e in plan.events}) == unique_dst  # many unique destinations
    assert unique_dst >= 50  # far above the benign baseline of < 10 in the window
    assert all((e.out_bytes or 0) < 100_000 for e in plan.events)  # small byte volume


def test_rep006_within_five_minute_window() -> None:
    plan = _plan("REP-006", "low", 1337)
    times = [e.eventtime for e in plan.events]
    assert max(times) - min(times) <= 5 * 60


def test_rep006_deterministic_same_seed() -> None:
    a = _plan("REP-006", "low", 1337)
    b = _plan("REP-006", "low", 1337)
    assert _serialize(a.events) == _serialize(b.events)


def test_rep006_destinations_are_synthetic() -> None:
    plan = _plan("REP-006", "low", 1337)
    for event in plan.events:
        assert event.dst is not None
        ip = ipaddress.ip_address(event.dst)
        assert any(ip in net for net in _SYNTHETIC_RANGES)


def test_rep010_denied_outbound_burst_shape() -> None:
    plan = _plan("REP-010", "low", 1337)
    preset = CATALOG.by_id("REP-010").params["low"]
    denies, window = preset["denies"], preset["window_s"]
    assert len(plan.events) == denies
    assert len({e.src for e in plan.events}) == 1  # one source, held
    assert all(e.action == "deny" for e in plan.events)  # all denied
    external = ipaddress.ip_network("203.0.113.0/24")
    for event in plan.events:
        assert event.dst is not None
        assert ipaddress.ip_address(event.dst) in external  # synthetic external destinations
    times = [e.eventtime for e in plan.events]
    assert max(times) - min(times) <= window  # inside the burst window


def test_rep010_rate_spikes_then_decays() -> None:
    plan = _plan("REP-010", "low", 1337)
    offsets = sorted(e.eventtime for e in plan.events)
    span = offsets[-1] - offsets[0]
    median = offsets[len(offsets) // 2] - offsets[0]
    assert median < span * 0.5  # more than half the events in the first half of the window


def test_rep010_deterministic_same_seed() -> None:
    a = _plan("REP-010", "low", 1337)
    b = _plan("REP-010", "low", 1337)
    assert _serialize(a.events) == _serialize(b.events)


def test_rep007_spray_many_users_few_attempts() -> None:
    plan = _plan("REP-007", "low", 1337)
    preset = CATALOG.by_id("REP-007").params["low"]
    users, attempts = preset["users"], preset["attempts_each"]
    assert preset["mode"] == "spray"
    assert len(plan.events) == users * attempts  # every user tried a few times
    assert len({e.src for e in plan.events}) == 1  # one attacking source, held
    assert len({e.duser for e in plan.events}) == users  # many distinct victims
    assert all(e.action == "ssl-login-fail" for e in plan.events)  # spray never succeeds
    counts = Counter(e.duser for e in plan.events)
    assert set(counts.values()) == {attempts}  # each user tried exactly attempts_each times


def test_rep007_brute_one_user_many_attempts_optional_success() -> None:
    plan = _plan("REP-007", "high", 1337)
    preset = CATALOG.by_id("REP-007").params["high"]
    attempts = preset["attempts_each"]
    assert preset["mode"] == "brute"
    assert len({e.src for e in plan.events}) == 1  # one source, held
    assert len({e.duser for e in plan.events}) == 1  # one victim, held (brute)
    fails = [e for e in plan.events if e.action == "ssl-login-fail"]
    successes = [e for e in plan.events if e.action == "tunnel-up"]
    assert len(fails) == attempts  # many attempts
    assert len(successes) == 1  # optional success at the end
    assert max(plan.events, key=lambda e: e.eventtime).action == "tunnel-up"  # success is last
    # both fail and success templates must serialize cleanly
    assert len(_serialize(plan.events)) == len(plan.events)


def test_rep007_reason_and_duser_vary() -> None:
    plan = _plan("REP-007", "low", 1337)
    assert len({e.duser for e in plan.events}) > 1  # duser varies
    assert len({e.extra["reason"] for e in plan.events}) > 1  # FTNTFGTreason varies


def test_rep007_source_is_synthetic() -> None:
    plan = _plan("REP-007", "low", 1337)
    src = plan.events[0].src
    assert src is not None
    assert any(ipaddress.ip_address(src) in net for net in _SYNTHETIC_RANGES)


def test_rep007_deterministic_same_seed() -> None:
    a = _plan("REP-007", "low", 1337)
    b = _plan("REP-007", "low", 1337)
    assert _serialize(a.events) == _serialize(b.events)
