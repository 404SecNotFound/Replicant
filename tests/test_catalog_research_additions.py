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
"""Regression tests for the 2026-09-08 catalog research implementation."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict

import pytest

from replicant.core.models import load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.base import VendorProfile
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()


def _plan(technique_id: str, intensity: str = "low", **overrides: object):
    return ENGINE.plan(
        CATALOG.by_id(technique_id),
        intensity,
        ENTITIES,
        1337,
        param_overrides=overrides or None,
    )


def _stream(technique_id: str, control: str, intensity: str = "low") -> list:
    return [event for event in _plan(technique_id, intensity).events if event.control == control]


def _gaps(events: list) -> list[int]:
    times = sorted(event.eventtime for event in events)
    return [later - earlier for earlier, later in zip(times, times[1:], strict=False)]


def test_rep001_control_matches_shape_but_is_less_periodic() -> None:
    positive = _stream("REP-001", "positive", "medium")
    negative = _stream("REP-001", "negative", "medium")

    assert len(positive) == len(negative)
    assert {event.src for event in positive} == {event.src for event in negative}
    assert {event.dpt for event in positive} == {event.dpt for event in negative}
    assert {event.proto for event in positive} == {event.proto for event in negative}
    assert {event.dst for event in positive}.isdisjoint({event.dst for event in negative})
    assert min(event.eventtime for event in positive) == min(event.eventtime for event in negative)
    assert max(event.eventtime for event in positive) - min(
        event.eventtime for event in positive
    ) == pytest.approx(
        max(event.eventtime for event in negative) - min(event.eventtime for event in negative),
        abs=90,
    )
    assert statistics.pstdev(_gaps(negative)) > statistics.pstdev(_gaps(positive)) * 2


@pytest.mark.parametrize("window_s", [5 * 60, 15 * 60, 60 * 60])
def test_rep001_observation_windows_have_explicit_callback_counts(window_s: int) -> None:
    positive = _stream("REP-001", "positive", "medium")
    start = min(event.eventtime for event in positive)
    observed = [event for event in positive if event.eventtime <= start + window_s]

    assert len(observed) >= {300: 5, 900: 14, 3600: 55}[window_s]
    assert len(observed) < len(positive)


@pytest.mark.parametrize("technique_id", ["REP-004", "REP-015"])
def test_dns_controls_match_volume_type_and_length_but_not_cardinality(
    technique_id: str,
) -> None:
    positive = _stream(technique_id, "positive")
    negative = _stream(technique_id, "negative")
    positive_names = [event.extra["qname"].split(".")[0] for event in positive]
    negative_names = [event.extra["qname"].split(".")[0] for event in negative]

    assert len(positive) == len(negative)
    assert Counter(event.extra["qtype"] for event in positive) == Counter(
        event.extra["qtype"] for event in negative
    )
    minimum, maximum = CATALOG.by_id(technique_id).params["low"]["label_len"]
    assert all(minimum <= len(name) <= maximum for name in positive_names + negative_names)
    assert (
        abs(statistics.fmean(map(len, positive_names)) - statistics.fmean(map(len, negative_names)))
        < 2
    )
    assert len(set(positive_names)) > len(set(negative_names)) * 4


@pytest.mark.parametrize("technique_id", ["REP-004", "REP-015"])
def test_dns_positive_sequence_has_setup_idle_and_transfer_phases(technique_id: str) -> None:
    positive = _stream(technique_id, "positive")
    prefixes = [event.extra["qname"].split(".")[0][:2] for event in positive]

    assert set(prefixes) == {"hs", "id", "tx"}
    assert prefixes.index("hs") < prefixes.index("id") < prefixes.index("tx")
    assert "hs" not in prefixes[prefixes.index("id") :]
    assert "id" not in prefixes[prefixes.index("tx") :]


def test_rep004_preset_qps_is_not_silently_reduced() -> None:
    technique = CATALOG.by_id("REP-004")
    for intensity in ("low", "medium", "high"):
        positive = _stream("REP-004", "positive", intensity)
        preset = technique.params[intensity]
        assert len(positive) == int(preset["qps"]) * int(preset["duration_min"]) * 60


def test_rep009_signature_selector_and_rate_control() -> None:
    mixed = _plan("REP-009", signature_mode="mixed")
    single = _plan("REP-009", signature_mode="single")
    mixed_positive = [event for event in mixed.events if event.control == "positive"]
    single_positive = [event for event in single.events if event.control == "positive"]
    single_negative = [event for event in single.events if event.control == "negative"]

    assert len({event.extra["attackid"] for event in mixed_positive}) > 1
    assert len({event.extra["attackid"] for event in single_positive}) == 1
    assert {event.extra["attackid"] for event in single_positive} == {
        event.extra["attackid"] for event in single_negative
    }
    assert len(single_positive) == len(single_negative)
    assert max(_gaps(single_negative)) > max(_gaps(single_positive)) * 5


def test_rep030_is_distributed_below_per_entity_thresholds() -> None:
    positive = _stream("REP-030", "positive")
    preset = CATALOG.by_id("REP-030").params["low"]

    assert all(event.action == "ssl-login-fail" for event in positive)
    assert len({event.src for event in positive}) == preset["sources"]
    assert len({event.duser for event in positive}) == preset["users"]
    assert max(Counter(event.src for event in positive).values()) == 5
    assert max(Counter(event.duser for event in positive).values()) == 1


def test_rep030_control_preserves_failed_edges_and_self_corrects() -> None:
    positive = _stream("REP-030", "positive")
    negative = _stream("REP-030", "negative")
    failed = [event for event in negative if event.action == "ssl-login-fail"]
    successes = [event for event in negative if event.action == "tunnel-up"]
    success_times = {(event.src, event.duser): event.eventtime for event in successes}

    assert len(failed) == len(positive) == len(successes)
    assert all((event.src, event.duser) in success_times for event in failed)
    assert all(success_times[(event.src, event.duser)] >= event.eventtime for event in failed)


def test_rep043_positive_chain_uses_role_aware_victim_join_in_order() -> None:
    positive = _stream("REP-043", "positive")
    ips = [event for event in positive if (event.log_type, event.subtype) == ("utm", "ips")]
    inbound = [
        event
        for event in positive
        if (event.log_type, event.subtype) == ("traffic", "forward")
        and event.extra.get("src_intf") == "port1"
    ]
    outbound = [
        event
        for event in positive
        if (event.log_type, event.subtype) == ("traffic", "forward")
        and event.extra.get("src_intf") != "port1"
    ]

    for victim in {event.dst for event in ips}:
        victim_alerts = [event.eventtime for event in ips if event.dst == victim]
        victim_inbound = [event.eventtime for event in inbound if event.dst == victim]
        victim_outbound = [event.eventtime for event in outbound if event.src == victim]
        assert victim_alerts and victim_inbound and victim_outbound
        assert max(victim_alerts) < min(victim_inbound) < min(victim_outbound)


def test_rep043_negative_stream_never_forms_the_ordered_victim_join() -> None:
    negative = _stream("REP-043", "negative")
    roles: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: {"alert": [], "inbound": [], "outbound": []}
    )
    for event in negative:
        if (event.log_type, event.subtype) == ("utm", "ips") and event.dst:
            roles[event.dst]["alert"].append(event.eventtime)
        elif event.extra.get("src_intf") == "port1" and event.dst:
            roles[event.dst]["inbound"].append(event.eventtime)
        elif event.src:
            roles[event.src]["outbound"].append(event.eventtime)

    for role in roles.values():
        if all(role.values()):
            assert not (min(role["alert"]) < min(role["inbound"]) < min(role["outbound"]))


@pytest.mark.parametrize("profile", [FortiGateProfile(), PaloAltoProfile(), CheckPointProfile()])
@pytest.mark.parametrize("technique_id", ["REP-030", "REP-043"])
def test_new_techniques_render_through_every_vendor(
    profile: VendorProfile, technique_id: str
) -> None:
    for event in _plan(technique_id).events:
        header, extension = profile.render(event)
        assert header.signature_id
        assert extension


@pytest.mark.parametrize("technique_id", ["REP-030", "REP-043"])
def test_new_techniques_are_deterministic(technique_id: str) -> None:
    first = _plan(technique_id)
    second = _plan(technique_id)
    assert first.events == second.events
