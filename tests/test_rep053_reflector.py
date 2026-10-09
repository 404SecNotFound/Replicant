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
"""REP-053: an internal reflector abused for amplification (Impact, T1498.002).

What the catalog promises and this file measures, over seeds and presets:

- inbound udp sessions on the preset's port from one external source to one
  internal server in the server pool, accepted, with the interface pair
  reversed, a count inside the preset's range, every session closing inside
  the window, requests inside the stated size band and replies inside the
  preset's amplification band;
- the benign foil is one chatty client against the same server: same count
  range, same request sizes, same durations, same irregular timing, replies in
  the symmetric band, drawn from the same external pool as the spoofed source,
  so the per-session reply-to-request ratio is the only separating feature;
- the catalog states, on its face, that event rate is bounded by the safety
  cap and is never the signal;
- the records render as the existing inbound traffic accept on all three
  vendors with the UDP service named, so no profile changed;
- ``--duration`` sets the window and preserves the count, and the engine's
  ceiling binds the count rather than the window.

Positive controls (recorded in the PR): with the foil drawn from a different
external pool the pool guard went red on every seed; with the foil's session
count pinned the count parity guard went red; with the attack's replies made
symmetric the ratio signal guard went red on every seed.
"""

from __future__ import annotations

import statistics
from collections import Counter

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import (
    REFLECT_DURATION_S,
    REFLECT_FOIL_RATIO,
    REFLECT_REQUEST_BYTES,
    ScenarioEngine,
)

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTENSITIES = ("low", "medium", "high")
SERVERS = set(ENTITIES.server_hosts)
EXTERNAL_POOL = set(ENTITIES.benign_external)
SERVICE_BY_PORT = {123: "NTP", 161: "SNMP"}


def _plan(intensity: str, seed: int):
    return ENGINE.plan(CATALOG.by_id("REP-053"), intensity, ENTITIES, seed, anchor_epoch=ANCHOR)


def _split(plan):
    positive = [e for e in plan.events if e.control == "positive"]
    negative = [e for e in plan.events if e.control != "positive"]
    return positive, negative


def _ratios(events) -> list[float]:
    return [(e.in_bytes or 0) / (e.out_bytes or 1) for e in events]


def _shape(events, preset, tag: str) -> None:
    """The structural promises both streams share."""

    lo, hi = preset["sessions"]
    window = preset["window_min"] * 60
    assert len({e.src for e in events}) == 1, f"{tag}: more than one source"
    assert len({e.dst for e in events}) == 1, f"{tag}: more than one server"
    assert events[0].src in EXTERNAL_POOL, f"{tag}: source outside the shared external pool"
    assert events[0].dst in SERVERS, f"{tag}: the server is not in the server pool"
    assert lo <= len(events) <= hi, f"{tag}: {len(events)} sessions outside [{lo}, {hi}]"
    for e in events:
        assert e.log_type == "traffic" and e.subtype == "forward" and e.action == "accept"
        assert e.proto == 17 and e.dpt == preset["dpt"], f"{tag}: not the preset's udp service"
        assert e.extra["service"] == SERVICE_BY_PORT[preset["dpt"]]
        assert (
            e.extra["src_intf"] == "port1" and e.extra["dst_intf"] == "port2"
        ), f"{tag}: interface pair is not inbound"
        assert REFLECT_REQUEST_BYTES[0] <= (e.out_bytes or 0) <= REFLECT_REQUEST_BYTES[1]
        assert REFLECT_DURATION_S[0] <= int(e.extra["duration"]) <= REFLECT_DURATION_S[1]
        assert ANCHOR < e.eventtime <= ANCHOR + window, f"{tag}: session closed outside window"


# -- the attack --------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_one_spoofed_source_gets_amplified_replies_from_one_server(
    intensity: str, seed: int
) -> None:
    preset = CATALOG.by_id("REP-053").params[intensity]
    positive, _ = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(positive, preset, tag)
    amp_lo, amp_hi = preset["amplification"]
    for ratio in _ratios(positive):
        assert amp_lo - 0.02 <= ratio <= amp_hi + 0.02, f"{tag}: amplification {ratio:.1f}x"


# -- the foil ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_foil_is_one_chatty_client_with_symmetric_replies(intensity: str, seed: int) -> None:
    preset = CATALOG.by_id("REP-053").params[intensity]
    positive, negative = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(negative, preset, f"{tag} foil")
    assert negative[0].src != positive[0].src
    assert negative[0].dst == positive[0].dst, f"{tag}: the foil hits a different server"
    for ratio in _ratios(negative):
        assert (
            REFLECT_FOIL_RATIO[0] - 0.02 <= ratio <= REFLECT_FOIL_RATIO[1] + 0.02
        ), f"{tag}: foil reply ratio {ratio:.2f} outside the symmetric band"
    # Same timing shape: both streams are irregular, neither is a metronome.
    for label, events in (("attack", positive), ("foil", negative)):
        times = sorted(e.eventtime for e in events)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        if len(gaps) >= 4:
            cv = statistics.pstdev(gaps) / max(statistics.mean(gaps), 1e-9)
            assert cv > 0.2, f"{tag}: {label} stream is a metronome (gap CV {cv:.2f})"


def test_the_ratio_is_the_only_separating_feature_pooled_over_seeds() -> None:
    """Session counts, request sizes and durations pooled over seeds at medium
    are drawn from the same distributions; the reply-to-request ratio, the
    feature the catalog names, separates the streams on every seed."""

    p_counts: list[int] = []
    n_counts: list[int] = []
    p_request: list[int] = []
    n_request: list[int] = []
    p_duration: list[int] = []
    n_duration: list[int] = []
    for seed in SEEDS:
        positive, negative = _split(_plan("medium", seed))
        p_counts.append(len(positive))
        n_counts.append(len(negative))
        p_request.extend(e.out_bytes or 0 for e in positive)
        n_request.extend(e.out_bytes or 0 for e in negative)
        p_duration.extend(int(e.extra["duration"]) for e in positive)
        n_duration.extend(int(e.extra["duration"]) for e in negative)
        assert min(_ratios(positive)) > max(
            _ratios(negative)
        ), f"seed {seed}: the attack's smallest reply ratio does not clear the foil's largest"
    assert abs(statistics.mean(p_counts) - statistics.mean(n_counts)) < 20
    assert abs(statistics.mean(p_request) - statistics.mean(n_request)) < 8
    assert abs(statistics.mean(p_duration) - statistics.mean(n_duration)) < 2


def test_the_catalog_states_that_rate_is_never_the_signal() -> None:
    """The round-3 standard for this entry: the cap statement is on the entry's
    face, so an operator is not taught to expect a rate spike."""

    technique = CATALOG.by_id("REP-053")
    assert "events per second" in (technique.transferability_note or "")
    assert "cap" in str(technique.distributions.get("rate", ""))
    assert "never" in str(technique.distributions.get("rate", ""))


# -- rendering -------------------------------------------------------------------------


def test_the_session_renders_as_an_inbound_udp_accept_on_every_vendor() -> None:
    positive, _ = _split(_plan("medium", 1337))
    event = positive[0]

    header, fgt = FortiGateProfile().render(event)
    assert header.signature_id == "00013"
    assert fgt["proto"] == "17" and fgt["dpt"] == "123" and fgt["FTNTFGTservice"] == "NTP"
    assert fgt["deviceInboundInterface"] == "port1" and fgt["deviceOutboundInterface"] == "port2"
    assert int(fgt["in"]) >= 30 * int(fgt["out"]) > 0

    _, pan = PaloAltoProfile().render(event)
    assert pan["proto"] in ("udp", "17") and pan["dpt"] == "123"
    assert int(pan["in"]) >= 30 * int(pan["out"]) > 0

    _, cp = CheckPointProfile().render(event)
    assert cp["deviceDirection"] == "0"  # the destination is internal
    assert cp["dpt"] == "123"


# -- duration and the ceiling -------------------------------------------------------------


def test_duration_sets_the_window_and_keeps_the_session_count(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    natural = orch.build_plan(RunRequest(technique_id="REP-053", intensity="medium", seed=7))
    short = orch.build_plan(
        RunRequest(technique_id="REP-053", intensity="medium", seed=7, duration="2m")
    )
    natural_positive = [e for e in natural.events if e.control == "positive"]
    short_positive = [e for e in short.events if e.control == "positive"]
    assert len(short_positive) == len(natural_positive)
    assert max(e.eventtime for e in short_positive) - natural.anchor_epoch <= 120


def test_the_ceiling_binds_the_session_count_not_the_window() -> None:
    plan = ScenarioEngine(max_events=40).plan(
        CATALOG.by_id("REP-053"), "high", ENTITIES, 3, anchor_epoch=ANCHOR
    )
    assert plan.truncated
    assert len(plan.events) <= 40
    positive, negative = _split(plan)
    assert positive and negative
    window = CATALOG.by_id("REP-053").params["high"]["window_min"] * 60
    assert max(e.eventtime for e in plan.events) <= ANCHOR + window
    counts = Counter(e.control for e in plan.events)
    assert counts["positive"] <= 20 and counts["negative"] <= 20
