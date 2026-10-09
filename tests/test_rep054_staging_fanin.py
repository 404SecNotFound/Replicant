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
"""REP-054, internal data staging fan-in (Collection, T1074.002), and SCEN-004,
the chain that joins it to the egress that follows.

What the catalog promises and this file measures, over seeds and presets:

- many distinct sources from the target pool push accepted tcp/445 sessions
  onto one staging host from the workstation pool, a source count inside the
  preset's range, the preset's sessions per source, every session closing
  inside the window, out-heavy inside the stated bands;
- the benign foil is the same fan-in onto a backup server in the server pool:
  same source count range, same sessions per source, same byte and duration
  draws, same irregular timing, sources from the same pool, so the
  destination's asset role is the only separating feature;
- the records render as the existing traffic:forward accept on all three
  vendors, so no profile changed;
- ``--duration`` sets the window and preserves the count, and the engine's
  ceiling binds the count rather than the window;
- SCEN-004 composes the fan-in onto the pinned victim and the exfil from the
  same victim, and the advisory names that phase transition from what the
  stages emitted rather than from the scenario text.

Positive controls (recorded in the PR): with the foil's destination drawn from
the workstation pool the role guard went red on every seed; with the foil's
source count pinned the count parity guard went red; with the advisory's
staging pivot removed the SCEN-004 guard went red.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import replace

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog, load_scenario_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose
from replicant.scenario.engine import (
    SMB_PORT,
    STAGING_ACK_RATIO,
    STAGING_DURATION_S,
    ScenarioEngine,
)

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTENSITIES = ("low", "medium", "high")
WORKSTATIONS = set(ENTITIES.internal_hosts)
SERVERS = set(ENTITIES.server_hosts)
SOURCE_POOL = set(ENTITIES.internal_targets)


def _plan(intensity: str, seed: int):
    return ENGINE.plan(CATALOG.by_id("REP-054"), intensity, ENTITIES, seed, anchor_epoch=ANCHOR)


def _split(plan):
    positive = [e for e in plan.events if e.control == "positive"]
    negative = [e for e in plan.events if e.control != "positive"]
    return positive, negative


def _shape(events, preset, tag: str) -> None:
    """The structural promises both streams share."""

    lo, hi = preset["sources"]
    sps_lo, sps_hi = preset["sessions_per_source"]
    window = preset["window_min"] * 60
    assert len({e.dst for e in events}) == 1, f"{tag}: more than one destination"
    sources = {e.src for e in events}
    assert sources <= SOURCE_POOL, f"{tag}: a source is outside the target pool"
    assert lo <= len(sources) <= hi, f"{tag}: {len(sources)} sources outside [{lo}, {hi}]"
    per_source = Counter(e.src for e in events)
    assert all(sps_lo <= n <= sps_hi for n in per_source.values()), (
        f"{tag}: sessions per source {sorted(set(per_source.values()))} outside "
        f"[{sps_lo}, {sps_hi}]"
    )
    for e in events:
        assert e.log_type == "traffic" and e.subtype == "forward" and e.action == "accept"
        assert e.dpt == SMB_PORT and e.proto == 6 and e.extra["service"] == "SMB"
        assert e.out_bytes and e.in_bytes
        ratio = e.in_bytes / e.out_bytes
        assert (
            STAGING_ACK_RATIO[0] - 0.005 <= ratio <= STAGING_ACK_RATIO[1] + 0.005
        ), f"{tag}: ack ratio {ratio:.3f}"
        assert int(e.extra["duration"]) <= min(STAGING_DURATION_S[1], window)
        assert ANCHOR < e.eventtime <= ANCHOR + window, f"{tag}: session closed outside window"


# -- the attack --------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_many_sources_push_onto_one_workstation_inside_the_window(
    intensity: str, seed: int
) -> None:
    preset = CATALOG.by_id("REP-054").params[intensity]
    positive, _ = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(positive, preset, tag)
    staging_host = positive[0].dst
    assert staging_host in WORKSTATIONS, f"{tag}: the staging host is not a workstation"
    assert staging_host not in SERVERS


# -- the foil ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_foil_is_the_same_fanin_onto_a_backup_server(intensity: str, seed: int) -> None:
    preset = CATALOG.by_id("REP-054").params[intensity]
    positive, negative = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(negative, preset, f"{tag} foil")
    assert negative[0].dst in SERVERS, f"{tag}: the foil's destination is not a backup server"
    assert negative[0].dst != positive[0].dst
    for label, events in (("attack", positive), ("foil", negative)):
        times = sorted(e.eventtime for e in events)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        if len(gaps) >= 4:
            cv = statistics.pstdev(gaps) / max(statistics.mean(gaps), 1e-9)
            assert cv > 0.2, f"{tag}: {label} fan-in is a metronome (gap CV {cv:.2f})"


def test_destination_role_is_the_only_separating_feature_pooled_over_seeds() -> None:
    """Source counts, session counts, pushed bytes, ack ratio and duration
    pooled over seeds at medium: the two streams are drawn from the same
    distributions, and a detection that ignores the destination's role has
    nothing to key on."""

    p_sources: list[int] = []
    n_sources: list[int] = []
    p_sessions: list[int] = []
    n_sessions: list[int] = []
    p_log_out: list[float] = []
    n_log_out: list[float] = []
    p_ratio: list[float] = []
    n_ratio: list[float] = []
    p_duration: list[int] = []
    n_duration: list[int] = []
    for seed in SEEDS:
        positive, negative = _split(_plan("medium", seed))
        p_sources.append(len({e.src for e in positive}))
        n_sources.append(len({e.src for e in negative}))
        p_sessions.append(len(positive))
        n_sessions.append(len(negative))
        p_log_out.extend(math.log(e.out_bytes or 1) for e in positive)
        n_log_out.extend(math.log(e.out_bytes or 1) for e in negative)
        p_ratio.extend((e.in_bytes or 0) / (e.out_bytes or 1) for e in positive)
        n_ratio.extend((e.in_bytes or 0) / (e.out_bytes or 1) for e in negative)
        p_duration.extend(int(e.extra["duration"]) for e in positive)
        n_duration.extend(int(e.extra["duration"]) for e in negative)
    assert abs(statistics.mean(p_sources) - statistics.mean(n_sources)) < 3
    assert abs(statistics.mean(p_sessions) - statistics.mean(n_sessions)) < 6
    assert abs(statistics.mean(p_log_out) - statistics.mean(n_log_out)) < 0.15
    assert abs(statistics.mean(p_ratio) - statistics.mean(n_ratio)) < 0.005
    assert abs(statistics.mean(p_duration) - statistics.mean(n_duration)) < 30


# -- rendering -------------------------------------------------------------------------


def test_the_push_renders_as_the_existing_traffic_record_on_every_vendor() -> None:
    positive, _ = _split(_plan("medium", 1337))
    event = positive[0]

    header, fgt = FortiGateProfile().render(event)
    assert header.signature_id == "00013"
    assert fgt["dpt"] == str(SMB_PORT) and fgt["FTNTFGTservice"] == "SMB"
    assert int(fgt["out"]) >= 20 * int(fgt["in"]) > 0

    _, pan = PaloAltoProfile().render(event)
    assert pan["dpt"] == str(SMB_PORT) and int(pan["out"]) >= 20 * int(pan["in"]) > 0

    _, cp = CheckPointProfile().render(event)
    assert cp["dpt"] == str(SMB_PORT)


# -- duration and the ceiling -------------------------------------------------------------


def test_duration_sets_the_window_and_keeps_the_source_count(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    natural = orch.build_plan(RunRequest(technique_id="REP-054", intensity="medium", seed=7))
    short = orch.build_plan(
        RunRequest(technique_id="REP-054", intensity="medium", seed=7, duration="5m")
    )
    natural_sources = {e.src for e in natural.events if e.control == "positive"}
    short_sources = {e.src for e in short.events if e.control == "positive"}
    assert len(short_sources) == len(natural_sources)
    positives = [e for e in short.events if e.control == "positive"]
    assert max(e.eventtime for e in positives) - natural.anchor_epoch <= 300


def test_the_ceiling_binds_the_source_count_not_the_window() -> None:
    plan = ScenarioEngine(max_events=40).plan(
        CATALOG.by_id("REP-054"), "high", ENTITIES, 3, anchor_epoch=ANCHOR
    )
    assert plan.truncated
    assert len(plan.events) <= 40
    positive, negative = _split(plan)
    assert positive and negative
    window = CATALOG.by_id("REP-054").params["high"]["window_min"] * 60
    assert max(e.eventtime for e in plan.events) <= ANCHOR + window


# -- SCEN-004: the staging host becomes the egress source ---------------------------------


@pytest.mark.parametrize("seed", (1, 7, 1337))
def test_scen004_joins_the_fanin_to_the_exfil_on_the_victim(seed: int) -> None:
    scenario = SCENARIOS.by_id("SCEN-004")
    composed = compose(scenario, CATALOG.by_id, ENGINE, seed, ANCHOR, ENTITIES)
    staging, exfil = composed.stages
    assert staging.technique_id == "REP-054" and exfil.technique_id == "REP-005"
    # The fan-in lands on the pinned victim and the exfil leaves from it.
    assert staging.top_dst == composed.victim, f"seed {seed}: fan-in did not land on the victim"
    assert exfil.top_src == composed.victim, f"seed {seed}: exfil did not leave from the victim"
    # The chain is ordered: every staging event precedes the exfil window.
    assert staging.end_epoch is not None and exfil.start_epoch is not None
    assert staging.end_epoch < exfil.start_epoch
    # Both tactics are covered and the phase transition is what the advisory names.
    text, coverage = build_advisory(scenario, composed, CATALOG)
    assert coverage["staging_pivot_stage_indices"] == [0]
    assert coverage["victim_stage_indices"] == [1]
    assert "TA0009 Collection" in coverage["covered_tactics"]
    assert "TA0010 Exfiltration" in coverage["covered_tactics"]
    assert f"`dst={composed.victim}` is the dominant destination in stage 0" in text
    assert "the host that collected the data becomes the host that sends it" in text


def test_scen004_pivot_is_measured_not_assumed() -> None:
    """A chain with no later victim-sourced stage carries no staging pivot even
    when the victim is a dominant destination: the join is the transition."""

    scenario = SCENARIOS.by_id("SCEN-004")
    composed = compose(scenario, CATALOG.by_id, ENGINE, 1337, ANCHOR, ENTITIES)
    only_staging = replace(composed, stages=composed.stages[:1])
    text, coverage = build_advisory(scenario, only_staging, CATALOG)
    assert coverage["staging_pivot_stage_indices"] == []
    assert "becomes the host that sends it" not in text
