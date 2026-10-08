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
"""REP-052: a ransomware-like SMB write fan-out (Impact, T1486).

What the catalog promises and this file measures, over seeds and presets:

- one source from the workstation pool, not the server pool, opens accepted
  sessions on tcp/445 to a number of distinct internal file servers inside the
  preset's range, with the preset's sessions per share, every session closing
  inside the window;
- every session is large in both directions and out is at least in, inside the
  catalog's stated ratio;
- the benign foil is the same fan-out from the server pool: same share count
  range, same sessions per share, same byte and duration draws, same write-to-
  read ratio, same irregular timing, and the only feature that separates it is
  the source's asset role;
- the records render as the existing traffic:forward accept on all three
  vendors, so no profile changed;
- ``--duration`` sets the window and preserves the share count, and the engine's
  ceiling binds the count rather than the window.

Positive controls (recorded in the PR): with the foil drawn from the workstation
pool the role guard went red on every seed; with the foil written in-heavy (the
backup-pull foil the backlog had sketched) the ratio parity guard went red on
every seed.
"""

from __future__ import annotations

import math
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
    SMB_PORT,
    SMB_WRITE_DURATION_S,
    SMB_WRITE_RATIO,
    ScenarioEngine,
)

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTENSITIES = ("low", "medium", "high")
SERVERS = set(ENTITIES.server_hosts)
WORKSTATIONS = set(ENTITIES.internal_hosts)
TARGETS = set(ENTITIES.internal_targets)


def _plan(intensity: str, seed: int, **kwargs):
    return ENGINE.plan(
        CATALOG.by_id("REP-052"), intensity, ENTITIES, seed, anchor_epoch=ANCHOR, **kwargs
    )


def _split(plan):
    positive = [e for e in plan.events if e.control == "positive"]
    negative = [e for e in plan.events if e.control != "positive"]
    return positive, negative


def _shape(events, preset, tag: str) -> None:
    """The structural promises both streams share."""

    shares_lo, shares_hi = preset["shares"]
    sps_lo, sps_hi = preset["sessions_per_share"]
    window = preset["window_min"] * 60
    sources = {e.src for e in events}
    assert len(sources) == 1, f"{tag}: {len(sources)} sources"
    assert all(e.log_type == "traffic" and e.subtype == "forward" for e in events)
    assert all(e.action == "accept" and e.dpt == SMB_PORT and e.proto == 6 for e in events)
    assert all(e.extra["service"] == "SMB" for e in events)
    destinations = {e.dst for e in events}
    assert destinations <= TARGETS, f"{tag}: a destination is outside the file-server pool"
    assert (
        shares_lo <= len(destinations) <= shares_hi
    ), f"{tag}: {len(destinations)} shares outside [{shares_lo}, {shares_hi}]"
    per_share = Counter(e.dst for e in events)
    assert all(sps_lo <= n <= sps_hi for n in per_share.values()), (
        f"{tag}: sessions per share {sorted(set(per_share.values()))} outside "
        f"[{sps_lo}, {sps_hi}]"
    )
    for e in events:
        assert e.out_bytes is not None and e.in_bytes is not None
        ratio = e.out_bytes / e.in_bytes
        assert (
            SMB_WRITE_RATIO[0] - 0.01 <= ratio <= SMB_WRITE_RATIO[1] + 0.01
        ), f"{tag}: write-to-read ratio {ratio:.2f}"
        assert int(e.extra["duration"]) <= min(SMB_WRITE_DURATION_S[1], window)
        assert (
            ANCHOR < e.eventtime <= ANCHOR + window
        ), f"{tag}: a session closed outside the window"


# -- the attack --------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_one_workstation_writes_to_many_shares_inside_the_window(intensity: str, seed: int) -> None:
    preset = CATALOG.by_id("REP-052").params[intensity]
    positive, _ = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(positive, preset, tag)
    source = positive[0].src
    assert source in WORKSTATIONS, f"{tag}: the source is not a workstation"
    assert source not in SERVERS, f"{tag}: the source is in the server pool"


# -- the foil ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_foil_is_the_same_fanout_from_the_server_pool(intensity: str, seed: int) -> None:
    preset = CATALOG.by_id("REP-052").params[intensity]
    positive, negative = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    _shape(negative, preset, f"{tag} foil")
    assert negative[0].src in SERVERS, f"{tag}: the foil did not come from the server pool"
    assert negative[0].src != positive[0].src
    # Same timing shape: both fan-outs are irregular, neither is a metronome.
    for label, events in (("attack", positive), ("foil", negative)):
        times = sorted(e.eventtime for e in events)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        if len(gaps) >= 4:
            cv = statistics.pstdev(gaps) / max(statistics.mean(gaps), 1e-9)
            assert cv > 0.2, f"{tag}: {label} fan-out is a metronome (gap CV {cv:.2f})"


def test_role_is_the_only_separating_feature_pooled_over_seeds() -> None:
    """Share counts, sessions per share, bytes, write-to-read ratio and duration
    pooled over seeds at medium: the two streams are drawn from the same
    distributions, and a detection that ignores the source's role has nothing
    to key on. An in-heavy foil (a backup pull) fails the ratio line."""

    p_shares: list[int] = []
    n_shares: list[int] = []
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
        p_shares.append(len({e.dst for e in positive}))
        n_shares.append(len({e.dst for e in negative}))
        p_sessions.append(len(positive))
        n_sessions.append(len(negative))
        p_log_out.extend(math.log(e.out_bytes or 1) for e in positive)
        n_log_out.extend(math.log(e.out_bytes or 1) for e in negative)
        p_ratio.extend((e.out_bytes or 0) / (e.in_bytes or 1) for e in positive)
        n_ratio.extend((e.out_bytes or 0) / (e.in_bytes or 1) for e in negative)
        p_duration.extend(int(e.extra["duration"]) for e in positive)
        n_duration.extend(int(e.extra["duration"]) for e in negative)
    assert abs(statistics.mean(p_shares) - statistics.mean(n_shares)) < 4
    assert abs(statistics.mean(p_sessions) - statistics.mean(n_sessions)) < 8
    assert abs(statistics.mean(p_log_out) - statistics.mean(n_log_out)) < 0.15
    assert abs(statistics.mean(p_ratio) - statistics.mean(n_ratio)) < 0.03, (
        f"write-to-read ratio separates the streams: attack {statistics.mean(p_ratio):.3f} "
        f"foil {statistics.mean(n_ratio):.3f}"
    )
    assert abs(statistics.mean(p_duration) - statistics.mean(n_duration)) < 20


# -- rendering -------------------------------------------------------------------------


def test_the_fanout_renders_as_the_existing_traffic_record_on_every_vendor() -> None:
    positive, _ = _split(_plan("medium", 1337))
    event = positive[0]

    header, fgt = FortiGateProfile().render(event)
    assert header.signature_id == "00013"
    assert fgt["dpt"] == str(SMB_PORT) and fgt["FTNTFGTservice"] == "SMB"
    assert fgt["act"] == "accept"
    assert int(fgt["out"]) >= int(fgt["in"]) > 0

    pan_header, pan = PaloAltoProfile().render(event)
    assert pan["dpt"] == str(SMB_PORT) and int(pan["out"]) >= int(pan["in"]) > 0

    cp_header, cp = CheckPointProfile().render(event)
    assert cp["dpt"] == str(SMB_PORT)


# -- duration and the ceiling -------------------------------------------------------------


def test_duration_sets_the_window_and_keeps_the_share_count(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    natural = orch.build_plan(RunRequest(technique_id="REP-052", intensity="medium", seed=7))
    short = orch.build_plan(
        RunRequest(technique_id="REP-052", intensity="medium", seed=7, duration="2m")
    )
    nat_shares = {e.dst for e in natural.events if e.control == "positive"}
    short_shares = {e.dst for e in short.events if e.control == "positive"}
    assert len(short_shares) == len(nat_shares)
    positives = [e for e in short.events if e.control == "positive"]
    assert max(e.eventtime for e in positives) - natural.anchor_epoch <= 120


def test_the_ceiling_binds_the_share_count_not_the_window() -> None:
    plan = ScenarioEngine(max_events=40).plan(
        CATALOG.by_id("REP-052"), "high", ENTITIES, 3, anchor_epoch=ANCHOR
    )
    assert plan.truncated
    assert len(plan.events) <= 40
    positive, negative = _split(plan)
    assert positive and negative
    window = CATALOG.by_id("REP-052").params["high"]["window_min"] * 60
    assert max(e.eventtime for e in plan.events) <= ANCHOR + window
