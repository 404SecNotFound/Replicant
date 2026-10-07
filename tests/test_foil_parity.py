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
"""A benign foil must not be separable on a feature the catalog does not name.

v0.7.0 established that a benign foil is a correctness requirement, not
decoration: a foil a detection separates for free reports as coverage. A
measurement pass over seeds 1..25 at every preset found ten foils that were
separable on something other than the catalog's stated discriminator: byte
identical relay pairs, a bare ``.invalid`` suffix, constant byte and duration
values, one hard-coded port, a per-source load that was itself a scan, and a
count ceiling that never scaled with the preset.

This guard is a table, not one statistic. Each technique maps to the parity
checks its catalog entry implies, so a failure names the feature that leaked,
and every check runs over a spread of seeds at every preset because the seed is
part of the guard (a guard whose seed avoids the defect has never failed).

Positive control: every technique-specific check below was run against the
unfixed engine and observed to fail on the seeds and presets recorded in the
PR, then to pass after the fix.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

import pytest

from replicant.core.models import EventRecord, Technique, load_catalog
from replicant.entities.model import EntityModel
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import (
    BENIGN_DENIES_PER_MIN,
    BENIGN_HOSTS_PER_MIN,
    BENIGN_PORTS_PER_MIN,
    ScenarioEngine,
)

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
INTENSITIES = ("low", "medium", "high")
SEEDS = tuple(range(1, 21))
# Documentation parents and the reserved TLD are the only suffixes a synthetic
# DNS name may carry (CLAUDE.md safety rule 2).
ALLOWED_PARENTS = frozenset(ENTITIES.parents)

# REP-004 plans 72k to 192k events per preset and takes seconds per seed, and
# nothing here measures its duration, so the sweep prices it at one minute.
OVERRIDES: dict[str, dict[str, Any]] = {"REP-004": {"duration_min": 1}}


@dataclass(frozen=True)
class Streams:
    technique: Technique
    intensity: str
    seed: int
    preset: dict[str, Any]
    positive: list[EventRecord]
    negative: list[EventRecord]

    @property
    def tag(self) -> str:
        return f"{self.technique.id} {self.intensity} seed {self.seed}"


Check = Callable[[Streams], None]


def _streams(technique: Technique, intensity: str, seed: int) -> Streams:
    plan = ENGINE.plan(
        technique,
        intensity,
        ENTITIES,
        seed,
        param_overrides=OVERRIDES.get(technique.id),
    )
    return Streams(
        technique=technique,
        intensity=intensity,
        seed=seed,
        preset=plan.effective_params,
        positive=[e for e in plan.events if e.control == "positive"],
        negative=[e for e in plan.events if e.control == "negative"],
    )


# -- shared measurements -------------------------------------------------------


def _cv(values: Iterable[float]) -> float:
    data = list(values)
    if len(data) < 2:
        return 0.0
    mean = statistics.fmean(data)
    return statistics.pstdev(data) / mean if mean else 0.0


def _gaps(events: list[EventRecord]) -> list[int]:
    times = sorted(e.eventtime for e in events)
    return [later - earlier for earlier, later in zip(times, times[1:], strict=False)]


def _max_in_sliding_window(times: list[int], window_s: int) -> int:
    """Largest number of ``times`` inside any half-open window of ``window_s``."""

    ordered = sorted(times)
    best = 0
    start = 0
    for end, when in enumerate(ordered):
        while ordered[start] <= when - window_s:
            start += 1
        best = max(best, end - start + 1)
    return best


def _per_group_window_max(
    events: list[EventRecord], key: Callable[[EventRecord], Any], window_s: int = 60
) -> tuple[Any, int]:
    """(group, count) of the group with the densest 60 s window."""

    groups: dict[Any, list[int]] = defaultdict(list)
    for event in events:
        groups[key(event)].append(event.eventtime)
    worst = max(groups, key=lambda g: _max_in_sliding_window(groups[g], window_s))
    return worst, _max_in_sliding_window(groups[worst], window_s)


def _families(events: list[EventRecord]) -> set[tuple[str, str]]:
    return {(e.log_type, e.subtype) for e in events}


def _traffic(events: list[EventRecord]) -> list[EventRecord]:
    return [e for e in events if e.log_type == "traffic"]


def _relay_pairs(events: list[EventRecord]) -> list[tuple[EventRecord, EventRecord]]:
    """REP-024 (inbound, outbound) legs, paired by consecutive session id."""

    by_session = {e.session_id: e for e in events}
    pairs = []
    for event in events:
        if event.extra.get("src_intf") != "port1":
            continue
        partner = by_session.get((event.session_id or 0) + 1)
        if partner is not None and partner.src == event.dst:
            pairs.append((event, partner))
    return pairs


# -- checks shared by every foil technique --------------------------------------


def both_streams_present(s: Streams) -> None:
    assert s.positive and s.negative, f"{s.tag}: a stream is empty"


def foil_families_within_attack_families(s: Streams) -> None:
    extra = _families(s.negative) - _families(s.positive)
    assert not extra, f"{s.tag}: foil emits families the attack never does: {sorted(extra)}"


# -- REP-002 / REP-003 / REP-010: per-source load under a declared ceiling -----


def rep002_foil_pair_ports_under_benign_ceiling(s: Streams) -> None:
    pair, count = _per_group_window_max(s.negative, lambda e: (e.src, e.dst))
    assert count <= BENIGN_PORTS_PER_MIN, (
        f"{s.tag}: benign pair {pair} touched {count} distinct ports in 60 s, "
        f"ceiling {BENIGN_PORTS_PER_MIN}: the foil is itself a scan"
    )


def rep002_attack_still_scans(s: Streams) -> None:
    ports = defaultdict(set)
    for e in s.positive:
        ports[(e.src, e.dst)].add(e.dpt)
    assert max(map(len, ports.values())) == int(s.preset["unique_ports"])


def rep003_foil_source_hosts_under_benign_ceiling(s: Streams) -> None:
    src, count = _per_group_window_max(s.negative, lambda e: (e.src, e.dpt))
    assert count <= BENIGN_HOSTS_PER_MIN, (
        f"{s.tag}: benign source {src} reached {count} hosts in 60 s, "
        f"ceiling {BENIGN_HOSTS_PER_MIN}: the foil is itself a sweep"
    )


def rep003_attack_still_sweeps(s: Streams) -> None:
    assert len({e.dst for e in s.positive}) == int(s.preset["unique_hosts"])


def rep010_foil_source_denies_under_benign_ceiling(s: Streams) -> None:
    src, count = _per_group_window_max(s.negative, lambda e: e.src)
    assert count <= BENIGN_DENIES_PER_MIN, (
        f"{s.tag}: benign source {src} was denied {count} times in 60 s, "
        f"ceiling {BENIGN_DENIES_PER_MIN}: the foil is itself a burst"
    )


def rep010_attack_still_bursts(s: Streams) -> None:
    assert len({e.src for e in s.positive}) == 1
    assert len(s.positive) == int(s.preset["denies"])


def _ceiling_in_catalog(technique_id: str, ceiling: int, unit: str) -> Check:
    def check(s: Streams) -> None:
        text = s.technique.benign_baseline or ""
        assert f"{ceiling} {unit}" in text, (
            f"{technique_id}: benign_baseline does not state the enforced ceiling "
            f"'{ceiling} {unit}'"
        )

    return check


# -- REP-005: history windows share the current window's draws ------------------


def _rep005_windows(events: list[EventRecord]) -> list[list[EventRecord]]:
    """The four per-host buckets of one stream, oldest first.

    Each bucket holds exactly ``sessions`` events (three history windows and
    one current window per host), so the stream is split by count rather than
    by time: the first event of a window is jittered inside its slot, so a
    split at fixed time boundaries from the first event misfiles the edges.
    """

    ordered = sorted(events, key=lambda e: (e.eventtime, e.session_id or 0))
    size = len(ordered) // 4
    assert size * 4 == len(ordered), f"{len(ordered)} events do not form four windows"
    return [ordered[i * size : (i + 1) * size] for i in range(4)]


def rep005_history_bytes_vary_like_current(s: Streams) -> None:
    for name, stream in (("positive", s.positive), ("negative", s.negative)):
        windows = _rep005_windows(stream)
        assert len(windows) == 4, f"{s.tag}: {name} stream has {len(windows)} windows"
        current_cv = _cv(float(e.out_bytes or 0) for e in windows[-1])
        for index, window in enumerate(windows[:-1]):
            history_cv = _cv(float(e.out_bytes or 0) for e in window)
            assert history_cv >= 0.5 * current_cv, (
                f"{s.tag}: {name} history window {index} out_bytes CV {history_cv:.3f} "
                f"against current window CV {current_cv:.3f}: history is a constant"
            )


def rep005_no_window_is_an_exact_grid(s: Streams) -> None:
    if int(s.preset["sessions"]) < 3:
        return
    for name, stream in (("positive", s.positive), ("negative", s.negative)):
        for index, window in enumerate(_rep005_windows(stream)):
            spread = statistics.pstdev(_gaps(window))
            assert spread > 0, f"{s.tag}: {name} window {index} sits on an exact grid"


def rep005_history_stays_below_current(s: Streams) -> None:
    windows = _rep005_windows(s.positive)
    history = sum(e.out_bytes or 0 for w in windows[:-1] for e in w)
    current = sum(e.out_bytes or 0 for e in windows[-1])
    assert history < current * 0.05, f"{s.tag}: history is not a low-volume baseline"


# -- REP-007: the NAT foil carries comparable volume at every preset ------------


def rep007_foil_volume_comparable(s: Streams) -> None:
    ratio = len(s.negative) / len(s.positive)
    assert ratio >= 0.25, (
        f"{s.tag}: NAT foil is {len(s.negative)} events against {len(s.positive)} "
        f"attack events (ratio {ratio:.2f})"
    )


# -- REP-012: the update check lives inside the beacon's envelope --------------


def rep012_foil_bytes_in_beacon_envelope(s: Streams) -> None:
    low, high = (int(v) for v in s.preset["out_bytes"])
    for e in s.negative:
        assert low <= (e.out_bytes or 0) <= high and low <= (e.in_bytes or 0) <= high, (
            f"{s.tag}: foil bytes out={e.out_bytes} in={e.in_bytes} outside the "
            f"beacon envelope [{low}, {high}]"
        )


def rep012_foil_duration_in_beacon_envelope(s: Streams) -> None:
    # The beacon draws its session duration uniformly from 1..179 s; the foil
    # used to draw 1..19 s, so a 20 s duration threshold picked it out.
    foil = [int(e.extra["duration"]) for e in s.negative]
    assert 1 <= min(foil) and max(foil) <= 179, f"{s.tag}: foil duration outside 1..179 s"
    if len(foil) >= 8:
        assert max(foil) > 20, f"{s.tag}: foil durations capped at {max(foil)} s"


def rep012_foil_interval_matches_beacon(s: Streams) -> None:
    interval = float(s.preset["interval_s"])
    mean_gap = statistics.fmean(_gaps(s.negative))
    assert (
        abs(mean_gap - interval) <= 0.35 * interval
    ), f"{s.tag}: foil mean gap {mean_gap:.0f} s against beacon interval {interval:.0f} s"


# -- REP-013: the server baseline shares the worm's leg draws -------------------


def rep013_foil_bytes_vary(s: Streams) -> None:
    accepted = [e for e in s.negative if e.action == "accept"]
    assert len({e.out_bytes for e in accepted}) > 1, f"{s.tag}: foil out_bytes constant"
    assert len({e.extra["duration"] for e in accepted}) > 1, f"{s.tag}: foil duration constant"


def rep013_foil_actions_mixed(s: Streams) -> None:
    assert {e.action for e in s.negative} == {"accept", "deny"}, (
        f"{s.tag}: foil actions {sorted({e.action for e in s.negative})} against the "
        "worm's accept/deny mix"
    )


def rep013_foil_per_source_volume_scales_with_fanout(s: Streams) -> None:
    fanout = int(s.preset["fanout"])
    generations = int(s.preset["generations"])
    per_source = defaultdict(int)
    for e in s.negative:
        per_source[e.src] += 1
    lowest = min(per_source.values()) / generations
    assert lowest >= 0.75 * fanout, (
        f"{s.tag}: a benign server emits {lowest:.1f} probes per generation against "
        f"fanout {fanout}"
    )


def rep013_source_growth_preserved(s: Streams) -> None:
    gap = int(s.preset["gen_gap_s"])
    start = min(e.eventtime for e in s.positive)
    per_generation: dict[int, set[str]] = defaultdict(set)
    for e in s.positive:
        per_generation[(e.eventtime - start) // gap].add(str(e.src))
    counts = [len(per_generation[g]) for g in sorted(per_generation)]
    assert counts == sorted(counts) and counts[-1] > counts[0], f"{s.tag}: no growth {counts}"


# -- REP-018: star legs share the chain's port and byte draws -------------------


def rep018_star_ports_match_chain_ports(s: Streams) -> None:
    chain = {e.dpt for e in _traffic(s.positive)}
    star = {e.dpt for e in _traffic(s.negative)}
    assert star == chain, f"{s.tag}: star ports {sorted(star)} against chain {sorted(chain)}"


def rep018_star_bytes_overlap_chain_bytes(s: Streams) -> None:
    # A chain has two to six legs, too few for a distribution test, so the
    # check is that the legs are not constants and that the star sits inside
    # the chain's envelope (the shared draw is clipped to a 2.6:1 range, so a
    # 2.7:1 band around the chain median admits every honest draw and rejects
    # a star drawn from a different range).
    chain = [int(e.out_bytes or 0) for e in _traffic(s.positive)]
    star = [int(e.out_bytes or 0) for e in _traffic(s.negative)]
    median = statistics.median(chain)
    assert all(0.35 * median <= value <= 2.7 * median for value in star), (
        f"{s.tag}: star out_bytes {min(star)}..{max(star)} outside the chain's "
        f"envelope around {median:.0f}"
    )
    if len(chain) + len(star) >= 4:
        assert (
            len(set(chain) | set(star)) > 2
        ), f"{s.tag}: legs carry constants {sorted(set(chain) | set(star))}"


# -- REP-019: sparse benign denies across several sources and ports ------------


def rep019_foil_sources_several(s: Streams) -> None:
    sources = {e.src for e in s.negative}
    assert len(sources) >= 2, f"{s.tag}: foil is one source {sources}"


def rep019_foil_ports_span_attack_ports(s: Streams) -> None:
    attack = {e.dpt for e in s.positive}
    foil = {e.dpt for e in s.negative}
    assert (
        foil <= attack and len(foil) >= 3
    ), f"{s.tag}: foil ports {sorted(foil)} against attack {sorted(attack)}"


def rep019_foil_gaps_random(s: Streams) -> None:
    cv = _cv(_gaps(s.negative))
    assert cv > 0.1, f"{s.tag}: foil gaps are fixed spacing (CV {cv:.3f})"


def rep019_foil_count_scales(s: Streams) -> None:
    ratio = len(s.negative) / len(s.positive)
    assert ratio >= 0.5, f"{s.tag}: foil {len(s.negative)} vs {len(s.positive)} probes"


# -- REP-023: the catalog states what separates browsing from the beacon --------


def rep023_foil_timing_irregular(s: Streams) -> None:
    cv = _cv(_gaps(s.negative))
    assert cv > 0.2, f"{s.tag}: browsing foil is as periodic as the beacon (gap CV {cv:.3f})"


def rep023_foil_port_and_count_match(s: Streams) -> None:
    assert {e.dpt for e in s.negative} == {e.dpt for e in s.positive} == {443}
    assert len(s.negative) == len(s.positive)


def rep023_catalog_states_discriminators(s: Streams) -> None:
    text = s.technique.benign_baseline or ""
    assert "neither port nor destination count" not in text, (
        "REP-023: benign_baseline claims destination count cannot separate the streams, "
        "but the beacon is one destination and the browsing is many"
    )
    assert "per-pair" in text and "destination count" in text, (
        "REP-023: benign_baseline must name destination count and per-pair session "
        "count as legitimate discriminators"
    )


# -- REP-024: the sanctioned proxy is the same pattern at the same scale --------


def rep024_foil_pairs_not_byte_identical(s: Streams) -> None:
    pairs = _relay_pairs(s.negative)
    assert pairs, f"{s.tag}: no foil pairs"
    identical = sum(1 for a, b in pairs if a.out_bytes == b.out_bytes and a.in_bytes == b.in_bytes)
    attack_pairs = _relay_pairs(s.positive)
    attack_identical = sum(
        1 for a, b in attack_pairs if a.out_bytes == b.out_bytes and a.in_bytes == b.in_bytes
    )
    assert identical / len(pairs) <= 0.2, (
        f"{s.tag}: {identical}/{len(pairs)} foil pairs are byte-identical against "
        f"{attack_identical}/{len(attack_pairs)} attack pairs"
    )


def rep024_foil_pair_count_scales(s: Streams) -> None:
    foil = len(_relay_pairs(s.negative))
    attack = len(_relay_pairs(s.positive))
    assert foil >= 0.5 * attack, f"{s.tag}: {foil} foil pairs against {attack} relay pairs"


# -- the table ------------------------------------------------------------------

COMMON: list[Check] = [both_streams_present, foil_families_within_attack_families]

CHECKS: dict[str, list[Check]] = {
    "REP-002": [
        rep002_foil_pair_ports_under_benign_ceiling,
        rep002_attack_still_scans,
        _ceiling_in_catalog("REP-002", BENIGN_PORTS_PER_MIN, "distinct ports per minute"),
    ],
    "REP-003": [
        rep003_foil_source_hosts_under_benign_ceiling,
        rep003_attack_still_sweeps,
        _ceiling_in_catalog("REP-003", BENIGN_HOSTS_PER_MIN, "distinct hosts per minute"),
    ],
    "REP-005": [
        rep005_history_bytes_vary_like_current,
        rep005_no_window_is_an_exact_grid,
        rep005_history_stays_below_current,
    ],
    "REP-007": [rep007_foil_volume_comparable],
    "REP-010": [
        rep010_foil_source_denies_under_benign_ceiling,
        rep010_attack_still_bursts,
        _ceiling_in_catalog("REP-010", BENIGN_DENIES_PER_MIN, "denies per minute"),
    ],
    "REP-012": [
        rep012_foil_bytes_in_beacon_envelope,
        rep012_foil_duration_in_beacon_envelope,
        rep012_foil_interval_matches_beacon,
    ],
    "REP-013": [
        rep013_foil_bytes_vary,
        rep013_foil_actions_mixed,
        rep013_foil_per_source_volume_scales_with_fanout,
        rep013_source_growth_preserved,
    ],
    "REP-018": [rep018_star_ports_match_chain_ports, rep018_star_bytes_overlap_chain_bytes],
    "REP-019": [
        rep019_foil_sources_several,
        rep019_foil_ports_span_attack_ports,
        rep019_foil_gaps_random,
        rep019_foil_count_scales,
    ],
    "REP-023": [
        rep023_foil_timing_irregular,
        rep023_foil_port_and_count_match,
        rep023_catalog_states_discriminators,
    ],
    "REP-024": [rep024_foil_pairs_not_byte_identical, rep024_foil_pair_count_scales],
}

FOIL_TECHNIQUES = [t for t in CATALOG.techniques if t.emits_foil]


def test_every_table_row_is_a_foil_technique() -> None:
    assert set(CHECKS) <= {t.id for t in FOIL_TECHNIQUES}


@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("technique", FOIL_TECHNIQUES, ids=lambda t: t.id)
def test_foil_is_not_separable_on_an_unnamed_feature(technique: Technique, intensity: str) -> None:
    failures: list[str] = []
    for seed in SEEDS:
        streams = _streams(technique, intensity, seed)
        for check in COMMON + CHECKS.get(technique.id, []):
            try:
                check(streams)
            except AssertionError as error:
                failures.append(f"{check.__name__}: {error}")
    assert not failures, "\n".join(failures[:6] + ([f"... {len(failures)} total"]))


# -- REP-020: an embedded baseline, held to the same bar ------------------------
#
# REP-020 has no standalone foil (its baseline is embedded in the positive
# stream), so it is outside the table above, but the same leak applied: every
# baseline name sat under one parent and every novel name was a bare
# ``<label>.invalid``, so "qname not under the baseline parent" scored perfectly
# without any notion of first contact.


def _rep020_names(intensity: str, seed: int) -> tuple[list[str], list[str], dict[str, Any]]:
    technique = CATALOG.by_id("REP-020")
    plan = ENGINE.plan(technique, intensity, ENTITIES, seed)
    names = [str(e.extra["qname"]) for e in plan.events]
    baseline_events = int(plan.effective_params["baseline_domains"])
    return names[:baseline_events], names[baseline_events:], plan.effective_params


def _parent(qname: str) -> str:
    return qname.split(".", 1)[1]


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep020_novel_names_share_the_baseline_parent_pool(intensity: str) -> None:
    for seed in SEEDS:
        baseline, novel, preset = _rep020_names(intensity, seed)
        tag = f"REP-020 {intensity} seed {seed}"
        assert len(novel) == int(preset["novel_domains"]), tag
        baseline_parents = {_parent(q) for q in baseline}
        novel_parents = {_parent(q) for q in novel}
        assert baseline_parents | novel_parents <= ALLOWED_PARENTS, (
            f"{tag}: parents {sorted((baseline_parents | novel_parents) - ALLOWED_PARENTS)} "
            "are not documentation parents"
        )
        assert len(baseline_parents) > 1, f"{tag}: baseline uses one parent {baseline_parents}"
        assert novel_parents <= baseline_parents, (
            f"{tag}: novel parents {sorted(novel_parents)} are not baseline parents "
            f"{sorted(baseline_parents)}"
        )
        baseline_labels = {q.split(".", 1)[0] for q in baseline}
        novel_labels = [q.split(".", 1)[0] for q in novel]
        assert not baseline_labels & set(novel_labels), f"{tag}: a novel name was queried before"
        assert len(set(novel_labels)) == len(novel_labels), f"{tag}: novel labels repeat"
        lengths = {len(label) for label in baseline_labels}
        assert all(len(label) in lengths for label in novel_labels), (
            f"{tag}: novel label lengths {[len(x) for x in novel_labels]} fall outside the "
            f"baseline range {min(lengths)}..{max(lengths)}"
        )
