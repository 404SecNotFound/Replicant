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
"""Guards for the 2026-09-26 review findings against the scenario engine.

Every test here was run against the unfixed engine and observed to fail on the
seed and preset named in its docstring, then to pass after the fix (CLAUDE.md,
"a new guard must be run against the unfixed code").
"""

from __future__ import annotations

import cmath
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import pytest

from replicant.core.models import EventRecord, Technique, load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.composer import compose
from replicant.scenario.engine import DEFAULT_ANCHOR_EPOCH, ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
INTENSITIES = ("low", "medium", "high")
PROFILES = {
    "fortigate": FortiGateProfile(),
    "paloalto": PaloAltoProfile(),
    "checkpoint": CheckPointProfile(),
}
_DUBAI = timezone(timedelta(hours=4))


def _plan(
    technique_id: str,
    intensity: str,
    seed: int = 1337,
    *,
    anchor: int = DEFAULT_ANCHOR_EPOCH,
    duration_s: int | None = None,
    **overrides: object,
):
    return ENGINE.plan(
        CATALOG.by_id(technique_id),
        intensity,
        ENTITIES,
        seed,
        anchor_epoch=anchor,
        duration_override_s=duration_s,
        param_overrides=overrides or None,
    )


# -- 1. every plan is emitted in time order -----------------------------------


@pytest.mark.parametrize("vendor", sorted(PROFILES))
@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda t: t.id)
def test_every_plan_is_non_decreasing_in_event_time(
    technique: Technique, intensity: str, vendor: str
) -> None:
    """The whole catalog, every preset, rendered through every vendor.

    REP-006 and REP-007 appended their foil after the attack without sorting, so
    at seed 1337 medium the plan stepped backwards: --to-file wrote a
    non-monotonic log and plan pacing sent each foil event up to a whole window
    late. The rendered time is checked too, because the emitter sends in list
    order and a profile is where rt is produced.
    """

    plan = _plan(technique.id, intensity)
    times = [event.eventtime for event in plan.events]
    assert times == sorted(times), f"{technique.id} {intensity} plan steps backwards"
    profile = PROFILES[vendor]
    sample = plan.events[:: max(1, len(plan.events) // 400)]
    rendered = [int(profile.render(event)[1].get("rt", event.eventtime)) for event in sample]
    assert rendered == sorted(rendered)


@pytest.mark.parametrize("scenario", SCENARIOS.scenarios, ids=lambda s: s.id)
def test_every_scenario_is_non_decreasing_in_event_time(scenario) -> None:
    composed = compose(scenario, CATALOG.by_id, ENGINE, 1337, DEFAULT_ANCHOR_EPOCH, ENTITIES)
    times = [event.eventtime for event in composed.events]
    assert times == sorted(times)


# -- 2. DNS foil labels cannot be separated by a prefix regex ------------------


def _prefix_counts(labels: list[str], length: int) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for label in labels:
        counts[label[:length]] += 1
    return counts


def _best_single_prefix(target: list[str], other: list[str], length: int) -> float:
    """Best min(precision, recall) of one rule 'label starts with P' at picking ``target``."""

    hits = _prefix_counts(target, length)
    misses = _prefix_counts(other, length)
    best = 0.0
    for prefix, tp in hits.items():
        precision = tp / (tp + misses.get(prefix, 0))
        recall = tp / len(target)
        best = max(best, min(precision, recall))
    return best


def _best_prefix_alternation(target: list[str], other: list[str], length: int) -> float:
    """min(precision, recall) of the best alternation of ``length``-char prefixes.

    Keeps every prefix more common in ``target`` than in ``other``, which is the
    ``^(hs|id|tx)`` regex an analyst writes after one look at the two streams.
    """

    hits = _prefix_counts(target, length)
    misses = _prefix_counts(other, length)
    chosen = [p for p in hits if hits[p] / len(target) > misses.get(p, 0) / len(other)]
    tp = sum(hits[p] for p in chosen)
    fp = sum(misses.get(p, 0) for p in chosen)
    return 0.0 if tp == 0 else min(tp / (tp + fp), tp / len(target))


@pytest.mark.parametrize("technique_id", ["REP-004", "REP-015"])
@pytest.mark.parametrize("seed", [1337, 7, 42, 2026])
def test_dns_foil_is_not_separable_by_a_leading_label_prefix(technique_id: str, seed: int) -> None:
    """Cardinality is the catalog's only intended discriminator.

    Every attack label began hs/id/tx and every foil label began sv, so at seed
    1337 low the single prefix ``sv`` picked the foil with precision and recall
    1.0. No fixed prefix of 2..6 characters (6 is the whole tag plus counter the
    engine writes) may pick either stream with precision and recall both above
    0.8, and no alternation of 2..4 character prefixes may either. At 5 and 6
    characters an alternation is a lookup table of individual foil labels, which
    IS the cardinality difference, so it is not held to this bar.
    """

    events = _plan(technique_id, "low", seed).events
    positive = [str(e.extra["qname"]).split(".")[0] for e in events if e.control == "positive"]
    negative = [str(e.extra["qname"]).split(".")[0] for e in events if e.control == "negative"]
    assert positive and negative
    for target, other, name in ((positive, negative, "attack"), (negative, positive, "foil")):
        for length in range(2, 7):
            score = _best_single_prefix(target, other, length)
            assert score <= 0.8, (
                f"{technique_id} seed {seed}: one {length}-char prefix picks the {name} "
                f"stream with precision and recall >= {score:.2f}"
            )
        for length in range(2, 5):
            score = _best_prefix_alternation(target, other, length)
            assert score <= 0.8, (
                f"{technique_id} seed {seed}: a {length}-char prefix alternation picks the "
                f"{name} stream with precision and recall >= {score:.2f}"
            )
    # Cardinality, the intended discriminator, is untouched.
    assert len(set(positive)) > 4 * len(set(negative))


# -- 3. REP-012 fleet period is recoverable and the foil is not a comb --------


def _rayleigh(times: list[int], period: float) -> float:
    """Rayleigh statistic of event phases at ``period``: |sum e^(2 pi i t/P)|^2 / n.

    About 1 for times with no structure at that period, about n for a perfect
    comb. Summing it over hosts is the fleet-level aggregation the catalog
    describes: each host's weak evidence adds up at the shared period.
    """

    total = sum(cmath.exp(2j * math.pi * t / period) for t in times)
    return abs(total) ** 2 / len(times)


def _cv(times: list[int]) -> float:
    ordered = sorted(times)
    gaps = [later - earlier for earlier, later in zip(ordered, ordered[1:], strict=False)]
    return statistics.pstdev(gaps) / statistics.fmean(gaps)


@pytest.mark.parametrize("intensity", ["medium", "high"])
@pytest.mark.parametrize("seed", [1337, 1, 2, 3, 4])
def test_rep012_fleet_period_is_recoverable_from_the_aggregate(intensity: str, seed: int) -> None:
    """Fleet mode: the period must be in the fleet aggregate, which is the whole technique.

    Each host's callbacks used to random-walk (offset += jittered interval), so
    the fleet's arrivals were random: at seed 1337 medium the summed Rayleigh
    z-score at the preset period was below zero. The bar is z >= 4, about 1 in
    30,000 by chance.
    """

    preset = CATALOG.by_id("REP-012").params[intensity]
    period = float(preset["interval_s"])
    by_host: dict[str, list[int]] = defaultdict(list)
    for event in _plan("REP-012", intensity, seed).events:
        if event.control == "positive":
            by_host[str(event.src)].append(event.eventtime)
    hosts = len(by_host)
    assert hosts == int(preset["hosts"])
    aggregate = sum(_rayleigh(times, period) for times in by_host.values())
    z = (aggregate - hosts) / math.sqrt(hosts)
    assert z >= 4.0, f"fleet period not recoverable at {intensity} seed {seed}: z={z:.1f}"


@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("seed", [1337, 1, 2, 3, 4])
def test_rep012_foil_is_not_a_perfect_comb(intensity: str, seed: int) -> None:
    """The update-check foil used to be exactly every 1800 s, gap CV 0.

    That made it the most periodic flow in the plan, so a naive per-flow
    periodicity test flagged the benign control more strongly than any attack
    host: the control rewarded the wrong detector. It now carries the beacon's
    own jitter process, so its per-flow gap CV comes from the same distribution
    as the attack hosts'. The update check sees only 8 to 24 gaps per run, so its
    sample CV is noisy; the comparative bar is 0.4 of the attack median rather
    than parity, which still fails the old comb by an unbounded margin.
    """

    flows: dict[tuple[str, str], list[int]] = defaultdict(list)
    controls: dict[tuple[str, str], str] = {}
    for event in _plan("REP-012", intensity, seed).events:
        key = (str(event.src), str(event.dst))
        flows[key].append(event.eventtime)
        controls[key] = event.control
    foil = [times for key, times in flows.items() if controls[key] == "negative"]
    attack = [times for key, times in flows.items() if controls[key] == "positive"]
    assert len(foil) == 1
    foil_cv = _cv(foil[0])
    attack_cv = statistics.median(_cv(times) for times in attack)
    assert foil_cv > 0.05, f"foil is a near-perfect comb: gap CV {foil_cv:.3f}"
    assert foil_cv >= attack_cv * 0.4, (
        f"foil far more periodic than the attack: foil CV {foil_cv:.3f}, "
        f"attack median CV {attack_cv:.3f}"
    )


# -- 6. severity never falls as the kill chain advances -----------------------


def _severity_rank(value: int | str) -> int:
    if isinstance(value, int):
        return value
    return ["Unknown", "Low", "Medium", "High", "Very-High"].index(value)


@pytest.mark.parametrize("vendor", sorted(PROFILES))
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep022_header_severity_ascends_on_every_vendor(vendor: str, intensity: str) -> None:
    """Catalog: 'ascending across stages, so a severity-weighted rule sees escalation'.

    FortiGate rendered 4,7,7,6,6 at seed 1337 high: FortiOS reverses priority,
    so level 'critical' is CEF 6, below 'alert' at 7, and the C2 and exfil
    stages de-escalated. Header severity must be non-decreasing through the
    chain and strictly rise wherever ips_severity rises.
    """

    profile = PROFILES[vendor]
    chain = [event for event in _plan("REP-022", intensity).events if "stage" in event.extra]
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    previous: tuple[int, int] | None = None
    for event in chain:
        header, _ = profile.render(event)
        current = (rank[str(event.extra["ips_severity"])], _severity_rank(header.severity))
        if previous is not None:
            assert current[1] >= previous[1], f"{vendor} severity fell: {previous} -> {current}"
            if current[0] > previous[0]:
                assert current[1] > previous[1], f"{vendor} did not rise with ips_severity"
        previous = current


@pytest.mark.parametrize("vendor", sorted(PROFILES))
def test_rep009_critical_hits_never_render_below_high_hits(vendor: str) -> None:
    """REP-009 had the same inversion: critical hits at CEF 6, high hits at 7 on FortiGate."""

    profile = PROFILES[vendor]
    by_severity: dict[str, set[int]] = defaultdict(set)
    for event in _plan("REP-009", "medium").events:
        header, _ = profile.render(event)
        by_severity[str(event.extra["ips_severity"])].add(_severity_rank(header.severity))
    assert min(by_severity["critical"]) >= max(by_severity["high"])


# -- 7. REP-005 finds the next off-hours window, never an earlier one ----------


def _at(hour: int, minute: int = 0) -> int:
    return int(datetime(2025, 7, 15, hour, minute, tzinfo=_DUBAI).timestamp())


@pytest.mark.parametrize(
    ("anchor_hour", "anchor_minute", "expect_same_day"),
    [
        (0, 0, True),  # at the window start
        (2, 30, True),  # inside the window, enough of it left
        (5, 30, False),  # inside, but less than an hour left: tonight's window
        (6, 0, False),  # the window just closed
        (14, 0, False),  # the review case: --anchor now in the afternoon
        (23, 40, False),  # the fixed default anchor's local time
    ],
)
def test_rep005_never_plans_before_its_anchor(
    anchor_hour: int, anchor_minute: int, expect_same_day: bool
) -> None:
    """--anchor now at 14:00 produced events 8 to 14 hours in the past.

    The window used 00:00 of the anchor's OWN day, so with plan pacing that
    history was sent at once, breaking 'an event is sent at the moment its own
    timestamp says it happened'. Anchors before, inside and after the window.
    The CLAUDE.md rule still holds: every event is inside 00:00-06:00.
    """

    anchor = _at(anchor_hour, anchor_minute)
    plan = _plan("REP-005", "low", anchor=anchor)
    times = [event.eventtime for event in plan.events]
    assert min(times) >= anchor, f"REP-005 planned {anchor - min(times)}s before its anchor"
    for when in times:
        local = datetime.fromtimestamp(when, _DUBAI)
        assert local.hour < 6 or (local.hour == 6 and local.minute == 0 and local.second == 0)
    first_day = datetime.fromtimestamp(min(times), _DUBAI).date()
    anchor_day = datetime.fromtimestamp(anchor, _DUBAI).date()
    assert (first_day == anchor_day) is expect_same_day
    assert max(times) - min(times) <= 6 * 3600


def test_rep005_inside_the_window_is_capped_at_what_remains() -> None:
    """A pinned window outranks the requested duration: from 02:30 only 3.5h remain."""

    anchor = _at(2, 30)
    plan = _plan("REP-005", "medium", anchor=anchor, duration_s=5 * 3600)
    times = [event.eventtime for event in plan.events]
    assert min(times) >= anchor
    assert max(times) <= _at(6, 0)


# -- 8. REP-008 says its history is compressed --------------------------------


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep008_note_states_the_history_is_compressed(intensity: str) -> None:
    """The note claimed '<N> known destinations over 30d' for history inside 3600 s.

    Decision (2026-09-26): keep the compression, correct the claim. Spreading
    the baseline over baseline_days of event time would make plan pacing take
    those days of wall clock and put the first contact weeks after the anchor.
    """

    plan = _plan("REP-008", intensity)
    days = int(CATALOG.by_id("REP-008").params[intensity]["baseline_days"])
    times = [event.eventtime for event in plan.events]
    assert max(times) - min(times) < 2 * 3600, "history span changed; revisit the note"
    assert plan.warmup_note is not None
    assert "compressed" in plan.warmup_note
    assert f"over {days}d" not in plan.warmup_note
    technique = CATALOG.by_id("REP-008")
    assert "compressed" in str(technique.distributions.get("baseline_time", ""))


# -- 9. a foil entity is never an attack entity -------------------------------

_SEEDS = range(500)


def _positive_negative(events: list[EventRecord]) -> tuple[list[EventRecord], list[EventRecord]]:
    return (
        [event for event in events if event.control == "positive"],
        [event for event in events if event.control == "negative"],
    )


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep012_foil_source_is_never_a_beaconing_host(intensity: str) -> None:
    """Collided on 15.5% of seeds at high: the 'benign' update checker was a C2 host.

    Planned for one interval, which is enough for every fleet host to call back
    once, so the positive stream names the whole fleet without the full preset.
    """

    period = int(CATALOG.by_id("REP-012").params[intensity]["interval_s"])
    collisions = []
    for seed in _SEEDS:
        positive, negative = _positive_negative(
            _plan("REP-012", intensity, seed, duration_s=period).events
        )
        if {e.src for e in negative} & {e.src for e in positive}:
            collisions.append(seed)
    assert collisions == [], f"REP-012 {intensity}: foil source beacons on seeds {collisions[:10]}"


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep019_foil_source_is_never_a_probe_source(intensity: str) -> None:
    """Collided on 6.4% of seeds at high: pool[-1] was also in the rotating probe pool.

    total_probes is overridden to exactly one rotation of the pool, which leaves
    the pool draw untouched (it is the builder's first draw) and puts every
    rotating source in the positive stream.
    """

    preset = CATALOG.by_id("REP-019").params[intensity]
    rotation = int(preset["src_pool"]) * int(preset["probes_per_dst"])
    collisions = []
    for seed in _SEEDS:
        positive, negative = _positive_negative(
            _plan("REP-019", intensity, seed, total_probes=rotation).events
        )
        assert len({e.src for e in positive}) == int(preset["src_pool"])
        if {e.src for e in negative} & {e.src for e in positive}:
            collisions.append(seed)
    assert collisions == [], f"REP-019 {intensity}: foil source probes on seeds {collisions[:10]}"


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep018_star_source_is_never_on_the_chain(intensity: str) -> None:
    """Collided on 3.8% of seeds: the admin star source sat on the lateral chain."""

    collisions = []
    for seed in _SEEDS:
        positive, negative = _positive_negative(_plan("REP-018", intensity, seed).events)
        chain_hosts = {e.src for e in positive} | {e.dst for e in positive}
        star_sources = {e.src for e in negative}
        if star_sources & chain_hosts:
            collisions.append(seed)
    assert collisions == [], f"REP-018 {intensity}: star source on chain, seeds {collisions[:10]}"


@pytest.mark.parametrize("intensity", INTENSITIES)
def test_rep024_sanctioned_proxy_is_never_the_relay(intensity: str) -> None:
    """Collided on 0.4% of seeds: the sanctioned proxy WAS the unsanctioned relay.

    One seed in 254 collides and the first 500 seeds happen to contain none (the
    first is 593), so this guard runs 1000 seeds. It is cheap at relay_pairs=2.
    """

    collisions = []
    for seed in range(1000):
        # relay_pairs does not move the relay draw (the builder's first draw).
        positive, negative = _positive_negative(
            _plan("REP-024", intensity, seed, relay_pairs=2).events
        )
        relays = {e.dst for e in positive if e.dpt == 8080}
        sanctioned = {e.dst for e in negative if e.dpt == 8080}
        if relays & sanctioned:
            collisions.append(seed)
    assert collisions == [], f"REP-024 {intensity}: proxy is relay on seeds {collisions[:10]}"
