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
"""Structural false-positive foils (roadmap 2026-09 item 9).

The existing foils and the continuous baseline add benign VOLUME; these break the
aggregation KEY, which is where REP-006 (source fan-out) and REP-007 (per-source
auth failures) actually fail in production. A foil that a detection separates for
free is worse than none, so each foil here must be:
  - inseparable by the naive key it targets (source fan-out count / per-source
    login count), so a rule using that key alone fires on it, and
  - inseparable by time (co-located in the run's window), so time of day is not a
    free discriminator, and
  - separable only by the RIGHT feature (destination context / fail ratio).

Positive control: revert either builder's foil block and the non-empty-negative
assertions go red (the technique yields no negative stream at all).
"""

from __future__ import annotations

from collections import Counter

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ORCH = Orchestrator(CATALOG, Settings())
BENIGN = set(ORCH.entities.benign_external)


def _events(tid: str, controls: str, intensity: str = "medium", seed: int = 1337) -> list:
    return ORCH.build_plan(
        RunRequest(
            technique_id=tid, intensity=intensity, seed=seed, no_send=True, controls=controls
        )
    ).events


def _window(events: list) -> tuple[int, int]:
    times = [e.eventtime for e in events]
    return min(times), max(times)


def _overlap(a: list, b: list) -> bool:
    a0, a1 = _window(a)
    b0, b1 = _window(b)
    return a0 <= b1 and b0 <= a1


# --- REP-006: shared-egress fan-out ------------------------------------------


def test_rep006_foil_is_a_second_fanout_source_not_a_volume_bump() -> None:
    pos = _events("REP-006", "positive")
    neg = _events("REP-006", "negative")
    assert neg, "REP-006 emits no structural foil"

    pos_src = Counter(e.src for e in pos).most_common(1)[0][0]
    neg_src = Counter(e.src for e in neg).most_common(1)[0][0]
    # The foil is a DIFFERENT source that is ALSO one-source-to-many-destinations,
    # so the source-fanout key (one src, many dst) cannot separate it.
    assert neg_src != pos_src
    assert len({e.src for e in neg}) == 1
    assert len({e.dst for e in neg}) >= 3


def test_rep006_foil_is_not_separable_by_time_but_is_by_destination() -> None:
    pos = _events("REP-006", "positive")
    neg = _events("REP-006", "negative")
    # co-located window: time of day is not a free discriminator
    assert _overlap(pos, neg)
    # the honest discriminator: the proxy reaches known-good externals only, while
    # the attack reaches destinations outside the benign pool.
    assert {e.dst for e in neg} <= BENIGN
    assert {e.dst for e in pos} - BENIGN, "attack should reach non-benign dsts"


def test_rep006_foil_is_not_separable_by_bytes_action_or_ports() -> None:
    """The foil must match the attack's distributions so destination is the ONLY
    discriminator. Diverging byte/action/port stats would be a free FP filter that
    works on synthetic data and fails in production."""
    pos = _events("REP-006", "positive")
    neg = _events("REP-006", "negative")
    assert {e.dpt for e in neg} <= {e.dpt for e in pos}  # same port set
    assert len({e.dpt for e in neg}) >= 3  # varied ports, not a narrow tell
    assert any(e.action == "deny" for e in neg)  # the occasional policy deny, like the attack
    # byte volume does not separate them: the foil draws from the same envelope as
    # the attack (out < 4000, in < 8000), so no threshold fires on only one of them.
    assert all(80 <= (e.out_bytes or 0) < 4000 for e in neg)
    assert all(80 <= (e.in_bytes or 0) < 8000 for e in neg)
    assert all(80 <= (e.out_bytes or 0) < 4000 for e in pos)
    assert all(80 <= (e.in_bytes or 0) < 8000 for e in pos)


# --- REP-007: NAT / proxy source-collapse ------------------------------------


def test_rep007_foil_collapses_to_one_source_like_the_attack() -> None:
    pos = _events("REP-007", "positive")
    neg = _events("REP-007", "negative")
    assert neg, "REP-007 emits no structural foil"
    # Both streams are a single source with many login events, so a per-source
    # login COUNT fires on both: the naive key cannot separate them.
    assert len({e.src for e in pos}) == 1
    assert len({e.src for e in neg}) == 1
    assert Counter(e.src for e in neg).most_common(1)[0][0] != (
        Counter(e.src for e in pos).most_common(1)[0][0]
    )


def test_rep007_foil_is_separable_by_fail_ratio_not_count() -> None:
    pos = _events("REP-007", "positive")
    neg = _events("REP-007", "negative")
    assert _overlap(pos, neg)  # co-located in time

    def fail_ratio(events: list) -> float:
        fails = sum(1 for e in events if e.action == "ssl-login-fail")
        return fails / len(events)

    # The attack is (nearly) all failures; the NAT mostly succeeds. That ratio,
    # and the presence of tunnel-up successes, is the honest discriminator.
    assert fail_ratio(pos) > 0.95
    assert fail_ratio(neg) < 0.6
    assert any(e.action == "tunnel-up" for e in neg)
    assert not any(e.action == "tunnel-up" for e in pos)  # spray has no success


# --- interactions: scenarios and the validation card -------------------------


def test_scenarios_compose_the_attack_only_no_benign_foil() -> None:
    """A scenario is a curated attack chain with no --controls escape hatch, so a
    foil-emitting stage (REP-007 in SCEN-003) must not leak benign negative-control
    events onto the wire. Positive control: drop the positive filter in compose()
    and SCEN-003 gains negative events."""
    from replicant.core.models import load_scenario_catalog
    from replicant.entities.model import EntityModel
    from replicant.resources import SCENARIO_CATALOG
    from replicant.scenario.composer import compose
    from replicant.scenario.engine import DEFAULT_ANCHOR_EPOCH, ScenarioEngine

    scenarios = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
    for sid in ("SCEN-001", "SCEN-002", "SCEN-003"):
        composed = compose(
            scenarios.by_id(sid),
            CATALOG.by_id,
            ScenarioEngine(),
            1337,
            DEFAULT_ANCHOR_EPOCH,
            EntityModel.build(),
        )
        assert composed.events, sid
        assert all(e.control == "positive" for e in composed.events), sid


def test_validation_card_pivots_on_the_attack_not_the_foil(tmp_path) -> None:
    """A structural foil adds a distinct benign source; the per-run card (roadmap
    #7) must pivot on the attack, not list the benign proxy as an attack source.
    Positive control: build the card from both streams and the foil src appears."""
    from replicant.config.settings import Settings as _S

    orch = Orchestrator(CATALOG, _S(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-006",
            intensity="low",
            to_file=str(tmp_path / "o.log"),
            no_send=True,
        )
    )
    text = result.card_path.read_text(encoding="utf-8")  # type: ignore[union-attr]
    positive = [e for e in result.plan.events if e.control == "positive"]
    negative = [e for e in result.plan.events if e.control == "negative"]
    attack_src = Counter(e.src for e in positive).most_common(1)[0][0]
    foil_src = Counter(e.src for e in negative).most_common(1)[0][0]
    assert attack_src != foil_src
    assert attack_src in text
    assert foil_src not in text
