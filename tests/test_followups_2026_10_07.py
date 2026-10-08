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
"""The two follow-ups the 2026-10-07 catalog review left open.

1. REP-022's fifth stage is an outbound-transfer alert (``HTTP.Large.Outbound
   .Transfer``, labelled exfil, mapped to T1041) and it rendered with
   ``direction=incoming`` on the adversary-to-victim pair, which is the shape
   of an inbound attack. A large outbound transfer is raised on the flow
   leaving the victim: same pair, reversed, direction outgoing.
2. SCEN-003's REP-011 to REP-001 hop had no join key. The VPN tunnel-up carried
   the user and the remote address but never the address the VPN assigned to
   the session, so nothing tied ``duser`` to the beacon's ``src``. The engine
   now assigns one from the internal pool, which under scenario pinning is the
   victim, and the advisory names it as the pivot.

Positive control: every test here was run against the engine and profiles
before the change. The REP-022 tests failed on ``direction`` and on the
reversed pair; the REP-011 and SCEN-003 tests failed on the missing
``tunnelip`` key.
"""

from __future__ import annotations

import pytest

from replicant.core.models import load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTERNAL = set(ENTITIES.internal_targets) | set(ENTITIES.internal_hosts)


def _plan(technique_id: str, intensity: str, seed: int):
    return ENGINE.plan(CATALOG.by_id(technique_id), intensity, ENTITIES, seed, anchor_epoch=ANCHOR)


# -- REP-022: the exfil stage leaves the victim -----------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_rep022_exfil_stage_is_the_reversed_pair_outgoing(seed: int) -> None:
    plan = _plan("REP-022", "high", seed)
    chain = [e for e in plan.events if "stage" in e.extra]
    exfil = [e for e in chain if e.extra["stage"] == "exfil"]
    inbound = [e for e in chain if e.extra["stage"] != "exfil"]
    assert exfil, "the high preset has five stages and the fifth is exfil"

    victim = {str(e.dst) for e in inbound}
    adversary = {str(e.src) for e in inbound}
    assert len(victim) == 1 and len(adversary) == 1
    assert victim <= INTERNAL and not (adversary & INTERNAL)

    for event in inbound:
        assert event.extra["direction"] == "incoming"
    for event in exfil:
        assert event.extra["direction"] == "outgoing", f"seed {seed}: exfil alert is inbound"
        assert str(event.src) in victim, "the transfer leaves the victim"
        assert str(event.dst) in adversary, "and reaches the adversary"
        assert event.dpt == 443 and event.extra["hostname"] == str(event.dst)
    # The chain is still one entity pair, read without direction.
    assert len({frozenset((str(e.src), str(e.dst))) for e in chain}) == 1


def test_rep022_exfil_direction_renders_on_every_vendor() -> None:
    plan = _plan("REP-022", "high", 1337)
    exfil = next(e for e in plan.events if e.extra.get("stage") == "exfil")
    inbound = next(e for e in plan.events if e.extra.get("stage") == "recon")

    _, fgt = FortiGateProfile().render(exfil)
    assert fgt["FTNTFGTdirection"] == "outgoing"
    assert FortiGateProfile().render(inbound)[1]["FTNTFGTdirection"] == "incoming"

    pan = PaloAltoProfile()
    _, out = pan.render(exfil)
    _, inn = pan.render(inbound)
    assert out["cn2"] == "1" and inn["cn2"] == "0"
    # Zones follow the flow: an outbound alert originates in the trust zone.
    assert out["cs4"] == inn["cs5"] and out["cs5"] == inn["cs4"]

    cp = CheckPointProfile()
    assert cp.render(exfil)[1]["deviceDirection"] == "1"
    assert cp.render(inbound)[1]["deviceDirection"] == "0"


def test_rep022_medium_has_no_outbound_stage() -> None:
    """Four stages end at c2; nothing below high reverses the pair."""
    plan = _plan("REP-022", "medium", 1337)
    chain = [e for e in plan.events if "stage" in e.extra]
    assert all(e.extra["direction"] == "incoming" for e in chain)
    assert len({(str(e.src), str(e.dst)) for e in chain}) == 1


# -- REP-011: the tunnel-up names the address the VPN assigned --------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
def test_rep011_every_login_carries_an_assigned_internal_address(seed: int, intensity: str) -> None:
    plan = _plan("REP-011", intensity, seed)
    assert plan.events
    for event in plan.events:
        assigned = event.extra.get("tunnelip")
        assert assigned, f"seed {seed}: tunnel-up without an assigned address"
        assert assigned in ENTITIES.internal_hosts
        assert assigned != event.src, "the assigned address is not the remote address"


def test_rep011_assigned_address_renders_on_every_vendor() -> None:
    event = _plan("REP-011", "medium", 1337).events[0]
    assigned = event.extra["tunnelip"]
    assert FortiGateProfile().render(event)[1]["FTNTFGTtunnelip"] == assigned
    assert PaloAltoProfile().render(event)[1]["PanOSPrivateIPv4"] == assigned
    assert CheckPointProfile().render(event)[1]["office_mode_ip"] == assigned


def test_a_tunnel_up_without_an_assignment_renders_as_before() -> None:
    """The golden VPN lines carry no assignment; the key must stay optional."""
    event = _plan("REP-011", "medium", 1337).events[0].model_copy(deep=True)
    event.extra.pop("tunnelip")
    assert "FTNTFGTtunnelip" not in FortiGateProfile().render(event)[1]
    assert "PanOSPrivateIPv4" not in PaloAltoProfile().render(event)[1]
    assert "office_mode_ip" not in CheckPointProfile().render(event)[1]


# -- SCEN-003: the assignment is the pivot from the user to the beacon ------------


@pytest.mark.parametrize("seed", [1, 7, 1337])
def test_scen003_vpn_assignment_is_the_beacon_source(seed: int) -> None:
    scenario = SCENARIOS.by_id("SCEN-003")
    composed = compose(scenario, CATALOG.by_id, ENGINE, seed, ANCHOR, ENTITIES)
    geo = composed.stages[2]
    beacon = composed.stages[3]
    assert (geo.technique_id, beacon.technique_id) == ("REP-011", "REP-001")

    vpn_events = [e for e in composed.events if e.action == "tunnel-up"]
    assert vpn_events and all(e.extra.get("tunnelip") == composed.victim for e in vpn_events)
    assert beacon.top_src == composed.victim
    assert geo.top_tunnelip == composed.victim

    text, coverage = build_advisory(scenario, composed, CATALOG)
    assert coverage["vpn_pivot_stage_indices"] == [geo.index]
    assert f"`tunnelip={composed.victim}`" in text
    assert "correlate on `duser`, not on `src`" in text
    assert "needs the VPN assignment as the pivot" not in text
