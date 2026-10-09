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
"""REP-046: a VPN login from a source network absent from that user's history
(Initial Access, T1078 and T1133).

What the catalog promises and this file measures, over seeds and presets:

- two self-contained populations of users, disjoint by name, each with a
  compressed history in which every user logs in from exactly two networks,
  all from the one benign documentation pool, with no country tag;
- in the window, the attack user logs in the preset's number of times from one
  fresh address in a network another user in the same population uses and the
  attack user never has;
- the foil user logs in the same number of times from one fresh address in
  that user's own rarely used network, which one other user also uses;
- a new address, a rare network, a network the organisation has seen and a
  network another user uses are true of both logins, and only per-user network
  novelty separates them;
- the run summary states the compressed warm-up, the records render as the
  existing tunnel-up on all three vendors, ``--duration`` bounds the span and
  keeps the counts, and the engine's ceiling binds counts.

Positive controls (recorded in the PR): with the foil drawn from a network the
foil user never used, the foil guard went red on every seed; with the attack
network taken from a different pool, the shared-pool guard went red; with the
attack address reused from another user's history, the fresh-address guard
went red.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict

import pytest

from replicant.config.settings import Settings
from replicant.core.models import EventRecord, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import VPN_HISTORY_SPAN_S, ScenarioEngine, _source_network

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTENSITIES = ("low", "medium", "high")
POOL = set(ENTITIES.benign_external)
WINDOW_START = ANCHOR + VPN_HISTORY_SPAN_S


def _plan(intensity: str, seed: int):
    return ENGINE.plan(CATALOG.by_id("REP-046"), intensity, ENTITIES, seed, anchor_epoch=ANCHOR)


def _split(plan):
    positive = [e for e in plan.events if e.control == "positive"]
    negative = [e for e in plan.events if e.control != "positive"]
    return positive, negative


class Stream:
    """One population: its history, its window, and the user whose window
    logins come from an address absent from that user's own history."""

    def __init__(self, events: list[EventRecord], tag: str) -> None:
        self.tag = tag
        self.history = [e for e in events if e.eventtime < WINDOW_START]
        self.window = [e for e in events if e.eventtime >= WINDOW_START]
        self.addresses: dict[str, set[str]] = defaultdict(set)
        self.networks: dict[str, Counter[str]] = defaultdict(Counter)
        for e in self.history:
            assert e.duser and e.src
            self.addresses[e.duser].add(e.src)
            self.networks[e.duser][_source_network(e.src)] += 1
        designated = {
            e.duser for e in self.window if e.src not in self.addresses.get(e.duser or "", set())
        }
        assert len(designated) == 1, f"{tag}: designated users {sorted(designated)}"
        self.user = designated.pop()
        self.logins = [e for e in self.window if e.duser == self.user]
        sources = {e.src for e in self.logins}
        assert len(sources) == 1, f"{tag}: the designated user used {len(sources)} addresses"
        self.address = sources.pop() or ""
        self.network = _source_network(self.address)

    @property
    def all_addresses(self) -> set[str]:
        return set().union(*self.addresses.values())

    def network_new_to_user(self) -> bool:
        return self.network not in self.networks[self.user]

    def network_seen_by_org(self) -> bool:
        return any(self.network in nets for nets in self.networks.values())

    def network_used_by_another_user(self) -> bool:
        return any(
            self.network in nets for user, nets in self.networks.items() if user != self.user
        )

    def address_new_to_user(self) -> bool:
        return self.address not in self.addresses[self.user]

    def address_new_to_org(self) -> bool:
        return self.address not in self.all_addresses


def _streams(intensity: str, seed: int) -> tuple[Stream, Stream]:
    positive, negative = _split(_plan(intensity, seed))
    tag = f"{intensity} seed {seed}"
    return Stream(positive, tag), Stream(negative, f"{tag} foil")


def _shape(stream: Stream, events: list[EventRecord], preset: dict, tag: str) -> None:
    window = preset["window_min"] * 60
    users = min(preset["users"], 8)
    assert len(stream.networks) == users, f"{tag}: {len(stream.networks)} users in the history"
    for user, nets in stream.networks.items():
        assert len(nets) == 2, f"{tag}: {user} has {len(nets)} networks"
    assert len(stream.logins) == preset["novel_logins"], f"{tag}: {len(stream.logins)} logins"
    for e in events:
        assert e.log_type == "event" and e.subtype == "vpn" and e.action == "tunnel-up"
        assert e.src in POOL, f"{tag}: {e.src} is outside the shared benign pool"
        assert "srccountry" not in e.extra, f"{tag}: a country tag is a free geo feature"
        assert "tunnelip" in e.extra
        assert ANCHOR <= e.eventtime < WINDOW_START + window
    assert all(e.eventtime >= WINDOW_START for e in stream.logins)


# -- the attack --------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_attack_login_is_from_a_network_another_user_uses_and_this_user_never_has(
    intensity: str, seed: int
) -> None:
    preset = CATALOG.by_id("REP-046").params[intensity]
    positive_events, _ = _split(_plan(intensity, seed))
    attack, _ = _streams(intensity, seed)
    tag = f"{intensity} seed {seed}"
    _shape(attack, positive_events, preset, tag)
    assert attack.network_new_to_user(), f"{tag}: the attack network is in the user's history"
    assert attack.network_used_by_another_user(), f"{tag}: no other user has the network"
    assert attack.address_new_to_org(), f"{tag}: the attack address appears in the history"


# -- the foil ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_foil_login_is_from_the_users_own_rarely_used_network(
    intensity: str, seed: int
) -> None:
    preset = CATALOG.by_id("REP-046").params[intensity]
    _, negative_events = _split(_plan(intensity, seed))
    attack, foil = _streams(intensity, seed)
    tag = f"{intensity} seed {seed}"
    _shape(foil, negative_events, preset, f"{tag} foil")
    assert not foil.network_new_to_user(), f"{tag}: the foil network is new to the foil user"
    counts = foil.networks[foil.user]
    assert counts[foil.network] < max(counts.values()), f"{tag}: the foil network is not rare"
    assert foil.network_used_by_another_user(), f"{tag}: no other user has the foil network"
    assert foil.address_new_to_org(), f"{tag}: the foil address appears in the history"
    assert not set(attack.networks) & set(foil.networks), f"{tag}: populations share users"


def test_per_user_network_novelty_is_the_only_separating_feature() -> None:
    """Every candidate rule other than per-user network novelty gives the same
    verdict on both logins, on every seed at every preset, and the shape of the
    two populations matches when pooled."""

    p_hist: list[int] = []
    n_hist: list[int] = []
    p_offset: list[int] = []
    n_offset: list[int] = []
    for intensity in INTENSITIES:
        for seed in SEEDS:
            attack, foil = _streams(intensity, seed)
            tag = f"{intensity} seed {seed}"
            for name, rule in (
                ("address new to the user", Stream.address_new_to_user),
                ("address new to the organisation", Stream.address_new_to_org),
                ("network seen by the organisation", Stream.network_seen_by_org),
                ("network used by another user", Stream.network_used_by_another_user),
            ):
                assert rule(attack) == rule(foil), f"{tag}: {name!r} separates the streams"
            assert attack.network_new_to_user() and not foil.network_new_to_user(), tag
            if intensity == "medium":
                p_hist.extend(sum(c.values()) for c in attack.networks.values())
                n_hist.extend(sum(c.values()) for c in foil.networks.values())
                p_offset.extend(e.eventtime - WINDOW_START for e in attack.logins)
                n_offset.extend(e.eventtime - WINDOW_START for e in foil.logins)
    assert abs(statistics.mean(p_hist) - statistics.mean(n_hist)) < 3
    assert abs(statistics.mean(p_offset) - statistics.mean(n_offset)) < 0.15 * 720 * 60


def test_the_run_summary_states_the_compressed_warmup() -> None:
    note = _plan("medium", 1337).warmup_note or ""
    assert "compressed" in note and f"{VPN_HISTORY_SPAN_S}s" in note


# -- rendering -------------------------------------------------------------------------


def test_the_login_renders_as_the_existing_tunnel_up_on_every_vendor() -> None:
    attack, _ = _streams("medium", 1337)
    event = attack.logins[0]

    header, fgt = FortiGateProfile().render(event)
    assert header.signature_id == "39947"
    assert fgt["duser"] == event.duser and fgt["src"] == event.src
    assert fgt["FTNTFGTtunnelip"] == event.extra["tunnelip"]
    assert "FTNTFGTsrccountry" not in fgt

    _, pan = PaloAltoProfile().render(event)
    assert pan["duser"] == event.duser and pan["PanOSPrivateIPv4"] == event.extra["tunnelip"]
    assert pan.get("cs4Label") != "Source Region"

    _, cp = CheckPointProfile().render(event)
    assert cp["duser"] == event.duser and cp["office_mode_ip"] == event.extra["tunnelip"]


# -- duration and the ceiling -------------------------------------------------------------


def test_duration_bounds_the_span_and_keeps_the_counts(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    natural = orch.build_plan(RunRequest(technique_id="REP-046", intensity="medium", seed=7))
    short = orch.build_plan(
        RunRequest(technique_id="REP-046", intensity="medium", seed=7, duration="20m")
    )
    assert len(short.events) == len(natural.events)
    times = [e.eventtime for e in short.events]
    assert max(times) - min(times) <= 1200


def test_the_ceiling_binds_the_counts_not_the_window() -> None:
    plan = ScenarioEngine(max_events=40).plan(
        CATALOG.by_id("REP-046"), "high", ENTITIES, 3, anchor_epoch=ANCHOR
    )
    assert plan.truncated
    assert len(plan.events) <= 40
    positive, negative = _split(plan)
    assert positive and negative
    window = CATALOG.by_id("REP-046").params["high"]["window_min"] * 60
    assert max(e.eventtime for e in plan.events) < WINDOW_START + window
