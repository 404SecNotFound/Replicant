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
"""An inbound traffic record renders as inbound on every vendor.

The engine marks an internet-to-inside session by reversing the interface pair
(``src_intf``/``dst_intf`` in ``extra``, ``trandisp=dnat`` on accepts). Until
2026-10-19 only FortiGate read the mark: PAN-OS rendered every traffic record
with the trust-to-untrust zones and interfaces and stamped the egress source NAT
on inbound accepts, and Check Point rendered ``inzone=Internal`` for a session
from the internet. A rule keyed on zone or interface could not see REP-021,
REP-043's inbound stage or REP-053 on those two vendors.

Measured on real plans of every technique that emits inbound traffic, at every
preset, and on the egress records beside them, which must not move.

Positive control (recorded in the PR): with the fix reverted, every inbound
assertion on PAN-OS and Check Point failed and the egress assertions held.
"""

from __future__ import annotations

import pytest

from replicant.core.models import EventRecord, load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile, PanOSDevice
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
INBOUND_TECHNIQUES = ("REP-021", "REP-043", "REP-053")
INTENSITIES = ("low", "medium", "high")
PAN = PanOSDevice()


def _traffic(technique: str, intensity: str) -> list[EventRecord]:
    plan = ENGINE.plan(CATALOG.by_id(technique), intensity, ENTITIES, 1337, anchor_epoch=ANCHOR)
    return [e for e in plan.events if e.log_type == "traffic" and e.subtype == "forward"]


def _inbound(events: list[EventRecord]) -> list[EventRecord]:
    return [e for e in events if "src_intf" in e.extra]


def _egress(events: list[EventRecord]) -> list[EventRecord]:
    return [e for e in events if "src_intf" not in e.extra]


def test_every_inbound_technique_emits_inbound_traffic() -> None:
    """The cases below would pass vacuously on a technique with no inbound record."""

    for technique in INBOUND_TECHNIQUES:
        assert _inbound(_traffic(technique, "medium")), technique


@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("technique", INBOUND_TECHNIQUES)
def test_paloalto_inbound_reverses_zones_and_interfaces(technique: str, intensity: str) -> None:
    for event in _inbound(_traffic(technique, intensity)):
        _, ext = PaloAltoProfile().render(event)
        assert (ext["cs4"], ext["cs5"]) == (PAN.dst_zone, PAN.src_zone), technique
        assert ext["deviceInboundInterface"] == PAN.outbound_intf, technique
        assert ext["deviceOutboundInterface"] == PAN.inbound_intf, technique
        assert "sourceTranslatedAddress" not in ext, f"{technique}: egress SNAT on inbound"


@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("technique", INBOUND_TECHNIQUES)
def test_checkpoint_inbound_enters_from_the_external_zone(technique: str, intensity: str) -> None:
    for event in _inbound(_traffic(technique, intensity)):
        _, ext = CheckPointProfile().render(event)
        assert (ext["inzone"], ext["outzone"]) == ("External", "Internal"), technique
        assert ext["deviceDirection"] == "0", technique
        assert "sourceTranslatedAddress" not in ext, technique


@pytest.mark.parametrize("technique", INBOUND_TECHNIQUES)
def test_fortigate_inbound_is_unchanged(technique: str) -> None:
    for event in _inbound(_traffic(technique, "medium")):
        _, ext = FortiGateProfile().render(event)
        assert (ext["deviceInboundInterface"], ext["deviceOutboundInterface"]) == (
            "port1",
            "port2",
        )


@pytest.mark.parametrize("technique", ("REP-001", "REP-005", "REP-043"))
def test_egress_records_keep_the_outbound_shape(technique: str) -> None:
    events = _egress(_traffic(technique, "medium"))
    assert events, technique
    for event in events:
        _, pan = PaloAltoProfile().render(event)
        assert (pan["cs4"], pan["cs5"]) == (PAN.src_zone, PAN.dst_zone), technique
        assert pan["deviceInboundInterface"] == PAN.inbound_intf, technique
        assert pan["deviceOutboundInterface"] == PAN.outbound_intf, technique
        _, cp = CheckPointProfile().render(event)
        assert cp["inzone"] == "Internal", technique
