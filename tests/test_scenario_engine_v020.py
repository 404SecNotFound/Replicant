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
"""v0.2.0 expansion techniques (REP-012 .. REP-024).

Each test asserts the property that makes the technique a distinct detection
exercise rather than a restatement of an existing entry. Where a technique
carries a benign look-alike, that look-alike is asserted too: a plan that emits
only the malicious pattern would let any rule score perfectly, which is the
failure mode the round 2 research doc argues against.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import Counter
from pathlib import Path

import pytest

from replicant.core.models import EventRecord, load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")
ENTITIES = EntityModel.build()

NEW_TECHNIQUES = [
    "REP-012",
    "REP-013",
    "REP-014",
    "REP-015",
    "REP-017",
    "REP-018",
    "REP-019",
    "REP-020",
    "REP-021",
    "REP-022",
    "REP-023",
    "REP-024",
]

_ADVERSARY = ipaddress.ip_network("203.0.113.0/24")
_BENIGN = ipaddress.ip_network("198.51.100.0/24")
_SCANNER = ipaddress.ip_network("192.0.2.0/24")


def _plan(technique_id: str, intensity: str, seed: int = 1337, duration_s: int | None = None):
    engine = ScenarioEngine()
    return engine.plan(
        CATALOG.by_id(technique_id),
        intensity,
        ENTITIES,
        seed,
        duration_override_s=duration_s,
    )


def _in(addr: str | None, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return addr is not None and ipaddress.ip_address(addr) in net


def _cv(values: list[float]) -> float:
    """Coefficient of variation. The shape metric, independent of magnitude."""
    if len(values) < 2 or statistics.fmean(values) == 0:
        return 0.0
    return statistics.pstdev(values) / statistics.fmean(values)


# -- cross-cutting guarantees -------------------------------------------------


@pytest.mark.parametrize("technique_id", NEW_TECHNIQUES)
def test_new_techniques_are_deterministic(technique_id: str) -> None:
    a = _plan(technique_id, "low", 1337, duration_s=1800)
    b = _plan(technique_id, "low", 1337, duration_s=1800)
    assert a.events == b.events


@pytest.mark.parametrize("technique_id", NEW_TECHNIQUES)
def test_new_techniques_produce_events(technique_id: str) -> None:
    plan = _plan(technique_id, "low", 1337, duration_s=1800)
    assert plan.events, f"{technique_id} produced no events"


@pytest.mark.parametrize("technique_id", NEW_TECHNIQUES)
def test_new_techniques_time_ordered(technique_id: str) -> None:
    plan = _plan(technique_id, "low", 1337, duration_s=1800)
    times = [e.eventtime for e in plan.events]
    assert times == sorted(times), f"{technique_id} emitted out-of-order events"


@pytest.mark.parametrize("technique_id", NEW_TECHNIQUES)
def test_new_techniques_render_on_all_three_vendors(technique_id: str) -> None:
    """Vendor parity: --vendor is a live flag, so every entry must render on all three."""
    plan = _plan(technique_id, "low", 1337, duration_s=600)
    for profile in (FortiGateProfile(), PaloAltoProfile(), CheckPointProfile()):
        for event in plan.events[:40]:
            header, ext = profile.render(event)
            assert header.name
            assert ext


@pytest.mark.parametrize("technique_id", NEW_TECHNIQUES)
def test_new_techniques_use_only_synthetic_addresses(technique_id: str) -> None:
    """Safety rule 2. Every address must be RFC1918 or IANA documentation space."""
    plan = _plan(technique_id, "low", 1337, duration_s=1800)
    for event in plan.events:
        for addr in (event.src, event.dst):
            if addr is None:
                continue
            ip = ipaddress.ip_address(addr)
            assert (
                ip.is_private or _in(addr, _ADVERSARY) or _in(addr, _BENIGN) or _in(addr, _SCANNER)
            ), f"{technique_id} emitted non-synthetic address {addr}"


def test_rep016_not_implemented_until_dns_response_path_exists() -> None:
    """REP-016 is catalogued in the research docs but deliberately unbuildable.

    A DGA technique with no NXDOMAIN in it would be worse than no technique, so
    the engine refuses rather than approximating.
    """
    assert "REP-016" not in {t.id for t in CATALOG.techniques}


# -- REP-012 jittered and fleet-aggregate callback ----------------------------


def test_rep012_fleet_mode_spreads_one_destination_across_many_sources() -> None:
    plan = _plan("REP-012", "medium", 1337, duration_s=7200)
    c2 = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    assert c2
    assert len({e.dst for e in c2}) == 1, "fleet mode must hold one shared destination"
    # The whole point of the ACSAC 2023 anchor: no single host looks periodic,
    # the aggregate at the destination does.
    assert len({e.src for e in c2}) > 1, "fleet mode must spread across many sources"


def test_rep012_jitter_mode_is_single_source() -> None:
    plan = _plan("REP-012", "low", 1337, duration_s=7200)
    c2 = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    assert len({e.src for e in c2}) == 1


def test_rep012_includes_benign_periodic_destination() -> None:
    """Both source papers name legitimate periodic software as the top false positive."""
    plan = _plan("REP-012", "medium", 1337, duration_s=7200)
    assert [e for e in plan.events if _in(e.dst, _BENIGN)], "missing benign periodic control"


# -- REP-013 self-propagating spread ------------------------------------------


def test_rep013_source_population_grows() -> None:
    plan = _plan("REP-013", "medium", 1337)
    worm = [e for e in plan.events if e.dpt == CATALOG.by_id("REP-013").params["medium"]["port"]]
    assert len({e.src for e in worm}) >= 4, "infected source count must grow across generations"


def test_rep013_mixes_landed_and_blocked_probes() -> None:
    plan = _plan("REP-013", "medium", 1337)
    actions = Counter(e.action for e in plan.events)
    assert actions["deny"] > 0, "most probes should be blocked"
    assert actions["accept"] > 0, "some probes must land, or nothing propagates"
    assert actions["deny"] > actions["accept"]


def test_rep013_stays_internal() -> None:
    """Nothing propagates and nothing leaves internal space."""
    plan = _plan("REP-013", "medium", 1337)
    for event in plan.events:
        assert ipaddress.ip_address(str(event.src)).is_private
        assert ipaddress.ip_address(str(event.dst)).is_private


# -- REP-014 cryptomining -----------------------------------------------------


def test_rep014_byte_ratio_is_symmetric_and_small() -> None:
    plan = _plan("REP-014", "low", 1337, duration_s=3600)
    mining = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    assert mining
    for event in mining:
        out_b, in_b = int(event.out_bytes or 0), int(event.in_bytes or 0)
        assert 0.7 <= in_b / out_b <= 1.5, "mining exchange is roughly symmetric"
        assert out_b < 1000, "job/share messages are small, unlike exfiltration"


def test_rep014_session_is_long_lived() -> None:
    """One session id across the whole pool connection, with growing duration."""
    plan = _plan("REP-014", "low", 1337, duration_s=3600)
    mining = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    assert len({e.session_id for e in mining}) == 1
    durations = [int(e.extra["duration"]) for e in mining]
    assert durations == sorted(durations)
    assert durations[-1] > durations[0]


def test_rep014_includes_bursty_benign_long_session() -> None:
    """MineShark auto-filtered over 99.3% of alarms; this is why the control exists."""
    plan = _plan("REP-014", "low", 1337, duration_s=3600)
    benign = [e for e in plan.events if _in(e.dst, _BENIGN)]
    mining = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    assert benign
    assert _cv([float(e.out_bytes or 0) for e in benign]) > _cv(
        [float(e.out_bytes or 0) for e in mining]
    ), "benign long session must be burstier than the miner"


# -- REP-015 low-throughput DNS exfiltration ----------------------------------


def test_rep015_rate_is_per_hour_not_per_second() -> None:
    """The distinguishing property versus REP-004: it sits under tunnel thresholds."""
    preset = CATALOG.by_id("REP-015").params["low"]
    plan = _plan("REP-015", "low", 1337)
    expected_gap = 3600 / int(preset["qph"])
    # Group on the exact parent, not a suffix match: one synthetic parent can be
    # a suffix of another, which would merge the exfil and benign streams.
    by_parent: dict[str, list[EventRecord]] = {}
    for event in plan.events:
        by_parent.setdefault(str(event.extra["qname"]).split(".", 1)[1], []).append(event)
    exfil_parent = max(
        by_parent,
        key=lambda p: len({str(e.extra["qname"]).split(".", 1)[0] for e in by_parent[p]}),
    )
    times = [e.eventtime for e in by_parent[exfil_parent]]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert statistics.fmean(gaps) == pytest.approx(expected_gap, rel=0.05)
    assert statistics.fmean(gaps) > 600, "must be far slower than a tunnel"


def test_rep015_high_cardinality_under_one_parent_with_lookalike() -> None:
    plan = _plan("REP-015", "low", 1337)
    by_parent: dict[str, set[str]] = {}
    for event in plan.events:
        label, parent = str(event.extra["qname"]).split(".", 1)
        by_parent.setdefault(parent, set()).add(label)
    cardinalities = sorted(len(labels) for labels in by_parent.values())
    assert cardinalities[-1] >= 100, "exfil parent must have high label cardinality"
    assert cardinalities[0] <= 10, "a same-volume low-cardinality benign parent must exist"


def test_rep015_qtypes_avoid_txt() -> None:
    """The query name is the channel, so a TXT-oriented tunnel rule sees nothing."""
    plan = _plan("REP-015", "low", 1337)
    assert {str(e.extra["qtype"]) for e in plan.events} <= {"A", "AAAA"}


# -- REP-017 DoH bypass -------------------------------------------------------


def test_rep017_resolver_traffic_stops_when_doh_begins() -> None:
    """The signal is an absence. Every dns record must precede every DoH session."""
    plan = _plan("REP-017", "low", 1337)
    dns = [e for e in plan.events if e.log_type == "dns"]
    doh = [e for e in plan.events if e.log_type == "traffic" and e.dpt == 443]
    assert dns and doh
    assert max(e.eventtime for e in dns) < min(e.eventtime for e in doh)


def test_rep017_spans_two_log_types_in_one_plan() -> None:
    plan = _plan("REP-017", "low", 1337)
    assert {e.log_type for e in plan.events} == {"dns", "traffic"}


def test_rep017_warmup_note_states_the_switch() -> None:
    plan = _plan("REP-017", "low", 1337)
    assert plan.warmup_note is not None
    assert "absence" in plan.warmup_note


def test_rep017_doh_resolvers_are_synthetic() -> None:
    """Never the real public resolvers the source corpus was built on."""
    plan = _plan("REP-017", "low", 1337)
    for event in plan.events:
        if event.log_type == "traffic":
            assert _in(event.dst, _ADVERSARY)


# -- REP-018 lateral movement login chain -------------------------------------


def test_rep018_credential_switches_partway_along_the_path() -> None:
    """The causal-user change Hopper keys on."""
    plan = _plan("REP-018", "medium", 1337)
    logins = [e for e in plan.events if e.log_type == "event" and e.subtype == "system"]
    assert len({e.duser for e in logins}) >= 2


def test_rep018_chain_hops_are_connected() -> None:
    """Each hop's source is the previous hop's target. A path, not a star."""
    plan = _plan("REP-018", "medium", 1337)
    legs = [
        e
        for e in plan.events
        if e.log_type == "traffic"
        and e.dpt in (3389, 445, 22)
        and e.extra.get("trandisp") == "snat"
    ]
    assert len(legs) >= 4
    hops = {(str(e.src), str(e.dst)) for e in legs}
    chained = sum(1 for src, dst in hops if any(dst == other_src for other_src, _ in hops))
    assert chained >= 2, "no connected path found in the traffic legs"


def test_rep018_includes_benign_star_pattern() -> None:
    """Same login count, different shape. Chain versus star IS the detection."""
    plan = _plan("REP-018", "medium", 1337)
    legs = [e for e in plan.events if e.log_type == "traffic"]
    fan_out = Counter(str(e.src) for e in legs)
    assert max(fan_out.values()) >= 2, "a star source contacting several hosts must exist"


def test_rep018_spans_vpn_and_traffic() -> None:
    plan = _plan("REP-018", "medium", 1337)
    assert {(e.log_type, e.subtype) for e in plan.events} == {
        ("event", "vpn"),
        ("event", "system"),
        ("traffic", "forward"),
    }


# -- REP-019 stealth scan -----------------------------------------------------


def test_rep019_all_probes_denied() -> None:
    plan = _plan("REP-019", "low", 1337)
    assert {e.action for e in plan.events} == {"deny"}


def test_rep019_stays_under_rate_thresholds() -> None:
    """Long gaps and source rotation are the evasion of a TRW-style detector."""
    preset = CATALOG.by_id("REP-019").params["low"]
    plan = _plan("REP-019", "low", 1337)
    span = max(e.eventtime for e in plan.events) - min(e.eventtime for e in plan.events)
    gap_lo = int(preset["gap_s"][0])
    assert span > int(preset["total_probes"]) * gap_lo * 0.8, "probes are not spread out enough"
    per_source = Counter(str(e.src) for e in plan.events)
    assert len(per_source) >= int(preset["src_pool"]), "source pool must be rotated"


# -- REP-020 newly registered domain ------------------------------------------


def test_rep020_novel_domains_follow_the_baseline() -> None:
    plan = _plan("REP-020", "low", 1337)
    novel = [e for e in plan.events if str(e.extra["qname"]).endswith(".invalid")]
    baseline = [e for e in plan.events if not str(e.extra["qname"]).endswith(".invalid")]
    assert novel and baseline
    assert min(e.eventtime for e in novel) > max(e.eventtime for e in baseline)


def test_rep020_novel_domains_cannot_resolve() -> None:
    """Reserved TLD, so a generated name cannot resolve even by accident."""
    plan = _plan("REP-020", "low", 1337)
    novel = [e for e in plan.events if str(e.extra["qname"]).endswith(".invalid")]
    assert novel
    for event in novel:
        assert str(event.extra["qname"]).endswith(".invalid")


def test_rep020_warmup_note_marks_first_contact() -> None:
    plan = _plan("REP-020", "low", 1337)
    assert plan.warmup_note is not None
    assert "First contact" in plan.warmup_note


# -- REP-021 inbound perimeter scan -------------------------------------------


def test_rep021_is_inbound_not_egress() -> None:
    """Reversed interface pair. This is what a real perimeter mostly logs."""
    plan = _plan("REP-021", "low", 1337)
    assert plan.events
    for event in plan.events:
        assert event.extra.get("src_intf") == "port1", "inbound records must arrive on WAN"
        assert event.extra.get("dst_intf") == "port2"


def test_rep021_high_source_cardinality_against_one_target() -> None:
    preset = CATALOG.by_id("REP-021").params["low"]
    plan = _plan("REP-021", "low", 1337)
    assert len({e.dst for e in plan.events}) == 1, "one perimeter address, held"
    assert len({e.src for e in plan.events}) == int(preset["unique_src"])


def test_rep021_source_distribution_is_heavy_tailed() -> None:
    """A few aggressive campaigns over a long tail, the two populations IMC separates."""
    preset = CATALOG.by_id("REP-021").params["low"]
    plan = _plan("REP-021", "low", 1337)
    counts = Counter(str(e.src) for e in plan.events).most_common()
    assert counts[0][1] >= int(preset["aggressive_probes"]), "no aggressive campaign present"
    assert counts[-1][1] <= 2, "no long tail present"


def test_rep021_reports_the_synthetic_range_cap() -> None:
    """Honesty: the source study saw 465,251 scanners and this cannot represent that.

    No shipped preset hits the ceiling (508 usable documentation addresses), so
    this forces it via an override. The point is that when the ceiling binds, the
    run summary says so instead of silently emitting fewer sources.
    """
    engine = ScenarioEngine()
    plan = engine.plan(
        CATALOG.by_id("REP-021"),
        "high",
        ENTITIES,
        1337,
        param_overrides={"unique_src": 900},
    )
    assert plan.warmup_note is not None
    assert "capped" in plan.warmup_note
    assert len({e.src for e in plan.events}) < 900


def test_rep021_shipped_presets_do_not_silently_truncate_sources() -> None:
    for intensity in ("low", "medium", "high"):
        preset = CATALOG.by_id("REP-021").params[intensity]
        plan = _plan("REP-021", intensity, 1337)
        assert len({e.src for e in plan.events}) == int(preset["unique_src"])
        assert plan.warmup_note is not None
        assert "capped" not in plan.warmup_note


# -- REP-022 multi-stage IDS alert chain --------------------------------------


def test_rep022_stages_are_strictly_ordered_in_time() -> None:
    """Ordering is the correlation signal. REP-009 has none."""
    plan = _plan("REP-022", "medium", 1337)
    chain = [e for e in plan.events if "stage" in e.extra]
    assert chain
    order = ["recon", "exploit", "post-exploit", "c2", "exfil"]
    seen = [order.index(str(e.extra["stage"])) for e in chain]
    assert seen == sorted(seen), "stages must never interleave out of order"
    assert len(set(seen)) >= 3, "a chain needs at least three distinct stages"


def test_rep022_chain_is_recoverable_from_rendered_cef() -> None:
    """The stage marker is engine-internal and never rendered, by design.

    A real FortiGate has no "stage" field, and emitting one would hand the answer
    to the detection under test. So the ordering has to survive into the actual
    CEF via attack-name order on the held entity pair. If it does not, the
    technique is untestable against a real correlation rule.
    """
    plan = _plan("REP-022", "medium", 1337)
    profile = FortiGateProfile()
    chain_src = next(str(e.src) for e in plan.events if "stage" in e.extra)
    chain_dst = next(str(e.dst) for e in plan.events if "stage" in e.extra)

    rendered_stages: list[str] = []
    for event in plan.events:
        _, ext = profile.render(event)
        assert "stage" not in ext, "the internal stage marker must not reach the log"
        if ext["src"] == chain_src and ext["dst"] == chain_dst:
            rendered_stages.append(str(event.extra["stage"]))

    order = ["recon", "exploit", "post-exploit", "c2", "exfil"]
    indices = [order.index(name) for name in rendered_stages]
    assert indices == sorted(indices)
    assert len(set(indices)) >= 3


def test_rep022_chain_shares_one_entity_pair() -> None:
    plan = _plan("REP-022", "medium", 1337)
    chain = [e for e in plan.events if "stage" in e.extra]
    assert len({(str(e.src), str(e.dst)) for e in chain}) == 1


def test_rep022_severity_escalates_across_stages() -> None:
    plan = _plan("REP-022", "medium", 1337)
    chain = [e for e in plan.events if "stage" in e.extra]
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severities = [rank[str(e.extra["ips_severity"])] for e in chain]
    assert severities == sorted(severities)


def test_rep022_chain_is_buried_in_unrelated_alert_noise() -> None:
    """AACT found 61% of real SOC alerts closable. A clean chain overstates any rule."""
    preset = CATALOG.by_id("REP-022").params["medium"]
    plan = _plan("REP-022", "medium", 1337)
    noise = [e for e in plan.events if "stage" not in e.extra]
    assert len(noise) == int(preset["noise_alerts"])
    chain_pair = {(str(e.src), str(e.dst)) for e in plan.events if "stage" in e.extra}
    assert all((str(e.src), str(e.dst)) not in chain_pair for e in noise)


# -- REP-023 TLS 1.3 flow-only C2 ---------------------------------------------


def test_rep023_byte_variance_is_low_against_high_variance_browsing() -> None:
    """With TLS 1.3 hiding the handshake, low variance is all that is left to key on."""
    plan = _plan("REP-023", "medium", 1337)
    c2 = [e for e in plan.events if _in(e.dst, _ADVERSARY)]
    browsing = [e for e in plan.events if _in(e.dst, _BENIGN)]
    assert c2 and browsing
    c2_cv = _cv([float(e.out_bytes or 0) for e in c2])
    browsing_cv = _cv([float(e.out_bytes or 0) for e in browsing])
    assert c2_cv < 0.35, f"C2 byte variance too high ({c2_cv:.3f})"
    assert browsing_cv > c2_cv * 2, "browsing control must be clearly burstier"


def test_rep023_emits_no_handshake_metadata() -> None:
    """A JA3 or cipher-suite rule must find nothing to match."""
    plan = _plan("REP-023", "low", 1337)
    for event in plan.events:
        assert not {"ja3", "cipher", "tls_version", "sni"} & set(event.extra)


def test_rep023_indistinguishable_by_port_alone() -> None:
    plan = _plan("REP-023", "low", 1337)
    assert {e.dpt for e in plan.events} == {443}


# -- REP-024 proxy relay ------------------------------------------------------


def test_rep024_inbound_legs_are_paired_with_correlated_outbound_legs() -> None:
    """Byte volumes track because the host forwards rather than originates."""
    plan = _plan("REP-024", "low", 1337)
    inbound = [e for e in plan.events if e.extra.get("src_intf") == "port1"]
    outbound = [e for e in plan.events if e.extra.get("src_intf") != "port1"]
    assert inbound and outbound

    matched = 0
    for leg in inbound:
        relay = str(leg.dst)
        for candidate in outbound:
            if str(candidate.src) != relay:
                continue
            if not (0 <= candidate.eventtime - leg.eventtime <= 5):
                continue
            ratio = float(candidate.out_bytes or 0) / max(float(leg.out_bytes or 1), 1.0)
            if 0.9 <= ratio <= 1.1:
                matched += 1
                break
    assert matched >= len(inbound) * 0.8, f"only {matched}/{len(inbound)} legs paired"


def test_rep024_relay_appears_as_both_destination_and_source() -> None:
    plan = _plan("REP-024", "low", 1337)
    inbound_dsts = {str(e.dst) for e in plan.events if e.extra.get("src_intf") == "port1"}
    outbound_srcs = {str(e.src) for e in plan.events if e.extra.get("src_intf") != "port1"}
    assert inbound_dsts & outbound_srcs, "the relay host must appear on both sides"


def test_rep024_includes_sanctioned_proxy_lookalike() -> None:
    """Identical pattern, different asset role. Tests role-awareness, not pattern."""
    plan = _plan("REP-024", "low", 1337)
    relays = {str(e.dst) for e in plan.events if e.extra.get("src_intf") == "port1"}
    assert len(relays) >= 2, "a sanctioned proxy with the same shape must be present"
