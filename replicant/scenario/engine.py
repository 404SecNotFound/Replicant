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
"""Scenario engine.

Turns one technique into a deterministic, time-ordered list of vendor-neutral
:class:`EventRecord` objects. Pure and seedable: the engine does no I/O, and the
same (seed, technique, params) yields the same plan (blueprint s12). Event times
are ``anchor_epoch + deterministic offset`` so ``--to-file`` output is byte
identical across runs with the same seed.

Every catalog technique has a registered builder. A technique id with no
builder raises NotImplementedError rather than emitting an approximation of it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from replicant.core.models import EventRecord, Technique
from replicant.entities.model import EntityModel
from replicant.scenario.distributions import (
    high_entropy_labels,
    jittered_interval,
    lognormal_bytes,
    make_rng,
    packet_count,
    unique_ints,
    weighted_choice,
)

# Fixed default so identical seeds produce byte-identical output (acceptance #8).
# Arbitrary but stable; overridable per run with --anchor. 2025-07-15T13:40:00Z.
DEFAULT_ANCHOR_EPOCH = 1_752_586_800

# Bound on materialized events, protecting memory and the operator's collector.
DEFAULT_MAX_EVENTS = 200_000
# TCP/UDP port space, 1..65535. A scan asking for more distinct ports than exist
# is a clamp, not an exception out of a distribution helper.
PORT_SPAN = 65535

# Declared benign ceilings for the scan and deny foils (REP-002, REP-003,
# REP-010). The foil spreads the attack's own probe volume over enough routine
# sources that no benign source exceeds these per-minute loads, so the foil is
# never itself a scan or a burst. Each number is written into the technique's
# catalog benign_baseline and asserted by tests/test_foil_parity.py.
BENIGN_PORTS_PER_MIN = 10  # distinct ports per source/destination pair
BENIGN_HOSTS_PER_MIN = 10  # distinct destinations per source on one port
BENIGN_DENIES_PER_MIN = 5  # denied attempts per source

_PORT_SERVICE: dict[int, tuple[str, str]] = {
    443: ("HTTPS", "HTTPS"),
    8443: ("HTTPS", "HTTPS"),
    8080: ("HTTP", "HTTP"),
    80: ("HTTP", "HTTP"),
    53: ("DNS", "DNS"),
    22: ("SSH", "SSH"),
    3389: ("RDP", "RDP"),
    445: ("SMB", "SMB"),
    123: ("NTP", "NTP"),
    161: ("SNMP", "SNMP"),
    23: ("TELNET", "TELNET"),
    21: ("FTP", "FTP"),
}


def port_service(dpt: int) -> tuple[str, str]:
    """Return (service, app) names for a destination port, or a tcp/<port> label."""

    return _PORT_SERVICE.get(dpt, (f"tcp/{dpt}", f"tcp/{dpt}"))


_DUBAI = timezone(timedelta(hours=4))  # UTC+04:00, the catalog timezone


OFF_HOURS_END_H = 6  # off-hours is 00:00-06:00 UTC+04:00 (catalog REP-005)


OFF_HOURS_MIN_REMAINING_S = 3600  # shortest in-window remainder worth starting in


def _off_hours_window(anchor: int, span_s: int) -> tuple[int, int]:
    """(start, span) of the first off-hours window at or after ``anchor``.

    Off-hours is 00:00-06:00 UTC+04:00. When the anchor already sits inside that
    window the plan starts at the anchor itself and its span is capped at what
    remains of the window, because the pinned window outranks the requested
    duration. A remainder shorter than ``min(span_s, 1h)`` is too thin to hold
    the history-plus-current comparison, so the plan moves to the next midnight
    with the full requested span instead. It never starts before the anchor.

    This used to snap BACKWARD to midnight of the anchor's own day, so ``--anchor
    now`` at 14:00 produced a plan 8 to 14 hours in the past. Under plan pacing
    that history was sent immediately, which breaks the invariant that an event is
    sent at the moment its own timestamp says it happened. The scenario composer
    had to compensate with ``align: next-off-hours``; that alignment is now a
    no-op kept only as a guard.
    """

    local = datetime.fromtimestamp(anchor, _DUBAI)
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    window_end = int((midnight + timedelta(hours=OFF_HOURS_END_H)).timestamp())
    remaining = window_end - anchor
    if remaining >= min(span_s, OFF_HOURS_MIN_REMAINING_S):
        return anchor, min(span_s, remaining)
    return int((midnight + timedelta(days=1)).timestamp()), span_s


def _scan_traffic_extra(is_open: bool, service: str, app: str) -> dict[str, str]:
    """FortiGate traffic:forward extension fields for a scan probe (open vs blocked)."""

    if is_open:
        return {
            "policyid": "7",
            "service": service,
            "app": app,
            "trandisp": "noop",
            "duration": "1",
            "sentpkt": "1",
            "rcvdpkt": "1",
        }
    return {
        "policyid": "0",
        "service": service,
        "policytype": "policy",
        "sentpkt": "1",
        "rcvdpkt": "0",
    }


# Synthetic SSL-VPN login-fail reason codes (labels only; no real auth occurs).
_VPN_FAIL_REASONS: tuple[str, ...] = (
    "sslvpn_login_permission_denied",
    "sslvpn_login_no_matching_policy",
    "sslvpn_login_incorrect_password",
    "sslvpn_login_user_not_found",
)

# A fixed synthetic surname corpus. Combined with an initial it yields a large
# pool of plausible-but-fake usernames for password-spray scenarios, so a spray
# of hundreds of victims never needs a real directory (safety rule 2).
_SURNAMES: tuple[str, ...] = (
    "smith",
    "doe",
    "khan",
    "lopez",
    "wong",
    "osei",
    "patel",
    "singh",
    "garcia",
    "chen",
    "nguyen",
    "brown",
    "ali",
    "kumar",
    "rossi",
    "haas",
    "novak",
    "kaur",
    "costa",
    "ivanov",
    "muller",
    "silva",
    "adams",
    "flores",
    "reyes",
    "walsh",
    "obrien",
    "park",
    "yamada",
    "petrov",
    "dubois",
    "meyer",
    "santos",
    "cohen",
    "murphy",
    "tanaka",
    "abbas",
    "romero",
    "fischer",
    "wu",
)


def synthetic_usernames(count: int, base: list[str]) -> list[str]:
    """Return ``count`` unique synthetic usernames: base pool first, then generated.

    Deterministic and seed-independent: the same ``count`` always yields the same
    list. Generated names are ``<initial><surname>`` combinations, falling back to
    a numeric suffix if the corpus is exhausted. Every name is fabricated.
    """

    names: list[str] = []
    seen: set[str] = set()
    for name in base:
        if name not in seen:
            seen.add(name)
            names.append(name)
            if len(names) >= count:
                return names[:count]
    for surname in _SURNAMES:
        for initial in "abcdefghijklmnopqrstuvwxyz":
            candidate = f"{initial}{surname}"
            if candidate not in seen:
                seen.add(candidate)
                names.append(candidate)
                if len(names) >= count:
                    return names[:count]
    suffix = 0
    while len(names) < count:
        candidate = f"user{suffix:05d}"
        if candidate not in seen:
            seen.add(candidate)
            names.append(candidate)
        suffix += 1
    return names[:count]


# IDS/IPS signature (name, signature-id) pairs. Labels only; Replicant never
# generates an exploit, it only writes the signature name a firewall would log
# (catalog safety_notes). Ids are illustrative FortiGuard-style identifiers.
_IPS_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("Apache.Struts.OGNL.Remote.Code.Execution", "40449"),
    ("HTTP.URI.SQL.Injection", "15621"),
    ("Backdoor.DoublePulsar", "42304"),
    ("MS.SMB.Server.SMBv1.Trans.Secondary.Handling.Code.Execution", "40269"),
    ("Web.Server.Password.Files.Access", "12688"),
    ("PHPUnit.Eval.Stdin.Remote.Code.Execution", "44035"),
    ("Apache.Log4j.Error.Log.Remote.Code.Execution", "51006"),
    ("Joomla.Core.Session.Remote.Code.Execution", "34321"),
)

# Kill-chain stage groups for REP-022. Attack names and ids here are synthetic
# LABELS, exactly as for _IPS_SIGNATURES and REP-009: Replicant emits no exploit
# text and generates no attack. The stage grouping is what a correlation rule
# keys on, so the ordering matters and the specific names do not.
# [Unverified] the recon and C2 entries are plausible-looking rather than
# confirmed FortiGate signature ids; confirm before customer-facing use.
#
# Stage log levels. The catalog promises severity ascends across stages, and the
# CEF header severity is derived from the LEVEL on FortiGate (reversed FortiOS
# priority) and PAN-OS (not reversed). Those two mappings disagree about
# "critical": FortiOS puts it BELOW alert (6 vs 7), PAN-OS puts it ABOVE (9 vs 8).
# The stages used to escalate alert -> critical, which rendered 4,7,7,6,6 on
# FortiGate and 5,8,8,9,9 on PAN-OS: a de-escalation on one vendor either way.
# The levels below are the longest run that is strictly ordered the same way on
# every vendor (notice < warning < error < alert), one per ips_severity step, so
# the header rises exactly where FTNTFGTseverity rises: 3,4,5,7,7 on FortiGate,
# 3,5,6,8,8 on PAN-OS. Check Point renders IPS severity from ips_severity and was
# already Low, Medium, High, Very-High, Very-High.
_IPS_LEVEL_BY_SEVERITY: dict[str, str] = {
    "low": "notice",
    "medium": "warning",
    "high": "error",
    "critical": "alert",
}

_IPS_STAGES: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "recon",
        "low",
        (("TCP.Port.Scan", "11279"), ("HTTP.Unix.Shell.IFS.Remote.Code.Execution", "34884")),
    ),
    (
        "exploit",
        "medium",
        (
            ("Apache.Log4j.Error.Log.Remote.Code.Execution", "51006"),
            ("PHPUnit.Eval.Stdin.Remote.Code.Execution", "44035"),
        ),
    ),
    (
        "post-exploit",
        "high",
        (("Web.Server.Password.Files.Access", "12688"), ("Generic.Web.Shell.Access", "40312")),
    ),
    (
        "c2",
        "critical",
        (("Botnet.C2.Generic.Callback", "16384"), ("Suspicious.Outbound.Tunnel.Traffic", "22515")),
    ),
    (
        "exfil",
        "critical",
        (("HTTP.Large.Outbound.Transfer", "18443"),),
    ),
)


# Fleet-mode callbacks are displaced from their slot by at most this fraction of
# the interval at jitter_pct=100, so every callback stays inside the middle three
# quarters of its own slot.
_FLEET_JITTER_SPAN = 0.375


def _callback_offsets(
    rng: Any,
    mode: str,
    interval_s: float,
    jitter_pct: float,
    phase_s: float,
    duration_s: float,
) -> list[float]:
    """Offsets of one source's callbacks for REP-012, in ascending order.

    ``jitter`` mode is a renewal process: each gap is the interval scaled by a
    uniform +/- ``jitter_pct``. Errors accumulate, so the phase random-walks and
    per-host periodicity weakens as jitter widens, which is the property that
    mode exists to demonstrate.

    ``fleet`` mode is grid-anchored: callback ``k`` lands at
    ``phase + k * interval + u`` with ``u`` uniform within
    ``+/- jitter_pct/100 * 0.375 * interval``. It used to be the same renewal
    process as jitter mode, and with 40 hosts each random-walking independently
    the arrivals at the destination were statistically indistinguishable from
    random (inter-arrival CV about 0.95), so the fleet-level period the catalog
    promises was not in the data at all. With a bounded displacement each host's
    phase stays put, so the evidence at the shared period adds up across hosts
    while any single host, calling back a dozen times, carries too little of it
    to stand out on its own. Offsets are clamped to the observation window.
    """

    pct = min(max(float(jitter_pct), 0.0), 100.0) / 100.0
    offsets: list[float] = []
    if mode != "fleet":
        offset = phase_s
        while offset <= duration_s:
            offsets.append(offset)
            offset += jittered_interval(rng, interval_s, jitter_pct)
        return offsets
    bound = pct * _FLEET_JITTER_SPAN * interval_s
    slot = 0
    while phase_s + slot * interval_s <= duration_s:
        centre = phase_s + slot * interval_s
        displaced = centre + float(rng.uniform(-bound, bound)) if bound > 0 else centre
        offsets.append(min(max(displaced, 0.0), float(duration_s)))
        slot += 1
    offsets.sort()
    return offsets


_IPS_REQUESTS: tuple[str, ...] = (
    "/struts2/index.action",
    "/index.php?option=login",
    "/api/v1/login",
    "/cgi-bin/test.cgi",
    "/wp-login.php",
    "/solr/admin/cores",
)


def _last_excluding(pool: list[str], excluded: set[str]) -> str:
    """The last entry of ``pool`` not in ``excluded``, for picking a foil entity.

    A benign foil entity that is also an attack entity makes the foil part of
    the attack. Taking the last free entry keeps every seed whose draw never
    collided byte-identical to before; only the colliding seeds change.
    """

    for candidate in reversed(pool):
        if candidate not in excluded:
            return candidate
    raise ValueError("entity pool is exhausted by the attack entities")


# (out_bytes range, in_bytes range, duration range) for one accepted east-west
# leg. Shared by the attack and its foil in each technique, so a byte or
# duration threshold cannot separate them: REP-013's worm and server baseline,
# REP-018's chain and admin star.
_LegShape = tuple[tuple[int, int], tuple[int, int], tuple[int, int]]
_WORM_LEG: _LegShape = ((600, 2_400), (1_500, 7_000), (2, 40))
_ADMIN_LEG: _LegShape = ((2_500, 6_500), (8_000, 18_000), (20, 120))


# REP-052: one SMB session that reads a share's files and writes them back.
# Both directions are large; out is at least in. The ranges and the write-to-read
# ratio are a design choice standing in for an encrypted rewrite, not a
# measurement, and the catalog says so.
SMB_WRITE_IN_BYTES = (300_000, 5_000_000)
SMB_WRITE_RATIO = (1.02, 1.25)
SMB_WRITE_DURATION_S = (20, 300)
SMB_PORT = 445


# REP-053: one inbound reflection session at an internal UDP service. The
# request is small; the reply is the request times the amplification factor the
# preset states. The foil's reply is the request times a symmetric band. The
# event rate is bounded by the events-per-second cap by design, so the signal
# lives in these bytes and never in rate, and the catalog says so.
REFLECT_REQUEST_BYTES = (60, 240)
REFLECT_FOIL_RATIO = (0.8, 1.25)
REFLECT_DURATION_S = (1, 30)


def _smb_write_leg(rng: Any) -> tuple[int, int, int]:
    """One (out_bytes, in_bytes, duration) draw for an accepted share rewrite."""

    in_b = lognormal_bytes(rng, SMB_WRITE_IN_BYTES[0], SMB_WRITE_IN_BYTES[1], sigma=0.5)
    out_b = int(in_b * float(rng.uniform(SMB_WRITE_RATIO[0], SMB_WRITE_RATIO[1])))
    duration = int(rng.integers(SMB_WRITE_DURATION_S[0], SMB_WRITE_DURATION_S[1] + 1))
    return out_b, in_b, duration


def _lateral_leg_shape(rng: Any, shape: _LegShape) -> tuple[int, int, int]:
    """One (out_bytes, in_bytes, duration) draw for an accepted lateral leg."""

    (out_lo, out_hi), (in_lo, in_hi), (dur_lo, dur_hi) = shape
    return (
        lognormal_bytes(rng, out_lo, out_hi, sigma=0.3),
        lognormal_bytes(rng, in_lo, in_hi, sigma=0.3),
        int(rng.integers(dur_lo, dur_hi + 1)),
    )


def _forwarded_bytes(rng: Any, value: int) -> int:
    """A forwarded leg's byte count: the original within a few percent.

    REP-024's relay and sanctioned proxy both forward rather than originate,
    so both outbound legs take this draw. The proxy used to copy the inbound
    count verbatim, which made exact byte equality a perfect foil detector.
    """

    return int(value * float(rng.uniform(0.97, 1.03)))


def _benign_sources_needed(volume: int, span_s: float, per_minute_ceiling: int) -> int:
    """How many routine sources must share ``volume`` events over ``span_s``.

    The answer keeps every source at or under ``per_minute_ceiling`` events in
    any one-minute window. The per-source budget is taken at 90% of the ceiling
    because event times are rounded to whole seconds, which can push one extra
    event into a window that the real-valued spacing would have excluded.
    """

    per_source = max(1, int(per_minute_ceiling * max(span_s, 1.0) / 60.0 * 0.9))
    return max(1, -(-volume // per_source))


def _control_pairs(sources: list[str], targets: list[str], count: int) -> list[tuple[str, str]]:
    """``count`` distinct (source, target) pairs cycling through both pools.

    Walks the sources in order and steps the target index by one extra each
    time the source list wraps, so no pair repeats until every combination has
    been used. The count is clamped to the number of combinations.
    """

    if not sources or not targets:
        return []
    count = min(count, len(sources) * len(targets))
    return [
        (sources[i % len(sources)], targets[(i + i // len(sources)) % len(targets)])
        for i in range(count)
    ]


_PHASE_TAGS = ("hs", "id", "tx")
_COUNTER_SPACE = 0x10000  # four hex digits


_PhaseSpans = tuple[tuple[int, int], tuple[int, int], tuple[int, int]]


def _phase_label_pools(
    rng: Any,
    count: int,
    minimum: int,
    maximum: int,
    spans: _PhaseSpans | None = None,
) -> tuple[tuple[list[str], list[str], list[str]], _PhaseSpans]:
    """Return setup, idle and transfer DNS labels with visible local structure.

    The random tail preserves the configured length and entropy envelope. The
    short ``<tag><counter>`` prefix gives adjacent labels within a phase a shared
    segment, which is observable in firewall query logs without inventing packet
    payload, TTL or response timing fields.

    Each phase's counters occupy a ``(base, width)`` span whose base is seeded
    rather than fixed at the label's index, and the spans are returned. The
    benign control passes them back in: its fewer labels are spread evenly
    across the SAME spans, so both streams share one prefix vocabulary, one
    counter range and one phase sequence. Before this the control's labels all
    began ``sv`` and the positive stream's began ``hs``/``id``/``tx``, so a regex
    on the first two characters separated them perfectly, while the catalog says
    unique-label cardinality is the only intended discriminator. Index-based
    counters were a second leak: the largest counter read off the cardinality.
    """

    count = max(count, 1)
    raw = high_entropy_labels(rng, count, minimum, maximum)
    setup_end = max(1, count // 10)
    idle_end = max(setup_end + 1, count * 3 // 10) if count > 1 else count
    idle_end = min(idle_end, count)
    chunks = (raw[:setup_end], raw[setup_end:idle_end], raw[idle_end:])
    if spans is None:
        widths = [max(len(chunk), 1) for chunk in chunks]
        spans = (
            (int(rng.integers(0, _COUNTER_SPACE - widths[0] + 1)), widths[0]),
            (int(rng.integers(0, _COUNTER_SPACE - widths[1] + 1)), widths[1]),
            (int(rng.integers(0, _COUNTER_SPACE - widths[2] + 1)), widths[2]),
        )

    def tagged(values: list[str], tag: str, span: tuple[int, int]) -> list[str]:
        base, width = span
        result: list[str] = []
        for index, value in enumerate(values):
            counter = base + (index * width) // max(len(values), 1)
            prefix = f"{tag}{counter % _COUNTER_SPACE:04x}"
            result.append(prefix + value[len(prefix) :])
        return result

    setup, idle, transfer = (
        tagged(chunk, tag, span)
        for chunk, tag, span in zip(chunks, _PHASE_TAGS, spans, strict=True)
    )
    # Tiny parameter overrides still produce a valid plan. Reusing the only
    # available pool is preferable to an index error and does not affect shipped
    # presets, all of which contain hundreds of unique labels.
    return (setup, idle or setup, transfer or idle or setup), spans


def _phase_pool(pools: tuple[list[str], list[str], list[str]], index: int, total: int) -> list[str]:
    """The setup (first 10%), idle (to 30%) or transfer pool for query ``index``."""

    fraction = index / max(total, 1)
    if fraction < 0.10:
        return pools[0]
    if fraction < 0.30:
        return pools[1]
    return pools[2]


@dataclass
class ScenarioPlan:
    technique_id: str
    technique_name: str
    intensity: str
    held: list[str]
    varied: list[str]
    effective_params: dict[str, Any]
    anchor_epoch: int
    warmup_note: str | None
    events: list[EventRecord] = field(default_factory=list)
    truncated: bool = False

    def __len__(self) -> int:
        return len(self.events)


# REP-028 configuration-change vocabulary. Labels only: nothing is configured.
# The weights are what the catalog states; test_rep028_admin_plane measures the
# emitted mix against them.
CFG_PATH_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("firewall.policy", 0.35),
    ("system.admin", 0.15),
    ("log.syslogd.setting", 0.15),
    ("system.interface", 0.15),
    ("firewall.address", 0.10),
    ("vpn.ssl.settings", 0.10),
)
CFG_ACTION_WEIGHTS: tuple[tuple[str, float], ...] = (("Edit", 0.7), ("Add", 0.2), ("Delete", 0.1))
_CFG_ATTRS: dict[str, tuple[str, ...]] = {
    "firewall.policy": (
        "status[enable->disable]",
        "action[deny->accept]",
        "logtraffic[all->disable]",
        "srcaddr[all]",
    ),
    "system.admin": ("trusthost1[0.0.0.0/0]", "accprofile[super_admin]", "password[*]"),
    "log.syslogd.setting": ("status[enable->disable]", "server[203.0.113.9]"),
    "system.interface": ("allowaccess[https ssh->https ssh ping]", "ip[10.20.30.1/24]"),
    "firewall.address": ("subnet[0.0.0.0/0]",),
    "vpn.ssl.settings": ("tunnel-ip-pools[SSLVPN_TUNNEL_ADDR1]", "source-interface[wan1]"),
}

_BuilderResult = tuple[list[EventRecord], str | None, bool]

# Technique id -> the ScenarioEngine method that plans it. Module level, and
# keyed by method NAME rather than by bound method, so that callers can ask
# which techniques are actually implemented without constructing an engine or
# provoking NotImplementedError.
#
# This is the single source of truth for that question. The web catalog used to
# answer it with its own hardcoded set of all eleven ids, which was true only by
# coincidence and silently made the "not yet implemented" UI states unreachable.
# test_engine_builder_names_resolve guards against a name here going stale.
_BUILDER_METHOD_NAMES: dict[str, str] = {
    "REP-001": "_plan_periodic_c2",
    "REP-002": "_plan_vertical_scan",
    "REP-003": "_plan_horizontal_sweep",
    "REP-004": "_plan_dns_tunnel",
    "REP-005": "_plan_exfil_volume",
    "REP-006": "_plan_destination_fanout",
    "REP-007": "_plan_brute_spray",
    "REP-008": "_plan_newly_observed_dst",
    "REP-009": "_plan_ips_spike",
    "REP-010": "_plan_denied_burst",
    "REP-011": "_plan_geovelocity",
    # v0.2.0 expansion (docs/technique-catalog-expansion-research*.md).
    "REP-012": "_plan_jittered_c2",
    "REP-013": "_plan_worm_spread",
    "REP-014": "_plan_cryptomining",
    "REP-015": "_plan_low_throughput_dns_exfil",
    "REP-016": "_plan_dga_nxdomain",
    "REP-017": "_plan_doh_bypass",
    "REP-018": "_plan_login_chain",
    "REP-019": "_plan_stealth_scan",
    "REP-020": "_plan_newly_registered_domain",
    "REP-021": "_plan_inbound_scan",
    "REP-022": "_plan_ids_alert_chain",
    "REP-023": "_plan_tls13_c2",
    "REP-024": "_plan_proxy_relay",
    # Research follow-up additions (docs/catalog-research-review-2026-09-08.md).
    "REP-030": "_plan_distributed_spray",
    "REP-043": "_plan_exploit_egress_dialog",
    "REP-028": "_plan_admin_config_burst",
    "REP-052": "_plan_smb_write_fanout",
    "REP-053": "_plan_reflection_amplification",
}


def implemented_technique_ids() -> frozenset[str]:
    """Technique ids the engine can plan. Everything else raises NotImplementedError."""
    return frozenset(_BUILDER_METHOD_NAMES)


class ScenarioEngine:
    """Deterministic technique-to-event planner. No I/O."""

    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        self.max_events = max_events

    def plan(
        self,
        technique: Technique,
        intensity: str,
        entities: EntityModel,
        seed: int,
        *,
        duration_override_s: int | None = None,
        anchor_epoch: int = DEFAULT_ANCHOR_EPOCH,
        param_overrides: dict[str, Any] | None = None,
    ) -> ScenarioPlan:
        preset = technique.preset(intensity)  # type: ignore[arg-type]
        if param_overrides:
            preset.update(param_overrides)

        builder_name = _BUILDER_METHOD_NAMES.get(technique.id)
        if builder_name is None:
            raise NotImplementedError(f"technique {technique.id} is not implemented")
        builder: Callable[..., _BuilderResult] = getattr(self, builder_name)

        rng = make_rng(seed)
        events, warmup, truncated = builder(
            technique, preset, entities, rng, anchor_epoch, duration_override_s
        )
        return ScenarioPlan(
            technique_id=technique.id,
            technique_name=technique.name,
            intensity=intensity,
            held=list(technique.cef_fields_held),
            varied=list(technique.cef_fields_varied),
            effective_params=preset,
            anchor_epoch=anchor_epoch,
            warmup_note=warmup,
            events=events,
            truncated=truncated,
        )

    # -- REP-001 periodic C2 callback -----------------------------------------

    def _plan_periodic_c2(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        interval_s = float(preset["interval_s"])
        jitter_pct = float(preset["jitter_pct"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_min"]) * 60
        )
        out_low, out_high = (int(v) for v in preset["out_bytes"])
        dpt_choices = list(technique.distributions.get("dpt_choices") or entities.c2_ports)

        src = str(rng.choice(entities.internal_hosts))
        dst = str(rng.choice(entities.adversary_external))
        dpt = int(rng.choice(dpt_choices))
        proto = 17 if dpt == 53 else 6
        service, app = port_service(dpt)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        offset = 0.0
        truncated = False
        # Leave room for the matched irregular control. A very long duration
        # must not silently consume the whole safety budget with the positive
        # stream and make a declared foil disappear.
        positive_cap = max(1, self.max_events // 2)
        while offset <= duration_s:
            out_b = lognormal_bytes(rng, out_low, out_high)
            in_b = max(out_b, lognormal_bytes(rng, out_low, out_high))
            spt = int(rng.integers(1024, 65535))
            duration = int(rng.integers(1, 180))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=technique.fortigate.action or "accept",
                    level="notice",
                    eventtime=anchor + int(offset),
                    src=src,
                    spt=spt,
                    dst=dst,
                    dpt=dpt,
                    proto=proto,
                    session_id=session,
                    out_bytes=out_b,
                    in_bytes=in_b,
                    extra={
                        "policyid": "7",
                        "service": service,
                        "app": app,
                        "trandisp": "snat",
                        "duration": str(duration),
                        "sentpkt": str(packet_count(out_b, session, typical_mss=150, spread=80)),
                        "rcvdpkt": str(packet_count(in_b, session, typical_mss=150, spread=80)),
                    },
                )
            )
            session += 1
            if len(events) >= positive_cap:
                truncated = True
                break
            offset += jittered_interval(rng, interval_s, jitter_pct)

        foil_start = len(events)
        positive_count = len(events)
        alternate = [candidate for candidate in entities.adversary_external if candidate != dst]
        foil_dst = str(rng.choice(alternate or entities.benign_external))
        # Same count, window, endpoint class, port and byte envelope as the
        # beacon. Only the interval shape changes. Random weights are normalized
        # to the same observation window so duration is not a shortcut either.
        weights = [float(rng.uniform(0.25, 1.75)) for _ in range(max(positive_count - 1, 0))]
        weight_total = sum(weights) or 1.0
        foil_offsets = [0.0]
        elapsed = 0.0
        for weight in weights:
            elapsed += weight
            foil_offsets.append(duration_s * elapsed / weight_total)
        for foil_offset in foil_offsets:
            if len(events) >= self.max_events:
                truncated = True
                break
            out_b = lognormal_bytes(rng, out_low, out_high)
            in_b = max(out_b, lognormal_bytes(rng, out_low, out_high))
            duration = int(rng.integers(1, 180))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=technique.fortigate.action or "accept",
                    level="notice",
                    eventtime=anchor + int(foil_offset),
                    src=src,
                    spt=int(rng.integers(1024, 65535)),
                    dst=foil_dst,
                    dpt=dpt,
                    proto=proto,
                    session_id=session,
                    out_bytes=out_b,
                    in_bytes=in_b,
                    extra={
                        "policyid": "7",
                        "service": service,
                        "app": app,
                        "trandisp": "snat",
                        "duration": str(duration),
                        "sentpkt": str(packet_count(out_b, session, typical_mss=150, spread=80)),
                        "rcvdpkt": str(packet_count(in_b, session, typical_mss=150, spread=80)),
                    },
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        note = (
            f"{positive_count} periodic callbacks and {len(events) - foil_start} "
            "same-shape irregular callbacks over the same observation window. "
            "Interval regularity is the intended discriminator."
        )
        return events, note, truncated

    # -- REP-002 vertical port scan -------------------------------------------

    def _plan_vertical_scan(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        unique_ports = int(preset["unique_ports"])
        window_s = int(preset["window_s"])

        truncated = False
        # A scan cannot visit more distinct ports than exist. Without this,
        # `unique_ints(rng, 1, 65535, unique_ports)` below raises out of a
        # distribution helper rather than the caller explaining itself. Clamped
        # rather than rejected, to match how max_events is handled on the next
        # two lines, and recorded the same way.
        if unique_ports > PORT_SPAN:
            unique_ports = PORT_SPAN
            truncated = True
        # Reserve half of the bounded plan for the matched sparse control. The
        # control repeats the same global port/action/time distribution but
        # spreads it over ordinary source/destination pairs, so the intended
        # per-pair distinct-port axis is the only count that changes.
        positive_cap = max(1, self.max_events // 2)
        if unique_ports > positive_cap:
            unique_ports = positive_cap
            truncated = True

        # The window is the detection surface: a vertical-scan rule counts
        # distinct ports per source INSIDE window_s, so the probes are spread
        # across the whole window (as REP-003 does) rather than fired at a
        # millisecond cadence and finishing long before the window closes. The
        # catalog used to carry a gap_ms parameter for that cadence; eventtime
        # is integer epoch seconds, so a 1 to 50 ms gap was not expressible and
        # the parameter was dropped rather than kept as a label with no effect.
        # A duration override is honoured the REP-019 way: the preset density is
        # kept and the probe count gives way to fit the shorter window.
        gap_s = window_s / max(unique_ports, 1)
        if duration_override_s is not None and gap_s > 0:
            unique_ports = max(1, min(unique_ports, int(duration_override_s / gap_s)))

        src = str(rng.choice(entities.internal_hosts))
        dst = str(rng.choice(entities.internal_targets))
        ports = unique_ints(rng, 1, 65535, unique_ports)
        open_count = max(1, unique_ports // 200)
        open_indices = set(unique_ints(rng, 0, unique_ports - 1, min(open_count, unique_ports)))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        for index, dpt in enumerate(ports):
            is_open = index in open_indices
            action = "accept" if is_open else "deny"
            level = "notice" if is_open else "warning"
            service, app = port_service(dpt)
            spt = int(rng.integers(1024, 65535))
            extra = _scan_traffic_extra(is_open, service, app)
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=action,
                    level=level,
                    eventtime=anchor + int(index * gap_s),
                    src=src,
                    spt=spt,
                    dst=dst,
                    dpt=dpt,
                    proto=6,
                    session_id=session,
                    out_bytes=0,
                    in_bytes=0,
                    extra=extra,
                )
            )
            session += 1
        foil_start = len(events)
        # The control spreads the SAME probes over enough routine pairs that no
        # pair exceeds BENIGN_PORTS_PER_MIN distinct ports in any minute. It
        # used to be sixteen fixed pairs whatever the preset, so at medium and
        # high every "benign" pair was itself a 63 to 250 port scan and the
        # per-pair rule it exists to test separated nothing.
        pairs = _control_pairs(
            [host for host in entities.internal_hosts if host != src],
            [host for host in entities.internal_targets if host != dst],
            _benign_sources_needed(unique_ports, unique_ports * gap_s, BENIGN_PORTS_PER_MIN),
        )
        if pairs:
            for index, dpt in enumerate(ports):
                control_src, control_dst = pairs[index % len(pairs)]
                is_open = index in open_indices
                service, app = port_service(dpt)
                events.append(
                    EventRecord(
                        log_type=technique.fortigate.log_type,
                        subtype=technique.fortigate.subtype,
                        action="accept" if is_open else "deny",
                        level="notice" if is_open else "warning",
                        eventtime=anchor + int(index * gap_s),
                        src=control_src,
                        spt=int(rng.integers(1024, 65535)),
                        dst=control_dst,
                        dpt=dpt,
                        proto=6,
                        session_id=session,
                        out_bytes=0,
                        in_bytes=0,
                        extra=_scan_traffic_extra(is_open, service, app),
                    )
                )
                session += 1
        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        return events, None, truncated

    # -- REP-003 horizontal sweep ---------------------------------------------

    def _plan_horizontal_sweep(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        unique_hosts = int(preset["unique_hosts"])
        port = int(preset["port"])
        window_s = (
            duration_override_s if duration_override_s is not None else int(preset["window_s"])
        )

        pool = entities.sweep_hosts
        truncated = False
        if unique_hosts > len(pool):
            unique_hosts = len(pool)
            truncated = True
        positive_cap = max(1, self.max_events // 2)
        if unique_hosts > positive_cap:
            unique_hosts = positive_cap
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        dst_indices = unique_ints(rng, 0, len(pool) - 1, unique_hosts)
        open_count = max(1, unique_hosts // 200)
        open_indices = set(unique_ints(rng, 0, unique_hosts - 1, min(open_count, unique_hosts)))
        service, app = port_service(port)
        gap_s = window_s / max(unique_hosts, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        for index, dst_index in enumerate(dst_indices):
            is_open = index in open_indices
            action = "accept" if is_open else "deny"
            level = "notice" if is_open else "warning"
            spt = int(rng.integers(1024, 65535))
            extra = _scan_traffic_extra(is_open, service, app)
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=action,
                    level=level,
                    eventtime=anchor + int(index * gap_s),
                    src=src,
                    spt=spt,
                    dst=pool[dst_index],
                    dpt=port,
                    proto=6,
                    session_id=session,
                    out_bytes=0,
                    in_bytes=0,
                    extra=extra,
                )
            )
            session += 1
        foil_start = len(events)
        # Enough routine sources that none reaches more than
        # BENIGN_HOSTS_PER_MIN destinations in any minute. Sixteen fixed sources
        # carried 64 to 256 hosts each at medium and high, which is a sweep. The
        # target subnet joins the pool because the high preset needs more
        # sources than one /24 holds; the sweep's own destinations are drawn
        # from a different range, so none of these hosts is also swept.
        source_pool = [host for host in entities.internal_hosts if host != src]
        source_pool += [host for host in entities.internal_targets if host not in source_pool]
        control_sources = source_pool[
            : _benign_sources_needed(unique_hosts, window_s, BENIGN_HOSTS_PER_MIN)
        ]
        if control_sources:
            for index, dst_index in enumerate(dst_indices):
                is_open = index in open_indices
                events.append(
                    EventRecord(
                        log_type=technique.fortigate.log_type,
                        subtype=technique.fortigate.subtype,
                        action="accept" if is_open else "deny",
                        level="notice" if is_open else "warning",
                        eventtime=anchor + int(index * gap_s),
                        src=control_sources[index % len(control_sources)],
                        spt=int(rng.integers(1024, 65535)),
                        dst=pool[dst_index],
                        dpt=port,
                        proto=6,
                        session_id=session,
                        out_bytes=0,
                        in_bytes=0,
                        extra=_scan_traffic_extra(is_open, service, app),
                    )
                )
                session += 1
        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        return events, None, truncated

    # -- REP-005 outbound exfil volume anomaly --------------------------------

    def _plan_exfil_volume(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        sessions = int(preset["sessions"])
        total_out_bytes = int(preset["total_out_mb"]) * 1_000_000
        dst_count = int(preset["dst_count"])
        dpt_choices = list(technique.distributions.get("dpt_choices") or [443, 22, 21])

        truncated = False
        # Current positive + three low-volume history windows + a matched
        # negative current window + three high-volume negative history windows.
        # Keeping the complete comparison is more important than consuming the
        # whole materialization budget with the positive spike.
        comparison_multiplier = 8
        if sessions * comparison_multiplier > self.max_events:
            sessions = max(1, self.max_events // comparison_multiplier)
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        dst_pool = entities.adversary_external
        dst_indices = unique_ints(rng, 0, len(dst_pool) - 1, min(dst_count, len(dst_pool)))
        destinations = [dst_pool[i] for i in dst_indices]
        dpt = int(rng.choice(dpt_choices))
        service, app = port_service(dpt)

        # 00:00-06:00 UTC+04:00, and that window is the signal rather than a
        # detail: the transfer is suspicious because of when it happens. A
        # shorter duration narrows the window inside off-hours, which stays
        # faithful. A longer one is capped instead of honoured, because spilling
        # into the working day would destroy the property being demonstrated.
        full_window_s = OFF_HOURS_END_H * 3600
        off_window_s = (
            min(duration_override_s, full_window_s) if duration_override_s else full_window_s
        )
        off_start, off_window_s = _off_hours_window(anchor, off_window_s)
        # The full comparison, not just the current spike, must honour
        # --duration. Divide the bounded off-hours span into three historical
        # buckets followed by one current bucket. This keeps the plan inside
        # one operator-requested window while still making "relative to this
        # host's own preceding traffic" observable without external history.
        history_windows = 3
        comparison_windows = history_windows + 1
        bucket_s = off_window_s / comparison_windows
        current_start = off_start + int(history_windows * bucket_s)
        per_session_out = total_out_bytes // max(sessions, 1)
        slot_s = bucket_s / max(sessions, 1)

        def session_offsets() -> list[int]:
            # One session per slot, placed somewhere inside its slot rather than
            # on the slot boundary. Every window draws its own, so no window is
            # an exact grid and no two windows share one timetable.
            return [
                int(index * slot_s + float(rng.uniform(0.0, 0.9 * slot_s)))
                for index in range(sessions)
            ]

        def session_bytes(per_session: int) -> tuple[int, int]:
            # The one byte draw every window uses, history and current alike.
            out_b = max(1, int(per_session * float(rng.uniform(0.8, 1.2))))
            return out_b, max(1, out_b // 40)  # out:in well above the 20:1 threshold

        events: list[EventRecord] = []
        session_id = int(rng.integers(10_000, 60_000))
        current_offsets = session_offsets()
        for index in range(sessions):
            out_b, in_b = session_bytes(per_session_out)
            duration = int(rng.integers(60, 3600))
            spt = int(rng.integers(1024, 65535))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=technique.fortigate.action or "accept",
                    level="notice",
                    eventtime=current_start + current_offsets[index],
                    src=src,
                    spt=spt,
                    dst=destinations[index % len(destinations)],
                    dpt=dpt,
                    proto=6,
                    session_id=session_id,
                    out_bytes=out_b,
                    in_bytes=in_b,
                    extra={
                        "policyid": "7",
                        "service": service,
                        "app": app,
                        "trandisp": "snat",
                        "duration": str(duration),
                        "sentpkt": str(packet_count(out_b, session_id)),
                        "rcvdpkt": str(packet_count(in_b, session_id)),
                    },
                )
            )
            session_id += 1

        current_positive = list(events)

        def history_window(history_index: int, per_session: int, source: str, control: str) -> None:
            # One preceding bucket of the same sessions (port, destinations,
            # durations) at a per-session volume drawn with the current window's
            # own jitter. History used to carry one constant byte value per
            # window on an exact grid, so "every session in this window is the
            # same size" picked the history out without reading any history.
            nonlocal session_id
            offsets = session_offsets()
            for index, current in enumerate(current_positive):
                out_b, in_b = session_bytes(per_session)
                events.append(
                    current.model_copy(
                        update={
                            "control": control,
                            "src": source,
                            "eventtime": off_start + int(history_index * bucket_s) + offsets[index],
                            "session_id": session_id,
                            "out_bytes": out_b,
                            "in_bytes": in_b,
                            "extra": {
                                **current.extra,
                                "sentpkt": str(packet_count(out_b, session_id)),
                                "rcvdpkt": str(packet_count(in_b, session_id)),
                            },
                        }
                    )
                )
                session_id += 1

        # Three preceding buckets establish that the positive host normally
        # emits at most 500 KB per bucket. These are part of the positive stream
        # because a per-host anomaly cannot be evaluated without history.
        for history_index in range(history_windows):
            history_total = int(rng.integers(100_000, 500_001))
            history_window(
                history_index, max(1, history_total // max(sessions, 1)), src, "positive"
            )

        foil_start = len(events)
        control_hosts = [host for host in entities.internal_hosts if host != src]
        if control_hosts:
            control_src = str(rng.choice(control_hosts))
            # The current negative window is byte-for-byte equivalent in its numeric
            # traffic fields. Its different meaning comes only from the history that
            # follows: this host has repeatedly carried the same bulk workload.
            for current in current_positive:
                events.append(
                    current.model_copy(
                        update={
                            "control": "negative",
                            "src": control_src,
                            "session_id": session_id,
                        }
                    )
                )
                session_id += 1
            # The control's history carries the current window's bulk volume,
            # drawn afresh per session rather than copied, so the control host
            # has a real history of this workload rather than three replays of
            # tonight's.
            for history_index in range(history_windows):
                history_window(history_index, per_session_out, control_src, "negative")
        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        note = (
            "Three prior per-host windows establish a low-volume positive baseline and a "
            "matched high-volume control baseline. Current-window session count, bytes, port, "
            "destinations and off-hours timing overlap; deviation from host history is the axis."
        )
        return events, note, truncated

    # -- REP-006 destination fan-out burst ------------------------------------

    def _plan_destination_fanout(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        unique_dst = int(preset["unique_dst"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        # A mix of synthetic internal and external destinations (blueprint/catalog).
        mixed = (
            entities.internal_targets
            + entities.benign_external
            + entities.adversary_external
            + entities.sweep_hosts
        )
        truncated = False
        if unique_dst > len(mixed):
            unique_dst = len(mixed)
            truncated = True
        if unique_dst > self.max_events:
            unique_dst = self.max_events
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        dst_indices = unique_ints(rng, 0, len(mixed) - 1, unique_dst)
        dpt_choices = [443, 80, 53, 8080, 22]
        gap_s = window_s / max(unique_dst, 1)

        events: list[EventRecord] = []
        session_id = int(rng.integers(10_000, 60_000))
        for index, dst_index in enumerate(dst_indices):
            dpt = int(rng.choice(dpt_choices))
            proto = 17 if dpt == 53 else 6
            is_open = index % 10 != 0  # mostly accept, occasional deny
            action = "accept" if is_open else "deny"
            level = "notice" if is_open else "warning"
            service, app = port_service(dpt)
            out_b = int(rng.integers(80, 4000))
            in_b = int(rng.integers(80, 8000))
            spt = int(rng.integers(1024, 65535))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=action,
                    level=level,
                    eventtime=anchor + int(index * gap_s),
                    src=src,
                    spt=spt,
                    dst=mixed[dst_index],
                    dpt=dpt,
                    proto=proto,
                    session_id=session_id,
                    out_bytes=out_b,
                    in_bytes=in_b,
                    extra=_scan_traffic_extra(is_open, service, app),
                )
            )
            session_id += 1

        # Structural FP foil (roadmap #9, shared-IP fan-out): a legitimate internal
        # proxy or egress gateway is ALSO 'one source, many destinations', so a rule
        # keyed on that aggregation alone fires on it. This breaks the source-fanout
        # key rather than adding benign volume, so the only honest discriminator is
        # destination context (the proxy reaches known-good externals, the attack
        # reaches the adversary and sweep pools), not the count of distinct dsts.
        # Co-located in the same window, so time of day is not a free discriminator.
        others = [h for h in entities.internal_hosts if h != src]
        if not truncated and others and entities.benign_external:
            foil_start = len(events)
            proxy = str(rng.choice(others))
            benign_dsts = entities.benign_external
            room = self.max_events - len(events)
            foil_count = max(0, min(len(benign_dsts), max(3, unique_dst // 2), room))
            proxy_session = int(rng.integers(60_000, 90_000))
            dpt_choices = [443, 80, 53, 8080, 22]
            for j in range(foil_count):
                dpt = int(rng.choice(dpt_choices))
                proto = 17 if dpt == 53 else 6
                # Match the attack's distributions so the ONLY discriminator is the
                # destination (a proxy reaches known-good externals): same ports,
                # same byte ranges, same occasional policy deny. Diverging on bytes,
                # action or ports would hand the analyst a free FP filter that works
                # on synthetic data and fails in production.
                is_open = j % 10 != 0
                action = "accept" if is_open else "deny"
                level = "notice" if is_open else "warning"
                service, app = port_service(dpt)
                events.append(
                    EventRecord(
                        log_type=technique.fortigate.log_type,
                        subtype=technique.fortigate.subtype,
                        action=action,
                        level=level,
                        eventtime=anchor + int(j * gap_s),
                        src=proxy,
                        spt=int(rng.integers(1024, 65535)),
                        dst=benign_dsts[j],
                        dpt=dpt,
                        proto=proto,
                        session_id=proxy_session + j,
                        out_bytes=int(rng.integers(80, 4000)),
                        in_bytes=int(rng.integers(80, 8000)),
                        extra=_scan_traffic_extra(is_open, service, app),
                    )
                )
            self._mark_negative(events, foil_start)
        # The foil is co-located in the attack's window but appended after it, so
        # without this the plan stepped backwards in time: --to-file wrote a
        # non-monotonic log and plan pacing sent the foil late.
        events.sort(key=lambda event: event.eventtime)
        return events, None, truncated

    # -- REP-010 denied outbound connection burst -----------------------------

    def _plan_denied_burst(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        denies = int(preset["denies"])
        window_s = (
            duration_override_s if duration_override_s is not None else int(preset["window_s"])
        )

        truncated = False
        positive_cap = max(1, self.max_events // 2)
        if denies > positive_cap:
            denies = positive_cap
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        pool = entities.adversary_external
        dst_count = min(5, len(pool))  # one src hammering a few blocked external destinations
        dst_indices = unique_ints(rng, 0, len(pool) - 1, dst_count)
        destinations = [pool[i] for i in dst_indices]
        dpt_choices = [443, 8443, 8080, 53, 4444]

        events: list[EventRecord] = []
        session_id = int(rng.integers(10_000, 60_000))
        count = max(denies, 1)
        for index in range(denies):
            # Sharp spike then decay: event density is highest at the start.
            fraction = (index / count) ** 2
            dpt = int(rng.choice(dpt_choices))
            proto = 17 if dpt == 53 else 6
            service, app = port_service(dpt)
            spt = int(rng.integers(1024, 65535))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="deny",
                    level="warning",
                    eventtime=anchor + int(fraction * window_s),
                    src=src,
                    spt=spt,
                    dst=destinations[index % len(destinations)],
                    dpt=dpt,
                    proto=proto,
                    session_id=session_id,
                    out_bytes=0,
                    in_bytes=0,
                    extra=_scan_traffic_extra(False, service, app),
                )
            )
            session_id += 1
        foil_start = len(events)
        # Enough routine sources that none is denied more than
        # BENIGN_DENIES_PER_MIN times in any minute. Sixteen fixed sources took
        # 19 to 63 denies each inside the one-minute window at medium and high,
        # so the "routine" foil was itself the burst the rule keys on.
        source_pool = [host for host in entities.internal_hosts if host != src]
        source_pool += [host for host in entities.internal_targets if host not in source_pool]
        control_sources = source_pool[
            : _benign_sources_needed(denies, window_s, BENIGN_DENIES_PER_MIN)
        ]
        if control_sources:
            for index, positive in enumerate(events[:foil_start]):
                dpt = positive.dpt or dpt_choices[0]
                service, app = port_service(dpt)
                events.append(
                    EventRecord(
                        log_type=technique.fortigate.log_type,
                        subtype=technique.fortigate.subtype,
                        action="deny",
                        level="warning",
                        eventtime=anchor + int(index * window_s / max(denies, 1)),
                        src=control_sources[index % len(control_sources)],
                        spt=int(rng.integers(1024, 65535)),
                        dst=positive.dst,
                        dpt=dpt,
                        proto=positive.proto,
                        session_id=session_id,
                        out_bytes=0,
                        in_bytes=0,
                        extra=_scan_traffic_extra(False, service, app),
                    )
                )
                session_id += 1
        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        return events, None, truncated

    # -- REP-007 brute force / password spray ---------------------------------

    def _plan_brute_spray(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        mode = str(preset["mode"])
        attempts_each = int(preset["attempts_each"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        # One external attacking source hammers the SSL-VPN portal (src is held).
        src = str(rng.choice(entities.adversary_external))

        if mode == "spray":
            usernames = synthetic_usernames(int(preset["users"]), entities.users)
            # (user, attempt) pairs: each victim tried attempts_each times.
            pairs = [(user, attempt) for user in usernames for attempt in range(attempts_each)]
        else:  # brute: one victim, many attempts
            usernames = synthetic_usernames(1, entities.users)
            pairs = [(usernames[0], attempt) for attempt in range(attempts_each)]

        truncated = False
        if len(pairs) > self.max_events:
            pairs = pairs[: self.max_events]
            truncated = True

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        gap_s = window_s / max(len(pairs), 1)
        for index, (user, _attempt) in enumerate(pairs):
            reason = _VPN_FAIL_REASONS[int(rng.integers(0, len(_VPN_FAIL_REASONS)))]
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="ssl-login-fail",
                    level="alert",
                    eventtime=anchor + int(index * gap_s),
                    duser=user,
                    src=src,
                    session_id=session,
                    extra={
                        "logdesc": "SSL VPN login fail",
                        "fgt_action": "ssl-login-fail",
                        "remip": src,
                        "tunneltype": "ssl-web",
                        "reason": reason,
                        "msg": "SSL user failed to logged in",
                    },
                )
            )
            session += 1
        # Brute force optionally ends in one successful login (the guessed password).
        if mode == "brute" and not truncated:
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="tunnel-up",
                    level="notice",
                    eventtime=anchor + window_s,
                    duser=usernames[0],
                    src=src,
                    session_id=session,
                    extra={
                        "logdesc": "SSL VPN tunnel up",
                        "fgt_action": "tunnel-up",
                        "remip": src,
                        "tunneltype": "ssl-tunnel",
                        "tunnelid": str(int(rng.integers(1_000_000, 9_999_999))),
                        "group": "vpn-users",
                        "reason": "login-success",
                        "msg": "SSL tunnel established",
                    },
                )
            )

        # Structural FP foil (roadmap #9, NAT/proxy source-collapse): a CGNAT or
        # office egress fronts many users, so per-source login counts spike benignly.
        # An analyst cannot set a per-source spray threshold honestly without this in
        # the data. The honest discriminator is the fail RATIO and the presence of
        # successes (this source mostly succeeds, across distinct users), not the raw
        # count of login events from one source, which the attack and a NAT share.
        # Co-located in the same window, so time of day is not a free discriminator.
        if not truncated and entities.benign_external:
            foil_start = len(events)
            nat = str(rng.choice(entities.benign_external))
            # Sized from the attack's login VOLUME, not its user count: in brute
            # mode `users` is 1, so a NAT sized from it fronted four users and
            # emitted 4 to 8 events against 400, and per-source count separated
            # the two for free at the one preset where it should not.
            nat_users = synthetic_usernames(max(4, len(pairs) // 2), entities.users)
            nat_session = int(rng.integers(60_000, 90_000))
            step = window_s / max(len(nat_users) * 2, 1)
            k = 0
            for user in nat_users:
                if len(events) >= self.max_events - 1:
                    break
                # a realistic office user: an occasional typo fail, then a success.
                if int(rng.integers(0, 10)) < 4:
                    reason = _VPN_FAIL_REASONS[int(rng.integers(0, len(_VPN_FAIL_REASONS)))]
                    events.append(
                        EventRecord(
                            log_type=technique.fortigate.log_type,
                            subtype=technique.fortigate.subtype,
                            action="ssl-login-fail",
                            level="alert",
                            eventtime=anchor + int(k * step),
                            duser=user,
                            src=nat,
                            session_id=nat_session + k,
                            extra={
                                "logdesc": "SSL VPN login fail",
                                "fgt_action": "ssl-login-fail",
                                "remip": nat,
                                "tunneltype": "ssl-web",
                                "reason": reason,
                                "msg": "SSL user failed to logged in",
                            },
                        )
                    )
                    k += 1
                events.append(
                    EventRecord(
                        log_type=technique.fortigate.log_type,
                        subtype=technique.fortigate.subtype,
                        action="tunnel-up",
                        level="notice",
                        eventtime=anchor + int(k * step),
                        duser=user,
                        src=nat,
                        session_id=nat_session + k,
                        extra={
                            "logdesc": "SSL VPN tunnel up",
                            "fgt_action": "tunnel-up",
                            "remip": nat,
                            "tunneltype": "ssl-tunnel",
                            "tunnelid": str(int(rng.integers(1_000_000, 9_999_999))),
                            "group": "vpn-users",
                            "reason": "login-success",
                            "msg": "SSL tunnel established",
                        },
                    )
                )
                k += 1
            self._mark_negative(events, foil_start)
        # Same reason as REP-006: the NAT foil shares the attack window and is
        # appended after it, so it has to be merged into time order.
        events.sort(key=lambda event: event.eventtime)
        return events, None, truncated

    # -- REP-009 IDS/IPS event-rate spike -------------------------------------

    def _plan_ips_spike(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        hits = int(preset["hits"])
        signature_mode = str(preset.get("signature_mode", "mixed"))
        if signature_mode not in {"mixed", "single"}:
            raise ValueError("REP-009 signature_mode must be 'mixed' or 'single'")
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )
        baseline_window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["baseline_window_min"]) * 60
        )

        truncated = False
        if hits > max(1, self.max_events // 2):
            hits = max(1, self.max_events // 2)
            truncated = True

        dst = str(rng.choice(entities.internal_targets))  # the attacked host, held
        src_pool = entities.adversary_external
        gap_s = window_s / max(hits, 1)
        baseline_gap_s = baseline_window_s / max(hits, 1)
        step = max(1, hits // 5)  # cnt escalates across five aggregation steps

        events: list[EventRecord] = []
        session = int(rng.integers(100, 9999))
        fixed_signature = _IPS_SIGNATURES[int(rng.integers(0, len(_IPS_SIGNATURES)))]
        signatures = [
            (
                fixed_signature
                if signature_mode == "single"
                else _IPS_SIGNATURES[int(rng.integers(0, len(_IPS_SIGNATURES)))]
            )
            for _ in range(hits)
        ]
        requests = [_IPS_REQUESTS[int(rng.integers(0, len(_IPS_REQUESTS)))] for _ in range(hits)]

        def append_hit(
            *,
            index: int,
            target: str,
            when: int,
            source: str,
            control: Literal["positive", "negative"] = "positive",
        ) -> None:
            nonlocal session
            attack, attackid = signatures[index]
            critical = index % 3 == 0
            # Both at FortiOS level "alert" (CEF 7 on FortiGate, 8 on PAN-OS).
            # Critical hits used level "critical", which FortiOS reverses to 6,
            # BELOW the high hits' 7: the most severe hits rendered as the least
            # severe. The level ordering of critical versus alert is opposite on
            # FortiGate and PAN-OS, so no pair of distinct levels ranks critical
            # above high on both. The severity split is carried where each vendor
            # defines it: FTNTFGTseverity, PAN-OS cs2, and Check Point's header,
            # which maps ips_severity to High and Very-High.
            level = "alert"
            ips_severity = "critical" if critical else "high"
            cnt = 1 + index // step
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="reset",
                    level=level,
                    eventtime=when,
                    control=control,
                    src=source,
                    spt=int(rng.integers(1024, 65535)),
                    dst=target,
                    dpt=443,
                    proto=6,
                    session_id=session,
                    extra={
                        "eventtype": "signature",
                        "ips_severity": ips_severity,
                        "service": "HTTPS",
                        "policyid": "7",
                        "attack": attack,
                        "attackid": attackid,
                        "hostname": target,
                        "request": requests[index],
                        "direction": "incoming",
                        "profile": "default",
                        "cnt": str(cnt),
                        "msg": f"applications3A {attack}",
                    },
                )
            )
            session += 1

        for index in range(hits):
            append_hit(
                index=index,
                target=dst,
                when=anchor + int(index * gap_s),
                source=str(rng.choice(src_pool)),
            )

        # Same hit count, signatures, severity mix and aggregation counters on a
        # second target, spread across a much longer window. Rate is the intended
        # discriminator; signature cardinality and severity are unavailable as
        # shortcuts.
        foil_targets = [target for target in entities.internal_targets if target != dst]
        foil_dst = str(rng.choice(foil_targets))
        for index in range(hits):
            append_hit(
                index=index,
                target=foil_dst,
                when=anchor + int(index * baseline_gap_s),
                source=str(rng.choice(src_pool)),
                control="negative",
            )

        events.sort(key=lambda event: event.eventtime)
        note = (
            f"signature_mode={signature_mode}; {hits} spike hits over {window_s}s and "
            f"{hits} matched baseline hits over {baseline_window_s}s."
        )
        return events, note, truncated

    # -- REP-008 newly observed external destination per host -----------------

    def _forward_accept(
        self,
        technique: Technique,
        rng: Any,
        src: str,
        dst: str,
        dpt: int,
        eventtime: int,
        session: int,
    ) -> EventRecord:
        """One benign-looking traffic:forward accept record (shared by baseline+novel)."""

        service, app = port_service(dpt)
        out_b = int(rng.integers(200, 20_000))
        in_b = int(rng.integers(500, 200_000))
        duration = int(rng.integers(1, 600))
        spt = int(rng.integers(1024, 65535))
        return EventRecord(
            log_type=technique.fortigate.log_type,
            subtype=technique.fortigate.subtype,
            action="accept",
            level="notice",
            eventtime=eventtime,
            src=src,
            spt=spt,
            dst=dst,
            dpt=dpt,
            proto=6,
            session_id=session,
            out_bytes=out_b,
            in_bytes=in_b,
            extra={
                "policyid": "7",
                "service": service,
                "app": app,
                "trandisp": "snat",
                "duration": str(duration),
                "sentpkt": str(packet_count(out_b, session)),
                "rcvdpkt": str(packet_count(in_b, session)),
            },
        )

    def _plan_newly_observed_dst(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        baseline_days = int(preset["baseline_days"])
        novel_dst = int(preset["novel_dst"])
        known_count = 5

        # One host talking to a small stable set of external peers, then to new ones.
        src = str(rng.choice(entities.internal_hosts))
        benign = entities.benign_external
        known = [
            benign[i] for i in unique_ints(rng, 0, len(benign) - 1, min(known_count, len(benign)))
        ]
        adversary = entities.adversary_external
        novel = [
            adversary[i]
            for i in unique_ints(rng, 0, len(adversary) - 1, min(novel_dst, len(adversary)))
        ]

        # Compressed history: one hit per known destination per baseline day.
        baseline_events = len(known) * baseline_days
        truncated = False
        if baseline_events + len(novel) > self.max_events:
            baseline_events = max(self.max_events - len(novel), 0)
            truncated = True

        dpt_choices = [443, 80, 8080, 8443, 22]
        # The baseline is COMPRESSED on purpose: baseline_days sets how many
        # contacts the history holds (one per known destination per simulated
        # day), not how much time it spans. Spreading it over baseline_days of
        # real time was considered and rejected: plan pacing reproduces the gap
        # between the first and last event, so a 30 day baseline would take 30
        # days of wall clock to send, and --duration could not bound it without
        # discarding the history the novelty signal is measured against. The
        # warm-up note states the compression rather than claiming the days.
        baseline_span_s = 3600  # compressed warm-up window
        anomaly_span_s = 300  # the first-seen destinations follow the warm-up

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        for index in range(baseline_events):
            dst = known[index % len(known)]
            dpt = int(rng.choice(dpt_choices))
            when = anchor + int(index * baseline_span_s / max(baseline_events, 1))
            events.append(self._forward_accept(technique, rng, src, dst, dpt, when, session))
            session += 1
        anomaly_start = anchor + baseline_span_s + 1
        for offset, dst in enumerate(novel):
            dpt = int(rng.choice(dpt_choices))
            when = anomaly_start + int(offset * anomaly_span_s / max(len(novel), 1))
            events.append(self._forward_accept(technique, rng, src, dst, dpt, when, session))
            session += 1

        note = (
            f"Baseline: {len(known)} known destinations, one contact each per simulated "
            f"day for {baseline_days}d ({baseline_events} events), compressed into the "
            f"{baseline_span_s}s before first contact rather than spread over "
            f"{baseline_days} days of event time. A detection whose novelty window is "
            f"measured in days sees this history as one hour. Anomaly begins at event "
            f"{baseline_events} with {len(novel)} first-seen external destination(s)."
        )
        return events, note, truncated

    # -- REP-011 VPN geovelocity anomaly --------------------------------------

    def _plan_geovelocity(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        logins = int(preset["logins"])
        countries = int(preset["countries"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        # Group the synthetic external pool by its GeoIP tag, then pick distant blocks.
        by_country: dict[str, list[str]] = {}
        for ip, country in entities.countries.items():
            by_country.setdefault(country, []).append(ip)
        country_names = sorted(by_country)
        chosen = [
            country_names[i]
            for i in unique_ints(rng, 0, len(country_names) - 1, min(countries, len(country_names)))
        ]

        user = str(rng.choice(entities.users))  # one user, held (impossible travel)
        gap_s = window_s / max(logins, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(1_000_000, 9_999_999))
        for index in range(logins):
            country = chosen[index % len(chosen)]
            pool = by_country[country]
            src = str(pool[int(rng.integers(0, len(pool)))])
            # The address the VPN assigned to this session. It is what ties the
            # login to everything the session then does from inside the network:
            # in a scenario the internal pool is pinned to the victim, so the
            # beacon that follows (SCEN-003's REP-001) has this as its source,
            # and a rule can pivot duser -> tunnelip -> src. Before 2026-10-07
            # the login carried only the remote address, so no such join existed.
            tunnelip = str(rng.choice(entities.internal_hosts))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="tunnel-up",
                    level="notice",
                    eventtime=anchor + int(index * gap_s),
                    duser=user,
                    src=src,
                    session_id=session,
                    extra={
                        "logdesc": "SSL VPN tunnel up",
                        "fgt_action": "tunnel-up",
                        "remip": src,
                        "srccountry": country,
                        "tunneltype": "ssl-tunnel",
                        "tunnelid": str(int(rng.integers(1_000_000, 9_999_999))),
                        "tunnelip": tunnelip,
                        "group": "vpn-users",
                        "reason": "login-success",
                        "msg": "SSL tunnel established",
                    },
                )
            )
            session += 1
        return events, None, False

    # -- REP-004 DNS tunneling ------------------------------------------------

    def _plan_dns_tunnel(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        qps = int(preset["qps"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_min"]) * 60
        )
        label_lo, label_hi = (int(v) for v in preset["label_len"])
        unique_labels = int(preset["unique_labels"])

        requested_total = qps * duration_s
        # Positive and negative streams carry equal query counts. Reserve half
        # the bounded plan for each rather than truncating the control away.
        total = min(requested_total, max(1, self.max_events // 2))
        truncated = False
        if total < requested_total:
            truncated = True
        total = max(total, 1)

        src = str(rng.choice(entities.internal_hosts))
        dst = entities.resolver
        parent = str(rng.choice(entities.parents))
        label_count = min(unique_labels, total)
        pools, spans = _phase_label_pools(rng, label_count, label_lo, label_hi)

        qtypes = ["TXT", "NULL", "CNAME", "A"]
        qtypevals = {"TXT": "16", "NULL": "10", "CNAME": "5", "A": "1"}
        weights = [0.40, 0.25, 0.20, 0.15]

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        chosen_qtypes: list[str] = []
        for index in range(total):
            pool = _phase_pool(pools, index, total)
            label = pool[index % len(pool)]
            qname = f"{label}.{parent}"
            qtype = weighted_choice(rng, qtypes, weights)
            chosen_qtypes.append(qtype)
            spt = int(rng.integers(1024, 65535))
            xid = int(rng.integers(0, 65535))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=technique.fortigate.action or "pass",
                    level="notice",
                    eventtime=anchor + int(index / qps),
                    src=src,
                    spt=spt,
                    dst=dst,
                    dpt=53,
                    proto=17,
                    session_id=session,
                    extra={
                        "policyid": "7",
                        "profile": "default",
                        "xid": str(xid),
                        "qname": qname,
                        "qtype": qtype,
                        "qtypeval": qtypevals[qtype],
                        "qclass": "IN",
                    },
                )
            )
            session += 1

        foil_start = len(events)
        benign_parent = str(
            rng.choice([item for item in entities.parents if item != parent] or [parent])
        )
        benign_unique = max(5, min(total, unique_labels // 8))
        # Same prefix vocabulary, same counter ranges and same phase sequence as
        # the positive stream (see _phase_label_pools), so no leading-label regex
        # separates them.
        benign_pools, _ = _phase_label_pools(rng, benign_unique, label_lo, label_hi, spans)
        benign_count = sum(len(set(pool)) for pool in benign_pools)
        # This synthetic service-discovery/cache-key stream matches query count,
        # qtype sequence, label-length envelope, high-entropy tails and label
        # prefix scheme. Its lower unique-label cardinality is the intended
        # discriminator.
        for index in range(total):
            benign_pool = _phase_pool(benign_pools, index, total)
            qname = f"{benign_pool[index % len(benign_pool)]}.{benign_parent}"
            events.append(
                self._dns_query_record(
                    rng,
                    src,
                    dst,
                    qname,
                    chosen_qtypes[index],
                    anchor + int(index / qps),
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda event: event.eventtime)
        note = (
            f"{total} phase-aware tunnel queries and {total} matched machine-generated "
            f"queries at {qps}/s; positive cardinality {label_count}, control cardinality "
            f"{benign_count}."
        )
        return events, note, truncated

    # =========================================================================
    # v0.2.0 expansion. Research anchors per technique are in the catalog entry
    # and in docs/technique-catalog-expansion-research*.md.
    #
    # Shared convention: where a technique's detection depends on separating the
    # signal from a look-alike, the planner emits the look-alike too. That is a
    # correctness requirement, not decoration. A plan containing only the
    # malicious pattern lets any rule score perfectly (round 2 doc, section 2).
    # =========================================================================

    def _dns_query_record(
        self,
        rng: Any,
        src: str,
        resolver: str,
        qname: str,
        qtype: str,
        eventtime: int,
        session: int,
    ) -> EventRecord:
        """One dns:dns-query record. Shared by the DNS-carried techniques."""

        qtypevals = {"A": "1", "AAAA": "28", "TXT": "16", "NULL": "10", "CNAME": "5"}
        return EventRecord(
            log_type="dns",
            subtype="dns-query",
            action="pass",
            level="notice",
            eventtime=eventtime,
            src=src,
            spt=int(rng.integers(1024, 65535)),
            dst=resolver,
            dpt=53,
            proto=17,
            session_id=session,
            extra={
                "policyid": "7",
                "profile": "default",
                "xid": str(int(rng.integers(0, 65535))),
                "qname": qname,
                "qtype": qtype,
                "qtypeval": qtypevals[qtype],
                "qclass": "IN",
            },
        )

    @staticmethod
    def _mark_negative(events: list[EventRecord], start: int) -> None:
        """Label every event appended since ``start`` as the benign foil.

        Called right after a builder's benign-foil block, so the foil is
        addressable (``--controls``) and separable from the technique's own
        pattern after ingestion. Marking a slice rather than each construction
        keeps the builders readable and cannot miss a record in the block.
        """

        for event in events[start:]:
            event.control = "negative"

    def _steady_accept(
        self,
        rng: Any,
        src: str,
        dst: str,
        dpt: int,
        eventtime: int,
        session: int,
        out_b: int,
        in_b: int,
        duration: int,
        *,
        inbound: bool = False,
        proto: int = 6,
    ) -> EventRecord:
        """A traffic:forward accept with caller-controlled byte and duration shape.

        ``inbound=True`` reverses the interface pair, which is what makes an
        internet-to-perimeter record distinguishable from an egress record.
        ``proto`` defaults to TCP; REP-053 passes 17 for its UDP services.
        """

        service, app = port_service(dpt)
        extra = {
            "policyid": "7",
            "service": service,
            "app": app,
            "trandisp": "snat" if not inbound else "dnat",
            "duration": str(duration),
            "sentpkt": str(packet_count(out_b, session)),
            "rcvdpkt": str(packet_count(in_b, session)),
        }
        if inbound:
            extra["src_intf"] = "port1"  # WAN
            extra["dst_intf"] = "port2"  # LAN
        return EventRecord(
            log_type="traffic",
            subtype="forward",
            action="accept",
            level="notice",
            eventtime=eventtime,
            src=src,
            spt=int(rng.integers(1024, 65535)),
            dst=dst,
            dpt=dpt,
            proto=proto,
            session_id=session,
            out_bytes=out_b,
            in_bytes=in_b,
            extra=extra,
        )

    def _deny_probe(
        self,
        rng: Any,
        src: str,
        dst: str,
        dpt: int,
        eventtime: int,
        session: int,
        *,
        inbound: bool = False,
    ) -> EventRecord:
        """A denied probe record, the unit of every scan technique."""

        service, app = port_service(dpt)
        extra = _scan_traffic_extra(False, service, app)
        if inbound:
            extra["src_intf"] = "port1"
            extra["dst_intf"] = "port2"
        return EventRecord(
            log_type="traffic",
            subtype="forward",
            action="deny",
            level="warning",
            eventtime=eventtime,
            src=src,
            spt=int(rng.integers(1024, 65535)),
            dst=dst,
            dpt=dpt,
            proto=6,
            session_id=session,
            out_bytes=0,
            in_bytes=0,
            extra=extra,
        )

    # -- REP-012 jittered and fleet-aggregate C2 callback ----------------------

    def _plan_jittered_c2(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        mode = str(preset["mode"])
        hosts = int(preset["hosts"])
        interval_s = float(preset["interval_s"])
        jitter_pct = float(preset["jitter_pct"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_min"]) * 60
        )
        out_low, out_high = (int(v) for v in preset["out_bytes"])
        dpt_choices = list(technique.distributions.get("dpt_choices") or entities.c2_ports)

        pool = entities.internal_hosts
        srcs = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(hosts, len(pool)))]
        dst = str(rng.choice(entities.adversary_external))
        dpt = int(rng.choice(dpt_choices))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False
        # In fleet mode each host is given a phase offset so that no single host
        # looks periodic over a short window, but the arrivals seen at the shared
        # destination are. That is the effect the ACSAC 2023 study measured.
        for index, src in enumerate(srcs):
            phase = (index * interval_s / max(len(srcs), 1)) if mode == "fleet" else 0.0
            for offset in _callback_offsets(rng, mode, interval_s, jitter_pct, phase, duration_s):
                out_b = lognormal_bytes(rng, out_low, out_high)
                in_b = max(out_b, lognormal_bytes(rng, out_low, out_high))
                events.append(
                    self._steady_accept(
                        rng,
                        src,
                        dst,
                        dpt,
                        anchor + int(offset),
                        session,
                        out_b,
                        in_b,
                        int(rng.integers(1, 180)),
                    )
                )
                session += 1
                if len(events) >= self.max_events:
                    truncated = True
                    break
            if truncated:
                break

        foil_start = len(events)
        # Benign periodic destination. Both source papers name legitimate
        # periodic software as the dominant false positive, so a plan without one
        # overstates how well a periodicity test performs.
        #
        # Drawn from outside the attacking fleet: at high intensity 40 of 254
        # hosts beacon, so an unfiltered draw made the "benign" source one of
        # the C2 hosts on about one seed in six.
        #
        # The update check runs on the SAME timing process, jitter fraction,
        # interval, port, byte envelope and duration draw as the beacon. It used
        # to be a perfect 1800 s comb with zero variance: the most periodic
        # thing in the plan by a wide margin, so a trivial periodicity test
        # flagged the foil far more strongly than the attack and the control
        # rewarded the wrong detector. Then it kept its own 30 minute cadence
        # with 2 to 40 KB responses and 1 to 20 s sessions against a beacon at
        # 300 or 3600 s with sub-2 KB responses, so interval, in_bytes and
        # duration each separated it on their own. Sharing every draw leaves
        # the discriminators the catalog names: aggregation across the fleet,
        # and destination context.
        attackers = set(srcs)
        benign_pool = [host for host in pool if host not in attackers] or pool
        benign_src = str(rng.choice(benign_pool))
        benign_dst = str(rng.choice(entities.benign_external))
        for benign_offset in _callback_offsets(rng, mode, interval_s, jitter_pct, 0.0, duration_s):
            if len(events) >= self.max_events:
                truncated = True
                break
            out_b = lognormal_bytes(rng, out_low, out_high)
            in_b = max(out_b, lognormal_bytes(rng, out_low, out_high))
            events.append(
                self._steady_accept(
                    rng,
                    benign_src,
                    benign_dst,
                    dpt,
                    anchor + int(benign_offset),
                    session,
                    out_b,
                    in_b,
                    int(rng.integers(1, 180)),
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"mode={mode}: {len(srcs)} source(s) to one destination, jitter "
            f"{jitter_pct:.0f}%. A benign periodic destination with the same jitter "
            "process is included as a false-positive control."
        )
        return events, note, truncated

    # -- REP-013 self-propagating malware spread ------------------------------

    def _plan_worm_spread(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        seed_hosts = int(preset["seed_hosts"])
        generations = int(preset["generations"])
        fanout = int(preset["fanout"])
        port = int(preset["port"])
        gen_gap_s = int(preset["gen_gap_s"])

        targets = entities.internal_targets
        pool = entities.internal_hosts
        infected = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(seed_hosts, len(pool)))]
        seed_set = set(infected)
        # A fixed fraction of probes land, so the infected population grows
        # geometrically. PORTFILER's signal is the count of DISTINCT sources on a
        # port per window, not the probe volume, so growth is the whole point.
        # Floor of 2, not 1: at 1 the population would stay flat and the
        # technique would degenerate into a slow version of REP-003.
        landed_per_source = max(2, fanout // 6)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False
        for generation in range(generations):
            gen_start = anchor + generation * gen_gap_s
            probes = max(len(infected) * fanout, 1)
            next_infected: list[str] = []
            for host_index, source in enumerate(infected):
                picks = unique_ints(rng, 0, len(targets) - 1, min(fanout, len(targets)))
                for probe_index, target_index in enumerate(picks):
                    dst = targets[target_index]
                    landed = probe_index < landed_per_source
                    when = gen_start + int((host_index * fanout + probe_index) * gen_gap_s / probes)
                    if landed:
                        out_b, in_b, duration = _lateral_leg_shape(rng, _WORM_LEG)
                        events.append(
                            self._steady_accept(
                                rng, source, dst, port, when, session, out_b, in_b, duration
                            )
                        )
                        if dst not in next_infected and dst not in infected:
                            next_infected.append(dst)
                    else:
                        events.append(self._deny_probe(rng, source, dst, port, when, session))
                    session += 1
                    if len(events) >= self.max_events:
                        truncated = True
                        break
                if truncated:
                    break
            if truncated:
                break
            if next_infected:
                infected = next_infected

        foil_start = len(events)
        # Benign east-west baseline: a small stable set of server sources on the
        # same port. Same protocol, same port, non-growing source population.
        # Each server reaches `fanout` targets per generation window with the
        # worm's own accept/deny mix and leg draws, so per-source volume, byte
        # size, duration and action cannot pick it out. It used to be twelve
        # constant accepted records (2400/8800/30 s) whatever the preset, which
        # a rule could key on without ever counting sources.
        # Drawn from outside the seed set: a baseline server that is also a seed
        # host would grow like the worm and the control would stop being one.
        benign_pool = [host for host in pool if host not in seed_set]
        for server_index in range(3):
            server = benign_pool[(server_index + 1) % len(benign_pool)]
            for step in range(generations):
                step_start = anchor + step * gen_gap_s
                picks = unique_ints(rng, 0, len(targets) - 1, min(fanout, len(targets)))
                for probe_index, target_index in enumerate(picks):
                    if len(events) >= self.max_events:
                        break
                    dst = targets[target_index]
                    when = step_start + int(probe_index * gen_gap_s / max(fanout, 1))
                    if probe_index < landed_per_source:
                        out_b, in_b, duration = _lateral_leg_shape(rng, _WORM_LEG)
                        events.append(
                            self._steady_accept(
                                rng, server, dst, port, when, session, out_b, in_b, duration
                            )
                        )
                    else:
                        events.append(self._deny_probe(rng, server, dst, port, when, session))
                    session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{generations} generation(s) from {seed_hosts} seed host(s) on port {port}; "
            "distinct source count grows per generation. A stable server baseline on "
            "the same port, with the same per-source fanout and accept/deny mix, is "
            "included as a false-positive control."
        )
        return events, note, truncated

    # -- REP-014 cryptomining pool session ------------------------------------

    def _plan_cryptomining(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        sessions = int(preset["sessions"])
        share_interval_s = int(preset["share_interval_s"])
        dpt = int(preset["dpt"])
        # Sessions run back to back, so the span is sessions * session_s. A
        # duration is a request for the TOTAL, and reading it as the per-session
        # length silently multiplied it by the session count: 2h asked, 6h
        # planned. Divided here, floored at one share so a session still
        # exchanges something. The share interval itself is never rescaled; a
        # steady exchange every share_interval_s is what separates a miner from
        # exfiltration.
        session_s = (
            max(duration_override_s // max(sessions, 1), share_interval_s)
            if duration_override_s is not None
            else int(preset["session_min"]) * 60
        )

        src = str(rng.choice(entities.internal_hosts))
        dst = str(rng.choice(entities.adversary_external))
        shares = max(session_s // max(share_interval_s, 1), 1)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False
        for pool_session in range(sessions):
            start = anchor + pool_session * session_s
            for share in range(shares):
                # Job in, share out: both small, roughly symmetric, and steady.
                # The distinguishing shape versus exfiltration is the ratio, and
                # versus a callback it is the single long-lived session id.
                out_b = int(rng.integers(180, 420))
                in_b = int(out_b * float(rng.uniform(0.85, 1.20)))
                events.append(
                    self._steady_accept(
                        rng,
                        src,
                        dst,
                        dpt,
                        start + share * share_interval_s,
                        session,
                        out_b,
                        in_b,
                        (share + 1) * share_interval_s,  # duration grows within the session
                    )
                )
                if len(events) >= self.max_events:
                    truncated = True
                    break
            session += 1
            if truncated:
                break

        foil_start = len(events)
        # Benign long-lived session: comparable duration profile, bursty bytes.
        # MineShark had to auto-filter over 99.3% of its alarms, which is the
        # argument for including this. The foil must reach the same order of
        # magnitude as the miner session: a foil that dies after a few minutes
        # while the miner holds for hours is separable on duration alone, which
        # is exactly the shortcut the foil exists to deny.
        benign_dst = str(rng.choice(entities.benign_external))
        benign_steps = max(1, min(12, shares))
        step_span_s = max(session_s // benign_steps, share_interval_s)
        for step in range(benign_steps):
            if len(events) >= self.max_events:
                break
            events.append(
                self._steady_accept(
                    rng,
                    src,
                    benign_dst,
                    443,
                    anchor + step * step_span_s,
                    session,
                    int(rng.integers(200, 90_000)),  # bursty, unlike the miner
                    int(rng.integers(200, 400_000)),
                    (step + 1) * step_span_s,
                )
            )
        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{sessions} pool session(s) of {session_s // 60} min, one exchange every "
            f"{share_interval_s}s on port {dpt}. A bursty long-lived benign session is "
            "included as a false-positive control."
        )
        return events, note, truncated

    # -- REP-015 low-throughput DNS exfiltration ------------------------------

    def _plan_low_throughput_dns_exfil(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        qph = int(preset["qph"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_h"]) * 3600
        )
        label_lo, label_hi = (int(v) for v in preset["label_len"])
        unique_labels = int(preset["unique_labels"])

        total = max(qph * duration_s // 3600, 1)
        truncated = False
        if total > self.max_events:
            total = self.max_events
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        parent = str(rng.choice(entities.parents))
        label_count = min(unique_labels, total)
        pools, spans = _phase_label_pools(rng, label_count, label_lo, label_hi)
        gap_s = 3600.0 / max(qph, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        # Weighted to A and AAAA, not TXT: the query name itself is the channel,
        # so the record type does not need to carry a payload. That is what makes
        # this class invisible to a TXT-oriented tunnel rule.
        qtypes = ["A", "AAAA"]
        weights = [0.75, 0.25]
        chosen_qtypes: list[str] = []
        for index in range(total):
            pool = _phase_pool(pools, index, total)
            qname = f"{pool[index % len(pool)]}.{parent}"
            qtype = weighted_choice(rng, qtypes, weights)
            chosen_qtypes.append(qtype)
            events.append(
                self._dns_query_record(
                    rng,
                    src,
                    entities.resolver,
                    qname,
                    qtype,
                    anchor + int(index * gap_s),
                    session,
                )
            )
            session += 1

        foil_start = len(events)
        # Benign machine-generated names with a comparable query count, qtype
        # sequence, label length and entropy tail, but lower cardinality. Familiar
        # five-label browsing was too easy and did not test the stated analytic.
        benign_parent = str(rng.choice([p for p in entities.parents if p != parent] or [parent]))
        benign_unique = max(5, min(total, unique_labels // 8))
        # Same prefix vocabulary, counter ranges and phase sequence as the
        # positive stream, so a leading-label regex cannot separate them.
        benign_pools, _ = _phase_label_pools(rng, benign_unique, label_lo, label_hi, spans)
        for index in range(min(total, self.max_events - len(events))):
            benign_pool = _phase_pool(benign_pools, index, total)
            qname = f"{benign_pool[index % len(benign_pool)]}.{benign_parent}"
            events.append(
                self._dns_query_record(
                    rng,
                    src,
                    entities.resolver,
                    qname,
                    chosen_qtypes[index],
                    anchor + int(index * gap_s) + 7,
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{qph} queries/hour over {duration_s // 3600}h ({total} exfil queries), "
            f"{label_count} phase-aware labels under one parent. Deliberately below "
            "tunnel-rate thresholds. A same-volume machine-generated control is included."
        )
        return events, note, truncated

    # -- REP-016 DGA NXDOMAIN cluster -----------------------------------------

    def _dns_response_record(
        self,
        rng: Any,
        src: str,
        resolver: str,
        qname: str,
        rcode: str,
        eventtime: int,
        session: int,
        ipaddr: str | None = None,
    ) -> EventRecord:
        """One dns:dns-response record. The resolution OUTCOME, which a query lacks."""

        extra = {
            "policyid": "7",
            "profile": "default",
            "xid": str(int(rng.integers(0, 65535))),
            "qname": qname,
            "qtype": "A",
            "qtypeval": "1",
            "qclass": "IN",
            "rcode": rcode,
        }
        if ipaddr is not None:
            extra["ipaddr"] = ipaddr
        return EventRecord(
            log_type="dns",
            subtype="dns-response",
            action="pass",
            level="notice",
            eventtime=eventtime,
            src=src,
            spt=int(rng.integers(1024, 65535)),
            dst=resolver,
            dpt=53,
            proto=17,
            session_id=session,
            extra=extra,
        )

    def _plan_dga_nxdomain(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        domains_per_epoch = int(preset["domains_per_epoch"])
        epochs = int(preset["epochs"])
        label_lo, label_hi = (int(v) for v in preset["label_len"])
        nx_ratio = float(preset["nx_ratio"])

        src = str(rng.choice(entities.internal_hosts))
        epoch_s = (duration_override_s or 3600) // max(epochs, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False
        resolved_total = 0
        for epoch in range(epochs):
            # The domain set regenerates per epoch, mirroring a time-seeded
            # generator. Distinct second-level labels, not subdomains of one
            # parent: that inversion is what separates this from REP-004.
            labels = high_entropy_labels(rng, domains_per_epoch, label_lo, label_hi)
            resolved_index = int(domains_per_epoch * nx_ratio)
            for index, label in enumerate(labels):
                resolved = index >= resolved_index
                when = anchor + epoch * epoch_s + int(index * epoch_s / max(domains_per_epoch, 1))
                events.append(
                    self._dns_response_record(
                        rng,
                        src,
                        entities.resolver,
                        # Reserved TLD: thousands of unseen names are generated
                        # here and none of them can ever resolve.
                        f"{label}.invalid",
                        "NOERROR" if resolved else "NXDOMAIN",
                        when,
                        session,
                        # Only the registered rendezvous domain returns an answer.
                        str(rng.choice(entities.adversary_external)) if resolved else None,
                    )
                )
                resolved_total += int(resolved)
                session += 1
                if len(events) >= self.max_events:
                    truncated = True
                    break
            if truncated:
                break

        foil_start = len(events)
        # Benign NXDOMAIN trickle: typos and stale records. Without it, a rule
        # that alerts on any NXDOMAIN at all would look perfect. Capped at the
        # plan window so the trickle cannot outlive the epochs (or a duration
        # override) it is meant to blend into.
        benign_parent = str(rng.choice(entities.parents))
        window_s = epochs * epoch_s
        for index in range(min(12, max(self.max_events - len(events), 0))):
            events.append(
                self._dns_response_record(
                    rng,
                    src,
                    entities.resolver,
                    f"{'wpad' if index % 2 else 'isatap'}.{benign_parent}",
                    "NXDOMAIN",
                    anchor + min(index * max(epoch_s // 2, 1), window_s),
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{epochs} epoch(s) of {domains_per_epoch} distinct generated domains, "
            f"{nx_ratio:.0%} answered NXDOMAIN and {resolved_total} resolved (the "
            "registered rendezvous domain). A benign NXDOMAIN trickle is included so "
            "thresholding on NXDOMAIN alone does not look sufficient."
        )
        return events, note, truncated

    # -- REP-017 encrypted DNS (DoH) policy bypass ----------------------------

    def _plan_doh_bypass(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        total_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["baseline_min"]) * 60
        )
        switch_s = min(int(preset["switch_at_min"]) * 60, total_s)
        doh_sessions = int(preset["doh_sessions"])
        resolvers = int(preset["resolvers"])

        src = str(rng.choice(entities.internal_hosts))
        pool = entities.adversary_external
        doh_hosts = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(resolvers, len(pool)))]
        benign_labels = ["www", "mail", "api", "cdn", "updates", "portal"]
        parent = str(rng.choice(entities.parents))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False

        # Phase 1: ordinary resolver traffic. This is the baseline, and the
        # detection has to notice when it STOPS.
        query_gap_s = 10
        for index in range(max(switch_s // query_gap_s, 1)):
            qname = f"{benign_labels[index % len(benign_labels)]}.{parent}"
            events.append(
                self._dns_query_record(
                    rng, src, entities.resolver, qname, "A", anchor + index * query_gap_s, session
                )
            )
            session += 1
            if len(events) >= self.max_events:
                truncated = True
                break

        # Phase 2: resolver traffic ceases; small repeated TLS sessions to the
        # synthetic DoH resolvers begin. No dns:dns-query record after switch_s.
        phase2_s = max(total_s - switch_s, 1)
        for index in range(doh_sessions):
            if len(events) >= self.max_events:
                truncated = True
                break
            events.append(
                self._steady_accept(
                    rng,
                    src,
                    doh_hosts[index % len(doh_hosts)],
                    443,
                    anchor + switch_s + int(index * phase2_s / max(doh_sessions, 1)),
                    session,
                    int(rng.integers(120, 480)),  # query out
                    int(rng.integers(200, 900)),  # answer in
                    int(rng.integers(1, 4)),
                )
            )
            session += 1

        events.sort(key=lambda e: e.eventtime)
        note = (
            f"Warm-up: normal resolver queries for the first {switch_s // 60} min. "
            f"At +{switch_s // 60} min resolver traffic stops and {doh_sessions} DoH "
            f"session(s) to {len(doh_hosts)} synthetic resolver(s) on 443 begin. The "
            "detection signal is the absence of port 53 traffic, not its presence."
        )
        return events, note, truncated

    # -- REP-018 lateral movement login chain ---------------------------------

    def _plan_login_chain(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        path_len = max(1, int(preset["path_len"]))
        user_count = max(1, int(preset["users"]))
        switch_at_hop = int(preset["switch_at_hop"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        pool = entities.internal_hosts
        hops = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(path_len, len(pool)))]
        user_pool = entities.users
        # A path of N hosts can carry at most N distinct causal identities: one
        # on entry and one at each later hop. Cap overrides to that physical
        # limit so the run note always describes identities actually emitted.
        users = [
            user_pool[i]
            for i in unique_ints(
                rng,
                0,
                len(user_pool) - 1,
                min(user_count, len(user_pool), len(hops)),
            )
        ]
        if len(users) > 1:
            # Leave at least one later hop for every requested identity. This
            # keeps even an over-late private override internally consistent.
            latest_complete_switch = len(hops) - len(users) + 1
            switch_at_hop = min(max(switch_at_hop, 1), latest_complete_switch)
        entry_src = str(rng.choice(entities.adversary_external))
        admin_ports = [3389, 445, 22]
        hop_gap_s = window_s / max(path_len, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(1_000_000, 9_999_999))
        truncated = False

        # Hop 1 is remote access into the estate: an SSL-VPN tunnel-up.
        events.append(
            EventRecord(
                log_type="event",
                subtype="vpn",
                action="tunnel-up",
                level="notice",
                eventtime=anchor,
                duser=users[0],
                src=entry_src,
                session_id=session,
                extra={
                    "logdesc": "SSL VPN tunnel up",
                    "fgt_action": "tunnel-up",
                    "remip": entry_src,
                    "srccountry": entities.countries.get(entry_src, "Wadiya"),
                    "tunneltype": "ssl-tunnel",
                    "tunnelid": str(int(rng.integers(1_000_000, 9_999_999))),
                    "group": "vpn-users",
                    "reason": "login-success",
                    "msg": "SSL tunnel established",
                },
            )
        )
        session += 1

        # Each subsequent hop: an authenticated login recorded on the system log,
        # plus the east-west traffic leg. The causal user changes at
        # switch_at_hop, which is the credential-switch signal Hopper keys on.
        for hop in range(1, len(hops)):
            if len(events) + 2 > self.max_events:
                truncated = True
                break
            if len(users) == 1 or hop < switch_at_hop:
                user = users[0]
            else:
                # The first credential change occurs at switch_at_hop. Spread
                # any remaining identities over the rest of the chain, making
                # the catalog's users parameter an exact emitted count rather
                # than an upper bound that medium intensity never reached.
                post_switch_hops = max(len(hops) - switch_at_hop, 1)
                progress = hop - switch_at_hop
                denominator = max(post_switch_hops - 1, 1)
                remaining_index = min(
                    len(users) - 2,
                    (progress * (len(users) - 1)) // denominator,
                )
                user = users[1 + remaining_index]
            source = hops[hop - 1]
            target = hops[hop]
            when = anchor + int(hop * hop_gap_s)
            dpt = admin_ports[hop % len(admin_ports)]
            events.append(
                EventRecord(
                    log_type="event",
                    subtype="system",
                    action="login",
                    level="notice",
                    eventtime=when,
                    duser=user,
                    src=source,
                    session_id=session,
                    extra={
                        "logdesc": "Admin login successful",
                        "fgt_action": "login",
                        "status": "success",
                        "ui": f"ssh({source})",
                        "method": "ssh",
                        "reason": "none",
                        "msg": f"Administrator {user} logged in successfully from {source}",
                    },
                )
            )
            session += 1
            out_b, in_b, duration = _lateral_leg_shape(rng, _ADMIN_LEG)
            events.append(
                self._steady_accept(
                    rng, source, target, dpt, when + 2, session, out_b, in_b, duration
                )
            )
            session += 1

        foil_start = len(events)
        # Benign star: one workstation logging into several hosts. Same login
        # count, same port rotation, same leg draw, different shape. Chain
        # versus star IS the detection. The legs used to be constants, 4200 /
        # 12800 / 60 s on the chain against 3900 / 11400 / 45 s on the star,
        # and the star sat on 3389 while the chain rotated 3389 / 445 / 22, so
        # bytes or port alone told them apart.
        # The last host OFF the chain: a fixed pool[-1] sat on the chain itself
        # whenever the hop draw included it, so the "benign" star source was
        # also a lateral-movement hop.
        star_src = _last_excluding(pool, set(hops))
        for index in range(1, len(hops)):
            if len(events) + 2 > self.max_events:
                truncated = True
                break
            target = hops[(index + 1) % len(hops)]
            when = anchor + int(index * hop_gap_s) + 5
            events.append(
                EventRecord(
                    log_type="event",
                    subtype="system",
                    action="login",
                    level="notice",
                    eventtime=when,
                    duser=users[0],
                    src=star_src,
                    session_id=session,
                    extra={
                        "logdesc": "Admin login successful",
                        "fgt_action": "login",
                        "status": "success",
                        "ui": f"ssh({star_src})",
                        "method": "ssh",
                        "reason": "none",
                        "msg": f"Administrator {users[0]} logged in successfully from {star_src}",
                    },
                )
            )
            session += 1
            out_b, in_b, duration = _lateral_leg_shape(rng, _ADMIN_LEG)
            events.append(
                self._steady_accept(
                    rng,
                    star_src,
                    target,
                    admin_ports[index % len(admin_ports)],
                    when + 2,
                    session,
                    out_b,
                    in_b,
                    duration,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"Chain of {len(hops)} hops with {len(users)} user(s), credential switch at "
            f"hop {switch_at_hop}. A benign admin star pattern with the same login count "
            "is included; separating chain from star is the detection."
        )
        return events, note, truncated

    # -- REP-019 stealth scan below rate threshold ----------------------------

    def _plan_stealth_scan(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        probes_per_dst = max(1, int(preset["probes_per_dst"]))
        gap_lo, gap_hi = (float(v) for v in preset["gap_s"])
        src_pool_size = int(preset["src_pool"])
        total_probes = int(preset["total_probes"])

        truncated = False
        if total_probes > self.max_events:
            total_probes = self.max_events
            truncated = True

        # The span is the probe count times the gap, and the LONG GAP is the
        # evasion: TRW converges on a few attempts from one source, so stretching
        # them out is the technique. Shrinking the gap to fit a window would
        # emulate a scan nobody is trying to hide. The probe count gives way
        # instead.
        mean_gap_s = (gap_lo + gap_hi) / 2.0
        if duration_override_s is not None and mean_gap_s > 0:
            total_probes = max(1, min(total_probes, int(duration_override_s / mean_gap_s)))

        pool = entities.internal_hosts
        sources = [
            pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(src_pool_size, len(pool)))
        ]
        targets = entities.internal_targets
        ports = list(entities.scan_ports) + [1433, 3306, 8080, 5900]

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        elapsed = 0.0
        dst = targets[0]
        dpt = ports[0]
        for index in range(total_probes):
            # Source rotation keeps per-source counts under per-source
            # thresholds; the long gap keeps any rate window from filling. TRW
            # converges on a small number of attempts FROM ONE SOURCE, so
            # spreading the walk across a pool is the evasion.
            target_index = index // probes_per_dst
            src = sources[target_index % len(sources)]
            if index % probes_per_dst == 0:
                dst = targets[int(rng.integers(0, len(targets)))]
                dpt = int(rng.choice(ports))
            events.append(self._deny_probe(rng, src, dst, dpt, anchor + int(elapsed), session))
            session += 1
            if index + 1 < total_probes:
                elapsed += float(rng.uniform(gap_lo, gap_hi))

        foil_start = len(events)
        # Sparse benign policy denies: as many unrelated hosts as the probe pool,
        # each retrying a couple of fixed (destination, port) targets it cannot
        # reach, with the probes' own gap distribution and total count. What
        # separates them is the graph: the probes cover many distinct targets
        # across the pool, the benign hosts each hit the same two. It used to
        # be one host on 445 at a fixed elapsed/20 spacing, twenty probes
        # whatever the preset, so source count, port, gap regularity and volume
        # each separated it alone. Unrelated means outside the rotating probe
        # pool, which a fixed pool[-1] was not whenever the draw included it.
        probing = set(sources)
        benign_sources = [host for host in reversed(pool) if host not in probing][: len(sources)]
        port_start = int(rng.integers(0, len(ports)))
        benign_targets = [
            [
                (targets[int(rng.integers(0, len(targets)))], ports[(port_start + k) % len(ports)])
                for k in (2 * which, 2 * which + 1)
            ]
            for which in range(len(benign_sources))
        ]
        benign_elapsed = float(rng.uniform(gap_lo, gap_hi))
        for index in range(total_probes if benign_sources else 0):
            if len(events) >= self.max_events:
                truncated = True
                break
            which = index % len(benign_sources)
            dst, dpt = benign_targets[which][int(rng.integers(0, 2))]
            events.append(
                self._deny_probe(
                    rng, benign_sources[which], dst, dpt, anchor + int(benign_elapsed), session
                )
            )
            session += 1
            benign_elapsed += float(rng.uniform(gap_lo, gap_hi))

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{total_probes} probes across {len(sources)} rotating sources over "
            f"{int(elapsed) // 60} min. Per-source and per-window counts are held below "
            "classic threshold detectors by design."
        )
        return events, note, truncated

    # -- REP-020 first contact with a newly registered domain -----------------

    def _plan_newly_registered_domain(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        baseline_domains = int(preset["baseline_domains"])
        novel_domains = int(preset["novel_domains"])
        hosts = int(preset["hosts"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        pool = entities.internal_hosts
        srcs = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(hosts, len(pool)))]
        # Organizational normal is a stable, repeatedly queried domain set, and
        # a first-contact domain is one never queried by any host before. Both
        # draw their parent from the same documentation and .invalid pool and
        # their label from one draw with one length envelope, so the only thing
        # that marks a novel name is its absence from the history. The baseline
        # used to sit under one parent with 5 to 9 character labels and every
        # novel name was a bare 8 to 14 character <label>.invalid, so "qname
        # not under the baseline parent" scored perfectly without any history.
        parents = list(entities.parents)
        labels = high_entropy_labels(rng, baseline_domains + novel_domains, 5, 12)
        known = [
            f"{label}.{parents[int(rng.integers(0, len(parents)))]}"
            for label in labels[:baseline_domains]
        ]
        novel = [
            f"{label}.{parents[int(rng.integers(0, len(parents)))]}"
            for label in labels[baseline_domains:]
        ]

        truncated = False
        baseline_events = min(baseline_domains, max(self.max_events - novel_domains, 1))
        if baseline_events < baseline_domains:
            truncated = True

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        baseline_span_s = max(window_s - 300, 60)
        for index in range(baseline_events):
            events.append(
                self._dns_query_record(
                    rng,
                    srcs[index % len(srcs)],
                    entities.resolver,
                    known[index % len(known)],
                    "A",
                    anchor + int(index * baseline_span_s / max(baseline_events, 1)),
                    session,
                )
            )
            session += 1

        novel_start = anchor + baseline_span_s + 1
        for index, qname in enumerate(novel):
            events.append(
                self._dns_query_record(
                    rng,
                    srcs[index % len(srcs)],
                    entities.resolver,
                    qname,
                    "A",
                    novel_start + index * 30,
                    session,
                )
            )
            session += 1

        note = (
            f"Baseline: {len(known)} known domains queried by {len(srcs)} host(s) "
            f"({baseline_events} events). First contact begins at event {baseline_events} "
            f"with {len(novel)} never-before-queried domain(s). Novelty is "
            "organization-wide, unlike REP-008 which is novel per host."
        )
        return events, note, truncated

    # -- REP-021 inbound perimeter scan reception -----------------------------

    def _plan_inbound_scan(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        unique_src = int(preset["unique_src"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_min"]) * 60
        )
        campaigns = int(preset["campaigns"])
        aggressive_probes = int(preset["aggressive_probes"])

        # Scanner sources come from the dedicated documentation range first, then
        # the adversary pool. The ceiling is the size of those ranges, which is a
        # safety constraint: the IMC study saw 465,251 unique scanners and this
        # cannot represent that without leaving synthetic space.
        available = list(entities.scanner_external) + list(entities.adversary_external)
        sources = available[: min(unique_src, len(available))]
        capped = len(sources) < unique_src
        ports = list(technique.distributions.get("port_choices") or entities.scan_ports)
        perimeter = str(rng.choice(entities.internal_targets))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False

        # Long tail: one or two probes each, the background radiation population.
        for index, src in enumerate(sources):
            for _ in range(int(rng.integers(1, 3))):
                events.append(
                    self._deny_probe(
                        rng,
                        src,
                        perimeter,
                        int(rng.choice(ports)),
                        anchor + int(index * duration_s / max(len(sources), 1)),
                        session,
                        inbound=True,
                    )
                )
                session += 1
                if len(events) >= self.max_events:
                    truncated = True
                    break
            if truncated:
                break

        # Aggressive campaigns: a few sources contributing most of the packets.
        for campaign in range(min(campaigns, len(sources))):
            src = sources[campaign]
            for probe in range(aggressive_probes):
                if len(events) >= self.max_events:
                    truncated = True
                    break
                events.append(
                    self._deny_probe(
                        rng,
                        src,
                        perimeter,
                        int(rng.choice(ports)),
                        anchor + int(probe * duration_s / max(aggressive_probes, 1)),
                        session,
                        inbound=True,
                    )
                )
                session += 1
            if truncated:
                break

        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{len(sources)} unique inbound sources against one perimeter address, "
            f"{min(campaigns, len(sources))} aggressive campaign(s) of {aggressive_probes} "
            "probes. Interface pair is reversed (inbound)."
        )
        if capped:
            note += (
                f" Source count capped at {len(sources)} (requested {unique_src}) by the "
                "size of the synthetic documentation ranges."
            )
        return events, note, truncated

    # -- REP-022 multi-stage IDS alert chain ----------------------------------

    def _plan_ids_alert_chain(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        stages = min(int(preset["stages"]), len(_IPS_STAGES))
        hits_lo, hits_hi = (int(v) for v in preset["hits_per_stage"])
        gap_lo, gap_hi = (int(v) for v in preset["stage_gap_s"])
        noise_alerts = int(preset["noise_alerts"])

        chain_src = str(rng.choice(entities.adversary_external))
        chain_dst = str(rng.choice(entities.internal_targets))

        events: list[EventRecord] = []
        session = int(rng.integers(100, 9999))
        truncated = False
        elapsed = 0
        for stage_index in range(stages):
            stage_name, ips_severity, signatures = _IPS_STAGES[stage_index]
            level = _IPS_LEVEL_BY_SEVERITY[ips_severity]
            hits = int(rng.integers(hits_lo, hits_hi + 1))
            # Recon through C2 are alerts on the flow INTO the victim. The exfil
            # stage is a large outbound transfer, which the IPS raises on the
            # flow leaving the victim: the same entity pair reversed, direction
            # outgoing. Until 2026-10-07 it carried the inbound shape, so the
            # one stage mapped to T1041 looked like one more inbound hit.
            outbound = stage_name == "exfil"
            flow_src, flow_dst = (chain_dst, chain_src) if outbound else (chain_src, chain_dst)
            for hit in range(hits):
                attack, attackid = signatures[hit % len(signatures)]
                events.append(
                    EventRecord(
                        log_type="utm",
                        subtype="ips",
                        action="reset" if stage_index < stages - 1 else "block",
                        level=level,
                        eventtime=anchor + elapsed,
                        src=flow_src,
                        spt=int(rng.integers(1024, 65535)),
                        dst=flow_dst,
                        dpt=443,
                        proto=6,
                        session_id=session,
                        extra={
                            "eventtype": "signature",
                            "ips_severity": ips_severity,
                            "service": "HTTPS",
                            "policyid": "7",
                            "attack": attack,
                            "attackid": attackid,
                            "hostname": flow_dst,
                            "request": _IPS_REQUESTS[hit % len(_IPS_REQUESTS)],
                            "direction": "outgoing" if outbound else "incoming",
                            "profile": "default",
                            "cnt": "1",
                            # Engine-internal marker, NOT rendered: the vendor
                            # profiles map a fixed key set and drop this one.
                            # That is deliberate. Real FortiOS has no "stage"
                            # field, so emitting one would make the record
                            # unrealistic and would also hand the answer to the
                            # detection under test. In the emitted telemetry the
                            # chain is carried by attack-name order, ascending
                            # severity, and the held src/dst pair. See
                            # test_rep022_chain_is_recoverable_from_rendered_cef.
                            "stage": stage_name,
                            "msg": f"applications3A {attack}",
                        },
                    )
                )
                session += 1
                elapsed += max(1, (gap_lo + gap_hi) // (2 * max(hits, 1)))
                if len(events) >= self.max_events:
                    truncated = True
                    break
            if truncated:
                break
            elapsed += int(rng.integers(gap_lo, gap_hi + 1))

        foil_start = len(events)
        # Unrelated alert noise on other entity pairs, spread across the whole
        # window. A rule that fires on any N alerts in a window fires on this.
        window = max(elapsed, 1)
        for index in range(noise_alerts):
            if len(events) >= self.max_events:
                truncated = True
                break
            attack, attackid = _IPS_SIGNATURES[int(rng.integers(0, len(_IPS_SIGNATURES)))]
            target_pool = entities.internal_targets
            noise_dst = str(rng.choice(target_pool))
            if noise_dst == chain_dst:  # keep the noise off the chain's pair
                noise_dst = target_pool[(target_pool.index(noise_dst) + 1) % len(target_pool)]
            events.append(
                EventRecord(
                    log_type="utm",
                    subtype="ips",
                    action="reset",
                    # The same level a low-severity chain alert carries, so the
                    # header severity cannot pick recon hits out of the noise.
                    level=_IPS_LEVEL_BY_SEVERITY["low"],
                    eventtime=anchor + int(index * window / max(noise_alerts, 1)),
                    src=str(rng.choice(entities.adversary_external)),
                    spt=int(rng.integers(1024, 65535)),
                    dst=noise_dst,
                    dpt=443,
                    proto=6,
                    session_id=session,
                    extra={
                        "eventtype": "signature",
                        "ips_severity": "low",
                        "service": "HTTPS",
                        "policyid": "7",
                        "attack": attack,
                        "attackid": attackid,
                        "hostname": noise_dst,
                        "request": _IPS_REQUESTS[index % len(_IPS_REQUESTS)],
                        "direction": "incoming",
                        "profile": "default",
                        "cnt": "1",
                        "msg": f"applications3A {attack}",
                    },
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{stages}-stage ordered chain on one src/dst pair, interleaved with "
            f"{noise_alerts} unrelated alerts. Stage order and the shared entity pair "
            "are the correlation signal; the noise is what makes it non-trivial."
        )
        return events, note, truncated

    # -- REP-023 TLS 1.3 C2 with flow-only signal -----------------------------

    def _plan_tls13_c2(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        sessions = int(preset["sessions"])
        interval_s = int(preset["interval_s"])
        out_lo, out_hi = (int(v) for v in preset["out_bytes"])
        in_lo, in_hi = (int(v) for v in preset["in_bytes"])

        truncated = False
        if sessions > self.max_events:
            sessions = self.max_events
            truncated = True

        # Sessions are one interval apart, so the span is sessions * interval_s.
        # The interval is the beacon, so a shorter window means fewer callbacks
        # at the same cadence, never the same number of callbacks closer
        # together: an interval-keyed rule has to still have something to key on.
        if duration_override_s is not None:
            sessions = max(1, min(sessions, duration_override_s // max(interval_s, 1) + 1))

        src = str(rng.choice(entities.internal_hosts))
        dst = str(rng.choice(entities.adversary_external))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        for index in range(sessions):
            # Low variance is the whole signal. No handshake-derived field is
            # emitted, so a JA3 or cipher-suite rule has nothing to match: that
            # is the condition TLS 1.3 creates, per the RAID 2024 result.
            events.append(
                self._steady_accept(
                    rng,
                    src,
                    dst,
                    443,
                    anchor + index * interval_s,
                    session,
                    lognormal_bytes(rng, out_lo, out_hi),
                    lognormal_bytes(rng, in_lo, in_hi),
                    int(rng.integers(2, 6)),
                )
            )
            session += 1

        foil_start = len(events)
        # Concurrent browsing to 443: high byte variance, varied durations, and
        # irregular timing spread over the beacon's own span. It used to copy
        # the beacon's exact period offset by 11 s, which made the browsing as
        # periodic as the C2 and rewarded a detector that keys on anything but
        # timing. The catalog names flow timing and destination context as the
        # discriminators, so the foil must carry no period at all.
        foil_count = min(sessions, max(self.max_events - len(events), 0))
        span_s = float((sessions - 1) * interval_s)
        weights = [float(rng.uniform(0.25, 1.75)) for _ in range(max(foil_count - 1, 0))]
        weight_total = sum(weights) or 1.0
        foil_elapsed = 0.0
        for index in range(foil_count):
            if index:
                foil_elapsed += span_s * weights[index - 1] / weight_total
            events.append(
                self._forward_accept(
                    technique,
                    rng,
                    src,
                    str(rng.choice(entities.benign_external)),
                    443,
                    anchor + int(foil_elapsed),
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{sessions} session(s) to one destination on 443 every {interval_s}s with "
            "narrow byte variance and no handshake metadata. Concurrent high-variance, "
            "irregularly timed browsing to 443 from the same host is included; port, source "
            "and session count do not separate them, timing regularity, byte variance and "
            "the single repeated destination do."
        )
        return events, note, truncated

    # -- REP-024 internal host as proxy relay ---------------------------------

    @staticmethod
    def _relay_lag_s(rng: Any, lag_lo: int, lag_hi: int) -> int:
        """Draw a forwarding lag in whole seconds from a millisecond range.

        The shipped ranges are sub-second to sub-two-second, and the lag is the
        anti-fixed-window-correlation property of the technique, so it must not
        be constant. Floor-dividing the range collapses every preset to one
        constant value; truncating the float draw does the same at the
        sub-second presets. The sub-second remainder is therefore dithered to a
        whole second, keeping the drawn variance visible on an integer-second
        timeline with the expected value equal to the drawn lag.
        """

        lag_s = float(rng.integers(lag_lo, lag_hi + 1)) / 1000.0
        whole = int(lag_s)
        return whole + int(float(rng.random()) < lag_s - whole)

    def _plan_proxy_relay(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        relay_pairs = int(preset["relay_pairs"])
        lag_lo, lag_hi = (int(v) for v in preset["lag_ms"])
        duration_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["duration_min"]) * 60
        )
        clients = int(preset["clients"])

        relay = str(rng.choice(entities.internal_hosts))
        client_pool = entities.adversary_external
        client_list = [
            client_pool[i]
            for i in unique_ints(rng, 0, len(client_pool) - 1, min(clients, len(client_pool)))
        ]
        upstream = entities.benign_external

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False
        gap_s = duration_s / max(relay_pairs, 1)

        for pair in range(relay_pairs):
            if len(events) + 2 > self.max_events:
                truncated = True
                break
            when = anchor + int(pair * gap_s)
            request_b = int(rng.integers(400, 2_400))
            response_b = int(rng.integers(1_200, 48_000))
            # Inbound leg: an external client reaches the relay host.
            events.append(
                self._steady_accept(
                    rng,
                    client_list[pair % len(client_list)],
                    relay,
                    8080,
                    when,
                    session,
                    request_b,
                    response_b,
                    int(rng.integers(1, 30)),
                    inbound=True,
                )
            )
            session += 1
            # Outbound leg: the relay forwards it. Byte volumes track the inbound
            # leg because the host is forwarding rather than originating, which is
            # the gateway-versus-relayed distinction in the source dataset.
            lag_s = self._relay_lag_s(rng, lag_lo, lag_hi)
            events.append(
                self._steady_accept(
                    rng,
                    relay,
                    str(rng.choice(upstream)),
                    443,
                    when + lag_s,
                    session,
                    _forwarded_bytes(rng, request_b),
                    _forwarded_bytes(rng, response_b),
                    int(rng.integers(1, 30)),
                )
            )
            session += 1

        foil_start = len(events)
        # A sanctioned proxy host producing the same pairing. Identical pattern,
        # different asset role. Tests whether a detection uses role or pattern.
        # It must be a different host from the relay, or the two roles collapse.
        # Identical means identical: the same pair count as the relay (it was
        # capped at twenty whatever the preset) and the same forwarding draw on
        # the outbound leg (it copied the inbound bytes verbatim, so every
        # proxy pair was byte-identical and no relay pair ever was).
        sanctioned = _last_excluding(entities.internal_hosts, {relay})
        for pair in range(min(relay_pairs, max((self.max_events - len(events)) // 2, 0))):
            when = anchor + int(pair * gap_s) + 3
            request_b = int(rng.integers(400, 2_400))
            response_b = int(rng.integers(1_200, 48_000))
            events.append(
                self._steady_accept(
                    rng,
                    client_list[pair % len(client_list)],
                    sanctioned,
                    8080,
                    when,
                    session,
                    request_b,
                    response_b,
                    int(rng.integers(1, 30)),
                    inbound=True,
                )
            )
            session += 1
            # Same lag draw as the relay legs: a fixed one-second offset would
            # give the foil a more mechanical signature than the technique.
            events.append(
                self._steady_accept(
                    rng,
                    sanctioned,
                    str(rng.choice(upstream)),
                    443,
                    when + self._relay_lag_s(rng, lag_lo, lag_hi),
                    session,
                    _forwarded_bytes(rng, request_b),
                    _forwarded_bytes(rng, response_b),
                    int(rng.integers(1, 30)),
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{relay_pairs} relayed request(s) through one host from {len(client_list)} "
            "external client(s): each inbound session is followed by a byte-correlated "
            "outbound session. A sanctioned proxy with the same pattern is included."
        )
        return events, note, truncated

    # -- REP-030 distributed low-and-slow password spray ---------------------

    def _plan_distributed_spray(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        failures = int(preset["failures"])
        source_count = min(int(preset["sources"]), len(entities.adversary_external))
        user_count = int(preset["users"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        # One positive failure plus a failed-and-corrected negative pair. Keep
        # both controls present under the materialization safety ceiling.
        truncated = False
        if failures * 3 > self.max_events:
            failures = max(1, self.max_events // 3)
            truncated = True
        source_count = max(1, min(source_count, failures))
        user_count = max(1, min(user_count, failures))

        attack_indices = unique_ints(rng, 0, len(entities.adversary_external) - 1, source_count)
        attack_sources = [entities.adversary_external[index] for index in attack_indices]
        benign_indices = unique_ints(rng, 0, len(entities.benign_external) - 1, source_count)
        benign_sources = [entities.benign_external[index] for index in benign_indices]
        users = synthetic_usernames(user_count * 2, entities.users)
        attack_users = users[:user_count]
        benign_users = users[user_count:]

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))

        def append_vpn(
            *,
            source: str,
            user: str,
            when: int,
            success: bool,
            control: Literal["positive", "negative"],
        ) -> None:
            nonlocal session
            if success:
                events.append(
                    EventRecord(
                        log_type="event",
                        subtype="vpn",
                        action="tunnel-up",
                        level="notice",
                        eventtime=when,
                        control=control,
                        duser=user,
                        src=source,
                        session_id=session,
                        extra={
                            "logdesc": "SSL VPN tunnel up",
                            "fgt_action": "tunnel-up",
                            "remip": source,
                            "tunneltype": "ssl-tunnel",
                            "tunnelid": str(int(rng.integers(1_000_000, 9_999_999))),
                            "group": "vpn-users",
                            "reason": "login-success",
                            "msg": "SSL tunnel established",
                        },
                    )
                )
            else:
                reason = _VPN_FAIL_REASONS[int(rng.integers(0, len(_VPN_FAIL_REASONS)))]
                events.append(
                    EventRecord(
                        log_type="event",
                        subtype="vpn",
                        action="ssl-login-fail",
                        level="alert",
                        eventtime=when,
                        control=control,
                        duser=user,
                        src=source,
                        session_id=session,
                        extra={
                            "logdesc": "SSL VPN login fail",
                            "fgt_action": "ssl-login-fail",
                            "remip": source,
                            "tunneltype": "ssl-web",
                            "reason": reason,
                            "msg": "SSL user failed to logged in",
                        },
                    )
                )
            session += 1

        correction_delay = max(1, window_s // max(failures * 4, 1))
        for index in range(failures):
            when = anchor + int(index * window_s / max(failures, 1))
            append_vpn(
                source=attack_sources[index % len(attack_sources)],
                user=attack_users[index % len(attack_users)],
                when=when,
                success=False,
                control="positive",
            )

            benign_source = benign_sources[index % len(benign_sources)]
            benign_user = benign_users[index % len(benign_users)]
            append_vpn(
                source=benign_source,
                user=benign_user,
                when=when,
                success=False,
                control="negative",
            )
            append_vpn(
                source=benign_source,
                user=benign_user,
                when=min(anchor + window_s, when + correction_delay),
                success=True,
                control="negative",
            )

        events.sort(key=lambda event: event.eventtime)
        note = (
            f"{failures} failures distributed across {source_count} sources and "
            f"{user_count} users over {window_s // 60} min. The control has the same "
            "failed source-user edges followed by successful self-correction."
        )
        return events, note, truncated

    # -- REP-043 inbound alert to victim egress dialog -----------------------

    def _plan_exploit_egress_dialog(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        chains = int(preset["chains"])
        alert_lo, alert_hi = (int(value) for value in preset["alert_hits"])
        inbound_lo, inbound_hi = (int(value) for value in preset["inbound_sessions"])
        outbound_lo, outbound_hi = (int(value) for value in preset["outbound_sessions"])
        noise_alerts = int(preset["noise_alerts"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        victims = [
            entities.internal_targets[index]
            for index in unique_ints(
                rng,
                0,
                len(entities.internal_targets) - 1,
                min(chains, len(entities.internal_targets)),
            )
        ]
        attackers = entities.scanner_external or entities.adversary_external
        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        truncated = False

        def append_ips(
            *,
            source: str,
            target: str,
            when: int,
            control: Literal["positive", "negative"],
            index: int,
        ) -> None:
            nonlocal session, truncated
            if len(events) >= self.max_events:
                truncated = True
                return
            attack, attackid = _IPS_SIGNATURES[index % len(_IPS_SIGNATURES)]
            events.append(
                EventRecord(
                    log_type="utm",
                    subtype="ips",
                    action="reset",
                    level="alert",
                    eventtime=when,
                    control=control,
                    src=source,
                    spt=int(rng.integers(1024, 65535)),
                    dst=target,
                    dpt=443,
                    proto=6,
                    session_id=session,
                    extra={
                        "eventtype": "signature",
                        "ips_severity": "high",
                        "service": "HTTPS",
                        "policyid": "7",
                        "attack": attack,
                        "attackid": attackid,
                        "hostname": target,
                        "request": _IPS_REQUESTS[index % len(_IPS_REQUESTS)],
                        "direction": "incoming",
                        "profile": "default",
                        "cnt": "1",
                        "msg": f"applications3A {attack}",
                    },
                )
            )
            session += 1

        def append_flow(
            *,
            source: str,
            target: str,
            when: int,
            inbound: bool,
            control: Literal["positive", "negative"],
        ) -> None:
            nonlocal session, truncated
            if len(events) >= self.max_events:
                truncated = True
                return
            out_b = int(rng.integers(400, 8_000))
            in_b = int(rng.integers(800, 32_000))
            event = self._steady_accept(
                rng,
                source,
                target,
                443,
                when,
                session,
                out_b,
                in_b,
                int(rng.integers(1, 90)),
                inbound=inbound,
            )
            event.control = control
            events.append(event)
            session += 1

        for chain_index, victim in enumerate(victims):
            attacker = str(rng.choice(attackers))
            callback = str(rng.choice(entities.adversary_external))
            chain_offset = int(chain_index * window_s / max(len(victims) * 12, 1))
            alert_hits = int(rng.integers(alert_lo, alert_hi + 1))
            inbound_sessions = int(rng.integers(inbound_lo, inbound_hi + 1))
            outbound_sessions = int(rng.integers(outbound_lo, outbound_hi + 1))

            for index in range(alert_hits):
                append_ips(
                    source=attacker,
                    target=victim,
                    when=anchor + chain_offset + index,
                    control="positive",
                    index=index,
                )
            for index in range(inbound_sessions):
                append_flow(
                    source=attacker,
                    target=victim,
                    when=anchor + chain_offset + window_s // 4 + index,
                    inbound=True,
                    control="positive",
                )
            for index in range(outbound_sessions):
                append_flow(
                    source=victim,
                    target=callback,
                    when=anchor + chain_offset + window_s // 2 + index,
                    inbound=False,
                    control="positive",
                )

        # Negative controls cover three common shortcuts: a blocked alert with
        # no continuation, unrelated egress from another host, and the complete
        # set of record types in reverse order. None forms the victim-role join
        # in alert -> inbound -> outbound order.
        used_victims = set(victims)
        foil_hosts = [host for host in entities.internal_targets if host not in used_victims]
        blocked_victim = foil_hosts[0]
        unrelated_host = foil_hosts[1]
        reversed_victim = foil_hosts[2]
        foil_attacker = str(rng.choice(attackers))
        append_ips(
            source=foil_attacker,
            target=blocked_victim,
            when=anchor + window_s // 8,
            control="negative",
            index=0,
        )
        append_flow(
            source=unrelated_host,
            target=str(rng.choice(entities.benign_external)),
            when=anchor + window_s // 2,
            inbound=False,
            control="negative",
        )
        append_flow(
            source=reversed_victim,
            target=str(rng.choice(entities.adversary_external)),
            when=anchor + window_s // 8,
            inbound=False,
            control="negative",
        )
        append_flow(
            source=foil_attacker,
            target=reversed_victim,
            when=anchor + window_s // 2,
            inbound=True,
            control="negative",
        )
        append_ips(
            source=foil_attacker,
            target=reversed_victim,
            when=anchor + window_s * 3 // 4,
            control="negative",
            index=1,
        )
        for index in range(noise_alerts):
            noise_target = str(rng.choice(foil_hosts[3:] or foil_hosts))
            append_ips(
                source=str(rng.choice(attackers)),
                target=noise_target,
                when=anchor + int(index * window_s / max(noise_alerts, 1)),
                control="negative",
                index=index,
            )

        events.sort(key=lambda event: event.eventtime)
        note = (
            f"{len(victims)} victim chain(s) join an IPS destination to an accepted "
            "inbound destination and later outbound source. Negative controls break "
            "the victim join or event order; alerts do not assert exploit success."
        )
        return events, note, truncated

    # -- REP-028 admin login from an unexpected source, then a config burst ----

    def _plan_admin_config_burst(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        """One successful administrator login from a host outside the management
        pool, then a burst of configuration changes by that account from that
        source inside the window. The foil is the same shape from the management
        jump host under the on-duty administrator's account: same count range,
        same change vocabulary and mix, same irregular timing, so the source's
        asset role is the only thing a detection can separate them on, and the
        catalog says so.

        ``--duration`` sets the window and keeps the count: the count inside the
        window is the signal, not the spacing.
        """

        changes_lo, changes_hi = (int(v) for v in preset["changes"])
        lead_lo, lead_hi = (int(v) for v in preset["login_lead_s"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )
        window_s = max(int(window_s), 2)
        # Direct constructions of EntityModel may predate the pool; the fallback
        # is still disjoint from internal_hosts, which is what the foil needs.
        mgmt_pool = entities.mgmt_hosts or entities.internal_targets[:4]
        admin_accounts = synthetic_usernames(2, entities.users)
        attack_src = str(rng.choice(entities.internal_hosts))
        benign_src = str(rng.choice(mgmt_pool))

        path_names = [path for path, _ in CFG_PATH_WEIGHTS]
        path_weights = [weight for _, weight in CFG_PATH_WEIGHTS]
        action_names = [action for action, _ in CFG_ACTION_WEIGHTS]
        action_weights = [weight for _, weight in CFG_ACTION_WEIGHTS]

        # Two bursts, each one login plus its changes, under the engine's ceiling.
        # The ceiling binds the count, never the window: a shorter burst is still
        # a burst, a longer window is a different technique.
        truncated = False
        per_burst_cap = max(1, self.max_events // 2 - 1)
        if changes_hi > per_burst_cap:
            changes_hi = per_burst_cap
            changes_lo = min(changes_lo, changes_hi)
            truncated = True

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))

        def burst(source: str, user: str, control: Literal["positive", "negative"]) -> None:
            nonlocal session
            count = int(rng.integers(changes_lo, changes_hi + 1))
            lead = min(int(rng.integers(lead_lo, lead_hi + 1)), max(1, window_s - 1))
            events.append(
                EventRecord(
                    log_type="event",
                    subtype="system",
                    action="login",
                    level="notice",
                    eventtime=anchor,
                    control=control,
                    duser=user,
                    src=source,
                    session_id=session,
                    extra={
                        "logdesc": "Admin login successful",
                        "fgt_action": "login",
                        "status": "success",
                        "ui": f"https({source})",
                        "method": "https",
                        "reason": "none",
                        "msg": f"Administrator {user} logged in successfully from {source}",
                    },
                )
            )
            session += 1
            # Changes land at uniform random offsets inside the window after the
            # login: an operator working through a change list, not a timer.
            offsets = sorted(
                int(value) for value in rng.uniform(anchor + lead, anchor + window_s, size=count)
            )
            for when in offsets:
                path = str(path_names[int(rng.choice(len(path_names), p=path_weights))])
                action = str(action_names[int(rng.choice(len(action_names), p=action_weights))])
                attrs = _CFG_ATTRS[path]
                attr = attrs[int(rng.integers(0, len(attrs)))]
                obj = str(int(rng.integers(1, 200)))
                events.append(
                    EventRecord(
                        log_type="event",
                        subtype="system",
                        action=action,
                        level="information",
                        eventtime=when,
                        control=control,
                        duser=user,
                        src=source,
                        session_id=session,
                        extra={
                            "logdesc": "Object attribute configured",
                            "fgt_action": action,
                            "ui": f"GUI({source})",
                            "method": "https",
                            "cfgtid": str(int(rng.integers(100_000, 999_999))),
                            "cfgpath": path,
                            "cfgobj": obj,
                            "cfgattr": attr,
                            "msg": f"{action} {path} {obj}",
                        },
                    )
                )
                session += 1

        burst(attack_src, admin_accounts[0], "positive")
        burst(benign_src, admin_accounts[1], "negative")
        events.sort(key=lambda e: (e.eventtime, e.control != "positive"))
        note = (
            f"admin login from {attack_src} (outside the management pool) followed by a "
            f"configuration-change burst; the benign foil is the same burst from "
            f"{benign_src}, a management jump host. Role is the intended discriminator."
        )
        return events, note, truncated

    # -- REP-052 ransomware-like SMB write fan-out ------------------------------

    def _plan_smb_write_fanout(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        """One workstation opens accepted SMB sessions to many distinct internal
        file servers inside the window, every session large in both directions
        with out at least in (each file is read, then written back). The foil is
        the same fan-out from a software-distribution server in the server pool:
        same share count range, same sessions per share, same byte and duration
        draws, same timing process, so the source's asset role is the only thing
        a detection can separate them on, and the catalog says so.

        A backup pull (in-heavy, from a server) was considered as the foil and set
        aside: it differs on two features, role and direction, and a foil may
        differ from the attack on only the one the catalog names.

        ``--duration`` sets the window and keeps the count: the number of distinct
        destinations written to inside the window is the signal, not the spacing.
        """

        shares_lo, shares_hi = (int(v) for v in preset["shares"])
        sps_lo, sps_hi = (int(v) for v in preset["sessions_per_share"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )
        window_s = max(int(window_s), 2)

        targets = entities.internal_targets
        shares_hi = min(shares_hi, len(targets))
        shares_lo = min(shares_lo, shares_hi)
        # Two streams under the engine's ceiling. The ceiling binds the share
        # count, never the window: a smaller fan-out is still a fan-out.
        truncated = False
        per_stream_cap = max(1, self.max_events // 2)
        if shares_hi * sps_hi > per_stream_cap:
            shares_hi = max(1, per_stream_cap // max(sps_hi, 1))
            shares_lo = min(shares_lo, shares_hi)
            truncated = True
        # Direct constructions of EntityModel may predate the pool; every
        # fallback is disjoint from internal_hosts, which is what the foil needs.
        server_pool = entities.server_hosts or entities.mgmt_hosts or entities.internal_targets[-4:]
        attack_src = str(rng.choice(entities.internal_hosts))
        benign_src = str(rng.choice(server_pool))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))

        def fanout(source: str) -> int:
            nonlocal session
            start = len(events)
            count = int(rng.integers(shares_lo, shares_hi + 1))
            picks = unique_ints(rng, 0, len(targets) - 1, count)
            for target_index in picks:
                dst = targets[target_index]
                for _ in range(int(rng.integers(sps_lo, sps_hi + 1))):
                    out_b, in_b, duration = _smb_write_leg(rng)
                    duration = min(duration, window_s)
                    # The record is written when the session closes, so the close
                    # time is what lands inside the window.
                    opened = anchor + int(rng.integers(0, window_s - duration + 1))
                    events.append(
                        self._steady_accept(
                            rng,
                            source,
                            dst,
                            SMB_PORT,
                            opened + duration,
                            session,
                            out_b,
                            in_b,
                            duration,
                        )
                    )
                    session += 1
            return start

        fanout(attack_src)
        foil_start = fanout(benign_src)
        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: (e.eventtime, e.control != "positive"))
        note = (
            f"SMB write fan-out from {attack_src} (workstation pool) to distinct internal "
            f"file servers on tcp/{SMB_PORT}; the benign foil is the same fan-out from "
            f"{benign_src}, a software-distribution server. Role is the intended discriminator."
        )
        return events, note, truncated

    # -- REP-053 internal reflector abused for amplification ------------------

    def _plan_reflection_amplification(
        self,
        technique: Technique,
        preset: dict[str, Any],
        entities: EntityModel,
        rng: Any,
        anchor: int,
        duration_override_s: int | None,
    ) -> _BuilderResult:
        """Inbound udp sessions at an internal service from one spoofed external
        source, each a small request answered with a reply many times its size.
        The firewall sees the reflector's side of a reflection attack: the
        interface pair is reversed (like REP-021), src is the address the replies
        are aimed at, dst is the internal server.

        The foil is one chatty external client against the same server: same
        session count range, same window, same request sizes, same durations,
        same irregular timing, replies inside a symmetric band. The per-session
        reply-to-request ratio is the only thing a detection can separate them
        on, and the catalog says so. The backlog's sketch (many clients, symmetric
        replies) was set aside because it differed on two features, ratio and
        client concentration, and a foil may differ on only the one the catalog
        names. Both sources are drawn from the same external pool so pool
        membership is not a free reputation feature either.

        Event rate is bounded by the events-per-second cap by design. A flood is
        never expressed as rate here, only as bytes per session.

        ``--duration`` sets the window and keeps the count: the count and the
        ratio inside the window are the signal, not the spacing.
        """

        dpt = int(preset["dpt"])
        sessions_lo, sessions_hi = (int(v) for v in preset["sessions"])
        amp_lo, amp_hi = (float(v) for v in preset["amplification"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )
        window_s = max(int(window_s), 2)

        # Two streams under the engine's ceiling. The ceiling binds the session
        # count, never the window or the ratio.
        truncated = False
        per_stream_cap = max(1, self.max_events // 2)
        if sessions_hi > per_stream_cap:
            sessions_hi = per_stream_cap
            sessions_lo = min(sessions_lo, sessions_hi)
            truncated = True
        # Direct constructions of EntityModel may predate the server pool.
        server_pool = entities.server_hosts or entities.internal_targets[:4]
        reflector = str(rng.choice(server_pool))
        pool = entities.benign_external
        victim_index, client_index = unique_ints(rng, 0, len(pool) - 1, 2)
        victim = pool[victim_index]
        client = pool[client_index]

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))

        def stream(source: str, ratio_lo: float, ratio_hi: float) -> int:
            nonlocal session
            start = len(events)
            count = int(rng.integers(sessions_lo, sessions_hi + 1))
            for _ in range(count):
                request = int(rng.integers(REFLECT_REQUEST_BYTES[0], REFLECT_REQUEST_BYTES[1] + 1))
                reply = int(request * float(rng.uniform(ratio_lo, ratio_hi)))
                duration = min(
                    int(rng.integers(REFLECT_DURATION_S[0], REFLECT_DURATION_S[1] + 1)), window_s
                )
                # The record is written when the session closes, so the close
                # time is what lands inside the window.
                opened = anchor + int(rng.integers(0, window_s - duration + 1))
                events.append(
                    self._steady_accept(
                        rng,
                        source,
                        reflector,
                        dpt,
                        opened + duration,
                        session,
                        request,
                        reply,
                        duration,
                        inbound=True,
                        proto=17,
                    )
                )
                session += 1
            return start

        stream(victim, amp_lo, amp_hi)
        foil_start = stream(client, REFLECT_FOIL_RATIO[0], REFLECT_FOIL_RATIO[1])
        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: (e.eventtime, e.control != "positive"))
        note = (
            f"inbound udp/{dpt} reflection at {reflector}: requests from one spoofed source "
            f"{victim} answered with replies {amp_lo:g}x to {amp_hi:g}x their size. Event rate "
            "is bounded by the events-per-second cap by design; the signal is bytes, never "
            f"rate. The benign foil is the same session count from {client} with symmetric "
            "replies. The reply-to-request ratio is the intended discriminator."
        )
        return events, note, truncated
