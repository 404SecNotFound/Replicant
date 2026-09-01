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
from typing import Any

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

_PORT_SERVICE: dict[int, tuple[str, str]] = {
    443: ("HTTPS", "HTTPS"),
    8443: ("HTTPS", "HTTPS"),
    8080: ("HTTP", "HTTP"),
    80: ("HTTP", "HTTP"),
    53: ("DNS", "DNS"),
    22: ("SSH", "SSH"),
    3389: ("RDP", "RDP"),
    445: ("SMB", "SMB"),
    23: ("TELNET", "TELNET"),
    21: ("FTP", "FTP"),
}


def port_service(dpt: int) -> tuple[str, str]:
    """Return (service, app) names for a destination port, or a tcp/<port> label."""

    return _PORT_SERVICE.get(dpt, (f"tcp/{dpt}", f"tcp/{dpt}"))


_DUBAI = timezone(timedelta(hours=4))  # UTC+04:00, the catalog timezone


def _off_hours_start(anchor: int) -> int:
    """Midnight (UTC+04:00) of the anchor's day: the start of an off-hours window."""

    day = datetime.fromtimestamp(anchor, _DUBAI).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(day.timestamp())


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
_IPS_STAGES: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "recon",
        "warning",
        (("TCP.Port.Scan", "11279"), ("HTTP.Unix.Shell.IFS.Remote.Code.Execution", "34884")),
    ),
    (
        "exploit",
        "alert",
        (
            ("Apache.Log4j.Error.Log.Remote.Code.Execution", "51006"),
            ("PHPUnit.Eval.Stdin.Remote.Code.Execution", "44035"),
        ),
    ),
    (
        "post-exploit",
        "alert",
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


_IPS_REQUESTS: tuple[str, ...] = (
    "/struts2/index.action",
    "/index.php?option=login",
    "/api/v1/login",
    "/cgi-bin/test.cgi",
    "/wp-login.php",
    "/solr/admin/cores",
)


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
            if len(events) >= self.max_events:
                truncated = True
                break
            offset += jittered_interval(rng, interval_s, jitter_pct)
        return events, None, truncated

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
        gap_lo, gap_hi = (float(v) for v in preset["gap_ms"])

        truncated = False
        # A scan cannot visit more distinct ports than exist. Without this,
        # `unique_ints(rng, 1, 65535, unique_ports)` below raises out of a
        # distribution helper rather than the caller explaining itself. Clamped
        # rather than rejected, to match how max_events is handled on the next
        # two lines, and recorded the same way.
        if unique_ports > PORT_SPAN:
            unique_ports = PORT_SPAN
            truncated = True
        if unique_ports > self.max_events:
            unique_ports = self.max_events
            truncated = True

        # The window is the detection surface: a vertical-scan rule counts
        # distinct ports per source INSIDE window_s, so the probes are spread
        # across the whole window (as REP-003 does) rather than fired at the
        # gap_ms cadence and finishing long before the window closes. A
        # duration override is honoured the REP-019 way: the preset density is
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
            # gap_ms survives as a small non-negative jitter on the even
            # spread, so the walk is not a metronome.
            jitter_s = float(rng.uniform(gap_lo, gap_hi)) / 1000.0
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=action,
                    level=level,
                    eventtime=anchor + int(index * gap_s + jitter_s),
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
        if unique_hosts > self.max_events:
            unique_hosts = self.max_events
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
        if sessions > self.max_events:
            sessions = self.max_events
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        dst_pool = entities.adversary_external
        dst_indices = unique_ints(rng, 0, len(dst_pool) - 1, min(dst_count, len(dst_pool)))
        destinations = [dst_pool[i] for i in dst_indices]
        dpt = int(rng.choice(dpt_choices))
        service, app = port_service(dpt)

        off_start = _off_hours_start(anchor)
        # 00:00-06:00 UTC+04:00, and that window is the signal rather than a
        # detail: the transfer is suspicious because of when it happens. A
        # shorter duration narrows the window inside off-hours, which stays
        # faithful. A longer one is capped instead of honoured, because spilling
        # into the working day would destroy the property being demonstrated.
        off_window_s = min(duration_override_s, 6 * 3600) if duration_override_s else 6 * 3600
        per_session_out = total_out_bytes // max(sessions, 1)

        events: list[EventRecord] = []
        session_id = int(rng.integers(10_000, 60_000))
        for index in range(sessions):
            factor = float(rng.uniform(0.8, 1.2))
            out_b = max(1, int(per_session_out * factor))
            in_b = max(1, out_b // 40)  # out:in well above the 20:1 exfil threshold
            duration = int(rng.integers(60, 3600))
            spt = int(rng.integers(1024, 65535))
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action=technique.fortigate.action or "accept",
                    level="notice",
                    eventtime=off_start + int(index * off_window_s / max(sessions, 1)),
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
        return events, None, truncated

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
        if denies > self.max_events:
            denies = self.max_events
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
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        truncated = False
        if hits > self.max_events:
            hits = self.max_events
            truncated = True

        dst = str(rng.choice(entities.internal_targets))  # the attacked host, held
        src_pool = entities.adversary_external
        gap_s = window_s / max(hits, 1)
        step = max(1, hits // 5)  # cnt escalates across five aggregation steps

        events: list[EventRecord] = []
        session = int(rng.integers(100, 9999))
        for index in range(hits):
            attack, attackid = _IPS_SIGNATURES[int(rng.integers(0, len(_IPS_SIGNATURES)))]
            request = _IPS_REQUESTS[int(rng.integers(0, len(_IPS_REQUESTS)))]
            src = str(rng.choice(src_pool))
            spt = int(rng.integers(1024, 65535))
            # Alternate high/critical: FortiOS level critical -> CEF 6, alert -> CEF 7.
            critical = index % 3 == 0
            level = "critical" if critical else "alert"
            ips_severity = "critical" if critical else "high"
            cnt = 1 + index // step
            events.append(
                EventRecord(
                    log_type=technique.fortigate.log_type,
                    subtype=technique.fortigate.subtype,
                    action="reset",
                    level=level,
                    eventtime=anchor + int(index * gap_s),
                    src=src,
                    spt=spt,
                    dst=dst,
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
                        "hostname": dst,
                        "request": request,
                        "direction": "incoming",
                        "profile": "default",
                        "cnt": str(cnt),
                        "msg": f"applications3A {attack}",
                    },
                )
            )
            session += 1
        return events, None, truncated

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
            f"Baseline: {len(known)} known destinations over {baseline_days}d "
            f"({baseline_events} events); anomaly begins at event {baseline_events} "
            f"with {len(novel)} first-seen external destination(s)."
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

        total = qps * duration_s
        truncated = False
        if total > self.max_events:
            total = self.max_events
            truncated = True
        total = max(total, 1)

        src = str(rng.choice(entities.internal_hosts))
        dst = entities.resolver
        parent = str(rng.choice(entities.parents))
        label_count = min(unique_labels, total)
        labels = high_entropy_labels(rng, label_count, label_lo, label_hi)

        qtypes = ["TXT", "NULL", "CNAME", "A"]
        qtypevals = {"TXT": "16", "NULL": "10", "CNAME": "5", "A": "1"}
        weights = [0.40, 0.25, 0.20, 0.15]

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        for index in range(total):
            label = labels[index % len(labels)]
            qname = f"{label}.{parent}"
            qtype = weighted_choice(rng, qtypes, weights)
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
        return events, None, truncated

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
    ) -> EventRecord:
        """A traffic:forward accept with caller-controlled byte and duration shape.

        ``inbound=True`` reverses the interface pair, which is what makes an
        internet-to-perimeter record distinguishable from an egress record.
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
            proto=6,
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
            offset = (index * interval_s / max(len(srcs), 1)) if mode == "fleet" else 0.0
            while offset <= duration_s:
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
                offset += jittered_interval(rng, interval_s, jitter_pct)
            if truncated:
                break

        foil_start = len(events)
        # Benign periodic destination. Both source papers name legitimate
        # periodic software as the dominant false positive, so a plan without one
        # overstates how well a periodicity test performs.
        benign_src = str(rng.choice(pool))
        benign_dst = str(rng.choice(entities.benign_external))
        benign_offset = 0.0
        while benign_offset <= duration_s and len(events) < self.max_events:
            events.append(
                self._steady_accept(
                    rng,
                    benign_src,
                    benign_dst,
                    443,
                    anchor + int(benign_offset),
                    session,
                    int(rng.integers(400, 1200)),
                    int(rng.integers(2_000, 40_000)),
                    int(rng.integers(1, 20)),
                )
            )
            session += 1
            benign_offset += 1800.0  # update-check cadence, no jitter

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"mode={mode}: {len(srcs)} source(s) to one destination, jitter "
            f"{jitter_pct:.0f}%. A benign periodic destination is included as a "
            "false-positive control."
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
                        events.append(
                            self._steady_accept(
                                rng, source, dst, port, when, session, 1200, 3400, 4
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
        # Drawn from outside the seed set: a baseline server that is also a seed
        # host would grow like the worm and the control would stop being one.
        benign_pool = [host for host in pool if host not in seed_set]
        for server_index in range(3):
            server = benign_pool[(server_index + 1) % len(benign_pool)]
            for step in range(4):
                if len(events) >= self.max_events:
                    break
                dst = targets[(server_index * 4 + step) % len(targets)]
                when = anchor + step * gen_gap_s
                events.append(
                    self._steady_accept(rng, server, dst, port, when, session, 2400, 8800, 30)
                )
                session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{generations} generation(s) from {seed_hosts} seed host(s) on port {port}; "
            "distinct source count grows per generation. A stable server baseline on "
            "the same port is included as a false-positive control."
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
        labels = high_entropy_labels(rng, min(unique_labels, total), label_lo, label_hi)
        gap_s = 3600.0 / max(qph, 1)

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        # Weighted to A and AAAA, not TXT: the query name itself is the channel,
        # so the record type does not need to carry a payload. That is what makes
        # this class invisible to a TXT-oriented tunnel rule.
        qtypes = ["A", "AAAA"]
        weights = [0.75, 0.25]
        for index in range(total):
            qname = f"{labels[index % len(labels)]}.{parent}"
            events.append(
                self._dns_query_record(
                    rng,
                    src,
                    entities.resolver,
                    qname,
                    weighted_choice(rng, qtypes, weights),
                    anchor + int(index * gap_s),
                    session,
                )
            )
            session += 1

        foil_start = len(events)
        # Benign parent with a comparable query count but low unique-label
        # cardinality, so per-minute rate cannot separate the two.
        benign_parent = str(rng.choice([p for p in entities.parents if p != parent] or [parent]))
        benign_labels = ["www", "mail", "api", "cdn", "vpn"]
        for index in range(min(total, self.max_events - len(events))):
            qname = f"{benign_labels[index % len(benign_labels)]}.{benign_parent}"
            events.append(
                self._dns_query_record(
                    rng,
                    src,
                    entities.resolver,
                    qname,
                    "A",
                    anchor + int(index * gap_s) + 7,
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{qph} queries/hour over {duration_s // 3600}h ({total} exfil queries), "
            f"{len(labels)} unique labels under one parent. Deliberately below "
            "tunnel-rate thresholds. A same-volume benign parent is included."
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
        path_len = int(preset["path_len"])
        user_count = int(preset["users"])
        switch_at_hop = int(preset["switch_at_hop"])
        window_s = (
            duration_override_s
            if duration_override_s is not None
            else int(preset["window_min"]) * 60
        )

        pool = entities.internal_hosts
        hops = [pool[i] for i in unique_ints(rng, 0, len(pool) - 1, min(path_len, len(pool)))]
        user_pool = entities.users
        users = [
            user_pool[i]
            for i in unique_ints(rng, 0, len(user_pool) - 1, min(user_count, len(user_pool)))
        ]
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
            user = users[min(hop // max(switch_at_hop, 1), len(users) - 1)]
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
            events.append(
                self._steady_accept(rng, source, target, dpt, when + 2, session, 4200, 12_800, 60)
            )
            session += 1

        foil_start = len(events)
        # Benign star: one workstation logging into several hosts. Same login
        # count, same ports, different shape. Chain versus star IS the detection.
        star_src = pool[(len(pool) - 1)]
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
            events.append(
                self._steady_accept(
                    rng, star_src, target, 3389, when + 2, session, 3900, 11_400, 45
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
        probes_per_dst = int(preset["probes_per_dst"])
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
        for index in range(total_probes):
            # Source rotation keeps per-source counts under per-source
            # thresholds; the long gap keeps any rate window from filling. TRW
            # converges on a small number of attempts FROM ONE SOURCE, so
            # spreading the walk across a pool is the evasion.
            src = sources[index % len(sources)]
            dst = targets[int(rng.integers(0, len(targets)))]
            dpt = int(rng.choice(ports))
            for _ in range(probes_per_dst):
                events.append(self._deny_probe(rng, src, dst, dpt, anchor + int(elapsed), session))
                session += 1
                if len(events) >= self.max_events:
                    truncated = True
                    break
            if truncated:
                break
            elapsed += float(rng.uniform(gap_lo, gap_hi))

        foil_start = len(events)
        # Sparse benign policy denies from an unrelated host, at a similar rate.
        benign_src = pool[len(pool) - 1]
        for index in range(min(20, max(self.max_events - len(events), 0))):
            events.append(
                self._deny_probe(
                    rng,
                    benign_src,
                    targets[index % len(targets)],
                    445,
                    anchor + int(index * (elapsed / 20 if elapsed else 600)),
                    session,
                )
            )
            session += 1

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
        parent = str(rng.choice(entities.parents))
        # Organizational normal: a stable, repeatedly queried domain set.
        known = [f"{label}.{parent}" for label in high_entropy_labels(rng, baseline_domains, 5, 9)]
        # First-contact domains: never queried by any host before. Reserved-TLD
        # parents guarantee they cannot resolve even by accident.
        novel = [f"{label}.invalid" for label in high_entropy_labels(rng, novel_domains, 8, 14)]

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
        severities = ["low", "medium", "high", "critical", "critical"]

        events: list[EventRecord] = []
        session = int(rng.integers(100, 9999))
        truncated = False
        elapsed = 0
        for stage_index in range(stages):
            stage_name, level, signatures = _IPS_STAGES[stage_index]
            hits = int(rng.integers(hits_lo, hits_hi + 1))
            for hit in range(hits):
                attack, attackid = signatures[hit % len(signatures)]
                events.append(
                    EventRecord(
                        log_type="utm",
                        subtype="ips",
                        action="reset" if stage_index < stages - 1 else "block",
                        level=level,
                        eventtime=anchor + elapsed,
                        src=chain_src,
                        spt=int(rng.integers(1024, 65535)),
                        dst=chain_dst,
                        dpt=443,
                        proto=6,
                        session_id=session,
                        extra={
                            "eventtype": "signature",
                            "ips_severity": severities[min(stage_index, len(severities) - 1)],
                            "service": "HTTPS",
                            "policyid": "7",
                            "attack": attack,
                            "attackid": attackid,
                            "hostname": chain_dst,
                            "request": _IPS_REQUESTS[hit % len(_IPS_REQUESTS)],
                            "direction": "incoming",
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
                    level="warning",
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
        # Concurrent browsing to 443: high byte variance, varied durations.
        for index in range(min(sessions, max(self.max_events - len(events), 0))):
            events.append(
                self._forward_accept(
                    technique,
                    rng,
                    src,
                    str(rng.choice(entities.benign_external)),
                    443,
                    anchor + index * interval_s + 11,
                    session,
                )
            )
            session += 1

        self._mark_negative(events, foil_start)
        events.sort(key=lambda e: e.eventtime)
        note = (
            f"{sessions} session(s) to one destination on 443 every {interval_s}s with "
            "narrow byte variance and no handshake metadata. Concurrent high-variance "
            "browsing to 443 is included, so neither port nor destination count separates them."
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
                    int(request_b * float(rng.uniform(0.97, 1.03))),
                    int(response_b * float(rng.uniform(0.97, 1.03))),
                    int(rng.integers(1, 30)),
                )
            )
            session += 1

        foil_start = len(events)
        # A sanctioned proxy host producing the same pairing. Identical pattern,
        # different asset role. Tests whether a detection uses role or pattern.
        sanctioned = entities.internal_hosts[len(entities.internal_hosts) - 1]
        for pair in range(min(20, max((self.max_events - len(events)) // 2, 0))):
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
                    request_b,
                    response_b,
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
