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

All eleven catalog techniques (REP-001 through REP-011) have registered builders.
A technique id with no builder raises NotImplementedError.
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
    unique_ints,
    weighted_choice,
)

# Fixed default so identical seeds produce byte-identical output (acceptance #8).
# Arbitrary but stable; overridable per run with --anchor. 2025-07-15T13:40:00Z.
DEFAULT_ANCHOR_EPOCH = 1_752_586_800

# Bound on materialized events, protecting memory and the operator's collector.
DEFAULT_MAX_EVENTS = 200_000

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
                        "sentpkt": str(max(1, out_b // 150)),
                        "rcvdpkt": str(max(1, in_b // 150)),
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
        gap_lo, gap_hi = (float(v) for v in preset["gap_ms"])

        truncated = False
        if unique_ports > self.max_events:
            unique_ports = self.max_events
            truncated = True

        src = str(rng.choice(entities.internal_hosts))
        dst = str(rng.choice(entities.internal_targets))
        ports = unique_ints(rng, 1, 65535, unique_ports)
        open_count = max(1, unique_ports // 200)
        open_indices = set(unique_ints(rng, 0, unique_ports - 1, min(open_count, unique_ports)))

        events: list[EventRecord] = []
        session = int(rng.integers(10_000, 60_000))
        cumulative_ms = 0.0
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
                    eventtime=anchor + int(cumulative_ms / 1000),
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
            cumulative_ms += float(rng.uniform(gap_lo, gap_hi))
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
        off_window_s = 6 * 3600  # 00:00-06:00 UTC+04:00
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
                        "sentpkt": str(max(1, out_b // 1400)),
                        "rcvdpkt": str(max(1, in_b // 1400)),
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
                "sentpkt": str(max(1, out_b // 1400)),
                "rcvdpkt": str(max(1, in_b // 1400)),
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
