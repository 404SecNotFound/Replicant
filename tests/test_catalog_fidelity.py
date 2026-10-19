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
"""Catalog-wide statistical fidelity (roadmap 2026-09 item 6).

Every catalog entry states, under ``distributions``, the quantitative shape of
what it emits: an interval and its jitter, a byte band, a count per preset, a
ratio, an ordering. ``tests/test_statistical_fidelity.py`` measured four of
those claims on three techniques. This file measures at least one claim for
every technique, on the attack stream, at every preset, over several seeds.
The foil is measured elsewhere (``tests/test_foil_parity.py``); this file asks
only whether the attack is what its own entry says it is.

``test_every_technique_has_a_fidelity_claim`` fails when an entry is added with
no measured claim, because a guard of one representative entry is how a flag
came to work on 20 of 24 techniques (CLAUDE.md, duration).

Each check quotes the catalog text it measures. A claim the records cannot
express is listed in ``UNMEASURABLE`` with the reason, rather than dropped.
"""

from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from replicant.core.models import EventRecord, load_catalog
from replicant.entities.model import EntityModel
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.distributions import shannon_entropy
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
INTENSITIES = ("low", "medium", "high")
# The seed is part of the guard: five seeds, not one lucky draw.
SEEDS = (1, 7, 42, 1337, 20_250_901)


@dataclass
class Run:
    tid: str
    intensity: str
    seed: int
    preset: dict[str, Any]
    events: list[EventRecord]
    truncated: bool

    @property
    def tag(self) -> str:
        return f"{self.tid}/{self.intensity}/seed {self.seed}"

    def times(self, events: list[EventRecord] | None = None) -> list[int]:
        return sorted(e.eventtime for e in (self.events if events is None else events))

    def span(self, events: list[EventRecord] | None = None) -> int:
        times = self.times(events)
        return times[-1] - times[0]


def _run(tid: str, intensity: str, seed: int) -> Run:
    technique = CATALOG.by_id(tid)
    plan = ENGINE.plan(technique, intensity, ENTITIES, seed, anchor_epoch=ANCHOR)
    positive = [e for e in plan.events if e.control == "positive"]
    return Run(tid, intensity, seed, technique.preset(intensity), positive, plan.truncated)


def _gaps(times: list[int]) -> list[int]:
    return [b - a for a, b in zip(times, times[1:], strict=False)]


_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
# The catalog's offset for every runtime timestamp (technique-catalog.yaml header).
CATALOG_UTC_OFFSET_S = 4 * 3600


def _internal(ip: str | None) -> bool:
    """RFC1918. Not ``is_private``, which also counts the documentation ranges
    every synthetic external pool is drawn from."""

    return ip is not None and any(ipaddress.ip_address(ip) in net for net in _RFC1918)


def _label(e: EventRecord) -> str:
    return e.extra["qname"].split(".")[0]


def _parent(e: EventRecord) -> str:
    return e.extra["qname"].split(".", 1)[1]


def _exact_or_capped(run: Run, measured: int, claimed: int, what: str) -> None:
    """A preset count is exact unless the engine's ceiling truncated the plan."""

    if run.truncated:
        assert measured <= claimed, f"{run.tag}: {what} {measured} above preset {claimed}"
    else:
        assert measured == claimed, f"{run.tag}: {what} {measured} != preset {claimed}"


# -- REP-001 periodic C2 -------------------------------------------------------------


def rep001_interval_is_base_plus_or_minus_jitter(run: Run) -> None:
    """interval: fixed base +/- jitter_pct."""

    base, jitter = run.preset["interval_s"], run.preset["jitter_pct"] / 100
    for gap in _gaps(run.times()):
        assert base * (1 - jitter) - 1 <= gap <= base * (1 + jitter) + 1, (run.tag, gap)


def rep001_callbacks_are_small(run: Run) -> None:
    """out_bytes: each callback small, inside the preset band; in usually >= out."""

    lo, hi = run.preset["out_bytes"]
    outs = [e.out_bytes or 0 for e in run.events]
    assert all(lo <= b <= hi for b in outs), (run.tag, min(outs), max(outs))
    tasking = sum(1 for e in run.events if (e.in_bytes or 0) >= (e.out_bytes or 0))
    assert tasking / len(run.events) >= 0.5, (run.tag, tasking, len(run.events))
    assert {e.dpt for e in run.events} <= {443, 8443, 8080, 53}, run.tag


# -- REP-002 vertical scan -------------------------------------------------------------


def rep002_many_ports_on_one_host_in_the_window(run: Run) -> None:
    """dpt randomized across 1-65535; probes spread evenly across window_s."""

    ports = [e.dpt or 0 for e in run.events]
    _exact_or_capped(run, len(set(ports)), run.preset["unique_ports"], "distinct dpt")
    assert len({e.dst for e in run.events}) == 1, run.tag
    assert all(1 <= p <= 65535 for p in ports), run.tag
    assert max(ports) - min(ports) > 30_000, (run.tag, "ports not spread across the range")
    window = run.preset["window_s"]
    assert run.span() <= window, (run.tag, run.span(), window)
    quarters = Counter(min(3, (t - run.times()[0]) * 4 // window) for t in run.times())
    for q in range(4):
        assert 0.1 <= quarters[q] / len(ports) <= 0.4, (run.tag, dict(quarters))


def rep002_mostly_deny_and_no_payload(run: Run) -> None:
    """action_mix: mostly deny; out_bytes ~0."""

    denies = sum(1 for e in run.events if e.action == "deny")
    assert denies / len(run.events) >= 0.9, (run.tag, denies, len(run.events))
    assert statistics.median(e.out_bytes or 0 for e in run.events) <= 100, run.tag


# -- REP-003 horizontal sweep ------------------------------------------------------------


def rep003_one_port_many_internal_hosts(run: Run) -> None:
    """dst iterates a synthetic internal range; one port from port_choices."""

    assert {e.dpt for e in run.events} == {run.preset["port"]}, run.tag
    assert run.preset["port"] in (445, 3389, 22, 23, 80), run.tag
    dsts = {e.dst for e in run.events}
    _exact_or_capped(run, len(dsts), run.preset["unique_hosts"], "distinct dst")
    assert all(_internal(d) for d in dsts), run.tag
    assert run.span() <= run.preset["window_s"], (run.tag, run.span())


# -- REP-004 DNS tunnel ---------------------------------------------------------------------


def rep004_labels_are_long_high_entropy_under_few_parents(run: Run) -> None:
    """qname: high-entropy labels (>3.5 bits/char) under one or few parent domains."""

    lo, hi = run.preset["label_len"]
    labels = [_label(e) for e in run.events]
    assert all(lo <= len(label) <= hi for label in labels), run.tag
    low = [label for label in labels if shannon_entropy(label) <= 3.5]
    assert not low, (run.tag, f"{len(low)} labels at or below 3.5 bits/char", low[:3])
    assert len({_parent(e) for e in run.events}) <= 3, run.tag


def rep004_qtype_weighted_to_txt_null_cname(run: Run) -> None:
    """qtype: weighted toward TXT, NULL, CNAME."""

    heavy = sum(1 for e in run.events if e.extra.get("qtype") in ("TXT", "NULL", "CNAME"))
    assert heavy / len(run.events) >= 0.6, (run.tag, heavy, len(run.events))


# -- REP-005 exfil volume -------------------------------------------------------------------


def rep005_out_heavy_off_hours_sessions(run: Run) -> None:
    """out_bytes large, out:in > 20:1; timing pinned to off-hours (00:00-06:00,
    in the catalog's UTC+04:00). The attack stream is the host's own three
    low-volume history windows, then the current window, which carries
    total_out_mb and is larger than every history window."""

    for e in run.events:
        assert (e.out_bytes or 0) > 20 * (e.in_bytes or 0), (run.tag, e.out_bytes, e.in_bytes)
        local = (e.eventtime + CATALOG_UTC_OFFSET_S) % 86_400
        assert local < 6 * 3600, (run.tag, local)
    assert {e.dpt for e in run.events} <= {443, 22, 21}, run.tag
    assert len({e.src for e in run.events}) == 1, run.tag
    sessions = len(run.events) // 4
    if not run.truncated:
        assert sessions == run.preset["sessions"], (run.tag, len(run.events))
    ordered = sorted(run.events, key=lambda e: e.eventtime)
    windows = [ordered[i * sessions : (i + 1) * sessions] for i in range(4)]
    totals = [sum(e.out_bytes or 0 for e in w) for w in windows]
    assert totals[-1] > 3 * max(totals[:-1]), (run.tag, totals)
    if not run.truncated:
        claimed = run.preset["total_out_mb"] * 1_000_000
        assert abs(totals[-1] - claimed) / claimed < 0.2, (run.tag, totals[-1], claimed)
    current = {e.dst for e in windows[-1]}
    assert len(current) == run.preset["dst_count"], (run.tag, current)


# -- REP-006 destination fan-out ----------------------------------------------------------


def rep006_many_destinations_small_bytes(run: Run) -> None:
    """dst: mix of internal and external; out_bytes small; inside window_min."""

    dsts = {e.dst for e in run.events}
    _exact_or_capped(run, len(dsts), run.preset["unique_dst"], "distinct dst")
    assert any(_internal(d) for d in dsts) and any(not _internal(d) for d in dsts), run.tag
    assert run.span() <= run.preset["window_min"] * 60, run.tag
    assert max(e.out_bytes or 0 for e in run.events) <= 10_000, run.tag


# -- REP-007 brute force / spray ------------------------------------------------------------


def rep007_spray_or_brute_shape(run: Run) -> None:
    """spray: many duser, few attempts each. brute: one duser, many attempts."""

    per_user = Counter(e.duser for e in run.events)
    failures = [e for e in run.events if "fail" in e.action or e.action == "login-fail"]
    attempts = run.preset["attempts_each"]
    if run.preset["mode"] == "spray":
        _exact_or_capped(run, len(per_user), run.preset["users"], "distinct duser")
        assert set(per_user.values()) == {attempts}, (run.tag, set(per_user.values()))
        assert len(failures) == len(run.events), run.tag
    else:
        assert len(per_user) == 1, run.tag
        assert len(failures) >= attempts - 1, (run.tag, len(failures))
        successes = [e for e in run.events if e not in failures]
        if successes:
            assert successes == [max(run.events, key=lambda e: e.eventtime)], run.tag
    assert run.span() <= run.preset["window_min"] * 60, run.tag


# -- REP-008 newly observed destination --------------------------------------------------------


def rep008_baseline_then_first_seen_destinations(run: Run) -> None:
    """approach: a baseline of known dst per host, then first-seen external dst.
    baseline_time: compressed into the hour before first contact."""

    first_seen: dict[tuple[str | None, str | None], int] = {}
    for e in sorted(run.events, key=lambda e: e.eventtime):
        first_seen.setdefault((e.src, e.dst), e.eventtime)
    per_pair = Counter((e.src, e.dst) for e in run.events)
    novel = [pair for pair, n in per_pair.items() if n < run.preset["baseline_days"]]
    hosts = {src for src, _ in per_pair}
    assert len(novel) == run.preset["novel_dst"] * len(hosts), (run.tag, len(novel), len(hosts))
    first_novel = min(first_seen[pair] for pair in novel)
    known = [p for p in per_pair if p not in novel]
    assert known, run.tag
    for pair in known:
        assert per_pair[pair] == run.preset["baseline_days"], (run.tag, per_pair[pair])
        # The hour is [anchor, anchor + 3600] and first contact is one second
        # after it, so the history can start 3601 s before first contact.
        assert first_novel - 3601 <= first_seen[pair] < first_novel, (run.tag, pair)
    for _src, dst in novel:
        assert not _internal(dst), (run.tag, dst)


# -- REP-009 IPS spike -------------------------------------------------------------------------


def rep009_high_severity_hits_in_the_window(run: Run) -> None:
    """severity: high or critical; hits inside window_min; mixed mode has many attackids."""

    spike = [e for e in run.events if e.log_type == "utm"]
    assert spike, run.tag
    assert {e.extra.get("ips_severity") for e in spike} <= {"high", "critical"}, run.tag
    _exact_or_capped(run, len(spike), run.preset["hits"], "hits")
    if run.preset["signature_mode"] == "mixed" and len(spike) > 5:
        assert len({e.extra.get("attackid") for e in spike}) > 1, run.tag


# -- REP-010 denied burst ------------------------------------------------------------------------


def rep010_sharp_spike_then_decay(run: Run) -> None:
    """pattern: sharp rate spike, then decay."""

    assert all(e.action == "deny" for e in run.events), run.tag
    _exact_or_capped(run, len(run.events), run.preset["denies"], "denies")
    times = run.times()
    assert run.span() <= run.preset["window_s"], run.tag
    third = max(1, (times[-1] - times[0]) / 3)
    first = sum(1 for t in times if t - times[0] < third)
    last = sum(1 for t in times if t - times[0] >= 2 * third)
    assert first > last, (run.tag, first, last)


# -- REP-011 geovelocity ---------------------------------------------------------------------


def rep011_one_user_hops_country_every_login(run: Run) -> None:
    """geo: successive logins from distant source blocks; one user."""

    logins = sorted(run.events, key=lambda e: e.eventtime)
    assert len({e.duser for e in logins}) == 1, run.tag
    assert len(logins) == run.preset["logins"], run.tag
    countries = [e.extra["srccountry"] for e in logins]
    for a, b in zip(countries, countries[1:], strict=False):
        assert a != b, (run.tag, countries)
    assert run.span() <= run.preset["window_min"] * 60, run.tag


# -- REP-012 jittered / fleet C2 -------------------------------------------------------------


def rep012_period_shape_by_mode(run: Run) -> None:
    """jitter: one src, each gap the interval +/- jitter_pct. fleet: each src on
    its own phase of a shared grid, displaced by at most jitter_pct/100 * 0.375."""

    interval, jitter = run.preset["interval_s"], run.preset["jitter_pct"] / 100
    by_src: dict[str | None, list[int]] = defaultdict(list)
    for e in run.events:
        by_src[e.src].append(e.eventtime)
    if run.preset["mode"] == "jitter":
        assert len(by_src) == 1, run.tag
        for gap in _gaps(sorted(next(iter(by_src.values())))):
            assert interval * (1 - jitter) - 1 <= gap <= interval * (1 + jitter) + 1, (run.tag, gap)
    else:
        assert len(by_src) == run.preset["hosts"], run.tag
        slack = 2 * jitter * 0.375 * interval + 1
        for times in by_src.values():
            for gap in _gaps(sorted(times)):
                assert abs(gap - interval * round(gap / interval)) <= slack, (run.tag, gap)
    lo, hi = run.preset["out_bytes"]
    assert all(lo <= (e.out_bytes or 0) <= hi for e in run.events), run.tag
    assert {e.dpt for e in run.events} <= {443, 8443}, run.tag


# -- REP-013 worm spread ----------------------------------------------------------------------


def rep013_distinct_sources_grow_by_generation(run: Run) -> None:
    """growth: the count of DISTINCT sources on the port grows geometrically.
    action_mix: majority deny."""

    assert {e.dpt for e in run.events} == {run.preset["port"]}, run.tag
    denies = sum(1 for e in run.events if e.action == "deny")
    assert denies / len(run.events) > 0.5, (run.tag, denies, len(run.events))
    first_probe: dict[str | None, int] = {}
    for e in sorted(run.events, key=lambda e: e.eventtime):
        first_probe.setdefault(e.src, e.eventtime)
    gap = run.preset["gen_gap_s"]
    start = min(first_probe.values())
    per_generation = Counter((t - start) // gap for t in first_probe.values())
    counts = [per_generation[g] for g in sorted(per_generation)]
    assert counts[0] == run.preset["seed_hosts"], (run.tag, counts)
    assert len(counts) >= 2 and counts[-1] > counts[0], (run.tag, counts)


# -- REP-014 cryptomining ----------------------------------------------------------------------


def rep014_long_symmetric_sessions(run: Run) -> None:
    """duration: single sessions lasting hours. byte_ratio: in:out close to 1:1,
    both small and steady. One record per share; the session's duration is the
    largest the session id reports, and it grows by share_interval_s per share."""

    assert {e.dpt for e in run.events} == {run.preset["dpt"]}, run.tag
    by_session: dict[int | None, list[EventRecord]] = defaultdict(list)
    for e in run.events:
        by_session[e.session_id].append(e)
        ratio = (e.in_bytes or 0) / max(1, e.out_bytes or 0)
        assert 0.8 <= ratio <= 1.25, (run.tag, ratio)
        assert max(e.in_bytes or 0, e.out_bytes or 0) < 1000, run.tag
    assert len(by_session) == run.preset["sessions"] or run.truncated, (run.tag, len(by_session))
    for records in by_session.values():
        longest = max(int(e.extra["duration"]) for e in records)
        assert longest >= 3600, (run.tag, longest)
        assert longest >= 0.95 * run.preset["session_min"] * 60, (run.tag, longest)


# -- REP-015 low-throughput DNS exfil --------------------------------------------------------


def rep015_queries_per_hour_short_labels_one_parent(run: Run) -> None:
    """rate: queries per HOUR. qname: shorter, lower-entropy labels than REP-004.
    qtype: weighted to A and AAAA. parent_domain: one, stable for the run."""

    hours = max(1, run.span() / 3600)
    rate = len(run.events) / hours
    assert rate <= run.preset["qph"] * 1.5, (run.tag, rate)
    lo, hi = run.preset["label_len"]
    assert all(lo <= len(_label(e)) <= hi for e in run.events), run.tag
    assert len({_parent(e) for e in run.events}) == 1, run.tag
    a = sum(1 for e in run.events if e.extra.get("qtype") in ("A", "AAAA"))
    assert a / len(run.events) >= 0.6, (run.tag, a, len(run.events))
    tunnel = _run("REP-004", run.intensity, run.seed)
    mean015 = statistics.mean(shannon_entropy(_label(e)) for e in run.events)
    mean004 = statistics.mean(shannon_entropy(_label(e)) for e in tunnel.events)
    assert mean015 < mean004, (run.tag, mean015, mean004)


# -- REP-016 DGA ------------------------------------------------------------------------------


def rep016_many_distinct_slds_regenerated_by_epoch(run: Run) -> None:
    """qname: many DISTINCT second-level labels. epochs: the set regenerates each epoch."""

    labels = [_label(e) for e in run.events]
    claimed = run.preset["domains_per_epoch"] * run.preset["epochs"]
    assert len(set(labels)) >= 0.95 * min(claimed, len(labels)), (run.tag, len(set(labels)))
    lo, hi = run.preset["label_len"]
    assert all(lo <= len(label) <= hi for label in labels), run.tag


# -- REP-017 DoH bypass ------------------------------------------------------------------------


def rep017_resolver_queries_stop_then_doh_begins(run: Run) -> None:
    """phase_1 dns-query to the resolver; phase_2 resolver queries stop, small 443
    sessions to the DoH resolvers begin."""

    dns = [e for e in run.events if e.log_type == "dns"]
    doh = [e for e in run.events if e.log_type == "traffic" and e.dpt == 443]
    assert dns and doh, run.tag
    assert max(e.eventtime for e in dns) < min(e.eventtime for e in doh), run.tag
    assert len({e.dst for e in doh}) == run.preset["resolvers"], run.tag
    _exact_or_capped(run, len(doh), run.preset["doh_sessions"], "DoH sessions")
    assert max((e.out_bytes or 0) + (e.in_bytes or 0) for e in doh) <= 20_000, run.tag


# -- REP-018 lateral movement chain -------------------------------------------------------------


def rep018_each_hop_is_the_next_source(run: Run) -> None:
    """path: each hop becomes the source of the next login, strictly ordered.
    user_switch: duser changes at switch_at_hop."""

    logins = sorted((e for e in run.events if e.log_type == "event"), key=lambda e: e.eventtime)
    legs = sorted((e for e in run.events if e.log_type == "traffic"), key=lambda e: e.eventtime)
    assert len(logins) == run.preset["path_len"], (run.tag, len(logins))
    assert len(legs) == len(logins) - 1, run.tag
    # The entry is a VPN tunnel-up whose assigned address is hop 1.
    assert logins[0].subtype == "vpn", run.tag
    assert logins[0].extra.get("tunnelip") == logins[1].src, (run.tag, "entry joins no hop")
    for login, leg, after in zip(logins[1:], legs, logins[2:], strict=False):
        assert leg.src == login.src and leg.dst == after.src, (run.tag, leg.dst, after.src)
    for a, b in zip(logins, logins[1:], strict=False):
        assert a.eventtime < b.eventtime, run.tag
    users = [e.duser for e in logins]
    switch = run.preset["switch_at_hop"]
    assert len(set(users[:switch])) == 1, (run.tag, users)
    assert users[switch] != users[switch - 1], (run.tag, users)
    assert len(set(users)) == run.preset["users"], (run.tag, users)
    assert run.span(logins) <= run.preset["window_min"] * 60, run.tag


# -- REP-019 stealth scan ------------------------------------------------------------------------


def rep019_slow_rotated_unordered_probes(run: Run) -> None:
    """gap: minutes between probes. src_rotation across src_pool. order: randomized."""

    lo, hi = run.preset["gap_s"]
    for gap in _gaps(run.times()):
        assert lo - 1 <= gap <= hi + 1, (run.tag, gap)
    per_src = Counter(e.src for e in run.events)
    assert len(per_src) == run.preset["src_pool"], (run.tag, len(per_src))
    assert max(per_src.values()) <= 2 * statistics.mean(per_src.values()), (run.tag, per_src)
    dsts = [int(ipaddress.ip_address(e.dst or "0.0.0.0")) for e in run.events]
    ascending = sum(1 for a, b in zip(dsts, dsts[1:], strict=False) if b > a)
    assert 0.2 < ascending / max(1, len(dsts) - 1) < 0.8, (run.tag, "sequential order")


# -- REP-020 newly registered domain ----------------------------------------------------------


def rep020_novel_domains_are_absent_from_history_only(run: Run) -> None:
    """novel: never queried before, under the same parent pool with the same
    label-length envelope as the baseline."""

    seen: set[str] = set()
    novel: list[EventRecord] = []
    baseline: list[EventRecord] = []
    for e in sorted(run.events, key=lambda e: e.eventtime):
        (
            novel
            if e.extra["qname"] not in seen
            and baseline
            and len(seen) >= run.preset["baseline_domains"]
            else baseline
        ).append(e)
        seen.add(e.extra["qname"])
    novel_names = {e.extra["qname"] for e in novel}
    assert len(novel_names) == run.preset["novel_domains"], (run.tag, len(novel_names))
    lengths = [len(_label(e)) for e in baseline]
    parents = {_parent(e) for e in baseline}
    for e in novel:
        assert min(lengths) <= len(_label(e)) <= max(lengths), (run.tag, _label(e))
        assert _parent(e) in parents, (run.tag, _parent(e))


# -- REP-021 inbound scan --------------------------------------------------------------------


def rep021_heavy_tailed_inbound_sources(run: Run) -> None:
    """src: many distinct sources, a few campaigns send aggressive_probes each, a
    long tail sends one or two. direction: INBOUND."""

    assert all("src_intf" in e.extra for e in run.events), run.tag
    per_src = Counter(e.src for e in run.events)
    _exact_or_capped(run, len(per_src), run.preset["unique_src"], "distinct src")
    top = sorted(per_src.values(), reverse=True)[: run.preset["campaigns"]]
    assert min(top) >= run.preset["aggressive_probes"] // 2, (run.tag, top)
    assert statistics.median(per_src.values()) <= 2, run.tag
    assert {e.dpt for e in run.events} <= {22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 8080}


# -- REP-022 IDS alert chain ------------------------------------------------------------------


def rep022_severity_escalates_in_time_order(run: Run) -> None:
    """stage_order: strictly ordered in time. severity: ascending across stages."""

    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    pair = Counter(frozenset((e.src, e.dst)) for e in run.events).most_common(1)[0][0]
    chain = sorted(
        (e for e in run.events if frozenset((e.src, e.dst)) == pair), key=lambda e: e.eventtime
    )
    severities = [rank[e.extra["ips_severity"]] for e in chain]
    assert severities == sorted(severities), (run.tag, severities)
    assert len(set(severities)) >= min(3, run.preset["stages"]), (run.tag, set(severities))


# -- REP-023 TLS 1.3 C2 ------------------------------------------------------------------------


def rep023_low_variance_443_without_handshake_fields(run: Run) -> None:
    """dpt always 443; byte_profile LOW variance; handshake: no handshake field."""

    assert {e.dpt for e in run.events} == {443}, run.tag
    out_lo, out_hi = run.preset["out_bytes"]
    in_lo, in_hi = run.preset["in_bytes"]
    outs = [e.out_bytes or 0 for e in run.events]
    assert all(out_lo <= b <= out_hi for b in outs), run.tag
    assert all(in_lo <= (e.in_bytes or 0) <= in_hi for e in run.events), run.tag
    assert statistics.pstdev(outs) / statistics.mean(outs) < 0.25, run.tag
    for e in run.events:
        assert not {k for k in e.extra if any(w in k.lower() for w in ("ja3", "cipher", "sni"))}


# -- REP-024 proxy relay -------------------------------------------------------------------------


def rep024_relayed_legs_are_lagged_and_byte_correlated(run: Run) -> None:
    """pairing: inbound to the relay then outbound from it within lag_ms, with
    correlated bytes. lag: jittered, wide at the high preset."""

    ordered = sorted(run.events, key=lambda e: (e.session_id or 0))
    legs = list(zip(ordered[0::2], ordered[1::2], strict=False))
    assert legs, run.tag
    lag_ceiling = math.ceil(run.preset["lag_ms"][1] / 1000)
    lags = []
    for inbound, outbound in legs:
        assert inbound.dst == outbound.src, (run.tag, inbound.dst, outbound.src)
        lag = outbound.eventtime - inbound.eventtime
        assert 0 <= lag <= lag_ceiling, (run.tag, lag)
        lags.append(lag)
        ratio = (outbound.out_bytes or 0) / max(1, inbound.out_bytes or 0)
        assert 0.8 <= ratio <= 1.25, (run.tag, ratio)
    if lag_ceiling > 1:
        assert len(set(lags)) > 1, (run.tag, "constant lag")


# -- REP-030 distributed spray -----------------------------------------------------------------


def rep030_one_failure_per_user_spread_across_sources(run: Run) -> None:
    """failures: one per user, even across sources. timing: evenly sparse."""

    per_user = Counter(e.duser for e in run.events)
    per_src = Counter(e.src for e in run.events)
    assert set(per_user.values()) == {1}, run.tag
    _exact_or_capped(run, len(run.events), run.preset["failures"], "failures")
    assert len(per_src) == run.preset["sources"], run.tag
    assert max(per_src.values()) - min(per_src.values()) <= 1, (run.tag, set(per_src.values()))
    assert run.span() <= run.preset["window_min"] * 60, run.tag


# -- REP-043 alert to egress dialog -----------------------------------------------------------


def rep043_alert_then_inbound_then_egress_on_one_host(run: Run) -> None:
    """chain: alert dst == inbound dst == later outbound src, in that order."""

    alerts = [e for e in run.events if e.log_type == "utm"]
    inbound = [e for e in run.events if e.log_type == "traffic" and "src_intf" in e.extra]
    outbound = [e for e in run.events if e.log_type == "traffic" and "src_intf" not in e.extra]
    victims = {e.dst for e in alerts}
    assert len(victims) == run.preset["chains"], (run.tag, victims)
    for victim in victims:
        a = [e.eventtime for e in alerts if e.dst == victim]
        i = [e.eventtime for e in inbound if e.dst == victim]
        o = [e.eventtime for e in outbound if e.src == victim]
        assert a and i and o, (run.tag, victim)
        assert max(a) <= min(i) and max(i) <= min(o), (run.tag, victim)


CLAIMS: dict[str, list[Callable[[Run], None]]] = {
    "REP-001": [rep001_interval_is_base_plus_or_minus_jitter, rep001_callbacks_are_small],
    "REP-002": [rep002_many_ports_on_one_host_in_the_window, rep002_mostly_deny_and_no_payload],
    "REP-003": [rep003_one_port_many_internal_hosts],
    "REP-004": [
        rep004_labels_are_long_high_entropy_under_few_parents,
        rep004_qtype_weighted_to_txt_null_cname,
    ],
    "REP-005": [rep005_out_heavy_off_hours_sessions],
    "REP-006": [rep006_many_destinations_small_bytes],
    "REP-007": [rep007_spray_or_brute_shape],
    "REP-008": [rep008_baseline_then_first_seen_destinations],
    "REP-009": [rep009_high_severity_hits_in_the_window],
    "REP-010": [rep010_sharp_spike_then_decay],
    "REP-011": [rep011_one_user_hops_country_every_login],
    "REP-012": [rep012_period_shape_by_mode],
    "REP-013": [rep013_distinct_sources_grow_by_generation],
    "REP-014": [rep014_long_symmetric_sessions],
    "REP-015": [rep015_queries_per_hour_short_labels_one_parent],
    "REP-016": [rep016_many_distinct_slds_regenerated_by_epoch],
    "REP-017": [rep017_resolver_queries_stop_then_doh_begins],
    "REP-018": [rep018_each_hop_is_the_next_source],
    "REP-019": [rep019_slow_rotated_unordered_probes],
    "REP-020": [rep020_novel_domains_are_absent_from_history_only],
    "REP-021": [rep021_heavy_tailed_inbound_sources],
    "REP-022": [rep022_severity_escalates_in_time_order],
    "REP-023": [rep023_low_variance_443_without_handshake_fields],
    "REP-024": [rep024_relayed_legs_are_lagged_and_byte_correlated],
    "REP-030": [rep030_one_failure_per_user_spread_across_sources],
    "REP-043": [rep043_alert_then_inbound_then_egress_on_one_host],
}

# Entries built after the 2026-10-07 review carry a dedicated file that measures
# every distribution claim over 20 seeds at 3 presets; they are not repeated here.
DEDICATED: dict[str, str] = {
    "REP-028": "tests/test_rep028_admin_plane.py",
    "REP-046": "tests/test_rep046_unfamiliar_vpn_source.py",
    "REP-052": "tests/test_rep052_smb_fanout.py",
    "REP-053": "tests/test_rep053_reflector.py",
    "REP-054": "tests/test_rep054_staging_fanin.py",
}

# Claims the records cannot express, so no test can measure them. Stated, not dropped.
UNMEASURABLE: dict[str, str] = {
    "REP-011": (
        "geo '> 900 km/h' is not measurable: the external pool's GeoIP tags are fictional "
        "countries with no coordinates; the entry is parser-only for that reason"
    ),
}


def test_every_technique_has_a_fidelity_claim() -> None:
    ids = {t.id for t in CATALOG.techniques}
    covered = set(CLAIMS) | set(DEDICATED)
    assert ids - covered == set(), f"no measured fidelity claim: {sorted(ids - covered)}"
    assert covered - ids == set(), f"claims for unknown ids: {sorted(covered - ids)}"
    assert not set(CLAIMS) & set(DEDICATED)


@pytest.mark.parametrize("tid", sorted(DEDICATED))
def test_dedicated_files_exist_and_name_their_technique(tid: str) -> None:
    path = Path(__file__).resolve().parent.parent / DEDICATED[tid]
    assert path.is_file(), path
    assert tid in path.read_text(encoding="utf-8"), path


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
@pytest.mark.parametrize("tid", sorted(CLAIMS))
def test_the_attack_has_the_shape_its_entry_claims(tid: str, intensity: str, seed: int) -> None:
    run = _run(tid, intensity, seed)
    assert run.events, run.tag
    for check in CLAIMS[tid]:
        check(run)
