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
"""Statistical fidelity regression (roadmap 2026-09 item 6).

F2 asks whether a rule fired; this asks whether the telemetry resembles the wire.
A rule can score perfectly against a stream that is nothing like real traffic, so
these tests assert the quantitative properties each technique claims: the DGA /
tunnel character distribution, the DGA NXDOMAIN ratio, C2 interval jitter, and
that bytes-per-packet is not the fixed fingerprint a fixed divisor produced.

Offline and deterministic; no SIEM, no collector. This is the class of evidence
producible here while the lab test cannot yet run.
"""

from __future__ import annotations

import statistics

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.distributions import packet_count, shannon_entropy

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ORCH = Orchestrator(CATALOG, Settings())

# The seed is part of the guard (CLAUDE.md): thresholds tuned to one lucky draw
# have never failed. Every property here is asserted across several seeds so a
# green run is not an artefact of seed 1337.
SEEDS = (1337, 7, 20_250_901, 42)


def _events(
    tid: str, intensity: str = "medium", seed: int = 1337, controls: str = "positive"
) -> list:
    return ORCH.build_plan(
        RunRequest(
            technique_id=tid, intensity=intensity, seed=seed, no_send=True, controls=controls
        )
    ).events


def _labels(events: list) -> list[str]:
    return [e.extra["qname"].split(".")[0] for e in events if "qname" in e.extra]


# --- packet-size realism -----------------------------------------------------


def test_packet_count_spreads_the_segment_size() -> None:
    """A fixed divisor pins every multi-packet flow's segment size at ~1400;
    packet_count moves it across a band and dips below that floor. Comparing
    multi-packet flows (>= 4 packets) isolates the fingerprint from the trivial
    single-packet edge, where any divisor gives segment == byte count."""

    varied = [b / packet_count(b, b % 97) for b in range(6000, 40000, 137)]
    # packet_count dips well below the old fixed 1400 segment (b // 1400 can never
    # yield a segment under 1400 for these flows) and takes many distinct values.
    assert min(varied) < 1200, min(varied)
    assert len({round(s / 50) for s in varied}) >= 5


def test_packet_count_has_conditional_variance_on_the_salt() -> None:
    """Same byte count, different flow (salt): the packet count is not a fixed
    function of size. Without this, a checker regressing packets on bytes finds a
    perfect fit no real capture shows; the salt gives real residual variance."""

    counts = {packet_count(12_000, salt) for salt in range(200)}
    assert len(counts) >= 3, counts


def test_emitted_bytes_per_packet_is_not_a_fixed_fingerprint() -> None:
    """The old engine derived sentpkt as out_b // <constant>, so a multi-packet
    beacon flow always reported ~150 bytes per packet, which an analyst spots at a
    glance. Measured on REP-001's multi-packet flows, where the fingerprint showed
    (single-packet flows report the byte count either way, so they are excluded).

    Positive control: restore ``out_b // 150`` and the segment size pins at >= 150
    with almost no distinct values, so both assertions below go red."""

    for seed in SEEDS:
        segments = [
            e.out_bytes / int(e.extra["sentpkt"])
            for e in _events("REP-001", "high", seed)
            if e.out_bytes
            and e.extra.get("sentpkt", "0").isdigit()
            and int(e.extra["sentpkt"]) >= 3
        ]
        assert len(segments) > 50, seed
        # the fix dips the segment size below the old fixed 150 floor and takes
        # several distinct values; the fixed divisor did neither.
        assert min(segments) < 130, (seed, min(segments))
        assert len({round(s / 20) for s in segments}) >= 4, seed


# --- DGA / tunnel character distribution -------------------------------------


def test_dga_and_tunnel_labels_have_a_near_uniform_char_distribution() -> None:
    """The claimed 'algorithmic character distribution': over many labels the
    base32 characters are near-uniform, so the concatenation approaches log2(32)=5.
    Per-label Shannon entropy is length-capped, so the distribution is measured
    over the whole run, not one short label."""

    for seed in SEEDS:
        for tid in ("REP-004", "REP-016"):
            labels = _labels(_events(tid, seed=seed))
            assert labels, (tid, seed)
            assert shannon_entropy("".join(labels)) > 4.5, (tid, seed)


def test_rep016_benign_foil_is_lower_entropy_than_the_dga_cluster() -> None:
    """The benign NXDOMAIN trickle must look like typos and stale records, not
    like the DGA. A lower-entropy foil is realistic and is what makes an entropy
    detector's separation honest rather than free."""

    for seed in SEEDS:
        malicious = shannon_entropy(
            "".join(_labels(_events("REP-016", "medium", seed, "positive")))
        )
        foil_labels = _labels(_events("REP-016", "medium", seed, "negative"))
        assert foil_labels, ("REP-016 emits no benign foil", seed)
        foil = shannon_entropy("".join(foil_labels))
        assert foil < 3.5 < malicious, (seed, foil, malicious)


def test_rep016_nxdomain_ratio_matches_its_preset() -> None:
    """The DGA cluster is mostly NXDOMAIN with a small registered-rendezvous
    remainder; the ratio the catalog declares is the ratio emitted."""

    nx_ratio = float(CATALOG.by_id("REP-016").params["medium"]["nx_ratio"])
    for seed in SEEDS:
        events = _events("REP-016", "medium", seed)
        nx = sum(1 for e in events if e.extra.get("rcode") == "NXDOMAIN")
        measured = nx / len(events)
        assert abs(measured - nx_ratio) < 0.05, (seed, measured, nx_ratio)


# --- C2 interval shape -------------------------------------------------------


def test_rep001_beacon_interval_has_bounded_jitter() -> None:
    """A beacon is jittered but regular: the gaps are not all identical (a fixed
    interval is trivially detectable) yet stay within a bounded envelope of the
    base (a wildly varying gap is not a beacon)."""

    for seed in SEEDS:
        times = sorted(e.eventtime for e in _events("REP-001", "medium", seed))
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        assert len(gaps) > 20, seed
        assert len(set(gaps)) >= 3, ("no jitter: every gap is identical", seed)
        assert max(gaps) <= 2 * min(gaps), (seed, min(gaps), max(gaps))
        # jitter around a stable centre, not a trend
        assert statistics.pstdev(gaps) > 0, seed
