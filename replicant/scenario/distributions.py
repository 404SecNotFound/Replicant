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
"""Seeded, numpy-backed distribution helpers for the scenario engine.

Every function is a pure transform of a seeded ``numpy`` Generator plus scalar
arguments, so a given seed yields the same draws in the same order. Public
functions return plain Python types (int/float/list/str) to keep the engine and
its type checking free of numpy's array types.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from typing import Any, TypeVar

import numpy as np

BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

T = TypeVar("T")


def make_rng(seed: int) -> Any:
    """Return a seeded numpy Generator. Same seed -> same stream."""

    return np.random.default_rng(seed)


def lognormal_bytes(rng: Any, low: int, high: int, sigma: float = 0.15) -> int:
    """A low-variance byte count clipped to ``[low, high]``.

    Median sits at the midpoint of the range; ``sigma`` controls spread. Used for
    C2 callbacks (small, near-constant) and exfil (large) byte fields.
    """

    if high < low:
        raise ValueError("high must be >= low")
    if high <= 0:
        return 0
    center = max((low + high) / 2.0, 1.0)
    value = float(rng.lognormal(mean=math.log(center), sigma=sigma))
    return int(min(max(value, low), high))


def packet_count(byte_count: int, typical_mss: int = 1400, spread: int = 400) -> int:
    """Packet count for a byte count, with a per-flow effective segment size.

    A fixed divisor (``byte_count // 1400``) makes bytes-per-packet a constant an
    analyst spots at a glance: every flow reports the same ~1400 (or ~150). Real
    captures never show one segment size across every session. The effective size
    here varies with the byte count itself, over ``[typical_mss - spread,
    typical_mss]``, so the ratio moves flow to flow.

    Deterministic on ``byte_count`` alone, and drawing from no rng, so it neither
    breaks reproducibility nor shifts the seeded stream (which would change every
    downstream draw for a given seed). ``byte_count`` already varies per flow, so
    a deterministic function of it still spreads the ratio across the stream.
    """

    if byte_count <= 0:
        return 1
    mss = typical_mss - (byte_count % (spread + 1))
    return max(1, byte_count // max(mss, 1))


def jittered_interval(rng: Any, base_s: float, jitter_pct: float) -> float:
    """``base_s`` scaled by a uniform +/- ``jitter_pct`` percent.

    ``jitter_pct`` is clamped to [0, 100]: an override above 100 would allow a
    negative factor, and a negative interval walks the timeline backwards.
    """

    pct = min(max(float(jitter_pct), 0.0), 100.0)
    factor = 1.0 + float(rng.uniform(-pct / 100.0, pct / 100.0))
    return base_s * factor


def unique_ints(rng: Any, low: int, high: int, count: int, ascending: bool = False) -> list[int]:
    """``count`` unique integers from the inclusive range ``[low, high]``."""

    span = high - low + 1
    if count > span:
        raise ValueError(f"cannot draw {count} unique ints from a span of {span}")
    if ascending:
        return list(range(low, low + count))
    chosen = rng.choice(span, size=count, replace=False)
    return [low + int(c) for c in chosen]


def high_entropy_labels(
    rng: Any,
    count: int,
    min_len: int,
    max_len: int,
    alphabet: str = BASE32_ALPHABET,
) -> list[str]:
    """``count`` unique high-entropy DNS labels with a near-uniform base32 look.

    The character distribution is near-uniform over the alphabet, so a long run of
    these labels measures close to log2(len(alphabet)) bits per character (~5 for
    base32). Per-character Shannon entropy of a SINGLE short label is capped by its
    length (an 8-char label tops out near 3 bits/char even when every character is
    distinct), so short labels read lower on that per-label metric while the
    distribution stays uniform; measure the distribution over many labels, not one.

    Lengths are clamped to the RFC 1035 63-octet label limit, so a label_len
    override above 63 cannot produce a label no resolver would ever emit. With
    the short synthetic parents the engine joins these to, the resulting qname
    stays well under the 253-octet wire limit too.
    """

    min_len = min(min_len, 63)
    max_len = min(max_len, 63)
    if min_len < 1 or max_len < min_len:
        raise ValueError("require 1 <= min_len <= max_len")
    alpha_size = len(alphabet)
    # The rejection loop below never terminates if more distinct labels are
    # asked for than the alphabet can form at these lengths: it keeps redrawing
    # collisions forever, pegging a CPU with no error. `unique_ints` already
    # refuses the integer version of this; do the same. The reachable count is
    # sum(alpha_size ** L for L in min_len..max_len), but we only need to know
    # whether it reaches `count`, so we stop summing the moment it does and
    # never compute the astronomically large powers when `count` is small.
    reachable = 0
    for length in range(min_len, max_len + 1):
        reachable += alpha_size**length
        if reachable >= count:
            break
    else:
        raise ValueError(
            f"cannot draw {count} unique labels from lengths [{min_len},{max_len}] "
            f"over a {alpha_size}-symbol alphabet"
        )
    seen: set[str] = set()
    labels: list[str] = []
    while len(labels) < count:
        length = int(rng.integers(min_len, max_len + 1))
        indices = rng.integers(0, alpha_size, size=length)
        label = "".join(alphabet[int(i)] for i in indices)
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def weighted_choice(rng: Any, options: Sequence[T], weights: Sequence[float]) -> T:
    """Pick one of ``options`` with probability proportional to ``weights``."""

    if len(options) != len(weights):
        raise ValueError("options and weights must be the same length")
    probs = np.asarray(weights, dtype=float)
    probs = probs / probs.sum()
    index = int(rng.choice(len(options), p=probs))
    return options[index]


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character."""

    length = len(text)
    if length == 0:
        return 0.0
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
