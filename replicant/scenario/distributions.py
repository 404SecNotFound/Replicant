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


def jittered_interval(rng: Any, base_s: float, jitter_pct: float) -> float:
    """``base_s`` scaled by a uniform +/- ``jitter_pct`` percent."""

    factor = 1.0 + float(rng.uniform(-jitter_pct / 100.0, jitter_pct / 100.0))
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
    """``count`` unique high-entropy DNS labels (base32 look, > 3.5 bits/char)."""

    if min_len < 1 or max_len < min_len:
        raise ValueError("require 1 <= min_len <= max_len")
    seen: set[str] = set()
    labels: list[str] = []
    alpha_size = len(alphabet)
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


def business_hours_weight(hour: int, work_start: int = 8, work_end: int = 18) -> float:
    """Relative event likelihood by hour of day (UTC+04:00). 1.0 in hours, else 0.25."""

    return 1.0 if work_start <= hour < work_end else 0.25


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character."""

    length = len(text)
    if length == 0:
        return 0.0
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
