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
"""No pixel of the one sanctioned image may drop canvas text under AA.

``docs/webui-factory-design.md`` section 4 sanctions exactly one image, on
``body``, under a flat ``--background``/0.4 scrim, and requires any future
imagery to be "darker than every text pair's measured floor". Nothing checked it,
and the image that shipped from v0.6.0 to v0.8.0 did not meet it: measured on the
rendered page across five scroll positions, its brightest trace put the run
panel's pacing hint at 1.77:1 and two technique-list subtitles at 2.34:1 and
2.59:1, all far under AA.

The rule asserted here is total rather than positional, and that is deliberate.
``background-attachment`` is ``fixed``, so the backdrop stands still while the
columns scroll text across it, and a measured occupancy map (8 viewports, 4 tabs,
6 scroll positions each) put canvas-level text over 61% of the plate, with the
remainder only slivers between lines. No region is reliably free, so no region is
allowed to exceed the ceiling, and the guard then does not have to model the
layout at all: every pixel is bounded, at every viewport, at every scroll
position, and it stays true as the layout keeps changing.

The bound is arithmetic rather than a preference. For the dimmest token that
renders on the canvas to hold AA against the backdrop, the composited background
luminance may not exceed ``(L_text + 0.05) / 4.5 - 0.05``.

Positive control, run before this test was kept: against the previous
``war-room-bg.webp`` it reports 1.69:1 and fails.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from PIL import Image

BACKDROP = Path(__file__).resolve().parents[1] / "webui" / "public" / "war-room-bg.webp"

# The frontend source tree is absent from a wheel and from an sdist; only the
# built `replicant/webui_dist` ships. Same reasoning as tests/test_ci_paths_filter.
pytestmark = pytest.mark.skipif(
    not BACKDROP.is_file(), reason="no webui/ in this tree (wheel or sdist)"
)

# index.css: linear-gradient(hsl(var(--background) / 0.4), ...) over the image.
CANVAS = (0x10, 0x10, 0x10)  # --background
SCRIM = 0.4

# --text-4 / --muted-foreground #8a8380, the dimmest token that renders directly
# on the canvas. It sets the floor: anything brighter clears it automatically.
DIMMEST_CANVAS_TEXT = (0x8A, 0x83, 0x80)
AA_BODY = 4.5


def _relative_luminance(rgb: np.ndarray) -> np.ndarray:
    """WCAG 2.x relative luminance for an (..., 3) array of 0-255 channels."""

    c = np.asarray(rgb, dtype=np.float64) / 255.0
    lin = np.where(c <= 0.03928, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * lin[..., 0] + 0.7152 * lin[..., 1] + 0.0722 * lin[..., 2]


def _contrast(a: float, b: float) -> float:
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def _composited() -> np.ndarray:
    """The plate as body paints it: the asset under the flat scrim.

    Read at the asset's own resolution rather than once per viewport.
    ``background-size: cover`` only ever scales and crops, and neither can create
    a pixel brighter than the brightest source pixel, so bounding the asset
    bounds every viewport at once.
    """

    pixels = np.asarray(Image.open(BACKDROP).convert("RGB")).astype(np.float64)
    return pixels * (1 - SCRIM) + np.array(CANVAS, dtype=np.float64) * SCRIM


def test_no_pixel_of_the_backdrop_drops_canvas_text_under_aa() -> None:
    """The whole plate stays under the ceiling, so every viewport does.

    Measured against the brightest pixel rather than the mean: one bright trace
    crossing one 12px subtitle is the defect this replaces, and an average
    reported the old image as fine.
    """

    text = float(_relative_luminance(np.array(DIMMEST_CANVAS_TEXT, dtype=np.float64)))
    floor = _contrast(text, float(_relative_luminance(_composited()).max()))

    assert floor >= AA_BODY, (
        f"the backdrop's brightest pixel puts #8a8380 at {floor:.2f}:1; section 4 "
        f"requires imagery darker than every text pair's measured floor"
    )


def test_backdrop_carries_no_chromatic_accent() -> None:
    """Signal orange on screen means live data, so the backdrop may not spend it.

    The image this replaces had orange trace endpoints. They were decorative, and
    a warm dot on the canvas is the verified-badge lie in another costume: it
    reads as status, beside an interface whose only other orange IS status. The
    plate is warm graphite now. The ceiling would have muted such accents to
    bronze in any case, so nothing was given up by saying it plainly.
    """

    pixels = np.asarray(Image.open(BACKDROP).convert("RGB")).astype(np.float64)
    spread = pixels.max(axis=2) - pixels.min(axis=2)

    assert float(spread.max()) <= 12.0, (
        f"the backdrop has a pixel with {spread.max():.0f}/255 channel spread; the "
        f"plate is warm graphite, and chromatic color is reserved for live data"
    )


def test_backdrop_stays_small_enough_to_ship() -> None:
    """It loads on every page view and rides in the wheel.

    Recorded because the size is a consequence of a correctness decision rather
    than a free choice: the plate must be encoded so that compression cannot
    raise its peak past the ceiling, which rules out the smallest settings.
    """

    kib = BACKDROP.stat().st_size / 1024

    assert kib <= 64.0, f"the backdrop is {kib:.0f} KiB; keep the plate under 64 KiB"
