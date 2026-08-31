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
"""The one sanctioned image may not put structure behind the reading columns.

``docs/webui-factory-design.md`` section 4 sanctions exactly one image, on
``body``, under a flat ``--background``/0.4 scrim, and requires any future
imagery to be "darker than every text pair's measured floor". Nothing checked it,
and the image that shipped from v0.6.0 to v0.8.0 did not meet it: measured on the
rendered page across five scroll positions, its brightest trace put the run
panel's pacing hint at 1.77:1 and two technique-list subtitles at 2.34:1 and
2.59:1, all far under AA.

The defect is positional, not one of overall brightness. ``background-attachment``
is ``fixed``, so the backdrop stands still while the columns scroll text across
it: any region the rail or the main column can ever cover has to stay at flat
canvas, and only the right gutter is free. This asserts exactly that, in the
units section 4 uses, and it is deterministic because the mapping from image to
viewport (``cover``, ``center top``) is arithmetic rather than a render.

Positive control, run before this test was kept: against the previous
``war-room-bg.webp`` the floor below measures 1.69:1 and the assertion fails.
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

# The reference viewport the design doc measures at, and the width the rail plus
# the main column's text occupy in it. Right of this is gutter the layout never
# fills with canvas-level text.
VIEWPORT = (1440, 900)
READING_COLUMNS_PX = 1150

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


def _composited_viewport(viewport: tuple[int, int] = VIEWPORT) -> np.ndarray:
    """The backdrop as body actually paints it: cover, center top, under the scrim."""

    image = Image.open(BACKDROP).convert("RGB")
    width, height = viewport
    scale = max(width / image.width, height / image.height)
    image = image.resize(
        (round(image.width * scale), round(image.height * scale)), Image.Resampling.LANCZOS
    )
    left = (image.width - width) // 2  # background-position: center top
    image = image.crop((left, 0, left + width, height))
    pixels = np.asarray(image).astype(np.float64)
    return pixels * (1 - SCRIM) + np.array(CANVAS, dtype=np.float64) * SCRIM


def _reading_column_floor(viewport: tuple[int, int]) -> float:
    """Worst contrast the dimmest canvas token can meet anywhere the columns cover.

    Against the brightest pixel in the band rather than its mean: a single bright
    trace crossing one 12px subtitle is the defect this replaces, and an average
    would have reported the old image as fine.
    """

    band = _relative_luminance(_composited_viewport(viewport)[:, :READING_COLUMNS_PX])
    text = float(_relative_luminance(np.array(DIMMEST_CANVAS_TEXT, dtype=np.float64)))
    return _contrast(text, float(band.max()))


def test_backdrop_leaves_the_reading_columns_at_flat_canvas() -> None:
    """No pixel the columns can cover may drop the dimmest canvas token under AA."""

    floor = _reading_column_floor(VIEWPORT)

    assert floor >= AA_BODY, (
        f"backdrop puts {floor:.2f}:1 under #8a8380 somewhere in the left "
        f"{READING_COLUMNS_PX}px of a {VIEWPORT[0]}x{VIEWPORT[1]} viewport; "
        f"section 4 requires imagery darker than every text pair's floor"
    )


def test_backdrop_chromatic_weight_stays_at_a_few_endpoints() -> None:
    """Signal orange in the image stays a few small endpoints, not a feature.

    Section 3 reserves the chromatics for live data. The image is allowed its
    orange trace endpoints because they are small; the guard is on area, which is
    what reads, not on peak brightness, which one anti-aliased pixel can carry.
    """

    pixels = np.asarray(Image.open(BACKDROP).convert("RGB")).astype(np.float64)
    red, green, blue = pixels[..., 0], pixels[..., 1], pixels[..., 2]
    orange = (red > 90) & (red > green * 1.5) & (green > blue)
    share = float(orange.mean())

    assert share <= 0.0005, (
        f"signal orange covers {share * 100:.3f}% of the backdrop; the sanctioned "
        f"treatment is a few small trace endpoints (0.05% ceiling)"
    )


@pytest.mark.parametrize("viewport", [(1280, 800), (1920, 1080), (2560, 1440)])
def test_backdrop_holds_at_other_viewports(viewport: tuple[int, int]) -> None:
    """`cover` re-crops per viewport, so one measurement proves one viewport.

    The reading columns are a fixed pixel width (the rail does not grow), so a
    wider viewport shows more of the image behind the same columns.
    """

    floor = _reading_column_floor(viewport)

    assert floor >= AA_BODY, f"{viewport[0]}x{viewport[1]}: floor is {floor:.2f}:1"
