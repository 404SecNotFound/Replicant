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
"""PTY output must survive a chunk boundary landing mid-character.

``os.read`` returns whatever bytes are ready, so a read can end part-way through
a multi-byte UTF-8 sequence. Decoding each chunk independently with
errors="replace" destroys that character. This surfaced as corrupted box-drawing
glyphs in the embedded terminal's menu table once the catalog was large enough
for a border line to straddle a read boundary.
"""

from __future__ import annotations

from replicant.web.pty_bridge import utf8_stream_decoder

# The Rich table border characters, all 3 bytes each in UTF-8.
BORDER = "└─────┴─────────┴──────────────┴─────────┘"


def test_split_multibyte_character_is_reassembled() -> None:
    decoder = utf8_stream_decoder()
    raw = "─".encode()
    assert len(raw) == 3

    assert decoder.decode(raw[:2]) == ""  # incomplete, held back
    assert decoder.decode(raw[2:]) == "─"  # completed on the next read


def test_border_survives_every_possible_split_point() -> None:
    raw = BORDER.encode()
    for split in range(len(raw) + 1):
        decoder = utf8_stream_decoder()
        out = decoder.decode(raw[:split]) + decoder.decode(raw[split:])
        assert out == BORDER, f"corrupted when split at byte {split}"
        assert "�" not in out


def test_naive_per_chunk_decode_is_what_corrupted_it() -> None:
    """Pins the old behavior, so the regression cannot quietly return."""
    raw = BORDER.encode()
    split = 4  # lands inside the second box-drawing character
    naive = raw[:split].decode("utf-8", "replace") + raw[split:].decode("utf-8", "replace")
    assert "�" in naive
    assert naive != BORDER


def test_decoder_handles_a_stream_of_many_small_chunks() -> None:
    raw = BORDER.encode()
    decoder = utf8_stream_decoder()
    out = "".join(decoder.decode(raw[i : i + 1]) for i in range(len(raw)))
    assert out == BORDER
    assert "�" not in out
