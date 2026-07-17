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
"""File sink.

Mirrors emitted CEF payloads to a ``.log`` file for offline review and CI
(blueprint s6). Following the reference guidance (s1.4), the file holds the bare
CEF payload starting at ``CEF:0|`` with no syslog prefix, so the same seed
produces a byte-identical file.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import TextIO


class FileSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh: TextIO | None = None
        self.count = 0

    def open(self) -> None:
        if self._fh is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8", newline="\n")

    def write(self, payload: str) -> None:
        if self._fh is None:
            self.open()
        assert self._fh is not None
        self._fh.write(payload + "\n")
        self.count += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> FileSink:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
