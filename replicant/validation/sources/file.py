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
"""Deterministic JSON-fixture and CEF-file telemetry sources."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from replicant.validation.sources.base import Observation

_FIELD_START = re.compile(r"(?:^| )([A-Za-z0-9_]+)=")


def _unescape(value: str) -> str:
    output: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            output.append({"n": "\n", "r": "\r"}.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            output.append(char)
    if escaped:
        output.append("\\")
    return "".join(output)


def _split_header(payload: str) -> tuple[list[str], str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in payload:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == "|" and len(fields) < 7:
            fields.append(_unescape("".join(current)))
            current = []
            continue
        current.append(char)
    if len(fields) != 7:
        raise ValueError("CEF payload does not contain seven header separators")
    return fields, "".join(current)


def parse_cef_line(line: str) -> dict[str, str]:
    """Parse one syslog-framed or bare CEF line into header and extension fields."""

    offset = line.find("CEF:")
    if offset < 0:
        raise ValueError("line contains no CEF payload")
    header, extension = _split_header(line[offset:].rstrip("\r\n"))
    record = {
        "cef_version": header[0].removeprefix("CEF:"),
        "device_vendor": header[1],
        "device_product": header[2],
        "device_version": header[3],
        "signature_id": header[4],
        "name": header[5],
        "severity": header[6],
    }
    matches = list(_FIELD_START.finditer(extension))
    for index, match in enumerate(matches):
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(extension)
        record[match.group(1)] = _unescape(extension[value_start:value_end].rstrip())
    return record


class FixtureSource:
    """A deterministic source backed by a JSON list or in-memory mappings."""

    name = "fixture"

    def __init__(self, events: str | Path | Sequence[Mapping[str, Any]]) -> None:
        if isinstance(events, (str, Path)):
            loaded = json.loads(Path(events).read_text(encoding="utf-8"))
            if not isinstance(loaded, list):
                raise ValueError("fixture must contain a JSON list")
            self._events = [dict(item) for item in loaded]
        else:
            self._events = [dict(item) for item in events]

    def fetch(self, run_id: str, window: tuple[int, int]) -> Observation:
        start, end = window
        records: list[dict[str, str]] = []
        for event in self._events:
            event_run = str(event.get("run_id", event.get("flexString1", "")))
            eventtime = int(event.get("eventtime", event.get("FTNTFGTeventtime", start)))
            if event_run == run_id and start <= eventtime <= end:
                records.append({str(key): str(value) for key, value in event.items()})
        return Observation(source=self.name, run_id=run_id, window=window, records=records)


class FileLogSource:
    """Read newline-delimited CEF records captured by a local syslog receiver."""

    name = "file-log"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def fetch(self, run_id: str, window: tuple[int, int]) -> Observation:
        records: list[dict[str, str]] = []
        raw_lines: list[str] = []
        undetermined: list[str] = []
        start, end = window
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if "CEF:" not in line:
                continue
            try:
                record = parse_cef_line(line)
            except ValueError as exc:
                undetermined.append(f"line {number}: {exc}")
                continue
            marker = record.get("flexString1", "")
            marker_label = record.get("flexString1Label", "")
            if marker_label != "ReplicantSynthetic" or marker != run_id:
                continue
            eventtime_text = record.get("FTNTFGTeventtime")
            if eventtime_text is not None:
                try:
                    eventtime = int(eventtime_text)
                except ValueError:
                    undetermined.append(f"line {number}: invalid event time {eventtime_text!r}")
                    continue
                if not start <= eventtime <= end:
                    continue
            records.append(record)
            raw_lines.append(line[line.find("CEF:") :])
        return Observation(
            source=self.name,
            run_id=run_id,
            window=window,
            records=records,
            raw_lines=raw_lines,
            undetermined=undetermined,
        )
