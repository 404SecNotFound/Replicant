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
"""Vendor profile abstraction.

A ``VendorProfile`` turns a vendor-neutral :class:`EventRecord` into a CEF header
plus an ordered extension. Adding a firewall vendor is implementing this interface
plus a reference file (blueprint s10). The Scenario Engine and CEF serializer stay
vendor-neutral; all field names, signature IDs, and severity mapping live behind
this boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from replicant.core.models import CefHeader, EventRecord


@dataclass(frozen=True)
class DetectionMetadata:
    """Stable vendor-native identifiers, with the concepts they represent named."""

    log_type: str
    subtype: str
    signature_id: str
    action: str | None
    semantics: str


@dataclass(frozen=True)
class DetectionFieldCoverage:
    """Rendered native keys plus logical signal fields this profile cannot carry."""

    available: tuple[str, ...]
    unavailable: tuple[str, ...]


def require(value: object, field: str) -> str:
    """Return ``str(value)`` or raise if the required field is ``None``."""

    if value is None:
        raise ValueError(f"event is missing required field '{field}'")
    return str(value)


def mapped_detection_field(
    mapping: Mapping[str, str | None],
    field: str,
) -> str | None:
    """Look up one explicitly supported catalog field.

    ``None`` is a deliberate profile gap. A missing key is different: it means
    the catalog vocabulary grew without anyone proving what the selected
    renderer emits, so fail closed instead of advertising the source key.
    """

    try:
        return mapping[field]
    except KeyError as exc:
        raise ValueError(f"unknown catalog detection field: {field!r}") from exc


class VendorProfile(ABC):
    """Interface every firewall vendor profile implements."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short profile name, e.g. ``fortigate``."""

    @property
    @abstractmethod
    def hostname(self) -> str:
        """Syslog frame hostname for this vendor's lab device.

        The transport prepends this to every record. It is vendor-specific, so it
        comes from the profile rather than a global setting, which would otherwise
        stamp one vendor's device name onto another vendor's logs.
        """

    @property
    @abstractmethod
    def accepted_as(self) -> str:
        """The SIEM log-source type a run's CEF should be parsed as.

        Recorded in the manifest so an operator knows which parser the events are
        built for. It is inherently vendor-specific; a shared default would tell a
        Palo Alto or Check Point run to parse as FortiGate.
        """

    @abstractmethod
    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        """Build the CEF header and ordered extension for one event."""

    def detection_metadata(
        self,
        log_type: str,
        subtype: str,
        signature_id: str,
        action: str | None,
    ) -> DetectionMetadata:
        """Map a catalog event family to the profile's native detection fields.

        Catalog dispatch uses vendor-neutral ``log_type`` and ``subtype`` values,
        while a SIEM rule sees the CEF header and native ``act`` value. Keeping
        this mapping beside ``render`` prevents the UI from describing every
        profile with FortiGate identifiers.
        """

        raise NotImplementedError(f"profile {self.name!r} has no detection metadata mapping")

    def detection_field_name(
        self,
        field: str,
        *,
        log_type: str,
        subtype: str,
    ) -> str | None:
        """Return an explicitly mapped emitted key, or ``None`` if absent."""

        raise ValueError(f"unknown catalog detection field for profile {self.name!r}: {field!r}")

    def detection_fields(
        self,
        fields: Iterable[str],
        *,
        log_type: str,
        subtype: str,
    ) -> DetectionFieldCoverage:
        """Translate logical/FortiGate catalog signals without hiding profile gaps."""

        available: list[str] = []
        unavailable: list[str] = []
        for field in fields:
            native = self.detection_field_name(
                field,
                log_type=log_type,
                subtype=subtype,
            )
            if native is None:
                unavailable.append(field)
            elif native not in available:
                available.append(native)
        return DetectionFieldCoverage(tuple(available), tuple(unavailable))

    @abstractmethod
    def severity(self, level: str) -> int | str:
        """Map a vendor log level to a CEF severity.

        FortiGate and PAN-OS return a 0-10 integer; Check Point Log Exporter uses a
        severity string (``Unknown``/``Low``/``Medium``/``High``/``Very-High``). CEF
        allows both, so the return type is ``int | str``.
        """
