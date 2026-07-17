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

from replicant.core.models import CefHeader, EventRecord


def require(value: object, field: str) -> str:
    """Return ``str(value)`` or raise if the required field is ``None``."""

    if value is None:
        raise ValueError(f"event is missing required field '{field}'")
    return str(value)


class VendorProfile(ABC):
    """Interface every firewall vendor profile implements."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short profile name, e.g. ``fortigate``."""

    @abstractmethod
    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        """Build the CEF header and ordered extension for one event."""

    @abstractmethod
    def severity(self, level: str) -> int:
        """Map a vendor log level (e.g. ``notice``) to a CEF severity integer."""
