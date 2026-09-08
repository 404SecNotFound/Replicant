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
"""Generate catalog-to-native mappings without inventing a SIEM field column."""

from __future__ import annotations

from replicant.core.models import Technique
from replicant.profiles.base import VendorProfile


def build_mapping(technique: Technique, profile: VendorProfile) -> str:
    """Return a Markdown table derived only from profile mappings in this build."""

    lines = [
        "# Observed field mapping",
        "",
        (
            "This table maps the catalog's normalized signal vocabulary to the selected "
            f"`{profile.name}` renderer. No SIEM field mapping is present because this run "
            "did not read fields back through a SIEM adapter."
        ),
        "",
        f"| Normalized field | Logical family | {profile.name} native field |",
        "|---|---|---|",
    ]
    fields = dict.fromkeys((*technique.cef_fields_held, *technique.cef_fields_varied))
    for field in fields:
        for log_type, subtype in technique.logical_families():
            native = profile.detection_field_name(field, log_type=log_type, subtype=subtype)
            lines.append(
                f"| `{field}` | `{log_type}:{subtype}` | "
                f"{f'`{native}`' if native is not None else 'unavailable'} |"
            )
    return "\n".join(lines) + "\n"
