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
"""Deterministic advisory coverage document for a composed scenario.

Presents facts and correlation prompts from catalog metadata. It never writes the
detection/AIE rule design (blueprint constraint); the human authors that.
"""

from __future__ import annotations

from typing import Any

from replicant.core.models import Catalog, Scenario
from replicant.scenario.composer import ComposedPlan

_BOUNDARY = (
    "> Advisory context only: coverage and correlation prompts. "
    "You author the detection/AIE rule design; no rule logic is generated here."
)


def _tactic_to_technique(catalog: Catalog) -> dict[str, str]:
    index: dict[str, str] = {}
    for technique in catalog.techniques:
        for tactic in technique.attack.tactics:
            index.setdefault(tactic, technique.id)
    return index


def build_advisory(
    scenario: Scenario, composed: ComposedPlan, technique_catalog: Catalog
) -> tuple[str, dict[str, Any]]:
    covered: list[str] = []
    for stage in composed.stages:
        for tactic in stage.tactics:
            if tactic not in covered:
                covered.append(tactic)
    tactic_index = _tactic_to_technique(technique_catalog)
    gaps = [
        {"tactic": tactic, "suggested_technique": tid}
        for tactic, tid in tactic_index.items()
        if tactic not in covered
    ]
    span = (composed.events[-1].eventtime - composed.events[0].eventtime) if composed.events else 0
    coverage = {"covered_tactics": covered, "gap_tactics": gaps, "span_seconds": span}

    lines: list[str] = []
    lines.append(f"# Advisory: {scenario.name} ({scenario.id})")
    lines.append("")
    lines.append(_BOUNDARY)
    lines.append("")
    lines.append("## Through-line (correlate on these)")
    lines.append(f"- victim host (src): `{composed.victim}`")
    lines.append(f"- adversary IP (dst): `{composed.adversary}`")
    lines.append(f"- chain span: {span} seconds across {len(composed.stages)} stages")
    lines.append("")
    lines.append("## Kill chain")
    lines.append("| # | stage | technique | tactic(s) | ndr_uc | start | events |")
    lines.append("|---|-------|-----------|-----------|--------|-------|--------|")
    for stage in composed.stages:
        tactics = ", ".join(stage.tactics) or "-"
        label = stage.label or ""
        lines.append(
            f"| {stage.index} | {label} | {stage.technique_id} | {tactics} | "
            f"{stage.ndr_uc} | {stage.start_offset} | {stage.event_count} |"
        )
    lines.append("")
    lines.append("## ATT&CK coverage")
    lines.append("Covered: " + (", ".join(covered) or "none"))
    if gaps:
        lines.append("")
        lines.append("Gaps (the catalog can exercise these; this chain does not):")
        for gap in gaps:
            lines.append(f"- {gap['tactic']}: consider {gap['suggested_technique']}")
    lines.append("")
    lines.append("## Cross-stage correlation opportunities")
    lines.append(
        f"- The compromised host `src={composed.victim}` recurs across the host-based stages; "
        f"a rule keyed on it over the {span}s window links the chain."
    )
    lines.append(
        f"- C2 and exfil share `dst={composed.adversary}` "
        "(same synthetic adversary infrastructure)."
    )
    return "\n".join(lines) + "\n", coverage
