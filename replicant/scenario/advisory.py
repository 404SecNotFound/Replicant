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

Presents facts and correlation prompts drawn from the composed events. It never writes the
detection/AIE rule design (blueprint constraint); the human authors that.

Every claim in the output is derived from what the stages actually emitted. Nothing about
the through-line is assumed: a chain that mixes host-keyed and credential-keyed techniques
gets the real per-stage correlation key, and a claim is omitted when the data does not
support it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from replicant.core.models import Catalog, Scenario
from replicant.scenario.composer import ComposedPlan, StageResult

_DUBAI = timezone(timedelta(hours=4))  # the catalog timezone

_BOUNDARY = (
    "> Advisory context only: coverage and correlation prompts. "
    "You author the detection/AIE rule design; no rule logic is generated here."
)

_C2_TACTIC = "TA0011"
_EXFIL_TACTIC = "TA0010"


def _fmt(epoch: int | None) -> str:
    """Format an epoch in the catalog timezone. Deterministic; no local-time dependency."""

    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, _DUBAI).strftime("%Y-%m-%d %H:%M")


def _tactic_to_technique(catalog: Catalog) -> dict[str, str]:
    index: dict[str, str] = {}
    for technique in catalog.techniques:
        for tactic in technique.attack.tactics:
            index.setdefault(tactic, technique.id)
    return index


def _stage_key(stage: StageResult, victim: str, adversary: str) -> str:
    """The field a detection would actually correlate this stage on, from its own events."""

    if stage.top_user:
        return f"duser={stage.top_user}"
    if stage.top_src == victim:
        return f"src={victim}"
    if stage.top_src == adversary:
        return f"src={adversary}"
    if stage.top_dst == adversary:
        return f"dst={adversary}"
    if stage.top_dst:
        return f"dst={stage.top_dst}"
    if stage.top_src:
        return f"src={stage.top_src}"
    return "-"


def _stage_list(indices: list[int]) -> str:
    return ", ".join(str(index) for index in indices)


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

    first = composed.events[0].eventtime if composed.events else None
    last = composed.events[-1].eventtime if composed.events else None
    span = (last - first) if (first is not None and last is not None) else 0

    # Which keys actually thread the chain, measured rather than assumed.
    victim_stages = [s.index for s in composed.stages if s.top_src == composed.victim]
    victim_events = sum(s.top_src_count for s in composed.stages if s.top_src == composed.victim)
    adversary_stages = [
        s.index for s in composed.stages if composed.adversary in (s.top_src, s.top_dst)
    ]
    adversary_events = sum(
        (s.top_src_count if s.top_src == composed.adversary else 0)
        + (s.top_dst_count if s.top_dst == composed.adversary else 0)
        for s in composed.stages
    )
    user_stages = [s for s in composed.stages if s.top_user]
    has_c2 = any(t.startswith(_C2_TACTIC) for t in covered)
    has_exfil = any(t.startswith(_EXFIL_TACTIC) for t in covered)

    coverage: dict[str, Any] = {
        "covered_tactics": covered,
        "gap_tactics": gaps,
        "span_seconds": span,
        "first_event_epoch": first,
        "last_event_epoch": last,
        "victim_stage_indices": victim_stages,
        "adversary_stage_indices": adversary_stages,
        "truncated_stage_indices": [s.index for s in composed.stages if s.truncated],
    }

    lines: list[str] = []
    lines.append(f"# Advisory: {scenario.name} ({scenario.id})")
    lines.append("")
    lines.append(_BOUNDARY)
    lines.append("")

    lines.append("## Through-line (correlate on these)")
    if victim_stages:
        lines.append(
            f"- victim host `{composed.victim}`: dominant src in "
            f"{'stages' if len(victim_stages) > 1 else 'stage'} "
            f"{_stage_list(victim_stages)} ({victim_events} events)"
        )
    else:
        lines.append(
            f"- victim host `{composed.victim}`: pinned, but not the dominant src in any stage"
        )
    if adversary_stages:
        lines.append(
            f"- adversary IP `{composed.adversary}`: external peer in "
            f"{'stages' if len(adversary_stages) > 1 else 'stage'} "
            f"{_stage_list(adversary_stages)} ({adversary_events} events)"
        )
    else:
        lines.append(
            f"- adversary IP `{composed.adversary}`: pinned, but not dominant in any stage"
        )
    for stage in user_stages:
        lines.append(
            f"- stage {stage.index} ({stage.technique_id}) is credential-keyed: "
            f"`duser={stage.top_user}` ({stage.top_user_count} events)"
        )
    lines.append(
        f"- chain span: {span} seconds across {len(composed.stages)} stages "
        f"({_fmt(first)} -> {_fmt(last)}, UTC+04:00)"
    )
    lines.append("")

    lines.append("## Kill chain")
    lines.append(
        "| # | stage | technique | tactic(s) | ndr_uc | offset | "
        "window (UTC+04:00) | correlate on | events |"
    )
    lines.append("|---|-------|-----------|-----------|--------|--------|------|------|--------|")
    for stage in composed.stages:
        tactics = ", ".join(stage.tactics) or "-"
        label = stage.label or ""
        window = f"{_fmt(stage.start_epoch)} -> {_fmt(stage.end_epoch)}"
        if stage.aligned_days:
            window += f" (+{stage.aligned_days}d aligned)"
        count = f"{stage.event_count}{' (truncated)' if stage.truncated else ''}"
        lines.append(
            f"| {stage.index} | {label} | {stage.technique_id} | {tactics} | "
            f"{stage.ndr_uc} | {stage.start_offset} | {window} | "
            f"{_stage_key(stage, composed.victim, composed.adversary)} | {count} |"
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
    claims: list[str] = []
    if len(victim_stages) > 1:
        claims.append(
            f"- `src={composed.victim}` is the dominant source across stages "
            f"{_stage_list(victim_stages)}; a rule keyed on it over the {span}s window "
            "links those stages."
        )
    elif len(victim_stages) == 1:
        claims.append(
            f"- `src={composed.victim}` is dominant only in stage {victim_stages[0]}, "
            "so it does not by itself thread this chain."
        )
    if len(adversary_stages) > 1:
        claims.append(
            f"- `{composed.adversary}` is the external peer across stages "
            f"{_stage_list(adversary_stages)} (same synthetic adversary infrastructure)."
        )
    if user_stages:
        names = ", ".join(f"stage {s.index}" for s in user_stages)
        claims.append(
            f"- the credential-keyed stages ({names}) correlate on `duser`, not on `src`; "
            "joining them to the host-keyed stages needs the VPN assignment as the pivot."
        )
    if has_c2 and has_exfil and len(adversary_stages) > 1:
        claims.append(
            f"- this chain covers both {_C2_TACTIC} and {_EXFIL_TACTIC} and they share "
            f"`dst={composed.adversary}`."
        )
    if not claims:
        claims.append("- no field recurs across more than one stage in this chain.")
    lines.extend(claims)

    truncated = [s for s in composed.stages if s.truncated]
    if truncated:
        lines.append("")
        lines.append("## Truncation")
        for stage in truncated:
            lines.append(
                f"- stage {stage.index} ({stage.technique_id}) hit the engine event cap; "
                f"its {stage.event_count} events are a truncated stream."
            )

    return "\n".join(lines) + "\n", coverage
