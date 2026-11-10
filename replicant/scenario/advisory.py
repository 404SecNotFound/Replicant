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
    # A credential-keyed stage whose VPN assignment IS the victim joins to every
    # host-keyed stage the victim dominates. Measured, not assumed: the stage
    # has to carry the assignment and it has to equal the pinned victim.
    pivot_stages = [s.index for s in user_stages if s.top_tunnelip == composed.victim]
    # A credential join: a stage with a successful VPN login for a user that a
    # strictly earlier stage failed logins for. Measured from the composed
    # positive events, not assumed from the scenario text. Maps the login stage
    # to (spray stage index, joined users).
    credential_joins: dict[int, tuple[int, list[str]]] = {}
    for stage in composed.stages:
        for earlier in composed.stages:
            if earlier.index >= stage.index:
                continue
            joined = sorted(set(stage.success_users) & set(earlier.failed_users))
            if joined and stage.index not in credential_joins:
                credential_joins[stage.index] = (earlier.index, joined)
    credential_stages = sorted(credential_joins)
    has_vpn_failures = any(s.failed_users for s in composed.stages)
    has_vpn_logins = any(s.success_users for s in composed.stages)
    # A staging stage is one the victim dominates as DESTINATION. When a later
    # stage has the victim as dominant source, the host that collected the data
    # has become the host that sends it, which is the phase transition a
    # staging-then-egress chain is built to exercise (SCEN-004). Measured, not
    # assumed: the destination has to equal the pinned victim and a later stage
    # has to carry the victim as its source.
    staging_stages = [
        s.index
        for s in composed.stages
        if s.top_dst == composed.victim and any(v > s.index for v in victim_stages)
    ]
    staging_events = sum(s.top_dst_count for s in composed.stages if s.index in staging_stages)
    # A lateral path is read from a stage's traffic legs (composer._lateral_path).
    # Two joins around it, both measured. The entry join: an earlier stage's VPN
    # logins were assigned the address the path starts at. The handoff join: a
    # later stage's dominant source is the host the path ended on. Each maps the
    # joined stage to the stage it joins to.
    path_stages = [s for s in composed.stages if s.path]
    lateral_entries: dict[int, int] = {}
    for stage in path_stages:
        for earlier in composed.stages:
            if earlier.index < stage.index and earlier.top_tunnelip == stage.path[0]:
                lateral_entries.setdefault(stage.index, earlier.index)
    lateral_handoffs: dict[int, int] = {}
    for stage in composed.stages:
        for earlier in path_stages:
            if earlier.index < stage.index and stage.top_src == earlier.path[-1]:
                lateral_handoffs.setdefault(stage.index, earlier.index)
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
        "vpn_pivot_stage_indices": pivot_stages,
        "staging_pivot_stage_indices": staging_stages,
        "credential_pivot_stage_indices": credential_stages,
        "lateral_path_stage_indices": [s.index for s in path_stages],
        "lateral_entry_stage_indices": sorted(lateral_entries),
        "lateral_handoff_stage_indices": sorted(lateral_handoffs),
        "truncated_stage_indices": [s.index for s in composed.stages if s.truncated],
    }

    lines: list[str] = []
    lines.append(f"# Advisory: {scenario.name} ({scenario.id})")
    lines.append("")
    lines.append(_BOUNDARY)
    lines.append("")
    if composed.negative_count:
        lines.append(
            f"Benign foils: {composed.negative_count} negative-control events were composed "
            f"onto this timeline (`--controls {composed.controls}`). Every count below "
            "describes the attack stream only; the foils are on the wire and in "
            "`planned_event_count`, and a rule that fires on them is a false positive."
        )
        lines.append("")

    lines.append("## Through-line (correlate on these)")
    if victim_stages:
        lines.append(
            f"- victim host `{composed.victim}`: dominant src in "
            f"{'stages' if len(victim_stages) > 1 else 'stage'} "
            f"{_stage_list(victim_stages)} ({victim_events} events)"
        )
    elif any(s.path[0] == composed.victim for s in path_stages):
        started = [s.index for s in path_stages if s.path[0] == composed.victim]
        lines.append(
            f"- victim host `{composed.victim}`: first host of the lateral path in "
            f"{'stages' if len(started) > 1 else 'stage'} {_stage_list(started)}"
        )
    else:
        lines.append(
            f"- victim host `{composed.victim}`: pinned, but not the dominant src in any stage"
        )
    if staging_stages:
        lines.append(
            f"- victim host `{composed.victim}`: dominant dst in "
            f"{'stages' if len(staging_stages) > 1 else 'stage'} "
            f"{_stage_list(staging_stages)} ({staging_events} events) before it becomes a source"
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
        # A stage that acts from a lateral path's last host is keyed on that
        # source; the generic rule would name its busiest destination instead.
        key = (
            f"src={stage.top_src}"
            if stage.index in lateral_handoffs
            else _stage_key(stage, composed.victim, composed.adversary)
        )
        lines.append(
            f"| {stage.index} | {label} | {stage.technique_id} | {tactics} | "
            f"{stage.ndr_uc} | {stage.start_offset} | {window} | {key} | {count} |"
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
        if pivot_stages and victim_stages:
            pivot = next(s for s in user_stages if s.index == pivot_stages[0])
            claims.append(
                f"- the credential-keyed stages ({names}) correlate on `duser`, not on `src`; "
                f"the VPN assignment is the pivot: stage {pivot.index} assigned "
                f"`tunnelip={composed.victim}` to `duser={pivot.top_user}`, and "
                f"`src={composed.victim}` is the host-keyed source in "
                f"{_stage_list(victim_stages)}."
            )
        elif pivot_stages and lateral_entries:
            claims.append(
                f"- the credential-keyed stages ({names}) correlate on `duser`, not on `src`; "
                "the VPN assignment is the pivot into the lateral path described below."
            )
        else:
            claims.append(
                f"- the credential-keyed stages ({names}) correlate on `duser`, not on `src`; "
                "joining them to the host-keyed stages needs the VPN assignment as the pivot, "
                "and no stage here carries one that matches the victim."
            )
    for login_index in credential_stages:
        spray_index, joined = credential_joins[login_index]
        login = next(s for s in composed.stages if s.index == login_index)
        user = login.top_user if login.top_user in joined else joined[0]
        claims.append(
            f"- stage {login_index} logged in successfully as `duser={user}`, a user that was "
            f"the target of failed VPN logins in stage {spray_index}; the shared `duser` is the "
            "credential join between those stages. This is a measured overlap of usernames "
            "in the emitted events, not evidence of how the credential was obtained."
        )
    if not credential_stages and has_vpn_failures and has_vpn_logins:
        claims.append(
            "- this chain has VPN authentication failures and a successful VPN login, but no "
            "credential join was measured: no user with a successful login was the target of "
            "a failed login in an earlier stage."
        )
    if staging_stages:
        later = [v for v in victim_stages if v > staging_stages[0]]
        claims.append(
            f"- `dst={composed.victim}` is the dominant destination in "
            f"{'stages' if len(staging_stages) > 1 else 'stage'} {_stage_list(staging_stages)} "
            f"and `src={composed.victim}` the dominant source in "
            f"{'stages' if len(later) > 1 else 'stage'} {_stage_list(later)}: the host that "
            "collected the data becomes the host that sends it. The phase transition on one "
            "address is the join, not either stage's volume on its own."
        )
    for stage in path_stages:
        claims.append(
            f"- stage {stage.index} ({stage.technique_id}) is a lateral path of "
            f"{len(stage.path)} hosts, `{stage.path[0]}` to `{stage.path[-1]}`: each leg's "
            "source is the previous leg's destination. The path is read from the emitted "
            "traffic legs."
        )
        if stage.index in lateral_entries:
            entry = next(s for s in composed.stages if s.index == lateral_entries[stage.index])
            shared = sorted(set(stage.success_users) & set(entry.success_users))
            users = (
                f"`duser={shared[0]}` logged in by VPN in both stages, an overlap of "
                "usernames that does not say which login in the earlier stage it was"
                if shared
                else "no VPN user of this stage logged in in that one, so no username joins them"
            )
            claims.append(
                f"- stage {entry.index} assigned `tunnelip={stage.path[0]}` in "
                f"{entry.top_tunnelip_count} VPN logins and stage {stage.index}'s path starts "
                f"at `{stage.path[0]}`: the VPN assignment is the join into the path. It is a "
                f"join on the address, shared by those logins, and it does not single one of "
                f"them out; {users}."
            )
        later_stages = [s for s in composed.stages if s.index > stage.index]
        handed_to = [i for i, source in lateral_handoffs.items() if source == stage.index]
        if handed_to:
            claims.append(
                f"- `src={stage.path[-1]}` is the dominant source in "
                f"{'stages' if len(handed_to) > 1 else 'stage'} "
                f"{_stage_list(sorted(handed_to))} and "
                f"the last host of stage {stage.index}'s path: the host the lateral movement "
                "arrived on is the host that acts next."
            )
        elif later_stages:
            claims.append(
                f"- no later stage's dominant source is `{stage.path[-1]}`, the last host of "
                f"stage {stage.index}'s path, so nothing here joins the path to what follows."
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
