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
"""Per-run analyst validation card for a single-technique run (roadmap 2026-09 item 7).

After an ad-hoc ``replicant run``, an analyst otherwise reverse-engineers the pivot
entities, the window, and the expected rule from a raw JSON manifest, which is the
manual toil the tool sells against. This writes a copy-pasteable card from the
plan's own events: what to search for, what to correlate on, the emitted window,
and what a green result does and does not prove.

Deterministic and derived from the emitted events. Like the scenario advisory it
authors no detection/AIE rule logic (blueprint constraint): the search below is a
hunt pivot that LOCATES the run's own events, not a detection rule. The human
authors the rule.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from replicant.audit.manifest import DUBAI_TZ
from replicant.core.models import EventRecord, RunManifest, Technique

_BOUNDARY = (
    "> Starting point for your own detection work: a hunt pivot that finds this "
    "run's events and the facts to correlate on. You author the rule; no rule "
    "logic is generated here."
)

# The marker fields, duplicated here rather than imported from orchestrator to
# keep this module free of that import cycle. Asserted equal in the tests.
_MARKER_LABEL_KEY = "flexString1Label"
_MARKER_KEY = "flexString1"
_MARKER_LABEL = "ReplicantSynthetic"


def _fmt(epoch: int | None) -> str:
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, DUBAI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def _span(seconds: int) -> str:
    if seconds <= 0:
        return "0s"
    parts = []
    for unit, size in (("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            parts.append(f"{seconds // size}{unit}")
            seconds %= size
    return " ".join(parts)


def _top(values: list[str], limit: int = 3) -> list[str]:
    """The most common non-empty values, most frequent first."""
    counts = Counter(v for v in values if v)
    return [v for v, _ in counts.most_common(limit)]


def _unmarked_query(srcs: list[str], dsts: list[str], first: int | None, last: int | None) -> str:
    """Entity + window pivot for an unmarked run, joined so it never leads with 'and'
    even when a technique's events carry no src or dst."""
    clauses = []
    if srcs:
        clauses.append(f"src IN ({', '.join(srcs)})")
    if dsts:
        clauses.append(f"dst IN ({', '.join(dsts)})")
    clauses.append(f"eventtime {_fmt(first)} .. {_fmt(last)}")
    return " and ".join(clauses)


def build_validation_card(
    technique: Technique, events: list[EventRecord], manifest: RunManifest, *, marked: bool
) -> str:
    """The card text. ``marked`` is whether the run stamped the synthetic marker,
    which decides whether the primary search can key on the run id."""

    srcs = _top([e.src or "" for e in events])
    dsts = _top([e.dst or "" for e in events])
    users = _top([e.duser or "" for e in events])
    times = [e.eventtime for e in events]
    first = min(times) if times else None
    last = max(times) if times else None
    span = (last - first) if (first is not None and last is not None) else 0

    lines: list[str] = [
        f"# Validation card: {technique.id} {technique.name}",
        "",
        f"Run `{manifest.run_id}` | seed {manifest.seed} | intensity {manifest.intensity} "
        f"| vendor {manifest.vendor or 'fortigate'}",
        "",
        "## What this run is meant to establish",
        "",
        technique.objective or "(no objective recorded)",
        "",
        f"Detection: **{technique.ndr_rule}** (use case {technique.ndr_uc})",
        "",
        "## Find this run's events",
        "",
    ]

    if marked:
        lines += [
            "Every line this run put on the wire carries the synthetic marker with "
            "the run id, so the exact events are one search away:",
            "",
            "```",
            f"{_MARKER_LABEL_KEY}={_MARKER_LABEL} {_MARKER_KEY}={manifest.run_id}",
            "```",
        ]
    else:
        lines += [
            "This run was not marked (loopback, `--to-file`, or `--no-send`), so pivot "
            "on the entities and window below rather than the run id:",
            "",
            "```",
            _unmarked_query(srcs, dsts, first, last),
            "```",
        ]

    lines += [
        "",
        "## Pivot",
        "",
        f"- Source(s): {', '.join(srcs) or '-'}",
        f"- Destination(s): {', '.join(dsts) or '-'}",
        f"- User(s): {', '.join(users) or '-'}",
        f"- Correlate on (held constant): {', '.join(technique.cef_fields_held) or '-'}",
        f"- What varies: {', '.join(technique.cef_fields_varied) or '-'}",
        f"- Emitted window: {_fmt(first)} to {_fmt(last)} ({_span(span)}), {len(events)} events",
        "",
        "  The window above is the event times as emitted (compressed by `--speed` if given). "
        "Under `--pace plan` the events leave the sender across that span; under `--pace burst` "
        "they are sent back to back and only the event times span it.",
        "",
        "## What a green result does and does not prove",
        "",
        f"- Transferability: **{technique.transferability}**",
    ]
    if technique.transferability_note:
        lines.append(f"  - {technique.transferability_note}")
    lines += [
        "- Delivery: every timing and delivery claim in this project is loopback-only "
        "until the first observed rule fire (see the roadmap). A green result here proves "
        "the generator and, where transferability is `transfers`, that the telemetry "
        "carries what the rule keys on; it does not prove end-to-end delivery.",
        "",
        _BOUNDARY,
        "",
    ]
    return "\n".join(lines)
