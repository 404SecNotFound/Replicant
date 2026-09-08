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
"""Deterministic, I/O-free validation evaluators."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from replicant.core.models import EventRecord
from replicant.scenario.engine import ScenarioPlan
from replicant.validation.contract import MeasurementAxis, ValidationContract
from replicant.validation.sources.base import Alert, Observation
from replicant.validation.verdict import ValidationCheck, ValidationResult, Verdict

PLAN_PROVES = "Tier 0 proves that the deterministic generated plan satisfies its contract."
PLAN_LIMIT = "Tier 0 does not prove that any event reached a collector or that any detection fired."
INGEST_PROVES = "Tier 1 proves delivery and parseability on this observed receiver path."
INGEST_LIMIT = "Tier 1 does not prove that any SIEM rule fired."

_EXTRA_FIELDS = {
    "FTNTFGTattack": "attack",
    "FTNTFGTattackid": "attackid",
    "FTNTFGTduration": "duration",
    "FTNTFGTqname": "qname",
    "FTNTFGTqtype": "qtype",
    "FTNTFGTrcode": "rcode",
    "FTNTFGTreason": "reason",
    "FTNTFGTseverity": "ips_severity",
    "FTNTFGTsrccountry": "srccountry",
    "FTNTFGTxid": "xid",
    "cnt": "cnt",
}


def _value(event: EventRecord, field: str) -> Any:
    direct = {
        "src": event.src,
        "spt": event.spt,
        "dst": event.dst,
        "dpt": event.dpt,
        "proto": event.proto,
        "duser": event.duser,
        "rt": event.eventtime,
        "eventtime": event.eventtime,
        "externalId": event.session_id,
        "out": event.out_bytes,
        "in": event.in_bytes,
        "act": event.action,
    }
    if field in direct:
        return direct[field]
    key = _EXTRA_FIELDS.get(field, field.removeprefix("FTNTFGT").lower())
    return event.extra.get(key)


def _groups(events: Sequence[EventRecord], fields: Sequence[str]) -> list[list[EventRecord]]:
    if not fields:
        return [list(events)]
    grouped: dict[tuple[Any, ...], list[EventRecord]] = defaultdict(list)
    for event in events:
        grouped[tuple(_value(event, field) for field in fields)].append(event)
    return list(grouped.values())


def _check(
    check_id: str,
    passed: bool,
    expected: str,
    observed: str,
    detail: str,
) -> ValidationCheck:
    return ValidationCheck(
        id=check_id,
        status="pass" if passed else "fail",
        expected=expected,
        observed=observed,
        detail=detail,
    )


def _axis_check(
    axis: MeasurementAxis,
    positive: list[EventRecord],
    negative: list[EventRecord],
    params: dict[str, Any],
) -> ValidationCheck:
    groups = _groups(positive, axis.group_by)
    threshold = float(params[axis.parameter]) * axis.scale if axis.parameter else None
    if axis.metric == "event_count":
        observed = max((len(group) for group in groups), default=0)
        passed = observed > 0 and (threshold is None or observed >= threshold)
        return _check(
            f"axis:{axis.id}",
            passed,
            f">= {threshold:g}" if threshold is not None else "> 0",
            str(observed),
            axis.description,
        )
    if axis.metric == "distinct":
        assert axis.field is not None
        observed_distinct = max(
            (len({_value(event, axis.field) for event in group}) for group in groups),
            default=0,
        )
        passed = observed_distinct > 0 and (threshold is None or observed_distinct >= threshold)
        return _check(
            f"axis:{axis.id}",
            passed,
            f">= {threshold:g} distinct" if threshold is not None else "> 0 distinct",
            f"{observed_distinct} distinct",
            axis.description,
        )
    if axis.metric == "sum":
        assert axis.field is not None
        observed_sum = max(
            (sum(float(_value(event, axis.field) or 0) for event in group) for group in groups),
            default=0.0,
        )
        minimum = (threshold or 0.0) * axis.minimum_ratio
        passed = observed_sum > 0 and (threshold is None or observed_sum >= minimum)
        return _check(
            f"axis:{axis.id}",
            passed,
            f">= {minimum:g}",
            f"{observed_sum:g}",
            axis.description,
        )
    if axis.metric == "field_presence":
        assert axis.field is not None
        present = sum(_value(event, axis.field) is not None for event in positive)
        return _check(
            f"axis:{axis.id}",
            present > 0,
            f"{axis.field} present",
            f"present on {present}/{len(positive)} events",
            axis.description,
        )
    if axis.metric == "temporal_span":
        times = [event.eventtime for event in positive]
        span = max(times) - min(times) if times else 0
        return _check(
            f"axis:{axis.id}",
            span > 0,
            "event span > 0 seconds",
            f"{span} seconds",
            axis.description,
        )
    if axis.metric == "ordered_families":
        first: dict[str, int] = {}
        for event in sorted(positive, key=lambda item: item.eventtime):
            family = f"{event.log_type}:{event.subtype}"
            first.setdefault(family, event.eventtime)
        observed_order = sorted(first, key=first.__getitem__)
        wanted = axis.ordered_families
        positions = [observed_order.index(family) for family in wanted if family in observed_order]
        passed = len(positions) == len(wanted) and positions == sorted(positions)
        return _check(
            f"axis:{axis.id}",
            passed,
            " -> ".join(wanted),
            " -> ".join(observed_order),
            axis.description,
        )
    assert axis.metric == "cadence_cv"
    cvs: list[float] = []
    for group in groups:
        times = sorted(event.eventtime for event in group)
        gaps = [right - left for left, right in zip(times, times[1:], strict=False)]
        if len(gaps) >= 2 and statistics.fmean(gaps) > 0:
            cvs.append(statistics.pstdev(gaps) / statistics.fmean(gaps))
    observed_cv = min(cvs) if cvs else math.inf
    jitter = float(params.get(axis.parameter or "", 25.0)) / 100.0
    maximum = max(0.05, (jitter / math.sqrt(3.0)) * 2.0 + 0.03)
    passed = observed_cv <= maximum
    negative_note = ""
    if axis.compare_negative and negative:
        negative_cvs: list[float] = []
        for group in _groups(negative, axis.group_by):
            times = sorted(event.eventtime for event in group)
            gaps = [right - left for left, right in zip(times, times[1:], strict=False)]
            if len(gaps) >= 2 and statistics.fmean(gaps) > 0:
                negative_cvs.append(statistics.pstdev(gaps) / statistics.fmean(gaps))
        negative_cv = min(negative_cvs) if negative_cvs else 0.0
        passed = passed and negative_cv > observed_cv
        negative_note = f"; negative CV={negative_cv:.3f}"
    return _check(
        f"axis:{axis.id}",
        passed,
        f"positive CV <= {maximum:.3f}",
        f"positive CV={observed_cv:.3f}{negative_note}",
        axis.description,
    )


def evaluate_plan(
    contract: ValidationContract,
    plan: ScenarioPlan,
    *,
    seed: int,
    run_id: str | None = None,
) -> ValidationResult:
    """Evaluate one generated plan without reading files, sockets, or clocks."""

    positive = [event for event in plan.events if event.control == "positive"]
    negative = [event for event in plan.events if event.control == "negative"]
    checks: list[ValidationCheck] = [
        _check(
            "positive-events",
            bool(positive),
            "at least one positive-control event",
            f"{len(positive)} events",
            "A plan with no positive stream cannot exercise the declared behavior.",
        ),
        _check(
            "not-truncated",
            not plan.truncated,
            "complete preset plan",
            "truncated" if plan.truncated else "complete",
            "Silent preset truncation would change the contract under evaluation.",
        ),
    ]
    observed_families = sorted({f"{event.log_type}:{event.subtype}" for event in positive})
    expected_families = sorted(contract.expected_event_families)
    checks.append(
        _check(
            "event-families",
            observed_families == expected_families,
            ", ".join(expected_families),
            ", ".join(observed_families),
            "Every declared logical event family must appear in the positive plan.",
        )
    )
    signal_fields = contract.signal_fields.held + contract.signal_fields.varied
    missing_fields = [
        field
        for field in signal_fields
        if not any(_value(event, field) is not None for event in positive)
    ]
    checks.append(
        _check(
            "signal-fields",
            not missing_fields,
            "all contract signal fields present",
            "none missing" if not missing_fields else f"missing {', '.join(missing_fields)}",
            "A signal field must be observable in at least one positive event.",
        )
    )
    negative_status = "not_run"
    if contract.negative_control.mode == "standalone":
        checks.append(
            _check(
                "negative-control",
                bool(negative),
                "standalone negative-control events",
                f"{len(negative)} events",
                contract.negative_control.reason,
            )
        )
        negative_status = "pass" if negative else "fail_no_events"
    else:
        checks.append(
            ValidationCheck(
                id="negative-control",
                status="not_run",
                expected=contract.negative_control.mode,
                observed="no standalone stream",
                detail=contract.negative_control.reason,
            )
        )
    checks.extend(
        _axis_check(axis, positive, negative, plan.effective_params)
        for axis in contract.measurable_axes
    )
    failed = any(check.status == "fail" for check in checks)
    verdict = Verdict.FAIL_NO_EVENTS if failed else Verdict.PASS
    return ValidationResult(
        technique_id=contract.technique_id,
        tier="plan",
        verdict=verdict,
        intensity=plan.intensity,
        seed=seed,
        run_id=run_id,
        expected_events=len(plan.events),
        observed_events=len(plan.events),
        dimensions={
            "plan": "fail_no_events" if failed else "pass",
            "delivery": "not_run",
            "detection": "not_run",
            "negative_control": negative_status,
        },
        checks=checks,
        proves=PLAN_PROVES,
        does_not_prove=PLAN_LIMIT,
        limitations=contract.limitations,
    )


def evaluate_ingest(
    plan_result: ValidationResult,
    observation: Observation,
    required_fields: Iterable[str],
) -> ValidationResult:
    """Compare an observation with a previously evaluated plan."""

    expected = plan_result.expected_events
    observed = len(observation.records)
    required = sorted(set(required_fields))
    absent = [
        field
        for field in required
        if not any(field in record and record[field] != "" for record in observation.records)
    ]
    checks = list(plan_result.checks)
    checks.extend(
        [
            _check(
                "ingest-count",
                observed == expected,
                f"{expected} records",
                f"{observed} records",
                "Expected and observed run-tagged record counts must match exactly.",
            ),
            _check(
                "ingest-fields",
                not absent,
                "all selected-profile signal fields parse",
                "none missing" if not absent else f"missing {', '.join(absent)}",
                "Required native signal fields must be present in the observed records.",
            ),
        ]
    )
    failed = plan_result.verdict != Verdict.PASS or observed != expected or bool(absent)
    verdict = Verdict.FAIL_NO_EVENTS if failed else Verdict.PASS
    dimensions = dict(plan_result.dimensions)
    dimensions["delivery"] = "fail_no_events" if failed else "pass"
    return plan_result.model_copy(
        update={
            "tier": "ingest",
            "verdict": verdict,
            "observed_events": observed,
            "dimensions": dimensions,
            "checks": checks,
            "proves": INGEST_PROVES,
            "does_not_prove": INGEST_LIMIT,
        }
    )


def evaluate_detection(
    ingest_result: ValidationResult, alerts: Sequence[Alert]
) -> ValidationResult:
    """Generic Tier 2 truth table, independent of any unimplemented SIEM adapter."""

    if ingest_result.verdict != Verdict.PASS:
        return ingest_result.model_copy(update={"tier": "detect"})
    verdict = Verdict.PASS if alerts else Verdict.FAIL_NO_ALERT
    dimensions = dict(ingest_result.dimensions)
    dimensions["detection"] = "pass" if alerts else "fail_no_alert"
    return ingest_result.model_copy(
        update={
            "tier": "detect",
            "verdict": verdict,
            "dimensions": dimensions,
            "checks": [
                *ingest_result.checks,
                _check(
                    "detection-alert",
                    bool(alerts),
                    "at least one observed alert",
                    f"{len(alerts)} alerts",
                    "No alert is a detection failure only after ingestion passed.",
                ),
            ],
            "proves": "Tier 2 proves an observed configured detection produced an alert.",
            "does_not_prove": (
                "Tier 2 does not prove exploit success, compromise, or performance outside the "
                "observed configuration."
            ),
        }
    )
