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
"""Orchestrator.

Resolves a :class:`RunRequest` into a plan, feeds records through the vendor
profile and CEF serializer to the emitter and/or file sink, writes the run
manifest, and honors the kill switch (blueprint s6). Both the menu and the CLI
call the Orchestrator; no behavior lives only in the TUI.

Safety: sending fails closed when no collector is configured, and the only socket
peer is the configured collector.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from replicant import __version__
from replicant.audit.manifest import (
    human_summary,
    new_run_id,
    now_dubai_iso,
    write_advisory,
    write_manifest,
    write_scenario_manifest,
)
from replicant.cef.serializer import to_cef
from replicant.config.settings import Settings, parse_duration
from replicant.core.models import (
    Catalog,
    CollectorProfile,
    EventRecord,
    RunManifest,
    RunRequest,
    RunStatus,
    ScenarioCatalog,
    ScenarioManifest,
    ScenarioRunRequest,
    ScenarioStageRecord,
    describe_error,
)
from replicant.core.pacing import (
    SPEED_WITHOUT_PLAN,
    Pace,
    compress_timeline,
    format_span,
    projected_seconds,
    resolve_pace,
    send_offsets,
)
from replicant.core.sendlock import sending_lock
from replicant.entities.model import EntityModel
from replicant.obs.log import RateCounter, get_logger
from replicant.profiles.base import VendorProfile
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateDevice, FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import ComposedPlan, compose
from replicant.scenario.engine import ScenarioEngine, ScenarioPlan
from replicant.transport.filesink import FileSink
from replicant.transport.syslog import SyslogEmitter

_log = get_logger("run")

ProgressCallback = Callable[[int, int], None]
EventCallback = Callable[[str, EventRecord], None]

#: CEF extension key for the synthetic-data marker (settings.benign_marker).
#: flexString1 is CEF's customer custom-string field and is used by none of the
#: three vendor profiles, so the marker cannot overwrite a real device field.
#: cs1..cs6 are all taken by at least one profile (Palo Alto uses cs6), which is
#: why this uses a flex slot rather than a custom-string one.
SYNTHETIC_MARKER_LABEL_KEY = "flexString1Label"
SYNTHETIC_MARKER_KEY = "flexString1"
SYNTHETIC_MARKER_LABEL = "ReplicantSynthetic"


def synthetic_marker(run_id: str | None) -> dict[str, str]:
    """The two CEF extension fields that flag a line as Replicant lab data.

    The blueprint's "clear labeling option" (s58): a switch that stamps a marker
    so synthetic telemetry is separable from production in a shared collector. The
    value is the run id when there is one, so a marked line is both flagged
    synthetic and traceable to the run that produced it; without a run context
    (a preview sample) it is the literal ``synthetic``.
    """

    return {
        SYNTHETIC_MARKER_LABEL_KEY: SYNTHETIC_MARKER_LABEL,
        SYNTHETIC_MARKER_KEY: run_id or "synthetic",
    }


@dataclass
class RunResult:
    manifest: RunManifest
    manifest_path: Path
    event_count: int
    plan: ScenarioPlan
    stopped: bool

    @property
    def run_id(self) -> str:
        return self.manifest.run_id

    def summary(self) -> str:
        return human_summary(self.manifest, self.manifest_path)


#: Attribute names used to carry a partial run record on a raised exception.
RUN_RECORD_ATTR = "replicant_run_record"


def attach_run_record(
    exc: BaseException, manifest: dict[str, Any], manifest_path: str, event_count: int
) -> None:
    """Attach the manifest of a failed run to the exception that ended it.

    Best effort by design: a few builtin exception types use ``__slots__`` and
    refuse new attributes. A diagnostic that raises while reporting a failure
    would replace the operator's real error with its own, which is strictly worse
    than the missing detail it was trying to add.
    """

    try:
        exc.__dict__[RUN_RECORD_ATTR] = {
            "manifest": manifest,
            "manifest_path": manifest_path,
            "event_count": event_count,
        }
    except (AttributeError, TypeError):  # pragma: no cover - slotted exception
        pass


def run_record_of(exc: BaseException) -> dict[str, Any] | None:
    """The partial record :func:`attach_run_record` left, if there is one."""

    record = getattr(exc, RUN_RECORD_ATTR, None)
    return record if isinstance(record, dict) else None


def _run_status(failure: BaseException | None, stopped: bool) -> RunStatus:
    """Which of the three ways a run can end. Failure outranks the kill switch:
    a run stopped *by* an error is an error, not a clean stop."""

    if failure is not None:
        return "error"
    return "stopped" if stopped else "done"


@dataclass
class PacingPreview:
    """What a run will cost on the wall clock, worked out before it starts.

    Plan pacing turns a three second run into a four hour one. That is the whole
    point of it and it must never be a surprise, so the CLI prints this before the
    first event and the web form shows it before the operator commits.
    """

    event_count: int
    #: The span the plan's own event times cover, before any compression.
    plan_span_s: int
    #: The span the rendered timestamps will actually claim. Equal to
    #: ``plan_span_s`` unless a speed compressed them, and the two differ for a
    #: reason worth showing: under burst the timestamps still claim the full span
    #: while delivery takes a fraction of a second, which is precisely why a burst
    #: run cannot satisfy a rule keyed on the interval between events.
    compressed_span_s: int
    #: How long delivery actually takes at this pace, speed and rate cap.
    projected_s: float
    #: The same figure for every pace, not only the selected one. A form that
    #: could price only the current choice would either show a stale number for
    #: the other option or blank it while a request is in flight, and the point of
    #: the control is to let an operator compare the two before committing.
    projected_by_pace: dict[str, float]
    pace: Pace
    speed: float

    def describe(self) -> str:
        if self.pace == "plan":
            shape = "plan timeline" + ("" if self.speed == 1.0 else f" compressed {self.speed:g}x")
        else:
            shape = "burst, plan timeline ignored"
        return (
            f"pacing: {shape}. {self.event_count} events spanning "
            f"{format_span(self.plan_span_s)} of event time; this run will take "
            f"{format_span(self.projected_s)}."
        )


@dataclass
class ScenarioRunResult:
    manifest: ScenarioManifest
    manifest_path: Path
    advisory_path: Path
    event_count: int
    plan: ComposedPlan
    stopped: bool


def build_profile(settings: Settings) -> VendorProfile:
    """Select the vendor profile from settings.vendor (blueprint s10, Phase 3).

    The single source of truth for the vendor -> profile mapping, shared by the
    Orchestrator and the web layer so the two cannot drift.
    """

    if settings.vendor == "paloalto":
        return PaloAltoProfile()
    if settings.vendor == "checkpoint":
        return CheckPointProfile()
    if settings.vendor == "fortigate":
        return FortiGateProfile(
            FortiGateDevice(
                byte_key_out=settings.byte_key_out,
                byte_key_in=settings.byte_key_in,
            )
        )
    raise ValueError(f"unknown vendor profile: {settings.vendor!r}")


def effective_identity(settings: Settings) -> tuple[str, str]:
    """(syslog hostname, accepted_as) an operator would see for these settings.

    Operator overrides on ``Settings`` win; otherwise the active vendor profile's
    own identity is used. Lets the web layer echo the same values a run records.
    """
    profile = build_profile(settings)
    return settings.hostname or profile.hostname, settings.accepted_as or profile.accepted_as


class Orchestrator:
    def __init__(
        self,
        catalog: Catalog,
        settings: Settings | None = None,
        profile: VendorProfile | None = None,
        entities: EntityModel | None = None,
        engine: ScenarioEngine | None = None,
    ) -> None:
        self.catalog = catalog
        self.settings = settings or Settings()
        self.entities = entities or EntityModel.build()
        self.engine = engine or ScenarioEngine()
        self.profile = profile or build_profile(self.settings)
        self._stop = threading.Event()
        #: What the last run's socket actually did, or None when it had no
        #: collector. Set by _emit on every exit path and read into the manifest.
        self.last_send_stats: dict[str, int] | None = None

    # -- vendor identity -------------------------------------------------------

    @property
    def syslog_hostname(self) -> str:
        """Syslog frame hostname: operator override, else the active profile's."""
        return self.settings.hostname or self.profile.hostname

    @property
    def accepted_as(self) -> str:
        """Log-source identity for the manifest: operator override, else the profile's."""
        return self.settings.accepted_as or self.profile.accepted_as

    # -- kill switch -----------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    def reset(self) -> None:
        self._stop.clear()

    # -- connection test -------------------------------------------------------

    def build_test_event(self, *, eventtime: int | None = None) -> EventRecord:
        """A benign traffic:forward accept to a benign external (safety: no adversary).

        ``eventtime`` defaults to the configured anchor, which keeps
        ``/api/connect/test``'s preview and the unit tests deterministic. The live
        send passes the current time instead: see :meth:`send_test`.
        """

        return EventRecord(
            log_type="traffic",
            subtype="forward",
            action="accept",
            level="notice",
            eventtime=eventtime if eventtime is not None else self.settings.anchor_epoch,
            src=self.entities.internal_hosts[0],
            spt=51544,
            dst=self.entities.benign_external[0],
            dpt=443,
            proto=6,
            session_id=1000,
            out_bytes=8421,
            in_bytes=61325,
            extra={
                "policyid": "7",
                "service": "HTTPS",
                "app": "HTTPS",
                "trandisp": "snat",
                "duration": "122",
                "sentpkt": "64",
                "rcvdpkt": "58",
            },
        )

    def _mark(self, extension: dict[str, str], run_id: str | None = None) -> dict[str, str]:
        """Stamp the synthetic-data marker when settings.benign_marker is on.

        Off by default, so the wire format and the golden lines are unchanged
        unless the operator asks for the marker (safety-labelling is opt-in to
        preserve fidelity). Applied at this single choke point, so every emitted
        line, sample and test line is marked identically regardless of vendor.
        """

        if self.settings.benign_marker:
            extension = {**extension, **synthetic_marker(run_id)}
        return extension

    def build_test_line(self, *, eventtime: int | None = None) -> str:
        header, extension = self.profile.render(self.build_test_event(eventtime=eventtime))
        return to_cef(header, self._mark(extension))

    def render_line(self, event: EventRecord, *, run_id: str | None = None) -> str:
        """Serialize one planned event to a CEF line via the active vendor profile."""
        header, extension = self.profile.render(event)
        return to_cef(header, self._mark(extension, run_id))

    def send_test(self, collector: CollectorProfile) -> bool:
        """Send one benign test line to the collector; return transport success.

        Stamped **now**, not with the deterministic anchor.

        The anchor exists so a seeded run reproduces byte for byte, which matters
        for ``--to-file`` artifacts and the golden tests. It is exactly wrong here.
        This datagram's whole job is to prove ingestion, and it was carrying an
        event time 381 days in the past while the syslog header said now: on a SIEM
        keying on parsed event time the operator's one proof lands over a year back
        and reads as never arriving. Found in a live LogRhythm capture, where the
        run events were correctly stamped and only the test was stale.
        """

        line = self.build_test_line(eventtime=int(datetime.now(tz=UTC).timestamp()))
        try:
            with SyslogEmitter(collector, hostname=self.syslog_hostname) as emitter:
                _log.info("connect test: one benign line, stamped now")
                return emitter.send_test(line)
        except OSError as exc:
            # This is annotated ``-> bool`` and has to return one. ``__enter__``
            # calls ``connect()``, so a refused or unreachable collector escaped
            # the contract entirely and both callers' failure branches were
            # unreachable: the operator got a traceback where a "could not reach
            # the collector" message was already written and waiting.
            _log.warning("connect test failed: %s", describe_error(exc))
            return False

    # -- planning / running ----------------------------------------------------

    def build_plan(self, request: RunRequest) -> ScenarioPlan:
        technique = self.catalog.by_id(request.technique_id)
        duration_s = parse_duration(request.duration) if request.duration else None
        return self.engine.plan(
            technique,
            request.intensity,
            self.entities,
            request.seed,
            duration_override_s=duration_s,
            anchor_epoch=request.anchor_epoch or self.settings.anchor_epoch,
            param_overrides=request.param_overrides,
        )

    def run(
        self,
        request: RunRequest,
        on_progress: ProgressCallback | None = None,
        on_event: EventCallback | None = None,
        run_id: str | None = None,
    ) -> RunResult:
        # Generated once here so every surface shares one id: the CLI prints it,
        # the manifest records it, the web runner passes its handle id in so the
        # id an operator sees in a 409 resolves to a manifest on disk. Created
        # before anything can raise, so even a run that dies on connect writes a
        # manifest carrying the id it was known by.
        run_id = run_id or new_run_id()
        technique = self.catalog.by_id(request.technique_id)

        want_send = not request.no_send
        if want_send and request.collector is None and request.to_file is None:
            raise RuntimeError(
                "fail-closed: sending requested but no collector is configured and no --to-file "
                "was given. Configure a collector or use --to-file/--no-send."
            )
        send = want_send and request.collector is not None
        file_path = request.to_file

        self.reset()
        self.last_send_stats = None
        plan = self.build_plan(request)

        target, transport = self._describe_target(request, send)
        eps_cap = request.rate_override or self.settings.eps_cap
        pace = self._resolve_pace(request.pace, request.speed, sending=send)

        started_at = now_dubai_iso()
        # The manifest is written whichever way this ends, including the ways that
        # raise. A transport failure used to exit before the record existed, so a
        # run could reach a collector part-way and leave nothing durable behind
        # saying what was attempted or how far it got. Safety rule 5 says every
        # run writes a manifest, and the failure path is the one that needs it.
        count = 0
        stopped = False
        failure: BaseException | None = None
        try:
            # F-08. The eps cap is enforced by this loop, so it is per process:
            # two sending processes deliver twice the cap and neither is doing
            # anything wrong. The supported scope is one sending run per host,
            # and this is where that is enforced rather than merely stated. Held
            # across the whole emit, and only when a collector is actually in
            # play: --no-send and --to-file cannot exceed anything.
            with ExitStack() as guard:
                if send:
                    guard.enter_context(sending_lock())
                count, stopped = self._emit(
                    plan.events,
                    send=send,
                    collector=request.collector,
                    to_file=file_path,
                    eps_cap=eps_cap,
                    pace=pace,
                    speed=request.speed,
                    on_event=on_event,
                    on_progress=on_progress,
                    run_id=run_id,
                )
        except BaseException as exc:  # noqa: BLE001 - recorded, then re-raised unchanged
            failure = exc
        ended_at = now_dubai_iso()

        warmup = plan.warmup_note
        if plan.truncated:
            note = f"event stream truncated at engine max_events={self.engine.max_events}"
            warmup = f"{warmup}; {note}" if warmup else note

        manifest = RunManifest(
            replicant_version=__version__,
            run_id=run_id,
            technique_id=technique.id,
            technique_name=technique.name,
            ndr_uc=technique.ndr_uc,
            intensity=request.intensity,
            seed=request.seed,
            params=plan.effective_params,
            entities=self.entities.summary(),
            target=target,
            transport=transport,
            accepted_as=self.accepted_as,
            event_count=count,
            started_at=started_at,
            ended_at=ended_at,
            anchor_epoch=plan.anchor_epoch,
            warmup_note=warmup,
            pace=pace,
            speed=request.speed,
            vendor=self.settings.vendor,
            duration=request.duration,
            rate=eps_cap,
            send_stats=self.last_send_stats,
            status=_run_status(failure, stopped),
            error=describe_error(failure) if failure is not None else None,
        )
        manifest_path = write_manifest(manifest, self.settings.manifest_dir)
        if failure is not None:
            # Recorded, then raised unchanged. The caller still sees the original
            # exception and its traceback; the manifest is a side effect, not a
            # replacement for the error.
            #
            # The record is attached to the exception rather than wrapped in a new
            # one, because the caller has no other way to find it: the whole point
            # of re-raising unchanged is that the operator sees their real error.
            # The web runner reported manifest=None and event_count=0 on failure
            # while a complete partial manifest sat on disk, which quietly undid
            # half of what F-02 was for.
            attach_run_record(failure, manifest.model_dump(), str(manifest_path), count)
            raise failure
        return RunResult(manifest, manifest_path, count, plan, stopped)

    def _emit(
        self,
        events: list[EventRecord],
        *,
        send: bool,
        collector: CollectorProfile | None,
        to_file: str | None,
        eps_cap: int,
        pace: Pace = "burst",
        speed: float = 1.0,
        on_event: EventCallback | None = None,
        on_progress: ProgressCallback | None = None,
        run_id: str | None = None,
    ) -> tuple[int, bool]:
        """Render + send/write a list of events. Shared by run() and run_scenario()."""
        # Compression moves the event times, not only the schedule, so it has to
        # happen before anything renders. See replicant.core.pacing.
        events = compress_timeline(events, speed)
        count = 0
        stopped = False
        sink = FileSink(to_file) if to_file else None
        emitter = (
            SyslogEmitter(collector, hostname=self.syslog_hostname)
            if send and collector is not None
            else None
        )
        total = len(events)
        rate = RateCounter()
        total_sends = 0
        total_bytes = 0
        # A run with no destination renders every event and delivers none of them.
        # It is legitimate (a dry render still produces a plan, a count and a
        # manifest) but it is indistinguishable from a working run unless it says
        # so: the event stream, the progress and the events-per-second readout are
        # all identical, because they measure rendering rather than delivery.
        #
        # This cost a live lab session. A run reported 921 events per second while
        # tcpdump saw nothing, because the destination switch was off and nothing
        # anywhere said so. WARNING rather than an exception, since refusing would
        # break dry renders that legitimately want no output.
        if emitter is None and sink is None:
            _log.warning(
                "no destination: rendering %d events and sending none. Nothing will reach a "
                "collector and nothing will be written to disk. The events-per-second figure "
                "below measures rendering, not delivery. Enable a collector or a file.",
                total,
            )
        elif emitter is None and sink is not None:
            _log.info("writing %d events to %s, not sending to any collector", total, to_file)

        if emitter is not None and events:
            # The anchor is the first thing to check when a SIEM shows nothing, so
            # it goes on the record at the start of every live run rather than
            # being something the operator has to remember they chose.
            first = datetime.fromtimestamp(events[0].eventtime, tz=UTC)
            drift_days = (datetime.now(tz=UTC) - first).days
            # `drift_days` is now minus the event time, so a POSITIVE value means
            # the events are historical. This read "%d days from now", which
            # described the default historical anchor as future-dated: the exact
            # opposite of the truth, in the first thing an operator checks when a
            # SIEM shows nothing. `stale_anchor_warning` in settings.py has always
            # phrased this correctly; this line did not.
            direction = "in the past" if drift_days > 0 else "in the future"
            _log.info(
                "live run: %d events, eps_cap=%d, first eventtime %s UTC (%d days %s)",
                total,
                eps_cap,
                first.strftime("%Y-%m-%d %H:%M:%S"),
                abs(drift_days),
                direction,
            )
            if abs(drift_days) >= 2:
                _log.warning(
                    "event time is %d days %s while the syslog header is stamped now. "
                    "A SIEM keying on parsed event time will not match recent-window rules, "
                    "and the events will look absent rather than late. Use anchor 'now'.",
                    abs(drift_days),
                    direction,
                )
        try:
            if sink is not None:
                sink.open()
            if emitter is not None:
                emitter.connect()
            # Each event waits for its own slot. Two things decide that slot.
            #
            # The rate cap is the flood guard: no two sends are ever closer than
            # 1/eps_cap. It replaced a fixed-window limiter that a live LogRhythm
            # test caught doing two wrong things at once. It only throttled on
            # REACHING the cap, so a run shorter than the cap was never paced at
            # all: 1000 events against a cap of 2000 left as 670 KB in about 0.4
            # seconds, measured, with zero send errors and nothing arriving. And
            # when it did engage it delivered the second's budget as a spike then
            # slept, which is not what a firewall does and not what a receive
            # buffer expects.
            #
            # The pace decides the shape. Burst asks only for the cap. Plan
            # reproduces the gaps the plan itself holds, which is the difference
            # between a beacon and a snapshot of one: the same lab test delivered
            # 49 events in 3 seconds carrying 238 minutes of event times, so any
            # rule keyed on the interval between callbacks had nothing to match.
            #
            # Both arrive as one precomputed list of offsets from the first send.
            # The arithmetic, and its tests, are in replicant.core.pacing.
            interval = 1.0 / eps_cap if eps_cap > 0 else 0.0
            offsets = send_offsets(events, pace=pace, interval=interval)
            # A slow send must not turn into a catch-up burst, which would recreate
            # the problem the schedule exists to prevent. Past this much lag the
            # baseline moves to now, leaving every remaining gap intact.
            resync_after = interval if interval > 0.0 else 0.001
            started = time.monotonic()
            # The time of the last actual send, which is what safety rule 4 is
            # really about. The offsets alone are only a plan: once real work runs
            # late, consecutive events whose slots have both passed would fire back
            # to back and the cap would be a number in a log line rather than a
            # property of the wire. Measured from the send, so it holds whatever
            # rendering costs.
            last_sent: float | None = None
            if emitter is not None and total:
                _log.info(
                    "pacing %d events: %s, cap %d/s, projected wall clock %s",
                    total,
                    (
                        f"plan timeline at {speed:g}x"
                        if pace == "plan"
                        else "burst, plan timeline ignored"
                    ),
                    eps_cap,
                    format_span(projected_seconds(offsets)),
                )
            for index, event in enumerate(events):
                if self._stop.is_set():
                    stopped = True
                    break
                # Wait for this event's slot BEFORE rendering it, not after.
                #
                # The wait used to sit between the render and the send. That was
                # harmless while every gap was a few milliseconds and is not once a
                # gap can be minutes: the event stream, the progress count and the
                # events-per-second readout would all race ahead of delivery. That
                # is the same "the readout measures rendering, not delivery" defect
                # that cost a live session. Waiting first makes the whole iteration
                # advance at the rate the collector is actually being fed.
                if emitter is not None and offsets:
                    plan_due = started + offsets[index]
                    due = plan_due if last_sent is None else max(plan_due, last_sent + interval)
                    now = time.monotonic()
                    if due > now:
                        # Event.wait, not time.sleep: a plan-paced gap can be
                        # minutes long and the kill switch has to be able to end it
                        # rather than being noticed whenever the sleep happens to
                        # finish.
                        if self._stop.wait(due - now):
                            stopped = True
                            break
                        now = time.monotonic()
                    # Behind the plan by more than one slot: move the baseline to
                    # now so every REMAINING gap survives intact.
                    #
                    # The lag is measured against the plan's own deadline and not
                    # against `due`. Once the loop runs late the rate floor sets
                    # `due` to roughly now, so a test against `due` reads a lag of
                    # zero, never fires, and the schedule quietly pays the delay
                    # back by squeezing the gaps that follow. A stall has to move
                    # the run later, not distort the shape after it, because
                    # reproducing that shape is the whole reason for plan pacing.
                    if now - plan_due > resync_after:
                        started = now - offsets[index]
                header, extension = self.profile.render(event)
                line = to_cef(header, self._mark(extension, run_id))
                if on_event is not None:
                    on_event(line, event)
                if sink is not None:
                    sink.write(line)
                if emitter is not None:
                    # The framed size, which only the emitter knows: the syslog
                    # envelope adds a PRI, a timestamp and a hostname to the CEF
                    # payload, so len(line) would understate what goes on the wire.
                    sent_bytes = emitter.send(line, level=event.level)
                    last_sent = time.monotonic()
                    rate.add(sent_bytes)
                    total_sends += 1
                    total_bytes += sent_bytes
                    # Once a second, what actually went out. Bytes beside the count,
                    # so "sent" can be checked against what the collector received.
                    if rate.due():
                        sent, byte_count, _, elapsed = rate.take()
                        _log.info(
                            "emitted %d events (%d bytes) in %.2fs; cumulative %d sends, %d bytes",
                            sent,
                            byte_count,
                            elapsed,
                            total_sends,
                            total_bytes,
                        )
                count += 1
                if on_progress is not None and count % 100 == 0:
                    on_progress(count, total)
        except KeyboardInterrupt:
            stopped = True
        finally:
            # One final callback with the real total. The cadence above only fires
            # on multiples of 100, so a 250-event run reported 200 as its last
            # word and every consumer sat at 80% on a finished run. Emitted in
            # `finally` so a stop or a transport failure also gets a true count
            # rather than leaving the last round number standing.
            if on_progress is not None and count % 100 != 0:
                on_progress(count, total)
            if sink is not None:
                sink.close()
            if emitter is not None:
                # Captured before close, and on every exit path, so a run that
                # failed part-way still records what its socket actually did.
                # `event_count` counts events rendered; this counts datagrams the
                # kernel accepted, and the two differing is the interesting case.
                # getattr, not emitter.stats: the emitter is an injection point
                # and several test doubles implement only send/close. Requiring a
                # stats attribute would make this record cost every future fake a
                # field it does not otherwise need.
                stats = getattr(emitter, "stats", None)
                if stats is not None:
                    self.last_send_stats = stats.as_dict()
                emitter.close()
        return count, stopped

    def preview_pacing(
        self, request: RunRequest, *, sending: bool, plan: ScenarioPlan | None = None
    ) -> PacingPreview:
        """How long this run will take, and refuse it now if it cannot be run.

        Builds the plan unless the caller already has one. Building is pure CPU
        with no I/O, but REP-004 at high intensity is 180,000 events and about
        1.6 seconds, so a caller holding a plan should pass it rather than pay
        for it twice.
        """

        plan = plan or self.build_plan(request)
        return self._pacing_preview(
            plan.events,
            pace=request.pace,
            speed=request.speed,
            rate_override=request.rate_override,
            sending=sending,
        )

    def preview_scenario_pacing(
        self,
        request: ScenarioRunRequest,
        scenario_catalog: ScenarioCatalog,
        *,
        sending: bool,
    ) -> PacingPreview:
        """The same, for a scenario. A scenario is a longer timeline, so the
        duration matters there more than for a single technique, not less."""

        composed = compose(
            scenario_catalog.by_id(request.scenario_id),
            self.catalog.by_id,
            self.engine,
            request.seed,
            request.anchor_epoch or self.settings.anchor_epoch,
            self.entities,
            intensity_override=request.intensity_override,
            duration_s=parse_duration(request.duration) if request.duration else None,
        )
        return self._pacing_preview(
            composed.events,
            pace=request.pace,
            speed=request.speed,
            rate_override=request.rate_override,
            sending=sending,
        )

    def _pacing_preview(
        self,
        events: Sequence[EventRecord],
        *,
        pace: Pace | None,
        speed: float,
        rate_override: int | None,
        sending: bool,
    ) -> PacingPreview:
        resolved = self._resolve_pace(pace, speed, sending=sending)
        eps_cap = rate_override or self.settings.eps_cap
        interval = 1.0 / eps_cap if eps_cap > 0 else 0.0
        compressed = compress_timeline(events, speed)
        # Burst reads only the count, so compression cannot change its figure.
        by_pace = {
            "plan": projected_seconds(send_offsets(compressed, pace="plan", interval=interval)),
            "burst": projected_seconds(send_offsets(events, pace="burst", interval=interval)),
        }
        return PacingPreview(
            event_count=len(events),
            plan_span_s=(events[-1].eventtime - events[0].eventtime) if events else 0,
            compressed_span_s=(
                (compressed[-1].eventtime - compressed[0].eventtime) if compressed else 0
            ),
            projected_s=by_pace[resolved],
            projected_by_pace=by_pace,
            pace=resolved,
            speed=speed,
        )

    def _resolve_pace(self, pace: Pace | None, speed: float, *, sending: bool) -> Pace:
        """Pick the pace, and refuse a speed that could not do anything.

        The request model already rejects an explicit ``pace='burst'`` beside a
        speed. This catches the case a field validator cannot see: no pace named at
        all, resolving to burst because the only destination is a file, with a
        speed that would then be silently discarded. A control whose output cannot
        change is decoration, so it is an error rather than a no-op.
        """

        resolved = resolve_pace(pace, sending=sending)
        if resolved == "burst" and speed != 1.0:
            raise RuntimeError(SPEED_WITHOUT_PLAN)
        return resolved

    def _describe_target(
        self, request: RunRequest | ScenarioRunRequest, send: bool
    ) -> tuple[str, str]:
        if send and request.collector is not None:
            return request.collector.endpoint(), request.collector.transport
        if request.to_file:
            return request.to_file, "file"
        return "dry-run", "none"

    def _scenario_note(self, composed: ComposedPlan) -> str | None:
        """Warm-up notes plus any stage truncation, so the scenario manifest records a cut
        stream exactly as run() does for a single technique (safety rule 5)."""

        notes = list(composed.warmup_notes)
        for stage in composed.stages:
            if stage.truncated:
                notes.append(
                    f"stage {stage.index} ({stage.technique_id}): event stream truncated at "
                    f"engine max_events={self.engine.max_events}"
                )
        return "; ".join(notes) or None

    def run_scenario(
        self,
        request: ScenarioRunRequest,
        scenario_catalog: ScenarioCatalog,
        on_progress: ProgressCallback | None = None,
        on_event: EventCallback | None = None,
    ) -> ScenarioRunResult:
        scenario = scenario_catalog.by_id(request.scenario_id)

        want_send = not request.no_send
        if want_send and request.collector is None and request.to_file is None:
            raise RuntimeError(
                "fail-closed: sending requested but no collector is configured and no "
                "--to-file was given. Configure a collector or use --to-file/--no-send."
            )
        send = want_send and request.collector is not None

        self.reset()
        composed = compose(
            scenario,
            self.catalog.by_id,
            self.engine,
            request.seed,
            request.anchor_epoch or self.settings.anchor_epoch,
            self.entities,
            intensity_override=request.intensity_override,
            duration_s=parse_duration(request.duration) if request.duration else None,
        )
        target, transport = self._describe_target(request, send)
        eps_cap = request.rate_override or self.settings.eps_cap
        pace = self._resolve_pace(request.pace, request.speed, sending=send)

        started_at = now_dubai_iso()
        # See run(): the manifest is written on every exit path, raising ones
        # included, and the exception is re-raised unchanged afterwards.
        count = 0
        stopped = False
        failure: BaseException | None = None
        try:
            count, stopped = self._emit(
                composed.events,
                send=send,
                collector=request.collector,
                to_file=request.to_file,
                eps_cap=eps_cap,
                pace=pace,
                speed=request.speed,
                on_event=on_event,
                on_progress=on_progress,
            )
        except BaseException as exc:  # noqa: BLE001 - recorded, then re-raised unchanged
            failure = exc
        ended_at = now_dubai_iso()

        advisory_text, coverage = build_advisory(scenario, composed, self.catalog)
        manifest = ScenarioManifest(
            replicant_version=__version__,
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            seed=request.seed,
            entities=composed.entities
            | {"victim": composed.victim, "adversary": composed.adversary},
            target=target,
            transport=transport,
            vendor=self.settings.vendor,
            accepted_as=self.accepted_as,
            total_event_count=count,
            stages=[
                ScenarioStageRecord(
                    index=s.index,
                    technique_id=s.technique_id,
                    label=s.label,
                    ndr_uc=s.ndr_uc,
                    intensity=s.intensity,
                    start_offset=s.start_offset,
                    event_count=s.event_count,
                    tactics=s.tactics,
                    techniques=s.techniques,
                    start_epoch=s.start_epoch,
                    end_epoch=s.end_epoch,
                    truncated=s.truncated,
                    aligned_days=s.aligned_days,
                )
                for s in composed.stages
            ],
            started_at=started_at,
            ended_at=ended_at,
            anchor_epoch=composed.anchor_epoch,
            warmup_note=self._scenario_note(composed),
            coverage=coverage,
            pace=pace,
            speed=request.speed,
            duration=request.duration,
            status=_run_status(failure, stopped),
            error=describe_error(failure) if failure is not None else None,
        )
        manifest_path = write_scenario_manifest(manifest, self.settings.manifest_dir)
        advisory_path = write_advisory(advisory_text, manifest_path)
        if failure is not None:
            raise failure
        return ScenarioRunResult(manifest, manifest_path, advisory_path, count, composed, stopped)
