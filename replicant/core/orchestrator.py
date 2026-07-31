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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from replicant import __version__
from replicant.audit.manifest import (
    human_summary,
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
    ScenarioCatalog,
    ScenarioManifest,
    ScenarioRunRequest,
    ScenarioStageRecord,
)
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


@dataclass
class RunResult:
    manifest: RunManifest
    manifest_path: Path
    event_count: int
    plan: ScenarioPlan
    stopped: bool

    def summary(self) -> str:
        return human_summary(self.manifest, self.manifest_path)


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

    def build_test_line(self, *, eventtime: int | None = None) -> str:
        header, extension = self.profile.render(self.build_test_event(eventtime=eventtime))
        return to_cef(header, extension)

    def render_line(self, event: EventRecord) -> str:
        """Serialize one planned event to a CEF line via the active vendor profile."""
        header, extension = self.profile.render(event)
        return to_cef(header, extension)

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
        with SyslogEmitter(collector, hostname=self.syslog_hostname) as emitter:
            _log.info("connect test: one benign line, stamped now")
            return emitter.send_test(line)

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
    ) -> RunResult:
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
        plan = self.build_plan(request)

        target, transport = self._describe_target(request, send)
        eps_cap = request.rate_override or self.settings.eps_cap

        started_at = now_dubai_iso()
        count, stopped = self._emit(
            plan.events,
            send=send,
            collector=request.collector,
            to_file=file_path,
            eps_cap=eps_cap,
            on_event=on_event,
            on_progress=on_progress,
        )
        ended_at = now_dubai_iso()

        warmup = plan.warmup_note
        if plan.truncated:
            note = f"event stream truncated at engine max_events={self.engine.max_events}"
            warmup = f"{warmup}; {note}" if warmup else note

        manifest = RunManifest(
            replicant_version=__version__,
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
        )
        manifest_path = write_manifest(manifest, self.settings.manifest_dir)
        return RunResult(manifest, manifest_path, count, plan, stopped)

    def _emit(
        self,
        events: list[EventRecord],
        *,
        send: bool,
        collector: CollectorProfile | None,
        to_file: str | None,
        eps_cap: int,
        on_event: EventCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> tuple[int, bool]:
        """Render + send/write a list of events. Shared by run() and run_scenario()."""
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
            _log.info(
                "live run: %d events, eps_cap=%d, first eventtime %s UTC (%d days from now)",
                total,
                eps_cap,
                first.strftime("%Y-%m-%d %H:%M:%S"),
                drift_days,
            )
            if abs(drift_days) >= 2:
                _log.warning(
                    "event time is %d days from now while the syslog header is stamped now. "
                    "A SIEM keying on parsed event time will not match recent-window rules, "
                    "and the events will look absent rather than late. Use anchor 'now'.",
                    drift_days,
                )
        try:
            if sink is not None:
                sink.open()
            if emitter is not None:
                emitter.connect()
            # Evenly paced, one event every 1/rate seconds.
            #
            # This replaces a fixed-window limiter that ran at full speed until
            # the window filled and then slept out the remainder. Two things were
            # wrong with it, and a live LogRhythm test found both:
            #
            # 1. It only throttled on reaching the cap. A run SHORTER than the cap
            #    was never paced at all. 1000 events against a cap of 2000 left as
            #    fast as the socket would take them: 670 KB in about 0.4 seconds,
            #    measured, with zero send errors and nothing arriving at the SIEM.
            # 2. Even when it did engage, it delivered the second's budget as a
            #    burst followed by silence. A firewall trickles; a receiver sized
            #    for the average still loses the spike.
            #
            # A deadline schedule fixes both. Each send waits until its own slot,
            # and the slot advances from the previous DEADLINE rather than from
            # the current time, so a slow send is absorbed instead of compounding
            # into drift. If the loop falls more than one interval behind (a long
            # GC pause, a blocked socket) the schedule resyncs to now rather than
            # trying to catch up with a burst, which would recreate the problem it
            # exists to prevent.
            #
            # The rate is now a target, not just a ceiling, so the delivered shape
            # matches what an operator asked for instead of only its average.
            interval = 1.0 / eps_cap if eps_cap > 0 else 0.0
            next_due = time.monotonic()
            if emitter is not None and interval > 0.0:
                _log.info(
                    "pacing %d events at %d/s, one every %.2f ms, evenly spaced rather "
                    "than sent as a burst",
                    total,
                    eps_cap,
                    interval * 1000.0,
                )
            for event in events:
                if self._stop.is_set():
                    stopped = True
                    break
                header, extension = self.profile.render(event)
                line = to_cef(header, extension)
                if on_event is not None:
                    on_event(line, event)
                if sink is not None:
                    sink.write(line)
                if emitter is not None:
                    # Wait for this event's slot before sending, so the collector
                    # sees a stream. See the pacing note above the loop.
                    if interval > 0.0:
                        now = time.monotonic()
                        if next_due > now:
                            time.sleep(next_due - now)
                            now = time.monotonic()
                        next_due += interval
                        if next_due < now:
                            next_due = now
                    # The framed size, which only the emitter knows: the syslog
                    # envelope adds a PRI, a timestamp and a hostname to the CEF
                    # payload, so len(line) would understate what goes on the wire.
                    sent_bytes = emitter.send(line, level=event.level)
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
            if sink is not None:
                sink.close()
            if emitter is not None:
                emitter.close()
        return count, stopped

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
        )
        target, transport = self._describe_target(request, send)
        eps_cap = request.rate_override or self.settings.eps_cap

        started_at = now_dubai_iso()
        count, stopped = self._emit(
            composed.events,
            send=send,
            collector=request.collector,
            to_file=request.to_file,
            eps_cap=eps_cap,
            on_event=on_event,
            on_progress=on_progress,
        )
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
        )
        manifest_path = write_scenario_manifest(manifest, self.settings.manifest_dir)
        advisory_path = write_advisory(advisory_text, manifest_path)
        return ScenarioRunResult(manifest, manifest_path, advisory_path, count, composed, stopped)
