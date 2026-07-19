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
from pathlib import Path

from replicant import __version__
from replicant.audit.manifest import human_summary, now_dubai_iso, write_manifest
from replicant.cef.serializer import to_cef
from replicant.config.settings import Settings, parse_duration
from replicant.core.models import (
    Catalog,
    CollectorProfile,
    EventRecord,
    RunManifest,
    RunRequest,
)
from replicant.entities.model import EntityModel
from replicant.profiles.base import VendorProfile
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateDevice, FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.scenario.engine import ScenarioEngine, ScenarioPlan
from replicant.transport.filesink import FileSink
from replicant.transport.syslog import SyslogEmitter

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
        self.profile = profile or self._build_profile(self.settings)
        self._stop = threading.Event()

    @staticmethod
    def _build_profile(settings: Settings) -> VendorProfile:
        """Select the vendor profile from settings.vendor (blueprint s10, Phase 3)."""

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

    # -- kill switch -----------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    def reset(self) -> None:
        self._stop.clear()

    # -- connection test -------------------------------------------------------

    def build_test_event(self) -> EventRecord:
        """A benign traffic:forward accept to a benign external (safety: no adversary)."""

        return EventRecord(
            log_type="traffic",
            subtype="forward",
            action="accept",
            level="notice",
            eventtime=self.settings.anchor_epoch,
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

    def build_test_line(self) -> str:
        header, extension = self.profile.render(self.build_test_event())
        return to_cef(header, extension)

    def render_line(self, event: EventRecord) -> str:
        """Serialize one planned event to a CEF line via the active vendor profile."""
        header, extension = self.profile.render(event)
        return to_cef(header, extension)

    def send_test(self, collector: CollectorProfile) -> bool:
        """Send one benign test line to the collector; return transport success."""

        line = self.build_test_line()
        with SyslogEmitter(collector, hostname=self.settings.hostname) as emitter:
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
        count = 0
        stopped = False
        sink = FileSink(file_path) if file_path else None
        emitter = (
            SyslogEmitter(request.collector, hostname=self.settings.hostname)
            if send and request.collector is not None
            else None
        )

        try:
            if sink is not None:
                sink.open()
            if emitter is not None:
                emitter.connect()
            window_start = time.monotonic()
            in_window = 0
            for event in plan.events:
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
                    emitter.send(line, level=event.level)
                    in_window += 1
                    if eps_cap > 0 and in_window >= eps_cap:
                        elapsed = time.monotonic() - window_start
                        if elapsed < 1.0:
                            time.sleep(1.0 - elapsed)
                        window_start = time.monotonic()
                        in_window = 0
                count += 1
                if on_progress is not None and count % 100 == 0:
                    on_progress(count, len(plan.events))
        except KeyboardInterrupt:
            stopped = True
        finally:
            if sink is not None:
                sink.close()
            if emitter is not None:
                emitter.close()

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
            accepted_as=self.settings.accepted_as,
            event_count=count,
            started_at=started_at,
            ended_at=ended_at,
            anchor_epoch=plan.anchor_epoch,
            warmup_note=warmup,
        )
        manifest_path = write_manifest(manifest, self.settings.manifest_dir)
        return RunResult(manifest, manifest_path, count, plan, stopped)

    def _describe_target(self, request: RunRequest, send: bool) -> tuple[str, str]:
        if send and request.collector is not None:
            return request.collector.endpoint(), request.collector.transport
        if request.to_file:
            return request.to_file, "file"
        return "dry-run", "none"
