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
"""Web run manager.

Runs a technique on a background thread using the shared Orchestrator (so the web
path reuses the CLI/menu run logic, fail-closed guard, eps cap, and manifest) and
publishes line/progress/done/error items to a thread-safe queue that the SSE
endpoint drains. Streamed lines are capped so a large run cannot flood the browser;
the full event count and manifest still come through on the ``done`` item.
"""

from __future__ import annotations

import queue
import threading
import uuid
from dataclasses import dataclass, field
from queue import Full, Queue
from typing import Any

from replicant.audit.manifest import new_run_id
from replicant.config.settings import Settings
from replicant.core.models import Catalog, EventRecord, RunRequest
from replicant.core.orchestrator import Orchestrator, run_record_of

MAX_STREAM_LINES = 2000
# Replayed to a consumer that connects after a run has already finished, which
# is routine: the client starts the run and then opens the stream.
MAX_HISTORY_ITEMS = MAX_STREAM_LINES + 64
QUEUE_MAXSIZE = 8000
# A terminal handle is kept so the client can fetch its final status/manifest, but
# only this many are retained: without a bound, ``_runs`` grows for the life of the
# server. A live run is never evicted.
MAX_TERMINAL_RETAINED = 16
_TERMINAL_STATES = frozenset({"done", "stopped", "error"})


class RunInProgressError(RuntimeError):
    """A run was requested while another is still active.

    Each run gets its own rate limiter, so concurrent runs to one collector would
    multiply the configured eps cap (safety rule 4). The web layer allows one
    active run at a time and surfaces this as HTTP 409.

    Carries the technique and vendor as well as the id. The id alone is a hex
    string the operator has no way to resolve, which made the 409 unactionable:
    a run they could not see was refusing runs they could.
    """

    def __init__(self, active_run_id: str, technique_id: str = "", vendor: str = "") -> None:
        identity = ", ".join(part for part in (technique_id, vendor) if part)
        named = f" ({identity})" if identity else ""
        super().__init__(f"a run is already in progress: {active_run_id}{named}")
        self.active_run_id = active_run_id
        self.technique_id = technique_id
        self.vendor = vendor


@dataclass
class RunHandle:
    run_id: str
    # None while the browser-visible admission is reserved or being prepared.
    # The same handle is promoted in place before the worker starts, so active
    # ownership never disappears between reservation and execution.
    orchestrator: Orchestrator | None
    #: The first subscriber's queue, kept as an attribute for the tests and
    #: callers that predate fan-out. Publishing goes through :meth:`publish`.
    queue: Queue[dict[str, Any]]
    total: int
    # Which technique this run is emitting. Recorded so the active-run endpoint
    # and the 409 can name it: the form's own "running" flag is per-panel state
    # and resets when the operator selects a different technique, so the server
    # is the only thing that knows a run is still going.
    technique_id: str = ""
    status: str = "running"
    dropped: int = 0
    thread: threading.Thread | None = None
    manifest: dict[str, Any] | None = None
    manifest_path: str | None = None
    event_count: int = 0
    # The resolved profile id used to build this run's orchestrator. Stored here
    # because a restored panel must follow the run, not the form's current vendor.
    vendor: str = "fortigate"
    # Browser-generated idempotency key for the admission handshake. It is kept
    # separate from run_id because run ids have a documented RUN-... format and
    # are written into manifests and optional CEF run markers.
    admission_id: str = ""
    #: Every live SSE consumer. One queue each, because a shared queue is
    #: destructive: `get()` removes the item, so two browser tabs on one run each
    #: received a random subset of the lines and neither saw the whole stream
    #: (F-12). Fan-out also isolates a stalled reader, whose own queue fills while
    #: everyone else keeps up.
    subscribers: list[Queue[dict[str, Any]]] = field(default_factory=list)
    #: What has been published so far, so a consumer that connects after the run
    #: finished still receives it. Bounded by MAX_STREAM_LINES + a little for the
    #: progress and terminal items.
    history: list[dict[str, Any]] = field(default_factory=list)
    #: Serialises subscribe/unsubscribe/publish. The worker thread publishes while
    #: request threads subscribe, and without this a tab connecting at the instant
    #: of a publish could snapshot history BEFORE an item was appended and join the
    #: subscriber list AFTER that item was fanned out, missing it, including the
    #: terminal done/error event that tells the UI the run finished.
    _fanout_lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    #: Set only after a done/error item is present in history and every subscriber
    #: has received it. Status can become terminal slightly earlier so status
    #: readers see a complete snapshot, but SSE must not close during that gap.
    terminal_published: threading.Event = field(
        default_factory=threading.Event, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        # The handle's own queue is the first subscriber, so existing callers
        # that read `handle.queue` keep working unchanged.
        self.subscribers.append(self.queue)

    def subscribe(self) -> Queue[dict[str, Any]]:
        """A private queue for one consumer, seeded with what it missed.

        The replay is not optional. The client starts a run and *then* opens the
        stream, so a short run routinely finishes before the subscriber exists.
        Under the old shared queue that worked by accident: nothing had drained
        it, so a late consumer found the whole run waiting. Fan-out removes that
        accident, and without history a fast run streams nothing at all.

        Bounded by the same MAX_STREAM_LINES that already caps what a run
        streams, so this holds no more than the old single queue did.
        """

        subscriber: Queue[dict[str, Any]] = Queue(maxsize=QUEUE_MAXSIZE)
        # Held across BOTH the history replay and the append: a publish cannot
        # then slip an item between the snapshot and the join, so every item is
        # delivered exactly once, either as replayed history or as a live push.
        with self._fanout_lock:
            for item in list(self.history):
                try:
                    subscriber.put_nowait(item)
                except Full:  # pragma: no cover - history is bounded below QUEUE_MAXSIZE
                    break
            self.subscribers.append(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: Queue[dict[str, Any]]) -> None:
        # Never drop the handle's own queue: it is what a caller with no
        # subscription still reads, and the worker would otherwise publish into
        # nothing.
        with self._fanout_lock:
            if subscriber is not self.queue and subscriber in self.subscribers:
                self.subscribers.remove(subscriber)

    def publish(self, item: dict[str, Any]) -> None:
        """Offer to every subscriber. A full queue drops for that reader only."""

        terminal = item.get("type") in {"done", "error"}
        with self._fanout_lock:
            self.history.append(item)
            if len(self.history) > MAX_HISTORY_ITEMS:
                del self.history[: len(self.history) - MAX_HISTORY_ITEMS]
            for subscriber in list(self.subscribers):
                try:
                    subscriber.put_nowait(item)
                except Full:
                    self.dropped += 1
                    if terminal:
                        # A stalled reader may lose an old line, but never the
                        # terminal item required to close and reconcile the run.
                        try:
                            subscriber.get_nowait()
                        except queue.Empty:  # pragma: no cover - Full proved otherwise
                            pass
                        subscriber.put_nowait(item)
        if terminal:
            # Publication barrier for the SSE loop. Set only after history and
            # all subscriber queues contain the terminal item.
            self.terminal_published.set()

    def stream_complete(self, subscriber: Queue[dict[str, Any]]) -> bool:
        """Whether one SSE subscriber drained a published terminal record."""

        return self.terminal_published.is_set() and subscriber.empty()


class RunAdmissionError(RuntimeError):
    """A requested admission cannot be claimed or does not match its identity."""

    def __init__(
        self,
        admission_id: str,
        message: str,
        *,
        code: str = "admission_not_claimable",
        admission_run_id: str | None = None,
        active: RunHandle | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.admission_id = admission_id
        self.admission_run_id = admission_run_id
        self.active_run_id = active.run_id if active is not None else None
        self.active_technique_id = active.technique_id if active is not None else None
        self.active_vendor = active.vendor if active is not None else None
        self.active_status = active.status if active is not None else None


class RunManager:
    def __init__(self, catalog: Catalog, settings: Settings) -> None:
        self.catalog = catalog
        self.settings = settings
        self._runs: dict[str, RunHandle] = {}
        self._admissions: dict[str, RunHandle] = {}
        self._lock = threading.Lock()

    def get(self, run_id: str) -> RunHandle | None:
        with self._lock:
            return self._runs.get(run_id)

    def get_admission(self, admission_id: str) -> RunHandle | None:
        """Return an idempotent browser admission by its client-generated id."""

        with self._lock:
            return self._admissions.get(admission_id)

    def stop(self, run_id: str) -> bool:
        cancelled_admission = False
        with self._lock:
            handle = self._runs.get(run_id)
            if handle is None:
                return False
            if handle.status in {"reserved", "admitting"}:
                handle.status = "stopped"
                cancelled_admission = True
            orchestrator = handle.orchestrator
        if cancelled_admission:
            handle.publish(
                {
                    "type": "done",
                    "status": "stopped",
                    "count": 0,
                    "dropped": handle.dropped,
                    "manifest": None,
                    "manifest_path": None,
                }
            )
        elif orchestrator is not None:
            orchestrator.stop()
        return True

    def _active_locked(self) -> RunHandle | None:
        """Return a non-terminal handle if one exists. Caller holds ``_lock``."""
        for handle in self._runs.values():
            if handle.status not in _TERMINAL_STATES:
                return handle
        return None

    def active(self) -> RunHandle | None:
        """The run currently holding the single-run lock, if any.

        Public because the client cannot otherwise discover it. Before this, the
        only signal was a 409 from attempting a start, which meant the operator
        had to provoke the error to learn why the last one happened.
        """
        with self._lock:
            return self._active_locked()

    def _evict_terminal(self) -> None:
        """Drop the oldest terminal handles beyond the retention bound, never a live one."""
        with self._lock:
            terminal_ids = [rid for rid, h in self._runs.items() if h.status in _TERMINAL_STATES]
            for rid in terminal_ids[: max(0, len(terminal_ids) - MAX_TERMINAL_RETAINED)]:
                handle = self._runs.pop(rid)
                if handle.admission_id:
                    self._admissions.pop(handle.admission_id, None)

    def reserve(
        self,
        technique_id: str,
        vendor: str,
        admission_id: str | None = None,
    ) -> RunHandle:
        """Atomically reserve the single-run owner before plan construction.

        ``admission_id`` is generated by the browser and therefore survives a
        lost response. Retrying the same identity is idempotent, while reusing
        it for a different technique or vendor is rejected.
        """

        self._evict_terminal()
        requested_id = admission_id or str(uuid.uuid4())
        with self._lock:
            existing = self._admissions.get(requested_id)
            if existing is not None:
                if existing.technique_id == technique_id and existing.vendor == vendor:
                    return existing
                raise RunAdmissionError(
                    requested_id,
                    "admission id is already bound to a different run identity",
                    code="admission_id_conflict",
                    admission_run_id=existing.run_id,
                    active=self._active_locked(),
                )
            active = self._active_locked()
            if active is not None:
                raise RunInProgressError(active.run_id, active.technique_id, active.vendor)
            handle = RunHandle(
                run_id=new_run_id(),
                orchestrator=None,
                queue=queue.Queue(maxsize=QUEUE_MAXSIZE),
                total=0,
                technique_id=technique_id,
                vendor=vendor,
                admission_id=requested_id,
                status="reserved",
            )
            self._runs[handle.run_id] = handle
            self._admissions[requested_id] = handle
            return handle

    def claim(self, admission_id: str, technique_id: str, vendor: str) -> RunHandle:
        """Claim exactly one reserved identity for plan preparation."""

        with self._lock:
            handle = self._admissions.get(admission_id)
            active = self._active_locked()
            if handle is None:
                raise RunAdmissionError(
                    admission_id,
                    "unknown run admission",
                    active=active,
                )
            if handle.technique_id != technique_id or handle.vendor != vendor:
                raise RunAdmissionError(
                    admission_id,
                    "run admission does not match the requested technique and vendor",
                    code="admission_identity_mismatch",
                    admission_run_id=handle.run_id,
                    active=active,
                )
            if handle.status != "reserved":
                raise RunAdmissionError(
                    admission_id,
                    f"run admission is already {handle.status}",
                    admission_run_id=handle.run_id,
                    active=active,
                )
            handle.status = "admitting"
            return handle

    def fail_admission(self, handle: RunHandle, message: str) -> None:
        """Release a reservation after preparation fails, without racing reuse."""

        failed = False
        with self._lock:
            if self._runs.get(handle.run_id) is handle and handle.status in {
                "reserved",
                "admitting",
            }:
                handle.status = "error"
                failed = True
        if failed:
            handle.publish(
                {
                    "type": "error",
                    "message": message,
                    "count": 0,
                    "manifest": None,
                    "manifest_path": None,
                }
            )

    def start(
        self,
        request: RunRequest,
        settings: Settings | None = None,
        total: int | None = None,
        admission: RunHandle | None = None,
    ) -> RunHandle:
        """Start a run. ``total`` skips a plan build the caller has already done.

        Building the plan is pure CPU but not free: REP-004 at high intensity is
        180,000 events and about 1.6 seconds. The endpoint now previews the run to
        price its pacing before starting it, and that preview already knows the
        count, so passing it through keeps a start at the two builds it always
        cost rather than three.
        """

        effective_settings = settings if settings is not None else self.settings
        handle = admission
        if handle is None:
            handle = self.reserve(request.technique_id, effective_settings.vendor)
            handle = self.claim(
                handle.admission_id, request.technique_id, effective_settings.vendor
            )

        try:
            if (
                handle.technique_id != request.technique_id
                or handle.vendor != effective_settings.vendor
            ):
                raise RunAdmissionError(
                    handle.admission_id,
                    "run admission does not match the requested technique and vendor",
                    code="admission_identity_mismatch",
                    admission_run_id=handle.run_id,
                    active=self.active(),
                )
            orchestrator = Orchestrator(self.catalog, effective_settings)
            # Clear reusable stop state before the handle becomes externally
            # stoppable. The worker must not reset it again after status changes
            # to running, or a Stop in that scheduling window can be lost.
            orchestrator.reset()
            resolved_total = total
            if resolved_total is None:
                resolved_total = len(orchestrator.build_plan(request))
            thread = threading.Thread(target=self._worker, args=(handle, request), daemon=True)
            with self._lock:
                if self._runs.get(handle.run_id) is not handle or handle.status != "admitting":
                    raise RunAdmissionError(
                        handle.admission_id,
                        f"run admission is already {handle.status}",
                        admission_run_id=handle.run_id,
                        active=self._active_locked(),
                    )
                handle.orchestrator = orchestrator
                handle.total = resolved_total
                handle.thread = thread
                handle.status = "running"
            try:
                thread.start()
            except Exception as exc:
                # A worker that never started must not hold the single-run lock.
                with self._lock:
                    if self._runs.get(handle.run_id) is handle and handle.status == "running":
                        handle.status = "error"
                handle.publish(
                    {
                        "type": "error",
                        "message": str(exc),
                        "count": 0,
                        "manifest": None,
                        "manifest_path": None,
                    }
                )
                raise
            return handle
        except Exception as exc:
            self.fail_admission(handle, str(exc))
            raise

    def _worker(self, handle: RunHandle, request: RunRequest) -> None:
        streamed = 0
        orchestrator = handle.orchestrator
        if orchestrator is None:  # pragma: no cover - start promotes before spawning
            handle.status = "error"
            self._offer(handle, {"type": "error", "message": "run was not admitted"})
            return

        def on_event(line: str, _event: EventRecord) -> None:
            nonlocal streamed
            # Orchestrator calls on_event exactly once after a CEF line renders
            # and its rendered-count checkpoint advances. Track every such line,
            # including those beyond the browser stream cap. on_progress assigns
            # the same count at its coarser SSE cadence, so it does not add again.
            handle.event_count += 1
            if streamed >= MAX_STREAM_LINES:
                return
            streamed += 1
            handle.publish({"type": "line", "data": line})

        def on_progress(count: int, total: int) -> None:
            # The queue drives a connected SSE consumer, while the handle drives
            # restored panels through both status endpoints. Keep those views on
            # the same callback count before publishing it to subscribers.
            handle.event_count = count
            handle.publish({"type": "progress", "count": count, "total": total})

        try:
            result = orchestrator.run(
                request,
                on_progress=on_progress,
                on_event=on_event,
                run_id=handle.run_id,
                _reset_stop=False,
            )
            handle.manifest = result.manifest.model_dump()
            handle.manifest_path = str(result.manifest_path)
            handle.event_count = result.event_count
            # Status is the publication barrier for status readers. Populate the
            # complete terminal snapshot first, then make it terminal, so a poll
            # can never observe done/stopped with stale manifest or count fields.
            handle.status = "stopped" if result.stopped else "done"
            self._offer(
                handle,
                {
                    "type": "done",
                    "status": handle.status,
                    "count": result.event_count,
                    "dropped": handle.dropped,
                    "manifest": handle.manifest,
                    "manifest_path": handle.manifest_path,
                },
            )
        except Exception as exc:  # noqa: BLE001 - report any failure to the client
            # A failed run still wrote a manifest (F-02). Reporting manifest=None
            # and event_count=0 while a complete partial record sat on disk meant
            # the UI could not show what a failed run had actually done, which is
            # most of what the audit guarantee was for.
            record = run_record_of(exc) or {}
            handle.manifest = record.get("manifest")
            handle.manifest_path = record.get("manifest_path")
            handle.event_count = int(record.get("event_count") or 0)
            # As on the successful path, terminal status is assigned only after
            # every field a status reader treats as final is ready.
            handle.status = "error"
            self._offer(
                handle,
                {
                    "type": "error",
                    "message": str(exc),
                    "count": handle.event_count,
                    "manifest": handle.manifest,
                    "manifest_path": handle.manifest_path,
                },
            )

    @staticmethod
    def _offer(handle: RunHandle, item: dict[str, Any]) -> None:
        """Deliver a terminal item, tolerating a client that has stopped reading."""

        handle.publish(item)
