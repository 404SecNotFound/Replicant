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

    Carries the technique as well as the id. The id alone is a hex string the
    operator has no way to resolve, which made the 409 unactionable: a run they
    could not see was refusing runs they could.
    """

    def __init__(self, active_run_id: str, technique_id: str = "") -> None:
        named = f" ({technique_id})" if technique_id else ""
        super().__init__(f"a run is already in progress: {active_run_id}{named}")
        self.active_run_id = active_run_id
        self.technique_id = technique_id


@dataclass
class RunHandle:
    run_id: str
    orchestrator: Orchestrator
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

        with self._fanout_lock:
            self.history.append(item)
            if len(self.history) > MAX_HISTORY_ITEMS:
                del self.history[: len(self.history) - MAX_HISTORY_ITEMS]
            for subscriber in list(self.subscribers):
                try:
                    subscriber.put_nowait(item)
                except Full:
                    self.dropped += 1


class RunManager:
    def __init__(self, catalog: Catalog, settings: Settings) -> None:
        self.catalog = catalog
        self.settings = settings
        self._runs: dict[str, RunHandle] = {}
        self._lock = threading.Lock()

    def get(self, run_id: str) -> RunHandle | None:
        with self._lock:
            return self._runs.get(run_id)

    def stop(self, run_id: str) -> bool:
        handle = self.get(run_id)
        if handle is None:
            return False
        handle.orchestrator.stop()
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
                del self._runs[rid]

    def start(
        self,
        request: RunRequest,
        settings: Settings | None = None,
        total: int | None = None,
    ) -> RunHandle:
        """Start a run. ``total`` skips a plan build the caller has already done.

        Building the plan is pure CPU but not free: REP-004 at high intensity is
        180,000 events and about 1.6 seconds. The endpoint now previews the run to
        price its pacing before starting it, and that preview already knows the
        count, so passing it through keeps a start at the two builds it always
        cost rather than three.
        """

        # One active run at a time: reject before doing any work so a second start
        # cannot spin up a second limiter against the same collector.
        with self._lock:
            active = self._active_locked()
            if active is not None:
                raise RunInProgressError(active.run_id, active.technique_id)
        self._evict_terminal()

        orchestrator = Orchestrator(self.catalog, settings or self.settings)
        if total is None:
            total = len(orchestrator.build_plan(request))
        events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=QUEUE_MAXSIZE)
        handle = RunHandle(
            # Same format the CLI and the manifest use, and passed into
            # orchestrator.run below so the manifest on disk carries this exact
            # id. The web 409 used to name a bare hex handle id that resolved to
            # nothing an operator could look up.
            run_id=new_run_id(),
            orchestrator=orchestrator,
            queue=events,
            total=total,
            technique_id=request.technique_id,
        )
        # Re-check under the lock: another start could have registered in the gap.
        with self._lock:
            active = self._active_locked()
            if active is not None:
                raise RunInProgressError(active.run_id, active.technique_id)
            self._runs[handle.run_id] = handle
        thread = threading.Thread(target=self._worker, args=(handle, request), daemon=True)
        handle.thread = thread
        thread.start()
        return handle

    def _worker(self, handle: RunHandle, request: RunRequest) -> None:
        streamed = 0

        def on_event(line: str, _event: EventRecord) -> None:
            nonlocal streamed
            if streamed >= MAX_STREAM_LINES:
                return
            streamed += 1
            handle.publish({"type": "line", "data": line})

        def on_progress(count: int, total: int) -> None:
            handle.publish({"type": "progress", "count": count, "total": total})

        try:
            result = handle.orchestrator.run(
                request, on_progress=on_progress, on_event=on_event, run_id=handle.run_id
            )
            handle.status = "stopped" if result.stopped else "done"
            handle.manifest = result.manifest.model_dump()
            handle.manifest_path = str(result.manifest_path)
            handle.event_count = result.event_count
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
            handle.status = "error"
            # A failed run still wrote a manifest (F-02). Reporting manifest=None
            # and event_count=0 while a complete partial record sat on disk meant
            # the UI could not show what a failed run had actually done, which is
            # most of what the audit guarantee was for.
            record = run_record_of(exc) or {}
            handle.manifest = record.get("manifest")
            handle.manifest_path = record.get("manifest_path")
            handle.event_count = int(record.get("event_count") or 0)
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
