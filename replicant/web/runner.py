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
from dataclasses import dataclass
from typing import Any

from replicant.config.settings import Settings
from replicant.core.models import Catalog, EventRecord, RunRequest
from replicant.core.orchestrator import Orchestrator

MAX_STREAM_LINES = 2000
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
    queue: queue.Queue[dict[str, Any]]
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
            run_id=uuid.uuid4().hex,
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
            try:
                handle.queue.put_nowait({"type": "line", "data": line})
            except queue.Full:
                handle.dropped += 1

        def on_progress(count: int, total: int) -> None:
            try:
                handle.queue.put_nowait({"type": "progress", "count": count, "total": total})
            except queue.Full:
                pass

        try:
            result = handle.orchestrator.run(request, on_progress=on_progress, on_event=on_event)
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
            self._offer(handle, {"type": "error", "message": str(exc)})

    @staticmethod
    def _offer(handle: RunHandle, item: dict[str, Any]) -> None:
        """Deliver a terminal item, tolerating a client that has stopped reading."""

        try:
            handle.queue.put(item, timeout=5.0)
        except queue.Full:  # pragma: no cover - consumer gone; status/manifest still on handle
            pass
