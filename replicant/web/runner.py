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


@dataclass
class RunHandle:
    run_id: str
    orchestrator: Orchestrator
    queue: queue.Queue[dict[str, Any]]
    total: int
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

    def start(self, request: RunRequest) -> RunHandle:
        orchestrator = Orchestrator(self.catalog, self.settings)
        total = len(orchestrator.build_plan(request))
        events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=QUEUE_MAXSIZE)
        handle = RunHandle(
            run_id=uuid.uuid4().hex,
            orchestrator=orchestrator,
            queue=events,
            total=total,
        )
        with self._lock:
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
