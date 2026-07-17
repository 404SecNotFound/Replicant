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
"""FastAPI backend for the Replicant web UI.

Exposes the same capabilities as the CLI and menu by calling the Orchestrator:
browse the catalog, send a test log, run a technique with a live event stream and
a stop control, and open the real terminal menu over a websocket PTY bridge.

Safety: the server binds to loopback only, every API and websocket call requires a
per-session token, and a middleware rejects requests whose Host header is not
localhost (a DNS-rebinding guard). Web runs use the same fail-closed Orchestrator,
eps cap, and manifest as the CLI.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import queue
import secrets
import socket
import threading
import webbrowser
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.websockets import WebSocket

from replicant import __version__
from replicant.config.settings import Settings
from replicant.core.models import Catalog, CollectorProfile, RunRequest
from replicant.core.orchestrator import Orchestrator
from replicant.web.pty_bridge import bridge_terminal
from replicant.web.runner import RunManager

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "webui" / "dist"


class CollectorBody(BaseModel):
    host: str
    port: int = 514
    transport: str = "udp"


class RunBody(BaseModel):
    technique_id: str
    intensity: str = "medium"
    duration: str | None = None
    seed: int | None = None
    to_file: str | None = None
    no_send: bool = True
    collector: CollectorBody | None = None


def _technique_json(catalog: Catalog) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for technique in catalog.techniques:
        out.append(
            {
                "id": technique.id,
                "name": technique.name,
                "ndr_rule": technique.ndr_rule,
                "ndr_uc": technique.ndr_uc,
                "log_type": technique.fortigate.log_type,
                "subtype": technique.fortigate.subtype,
                "attack": technique.attack.techniques,
                "tactics": technique.attack.tactics,
                "intensities": sorted(technique.params.keys()),
                "implemented": technique.id
                in {"REP-001", "REP-002", "REP-003", "REP-004", "REP-005", "REP-006", "REP-010"},
                "safety_notes": technique.safety_notes,
            }
        )
    return out


def create_app(catalog: Catalog, settings: Settings, token: str) -> FastAPI:
    app = FastAPI(title="Replicant", version=__version__, docs_url=None, redoc_url=None)
    manager = RunManager(catalog, settings)
    base_orchestrator = Orchestrator(catalog, settings)

    def require_token(
        token_q: str | None = Query(default=None, alias="token"),
        token_h: str | None = Header(default=None, alias="x-replicant-token"),
    ) -> None:
        if not secrets.compare_digest(token, token_q or token_h or ""):
            raise HTTPException(status_code=401, detail="invalid or missing token")

    @app.middleware("http")
    async def _localhost_only(request: Request, call_next: Any) -> Any:
        hostname = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if hostname and hostname not in _ALLOWED_HOSTS:
            return JSONResponse(status_code=403, content={"detail": "non-local host rejected"})
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "vendor": catalog.vendor_profile}

    @app.get("/api/catalog", dependencies=[Depends(require_token)])
    def get_catalog() -> dict[str, Any]:
        return {
            "vendor_profile": catalog.vendor_profile,
            "timezone": catalog.timezone,
            "techniques": _technique_json(catalog),
        }

    @app.get("/api/config", dependencies=[Depends(require_token)])
    def get_config() -> dict[str, Any]:
        return {
            "default_seed": settings.default_seed,
            "eps_cap": settings.eps_cap,
            "default_intensity": settings.default_intensity,
            "hostname": settings.hostname,
            "anchor_epoch": settings.anchor_epoch,
            "accepted_as": settings.accepted_as,
        }

    @app.post("/api/connect/test", dependencies=[Depends(require_token)])
    def connect_test(body: CollectorBody) -> dict[str, Any]:
        collector = CollectorProfile(
            name="web", host=body.host, port=body.port, transport=body.transport
        )
        try:
            ok = base_orchestrator.send_test(collector)
        except OSError as exc:
            return {"ok": False, "error": str(exc), "endpoint": collector.endpoint()}
        return {
            "ok": ok,
            "endpoint": collector.endpoint(),
            "line": base_orchestrator.build_test_line(),
        }

    @app.post("/api/runs", dependencies=[Depends(require_token)])
    def start_run(body: RunBody) -> dict[str, Any]:
        try:
            catalog.by_id(body.technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        collector = None
        if body.collector is not None:
            collector = CollectorProfile(
                name="web",
                host=body.collector.host,
                port=body.collector.port,
                transport=body.collector.transport,
            )
        request = RunRequest(
            technique_id=body.technique_id,
            intensity=body.intensity,
            seed=body.seed if body.seed is not None else settings.default_seed,
            duration=body.duration,
            to_file=body.to_file,
            no_send=body.no_send,
            collector=collector,
        )
        try:
            handle = manager.start(request)
        except (RuntimeError, NotImplementedError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"run_id": handle.run_id, "total": handle.total}

    @app.get("/api/runs/{run_id}", dependencies=[Depends(require_token)])
    def run_status(run_id: str) -> dict[str, Any]:
        handle = manager.get(run_id)
        if handle is None:
            raise HTTPException(status_code=404, detail="unknown run")
        return {
            "run_id": handle.run_id,
            "status": handle.status,
            "total": handle.total,
            "event_count": handle.event_count,
            "dropped": handle.dropped,
            "manifest": handle.manifest,
            "manifest_path": handle.manifest_path,
        }

    @app.post("/api/runs/{run_id}/stop", dependencies=[Depends(require_token)])
    def stop_run(run_id: str) -> dict[str, bool]:
        return {"ok": manager.stop(run_id)}

    @app.get("/api/runs/{run_id}/events", dependencies=[Depends(require_token)])
    def stream_run(run_id: str) -> StreamingResponse:
        handle = manager.get(run_id)
        if handle is None:
            raise HTTPException(status_code=404, detail="unknown run")

        async def generator() -> Any:
            loop = asyncio.get_running_loop()
            getter = functools.partial(handle.queue.get, True, 0.25)
            while True:
                try:
                    item = await loop.run_in_executor(None, getter)
                except queue.Empty:
                    if handle.status != "running" and handle.queue.empty():
                        break
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(item)}\n\n"
                if item["type"] in ("done", "error"):
                    break

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.websocket("/ws/terminal")
    async def terminal(websocket: WebSocket) -> None:
        supplied = websocket.query_params.get("token", "")
        if not secrets.compare_digest(token, supplied):
            await websocket.close(code=1008)
            return
        if os.name != "posix":
            await websocket.accept()
            await websocket.send_text("Embedded terminal requires a POSIX host.\r\n")
            await websocket.close()
            return
        await websocket.accept()
        await bridge_terminal(websocket)

    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI) -> None:
    if FRONTEND_DIST.is_dir():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
        return

    @app.get("/", response_class=HTMLResponse)
    def missing_frontend() -> str:
        return (
            "<h1>Replicant web</h1><p>Frontend build not found. Build it with:</p>"
            "<pre>cd webui &amp;&amp; npm install &amp;&amp; npm run build</pre>"
            "<p>The API is live under <code>/api</code>.</p>"
        )


def serve(
    catalog: Catalog,
    settings: Settings,
    host: str = "127.0.0.1",
    open_browser: bool = True,
) -> None:
    """Start the web server on a random loopback port and print its URL."""

    token = secrets.token_urlsafe(16)
    app = create_app(catalog, settings, token)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    url = f"http://{host}:{port}/?token={token}"

    print("Replicant web UI", flush=True)
    print(f"  URL   : {url}", flush=True)
    print(f"  bind  : {host}:{port} (loopback only)", flush=True)
    print("  stop  : Ctrl-C", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    # Force the stdlib asyncio loop rather than uvloop: the terminal bridge relies
    # on loop.add_reader on a PTY master fd, which the selector loop supports
    # reliably (uvloop does not re-fire it dependably for PTYs).
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", loop="asyncio"))
    server.run(sockets=[sock])
