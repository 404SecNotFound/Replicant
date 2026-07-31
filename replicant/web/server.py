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

Access: the server binds loopback by default but any local address is allowed, so the
controls do not assume a local-only listener. Every API and websocket call requires
the persistent token, accepted as a Bearer header, an ``X-Replicant-Token`` header, a
query parameter, or an httpOnly ``SameSite=Strict`` session cookie. A middleware
rejects any Host that is not the bind address, loopback, or an explicitly allowed
name (the DNS-rebinding guard). Because the cookie is the only credential a browser
attaches by itself, a cookie-authenticated write must also carry a matching Origin.
The terminal websocket repeats all of that inline: websocket scopes never traverse
HTTP middleware, and it is off by default whenever the bind is not loopback.

Web runs use the same fail-closed Orchestrator, eps cap, and manifest as the CLI.
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import ipaddress
import json
import os
import queue
import secrets
import socket
import sys
import threading
import webbrowser
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocket

from replicant import __version__
from replicant import resources as _resources
from replicant.config.settings import (
    VENDORS,
    WEB_DEFAULT_PORT,
    Settings,
    load_or_create_web_token,
    parse_anchor,
    stale_anchor_warning,
    web_token_path,
)
from replicant.core.models import Catalog, CollectorProfile, Intensity, RunRequest, Transport
from replicant.core.orchestrator import Orchestrator, effective_identity
from replicant.obs import log as obs_log
from replicant.scenario.engine import implemented_technique_ids
from replicant.web.pty_bridge import bridge_terminal
from replicant.web.runner import RunInProgressError, RunManager

FRONTEND_DIST = _resources.FRONTEND_DIST
DOCS_DIR = _resources.DOCS_DIR


@dataclass(frozen=True)
class DocPage:
    id: str
    title: str
    filename: str


# The reference material the Docs tab serves, as a fixed allowlist. The requested
# id is a dictionary key and is never joined onto a path, so a traversal attempt
# resolves to nothing rather than to a file.
#
# These read from the repository, not the installed package. The catalogs and the
# built frontend now live inside `replicant/` and ship in a wheel; docs/ does not,
# deliberately. It is documentation rather than runtime data, and duplicating it
# into the package would guarantee the two copies drift. A wheel install therefore
# has no reference docs, and these endpoints say so rather than failing.
DOC_PAGES: tuple[DocPage, ...] = (
    DocPage("fortigate-cef", "FortiGate CEF reference", "fortigate-cef-reference.md"),
    DocPage("paloalto-cef", "Palo Alto PAN-OS CEF reference", "paloalto-cef-reference.md"),
    DocPage("checkpoint-cef", "Check Point CEF reference", "checkpoint-cef-reference.md"),
    DocPage(
        "catalog-research",
        "Catalog expansion research",
        "technique-catalog-expansion-research.md",
    ),
    DocPage(
        "catalog-research-2",
        "Catalog expansion research, round 2",
        "technique-catalog-expansion-research-round2.md",
    ),
)
_DOC_BY_ID = {page.id: page for page in DOC_PAGES}

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_WILDCARD_BINDS = frozenset({"0.0.0.0", "::"})

# Set on the first authenticated load so the token does not have to live in the
# URL bar for the rest of the session.
SESSION_COOKIE = "replicant_session"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _normalize_host(value: str) -> str:
    """Fold a host to one comparable form: lower-cased, IPv6 brackets stripped."""
    text = value.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def _hostname_of(header_value: str) -> str:
    """Strip the optional ``:port`` from a Host or Origin authority.

    A bare ``rsplit(":", 1)`` truncates an unbracketed IPv6 literal to its own
    prefix, so bracketed forms are handled first and an unbracketed value is only
    split when it carries exactly one colon.
    """
    text = header_value.strip()
    if text.startswith("["):
        end = text.find("]")
        return text if end == -1 else text[: end + 1]
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _authority_of(origin: str) -> str:
    """Reduce an Origin (``scheme://host:port``) to the authority the Host guard reads."""
    _, separator, rest = origin.partition("://")
    return rest if separator else origin


def is_loopback(host: str) -> bool:
    """True when a bind address reaches only this machine.

    Replaces the old ``_require_loopback``, which refused any other address
    outright. Remote hosting is now supported, so this is no longer a gate: it
    decides the two defaults that depend on exposure, the terminal tab and whether
    ``--no-auth`` needs an explicit acknowledgement.
    """
    normalized = _normalize_host(host)
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class AccessPolicy:
    """Who may reach this server, decided once at bind time.

    The Host guard used to hardcode localhost, which made ``--host`` unusable: an
    operator who bound to a routable address then had to defeat their own
    DNS-rebinding check to open the page. The allowlist now follows the address the
    server was actually told to bind, plus loopback, plus anything named with
    ``--allowed-host``.
    """

    allowed_hosts: frozenset[str] = LOOPBACK_HOSTS
    wildcard_bind: bool = False
    terminal_enabled: bool = True
    require_auth: bool = True

    @classmethod
    def for_bind(
        cls,
        host: str,
        extra: Iterable[str] = (),
        *,
        enable_terminal: bool = False,
    ) -> AccessPolicy:
        """Derive the policy from the address the operator asked to bind.

        ``enable_terminal`` is the ``--enable-terminal`` flag, so False means "use
        the default for this bind" rather than "off": the terminal is on for
        loopback either way, and the flag is what turns it back on elsewhere.
        """
        normalized = _normalize_host(host)
        wildcard = normalized in _WILDCARD_BINDS
        allowed = set(LOOPBACK_HOSTS)
        if not wildcard:
            allowed.add(normalized)
        allowed.update(_normalize_host(value) for value in extra if value.strip())
        return cls(
            allowed_hosts=frozenset(allowed),
            wildcard_bind=wildcard,
            terminal_enabled=is_loopback(host) or enable_terminal,
        )

    def allows_host(self, header_value: str) -> bool:
        """Accept a Host (or Origin authority) header value.

        On a wildcard bind the machine's own addresses cannot be enumerated without
        probing the network, so any IP *literal* is accepted: DNS rebinding needs a
        hostname whose resolution the attacker controls, and a literal has none. A
        hostname still has to be named explicitly with ``--allowed-host``.
        """
        name = _normalize_host(_hostname_of(header_value))
        if not name:  # HTTP/1.0 client with no Host header; nothing to rebind
            return True
        if name in self.allowed_hosts:
            return True
        return self.wildcard_bind and _is_ip_literal(name)


class CollectorBody(BaseModel):
    host: str
    port: int = Field(default=514, ge=1, le=65535)
    transport: Transport = "udp"
    tls_verify: bool = True
    tls_cafile: str | None = None
    vendor: str | None = None  # override the CEF dialect of the rendered test line


class RunBody(BaseModel):
    technique_id: str
    intensity: Intensity = "medium"
    duration: str | None = None
    seed: int | None = None
    to_file: str | None = None
    no_send: bool = True
    collector: CollectorBody | None = None
    vendor: str | None = None  # override settings.vendor for this run
    # "now", "fixed", an epoch, or an ISO-8601 timestamp. None and "fixed" both mean
    # the deterministic default; everything else goes through the same parse_anchor
    # the CLI uses, so the two surfaces cannot drift.
    anchor: str | None = None


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
                "implemented": technique.id in implemented_technique_ids(),
                "safety_notes": technique.safety_notes,
                "signature_id": technique.fortigate.signature_id,
                "action": technique.fortigate.action,
                "cef_fields_held": technique.cef_fields_held,
                "cef_fields_varied": technique.cef_fields_varied,
                "params": technique.params,
                "distributions": technique.distributions,
                "benign_baseline": technique.benign_baseline,
                "references": technique.references,
            }
        )
    return out


SSE_KEEPALIVE = ": keepalive\n\n"


def sse_log_line(entry: obs_log.LogEntry) -> str:
    """One log record as a server-sent event.

    Module level, and separate from the endpoint, because the log stream has no
    natural end: driving it through a test client to check the wire format means
    reading from a generator that never stops. Testing the formatting here and
    the buffer semantics through the JSON endpoint covers the same ground without
    a test that can only be ended by a timeout.
    """

    return f"data: {json.dumps(entry.as_dict())}\n\n"


def create_app(
    catalog: Catalog,
    settings: Settings,
    token: str,
    policy: AccessPolicy | None = None,
) -> FastAPI:
    policy = policy or AccessPolicy()
    app = FastAPI(title="Replicant", version=__version__, docs_url=None, redoc_url=None)
    # Idempotent, so a test that builds several apps does not stack handlers.
    obs_log.install()
    manager = RunManager(catalog, settings)
    base_orchestrator = Orchestrator(catalog, settings)

    def _resolve_vendor(vendor: str | None) -> str:
        if vendor is not None and vendor not in VENDORS:
            raise HTTPException(status_code=400, detail=f"unknown vendor: {vendor}")
        return vendor or settings.vendor

    def _settings_for(vendor: str | None) -> Settings:
        resolved = _resolve_vendor(vendor)
        if resolved == settings.vendor:
            return settings
        return settings.model_copy(update={"vendor": resolved})

    def _resolve_anchor(value: str | None) -> int:
        """Resolve the run form's anchor control to an epoch.

        ``fixed`` is the form's name for the deterministic default and is not
        something ``parse_anchor`` knows, so it is translated here rather than
        being allowed to fall through and 400.
        """
        if value is None or value.strip().lower() == "fixed":
            return settings.anchor_epoch
        return parse_anchor(value)

    def _orchestrator_for(vendor: str | None) -> Orchestrator:
        resolved = _resolve_vendor(vendor)
        if resolved == settings.vendor:
            return base_orchestrator
        return Orchestrator(catalog, settings.model_copy(update={"vendor": resolved}))

    def _authenticated_source(request: HTTPConnection) -> str | None:
        """Return which credential authenticated this request, or None.

        Explicit sources are checked before the cookie, because the source decides
        whether the CSRF rule applies: a request that carried a header or query
        token proved intent, while a cookie is attached by the browser whether the
        page meant it or not.

        Each candidate is skipped when empty. ``compare_digest("", "")`` is true,
        so an absent credential must never reach the comparison.
        """
        scheme, _, bearer = (request.headers.get("authorization") or "").partition(" ")
        candidates = (
            ("header", bearer.strip() if scheme.lower() == "bearer" else ""),
            ("header", request.headers.get("x-replicant-token") or ""),
            ("query", request.query_params.get("token") or ""),
            ("cookie", request.cookies.get(SESSION_COOKIE) or ""),
        )
        for source, supplied in candidates:
            if supplied and secrets.compare_digest(token, supplied):
                return source
        return None

    def _origin_ok(connection: HTTPConnection, *, required: bool) -> bool:
        """Validate the Origin header. ``required`` rejects its absence outright."""
        origin = connection.headers.get("origin") or ""
        if not origin:
            return not required
        return policy.allows_host(_authority_of(origin))

    def require_token(request: Request) -> None:
        if not policy.require_auth:
            return
        source = _authenticated_source(request)
        if source is None:
            raise HTTPException(status_code=401, detail="invalid or missing token")
        if source == "cookie" and request.method not in _SAFE_METHODS:
            # The cookie is the only ambient credential here, so it is the only one
            # a cross-site page can spend. SameSite=Strict already blocks that in a
            # current browser; this covers the ones that do not honour it. Browsers
            # send Origin on every non-GET, so its absence here is not the SPA.
            if not _origin_ok(request, required=True):
                raise HTTPException(status_code=403, detail="cross-origin write rejected")

    @app.middleware("http")
    async def _session_cookie(request: Request, call_next: Any) -> Any:
        """Promote an explicit token to a session cookie once it has worked.

        This lives in middleware rather than a route because ``StaticFiles`` is
        mounted at ``/``: the page the operator actually opens is served by the
        mount, so no handler in this module ever sees it.
        """
        source = _authenticated_source(request)
        response = await call_next(request)
        if source is not None and source != "cookie" and response.status_code < 400:
            response.set_cookie(
                SESSION_COOKIE,
                token,
                httponly=True,
                samesite="strict",
                path="/",
            )
        return response

    @app.middleware("http")
    async def _host_guard(request: Request, call_next: Any) -> Any:
        # Registered last, so it is the outermost layer: a rejected Host never
        # reaches the cookie logic or a route.
        if not policy.allows_host(request.headers.get("host") or ""):
            return JSONResponse(status_code=403, content={"detail": "host not allowed"})
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

    @app.get("/api/catalog/{technique_id}/sample", dependencies=[Depends(require_token)])
    def technique_sample(
        technique_id: str,
        vendor: str | None = Query(default=None),
        intensity: str = Query(default="low"),
    ) -> dict[str, Any]:
        try:
            technique = catalog.by_id(technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        orch = _orchestrator_for(vendor)
        request = RunRequest(
            technique_id=technique_id,
            intensity=intensity if intensity in technique.params else settings.default_intensity,
            seed=settings.default_seed,
            no_send=True,
        )
        events = list(orch.build_plan(request).events)
        if events:
            idxs = sorted({0, len(events) // 2, len(events) - 1})
            lines = [orch.render_line(events[i]) for i in idxs]
        else:
            lines = []
        return {
            "technique_id": technique.id,
            "vendor": _resolve_vendor(vendor),
            "intensity": request.intensity,
            "log_type": technique.fortigate.log_type,
            "subtype": technique.fortigate.subtype,
            "signature_id": technique.fortigate.signature_id,
            "cef_fields_held": technique.cef_fields_held,
            "cef_fields_varied": technique.cef_fields_varied,
            "lines": lines,
        }

    @app.get("/api/config", dependencies=[Depends(require_token)])
    def get_config() -> dict[str, Any]:
        hostname, accepted_as = effective_identity(settings)
        return {
            "default_seed": settings.default_seed,
            "eps_cap": settings.eps_cap,
            "default_intensity": settings.default_intensity,
            "hostname": hostname,
            "anchor_epoch": settings.anchor_epoch,
            "accepted_as": accepted_as,
            "vendor": settings.vendor,
            "vendors": list(VENDORS),
            "terminal_enabled": policy.terminal_enabled,
        }

    @app.get("/api/docs", dependencies=[Depends(require_token)])
    def list_docs() -> dict[str, Any]:
        return {
            "available": DOCS_DIR.is_dir(),
            "pages": [
                {
                    "id": page.id,
                    "title": page.title,
                    "available": (DOCS_DIR / page.filename).is_file(),
                }
                for page in DOC_PAGES
            ],
        }

    @app.get("/api/docs/{doc_id}", dependencies=[Depends(require_token)])
    def get_doc(doc_id: str) -> dict[str, Any]:
        page = _DOC_BY_ID.get(doc_id)
        if page is None:
            raise HTTPException(status_code=404, detail="unknown document")
        path = DOCS_DIR / page.filename
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail=(
                    "reference documents are not present in this install. They ship with "
                    "the repository, not the package, so they are available from an "
                    "editable install (pip install -e) or a git checkout."
                ),
            )
        return {
            "id": page.id,
            "title": page.title,
            "markdown": path.read_text(encoding="utf-8"),
        }

    @app.post("/api/connect/test", dependencies=[Depends(require_token)])
    def connect_test(body: CollectorBody) -> dict[str, Any]:
        orch = _orchestrator_for(body.vendor)
        collector = CollectorProfile(
            name="web",
            host=body.host,
            port=body.port,
            transport=body.transport,
            tls_verify=body.tls_verify,
            tls_cafile=body.tls_cafile,
        )
        try:
            ok = orch.send_test(collector)
        except OSError as exc:
            return {"ok": False, "error": str(exc), "endpoint": collector.endpoint()}
        return {
            "ok": ok,
            "endpoint": collector.endpoint(),
            "line": orch.build_test_line(),
        }

    @app.post("/api/runs", dependencies=[Depends(require_token)])
    def start_run(body: RunBody) -> dict[str, Any]:
        try:
            catalog.by_id(body.technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        _resolve_vendor(body.vendor)  # 400 on an unknown vendor before starting
        try:
            anchor = _resolve_anchor(body.anchor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"bad anchor: {exc}") from exc
        collector = None
        if body.collector is not None:
            collector = CollectorProfile(
                name="web",
                host=body.collector.host,
                port=body.collector.port,
                transport=body.collector.transport,
                tls_verify=body.collector.tls_verify,
                tls_cafile=body.collector.tls_cafile,
            )
        request = RunRequest(
            technique_id=body.technique_id,
            intensity=body.intensity,
            seed=body.seed if body.seed is not None else settings.default_seed,
            duration=body.duration,
            to_file=body.to_file,
            no_send=body.no_send,
            collector=collector,
            anchor_epoch=anchor,
        )
        try:
            handle = manager.start(request, settings=_settings_for(body.vendor))
        except RunInProgressError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (RuntimeError, NotImplementedError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "run_id": handle.run_id,
            "total": handle.total,
            "anchor_epoch": anchor,
            "anchor_warning": stale_anchor_warning(
                anchor, sending=not body.no_send and collector is not None
            ),
        }

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

    # -- logs ------------------------------------------------------------------
    #
    # The buffer is in this process, so these endpoints read memory and never
    # touch the network. Safety rule 1 is unaffected: no new egress exists here.

    @app.get("/api/logs", dependencies=[Depends(require_token)])
    def logs_index(after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=5000)) -> Any:
        entries = obs_log.snapshot(after=after, limit=limit)
        return {
            "level": obs_log.current_level(),
            "levels": list(obs_log.LEVEL_NAMES),
            "entries": [entry.as_dict() for entry in entries],
            # The client tails from here. Sent explicitly rather than inferred from
            # the last entry, so an empty page still advances the cursor.
            "cursor": entries[-1].seq if entries else after,
        }

    @app.put("/api/logs/level", dependencies=[Depends(require_token)])
    def set_log_level(payload: dict[str, str]) -> Any:
        level = payload.get("level", "")
        try:
            obs_log.set_level(level)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        obs_log.get_logger("web").info("log level set to %s", level)
        return {"level": obs_log.current_level()}

    @app.get("/api/logs/stream", dependencies=[Depends(require_token)])
    def stream_logs(request: Request, after: int = Query(0, ge=0)) -> StreamingResponse:
        async def generator() -> Any:
            cursor = after
            # Unlike the run stream, this one has no natural end: the log buffer
            # outlives every run. Without the disconnect check each closed Logs
            # tab would leave a task polling the ring for the life of the process.
            while not await request.is_disconnected():
                entries = obs_log.snapshot(after=cursor)
                if entries:
                    cursor = entries[-1].seq
                    for entry in entries:
                        yield sse_log_line(entry)
                else:
                    yield SSE_KEEPALIVE
                # Polling the ring rather than fanning out per-subscriber queues.
                # One buffer, many readers, each holding only an integer cursor,
                # so a slow client cannot stall the emit loop.
                await asyncio.sleep(0.4)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.websocket("/ws/terminal")
    async def terminal(websocket: WebSocket) -> None:
        # Every check the /api routes get from middleware and dependencies is
        # repeated here by hand. A websocket scope never traverses HTTP
        # middleware, so the Host guard above does not cover this endpoint. That
        # was invisible while the bind was loopback-only and is not any more.
        if not policy.terminal_enabled:
            await websocket.close(code=1008)
            return
        if not policy.allows_host(websocket.headers.get("host") or ""):
            await websocket.close(code=1008)
            return
        source = _authenticated_source(websocket)
        if source is None:
            await websocket.close(code=1008)
            return
        if not _origin_ok(websocket, required=source == "cookie"):
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


def check_unauthenticated_exposure(host: str, *, no_auth: bool, acknowledged: bool) -> None:
    """Refuse ``--no-auth`` on an address other machines can reach.

    Turning auth off on loopback is a convenience. Turning it off on a routable
    address publishes an unauthenticated run trigger, and the embedded terminal
    with it, to everything that can route to the host. That needs a deliberate
    second flag, not a default.
    """
    if not no_auth or acknowledged or is_loopback(host):
        return
    raise ValueError(
        f"--no-auth refused: {host} is reachable from other machines, which would expose "
        "an unauthenticated run trigger and the embedded terminal. Pass "
        "--i-understand-this-is-unauthenticated to override, or drop --no-auth."
    )


def bind_socket(host: str, port: int) -> socket.socket:
    """Bind the listening socket, failing loudly when the fixed port is taken.

    The port is fixed so the URL stays predictable across restarts. Falling back to
    a different port on a conflict would quietly undo that, so a conflict is an
    error naming both the port and the flag that changes it.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as exc:
        sock.close()
        raise OSError(
            f"cannot bind {host}:{port} ({exc.strerror or exc}). "
            f"Free port {port} or choose another with --port."
        ) from exc
    return sock


def display_available(platform: str, env: Mapping[str, str]) -> bool:
    """Whether opening a browser could possibly work.

    On a headless Linux host ``webbrowser.open`` shells out to ``gio``, which
    printed "Operation not supported" over the startup banner on every run. There
    is no display to open into, so do not try.
    """
    if platform.startswith("darwin") or platform.startswith("win"):
        return True
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def display_url(host: str, port: int, token: str | None) -> str:
    """A URL someone can actually open.

    A wildcard bind has no address of its own, and ``http://0.0.0.0:9787`` is not
    openable, so the loopback form is printed and the all-interfaces fact is stated
    separately rather than being smuggled into a broken link.
    """
    display_host = "127.0.0.1" if _normalize_host(host) in _WILDCARD_BINDS else host
    if ":" in display_host and not display_host.startswith("["):
        display_host = f"[{display_host}]"
    return f"http://{display_host}:{port}/" + (f"?token={token}" if token else "")


def _no_auth_warning(host: str, port: int) -> list[str]:
    return [
        "",
        "  ####################################################################",
        "  #  AUTHENTICATION IS DISABLED (--no-auth)                          #",
        f"  #  Anyone who can reach {host}:{port} can start runs against your",
        "  #  collector with no credential of any kind.",
        "  #  The embedded terminal, when enabled, is a real shell-adjacent PTY",
        "  #  and is exposed on the same terms.",
        "  ####################################################################",
        "",
    ]


def startup_lines(
    host: str,
    port: int,
    *,
    token: str | None,
    token_state: str,
    terminal: bool,
    reveal_token: bool = True,
    token_path: str | None = None,
) -> list[str]:
    """The startup banner: URL, then token state, then terminal state.

    ``reveal_token`` is False when stdout is not a terminal, which under systemd
    means the journal. Printing the token there writes it in cleartext to a file
    readable by root and the systemd-journal group, giving away precisely what the
    0600 token file protects. In that case the banner names the file instead, and
    drops the Ctrl-C hint, since nobody is at a keyboard.
    """
    wildcard = _normalize_host(host) in _WILDCARD_BINDS
    url = display_url(host, port, token if reveal_token else None)
    bind = f"{host}:{port}" + (" (all interfaces)" if wildcard else "")
    token_line = token_state
    if token and not reveal_token:
        token_line = f"{token_state}, read it from {token_path or web_token_path()}"
    lines = [
        "Replicant web UI",
        f"  URL      : {url}",
        f"  bind     : {bind}",
        f"  token    : {token_line}",
        f"  terminal : {'enabled' if terminal else 'disabled (--enable-terminal to allow)'}",
    ]
    if reveal_token:
        lines.append("  stop     : Ctrl-C")
    if wildcard:
        lines.insert(
            2, f"  remote   : http://<this host's address>:{port}/ from the rest of the segment"
        )
    return lines


def serve(
    catalog: Catalog,
    settings: Settings,
    host: str = "127.0.0.1",
    port: int = WEB_DEFAULT_PORT,
    open_browser: bool = True,
    allowed_hosts: Iterable[str] = (),
    no_auth: bool = False,
    acknowledged_unauthenticated: bool = False,
    rotate_token: bool = False,
    enable_terminal: bool = False,
) -> None:
    """Start the web server on a fixed port and print how to reach it."""

    check_unauthenticated_exposure(host, no_auth=no_auth, acknowledged=acknowledged_unauthenticated)

    if no_auth:
        token, token_state = "", "disabled (--no-auth)"
        for line in _no_auth_warning(host, port):
            print(line, flush=True)
    else:
        token, token_state = load_or_create_web_token(rotate=rotate_token)

    policy = AccessPolicy.for_bind(host, allowed_hosts, enable_terminal=enable_terminal)
    policy = dataclasses.replace(policy, require_auth=not no_auth)
    app = create_app(catalog, settings, token, policy)

    sock = bind_socket(host, port)
    bound_port = int(sock.getsockname()[1])

    # A non-tty stdout means something is capturing this: under systemd, the
    # journal. The token must not go there.
    reveal = sys.stdout.isatty()
    for line in startup_lines(
        host,
        bound_port,
        token=token or None,
        token_state=token_state,
        terminal=policy.terminal_enabled,
        reveal_token=reveal,
        token_path=str(web_token_path()),
    ):
        print(line, flush=True)

    if open_browser and display_available(sys.platform, os.environ):
        url = display_url(host, bound_port, token or None)
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    # Force the stdlib asyncio loop rather than uvloop: the terminal bridge relies
    # on loop.add_reader on a PTY master fd, which the selector loop supports
    # reliably (uvloop does not re-fire it dependably for PTYs).
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", loop="asyncio"))
    server.run(sockets=[sock])
