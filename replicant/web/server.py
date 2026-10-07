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
a credential: either the persistent launch token (a Bearer header, an
``X-Replicant-Token`` header, or a query parameter), or the httpOnly
``SameSite=Strict`` session cookie the server issues in exchange for it. The cookie
holds a short-lived random id from :class:`SessionStore`, never the launch token
itself, so it expires, can be revoked one browser at a time, and is worth nothing
once it lapses. The initial bootstrap navigation carries the launch token only
until the server exchanges it and redirects to a clean URL, before any SPA code
is served. Subsequent API, SSE, and WebSocket requests rely only on the cookie. A middleware
rejects any Host that is not the bind address, loopback, or an explicitly allowed
name (the DNS-rebinding guard). Because the cookie is the only credential a browser
attaches by itself, a cookie-authenticated write must also carry a matching Origin.
The terminal websocket repeats all of that inline: websocket scopes never traverse
HTTP middleware, and it is off by default whenever the bind is not loopback, a
non-loopback ``--allowed-host`` is configured, or ``--collector-allow`` is set.

Resource bounds from the 2026-09-26 review (``docs/security-review-2026-09-26.md``):
request bodies are capped before they are read and unauthenticated writes are
refused before their body is read, one validation runs at a time and never beside
a run, plan pricing is bounded, connect tests are rate limited, and live event
streams are capped. See :mod:`replicant.web.guards`.

Web runs use the same fail-closed Orchestrator, eps cap, and manifest as the CLI.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import hashlib
import ipaddress
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
import webbrowser
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode
from uuid import UUID

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocket

from replicant import __version__
from replicant import resources as _resources
from replicant.config.confine import ConfinementError, confined_output_path
from replicant.config.settings import (
    VENDORS,
    WEB_DEFAULT_PORT,
    Settings,
    config_dir,
    load_or_create_web_token,
    parse_anchor,
    stale_anchor_warning,
    web_token_path,
)
from replicant.core.models import (
    Catalog,
    CollectorHost,
    CollectorProfile,
    Intensity,
    RunRequest,
    Technique,
    Transport,
    validate_duration,
)
from replicant.core.orchestrator import Orchestrator, PacingPreview, effective_identity
from replicant.core.pacing import MAX_SPEED, SPEED_WITHOUT_PLAN, Pace
from replicant.obs import log as obs_log
from replicant.profiles.base import VendorProfile
from replicant.scenario.engine import implemented_technique_ids
from replicant.transport.syslog import probe_collector
from replicant.web.guards import (
    DEFAULT_EVIDENCE_KEEP,
    MAX_STREAMS,
    BodyLimitMiddleware,
    BuildGate,
    CAFileRefused,
    CollectorPolicy,
    GateBusy,
    StreamLimiter,
    TokenBucket,
    confined_cafile,
    prune_evidence,
)
from replicant.web.pty_bridge import MAX_FRAME_BYTES, bridge_terminal
from replicant.web.runner import (
    RunAdmissionError,
    RunHandle,
    RunInProgressError,
    RunManager,
    ValidationInProgressError,
)

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
    DocPage(
        "offline-validation",
        "Offline detection validation",
        "offline-detection-validation.md",
    ),
    DocPage("run-manifest", "Run manifest contract", "run-manifest.md"),
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
    DocPage(
        "catalog-research-5",
        "Catalog research, round 5",
        "technique-catalog-expansion-research-round5.md",
    ),
    DocPage(
        "catalog-research-review",
        "Catalog research review, rounds 1 through 5",
        "catalog-research-review-2026-09-08.md",
    ),
)
_DOC_BY_ID = {page.id: page for page in DOC_PAGES}

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_WILDCARD_BINDS = frozenset({"0.0.0.0", "::"})

# Issued by the tokenized bootstrap redirect before the first SPA document loads,
# so the launch token is absent from browser JavaScript and later requests.
SESSION_COOKIE = "replicant_session"

#: How long a browser session is good for. Long enough that an operator running a
#: four hour plan-paced technique is not logged out mid-run, short enough that a
#: cookie copied off a shared machine is not a permanent credential.
SESSION_TTL_S = 12 * 3600
# A launch-token holder can create browser sessions, but must not be able to grow
# the in-memory credential table without limit.
MAX_BROWSER_SESSIONS = 256

#: Connect tests one credential may run: CONNECT_TEST_BURST per CONNECT_TEST_WINDOW_S.
#: A human testing a collector needs a handful; the endpoint was measured at 311
#: probes a second, which made it a port scanner for anything the host can route
#: to. The global bucket stops minted browser sessions multiplying the allowance.
CONNECT_TEST_BURST = 10
CONNECT_TEST_WINDOW_S = 60.0
CONNECT_TEST_GLOBAL_BURST = 30
#: Summary returned for a connect test that failed before a handshake. The raw
#: exception text distinguished timeouts from resets from TLS and file errors,
#: which is more than a verdict needs and more than a scan should learn.
CONNECT_FAILED_SUMMARY = (
    "The connection attempt failed before a handshake completed. Run "
    "`replicant connect --test` on the server for the underlying error."
)


class SessionStore:
    """Short-lived random session ids, exchanged for the persistent launch token.

    F-04: the cookie used to hold the launch token itself, the same value that
    sits in ``~/.config/replicant/web-token``. That made the cookie the master
    credential: no expiry, no rotation, and no way to revoke one browser without
    regenerating the token file and breaking every other client.

    An id here grants the same access while it lives, and nothing once it does
    not. The launch token remains the bootstrap and the only thing a non-browser
    client needs, because a script cannot run a cookie jar.

    FastAPI executes synchronous dependencies and endpoints in worker threads, so
    every dictionary lifecycle operation is serialized. Session issuance is rare
    enough that a single small lock is simpler and safer than split read/write
    locking or relying on individual dict operations being atomic.
    """

    def __init__(
        self,
        ttl_s: int = SESSION_TTL_S,
        clock: Any = None,
        max_sessions: int = MAX_BROWSER_SESSIONS,
    ) -> None:
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        self.ttl_s = ttl_s
        self.max_sessions = max_sessions
        self._clock = clock or time.monotonic
        self._expiry: dict[str, float] = {}
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._expiry)

    def _sweep(self) -> None:
        """Drop expired ids. Called on issue, so a reconnect loop cannot grow this
        without bound on a long-lived server."""
        with self._lock:
            now = self._clock()
            for sid in [s for s, exp in self._expiry.items() if exp <= now]:
                self._expiry.pop(sid, None)

    def issue(self) -> str:
        with self._lock:
            self._sweep()
            if len(self._expiry) >= self.max_sessions:
                # Fixed TTL makes the earliest expiry the oldest session. The
                # launch-token holder already has authority to replace it, so
                # oldest-first eviction is preferable to unbounded growth.
                oldest = min(self._expiry, key=self._expiry.__getitem__)
                self._expiry.pop(oldest, None)
            sid = secrets.token_urlsafe(32)
            self._expiry[sid] = self._clock() + self.ttl_s
            return sid

    def validate(self, sid: str) -> bool:
        if not sid:
            return False
        with self._lock:
            expiry = self._expiry.get(sid)
            if expiry is None:
                return False
            if expiry <= self._clock():
                self._expiry.pop(sid, None)
                return False
            return True

    def revoke(self, sid: str) -> None:
        with self._lock:
            self._expiry.pop(sid, None)

    def revoke_all(self) -> None:
        with self._lock:
            self._expiry.clear()


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


#: Default ports, so ``http://localhost`` and ``http://localhost:80`` compare equal.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _port_of(authority: str, default: int | None = None) -> int | None:
    """The explicit port in an authority, or ``default``.

    Mirrors ``_hostname_of``: a bracketed IPv6 literal keeps its own colons, and
    an unbracketed value is only split when it carries exactly one.
    """

    text = authority.strip()
    if text.startswith("["):
        end = text.find("]")
        rest = text[end + 1 :] if end != -1 else ""
        if rest.startswith(":"):
            rest = rest[1:]
    elif text.count(":") == 1:
        rest = text.rsplit(":", 1)[1]
    else:
        rest = ""
    if not rest.isdigit():
        return default
    return int(rest)


def _origin_triple(origin: str) -> tuple[str, str, int] | None:
    """An Origin as the (scheme, host, port) triple RFC 6454 defines, or None.

    None covers everything that names no origin: an empty header, the literal
    ``null`` a sandboxed iframe sends, a scheme Replicant is never served over,
    and anything unparseable. None is never equal to an origin, so a caller can
    reject it without a special case.
    """

    scheme, separator, rest = origin.strip().partition("://")
    if not separator:
        return None
    scheme = scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    authority = rest.split("/", 1)[0]
    host = _normalize_host(_hostname_of(authority))
    if not host:
        return None
    port = _port_of(authority, _DEFAULT_PORTS[scheme])
    if port is None:
        return None
    return scheme, host, port


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
        collector_restricted: bool = False,
    ) -> AccessPolicy:
        """Derive the policy from the address the operator asked to bind.

        ``enable_terminal`` is the ``--enable-terminal`` flag, so False means "use
        the default for this bind" rather than "off". The default is on only when
        nothing but this machine can reach the server:

        - the bind is loopback, and
        - no ``--allowed-host`` names anything other than loopback. A loopback
          bind behind a reverse proxy is reachable from the proxy's clients, and
          the allowed Host is exactly what says so. Deciding from the bind alone
          handed a live PTY to anyone the proxy served (2026-09-26 M-04).
        - no ``--collector-allow`` is set. The menu in the terminal is a separate
          process the web allow list does not govern, so an operator who
          restricted destinations would otherwise have a way around it.

        ``--enable-terminal`` still turns it on in every case.
        """
        normalized = _normalize_host(host)
        wildcard = normalized in _WILDCARD_BINDS
        allowed = set(LOOPBACK_HOSTS)
        if not wildcard:
            allowed.add(normalized)
        extra_hosts = {_normalize_host(value) for value in extra if value.strip()}
        allowed.update(extra_hosts)
        proxied = any(not is_loopback(name) for name in extra_hosts)
        local_only = is_loopback(host) and not proxied and not collector_restricted
        return cls(
            allowed_hosts=frozenset(allowed),
            wildcard_bind=wildcard,
            terminal_enabled=local_only or enable_terminal,
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

    def allows_origin(self, origin: str, host_header: str) -> bool:
        """True when ``origin`` is the origin this request was actually served from.

        An origin is (scheme, host, port). The previous check reduced the header
        to an authority and handed it to ``allows_host``, which strips the port,
        so a page on ``http://localhost:9999`` was accepted as same-origin by a
        server on ``localhost:9787``. On a machine running several development
        servers -- the normal analyst laptop -- that let any of them drive the
        embedded terminal with the browser's ambient Replicant cookie.

        The comparison is against the request's own Host, so it stays correct
        behind a TLS proxy without having to trust a forwarding header: whatever
        authority the browser was told to talk to is the one the Origin must
        name. The scheme cannot be recovered from Host, so it is constrained to
        the two Replicant is ever served over rather than compared.

        ``allows_host`` is still applied. It defends DNS rebinding, which is a
        different attack, and neither check subsumes the other: a rebound name
        would otherwise present a perfectly self-consistent Origin/Host pair.
        """

        parsed = _origin_triple(origin)
        if parsed is None:
            return False
        scheme, host, port = parsed
        if not self.allows_host(host):
            return False
        expected_host = _normalize_host(_hostname_of(host_header))
        expected_port = _port_of(host_header, _DEFAULT_PORTS[scheme])
        return host == expected_host and port == expected_port


class CollectorBody(BaseModel):
    host: CollectorHost
    port: int = Field(default=514, ge=1, le=65535)
    transport: Transport = "udp"
    tls_verify: bool = True
    tls_cafile: str | None = None
    vendor: str | None = None  # override the CEF dialect of the rendered test line


class RunBody(BaseModel):
    technique_id: str
    intensity: Intensity = "medium"
    # Validated here, at the request boundary, so a malformed value is a 422
    # with the field named rather than a 500 from the RunRequest built inside
    # the handler (2026-10-07 review, N-02).
    duration: str | None = None
    seed: int | None = Field(default=None, ge=0)
    to_file: str | None = None
    # Defaults to sending, because a caller who supplies a collector has said
    # where the events go. `replicant run REP-001 --host ...` has always read it
    # that way, with `--no-send` as the opt-out; this defaulted the other way, so
    # supplying a collector and saying nothing else produced a run that rendered
    # everything and delivered nothing. Fail-closed is unaffected: `sending` below
    # still requires a collector, so a body with no collector sends nothing.
    no_send: bool = False
    collector: CollectorBody | None = None
    vendor: str | None = None  # override settings.vendor for this run
    # Optional browser-created idempotency key from POST /api/run-admissions.
    # Older API callers can omit it and retain the one-call start contract.
    admission_id: UUID | None = None
    # "now", "fixed", an epoch, or an ISO-8601 timestamp. None and "fixed" both mean
    # the deterministic default; everything else goes through the same parse_anchor
    # the CLI uses, so the two surfaces cannot drift.
    anchor: str | None = None
    # Events per second. The CLI has had `--rate` since Phase 1; the form had no
    # equivalent, so an operator whose collector could not digest the default had
    # no way to slow it down without dropping to a terminal. None means the
    # configured eps cap; an explicit value may lower that ceiling, never raise it.
    rate: int | None = Field(default=None, gt=0)
    # Delivery shape. None lets the server decide from the destination, which is
    # the same rule the CLI follows, resolved in one place so the two surfaces
    # cannot drift. See replicant.core.pacing.resolve_pace.
    pace: Pace | None = None
    speed: float = Field(default=1.0, gt=0, le=MAX_SPEED)
    # REP-009 can exercise a broad mixed-signature spike or a targeted spike
    # that repeats one signature. Other techniques reject the option rather
    # than accepting an inert control.
    signature_mode: Literal["mixed", "single"] | None = None

    _check_duration = field_validator("duration")(validate_duration)

    @model_validator(mode="after")
    def _signature_mode_is_rep009_only(self) -> RunBody:
        if self.signature_mode is not None and self.technique_id != "REP-009":
            raise ValueError("signature_mode applies only to REP-009")
        return self

    @model_validator(mode="after")
    def _speed_needs_a_timeline(self) -> RunBody:
        if self.pace == "burst" and self.speed != 1.0:
            raise ValueError(SPEED_WITHOUT_PLAN)
        return self


class RunAdmissionBody(BaseModel):
    """Small first phase of browser run admission, before plan construction."""

    technique_id: str
    vendor: str | None = None
    # crypto.randomUUID() lets a browser safely retry when the reserve response
    # is lost. The server's manifest/run id remains in its documented format.
    admission_id: UUID | None = None


class ValidationBody(BaseModel):
    technique_id: str
    tier: Literal["plan", "ingest"] = "plan"
    intensity: Intensity = "medium"
    seed: int | None = Field(default=None, ge=0)
    vendor: str | None = None
    transport: Literal["udp", "tcp"] = "udp"


def _native_field_coverage(technique: Technique, profile: VendorProfile) -> dict[str, Any]:
    """Describe plan-wide and per-family native field coverage.

    A mixed plan cannot use one family's extension keys to validate another
    family's metadata. The aggregate is useful for rule authoring, while the
    bounded per-family map states exactly where each signal is available.
    """

    source_fields = {
        "held": technique.cef_fields_held,
        "varied": technique.cef_fields_varied,
    }
    families = technique.logical_families()
    mapped: dict[tuple[str, str], dict[str, str | None]] = {}
    by_family: dict[str, dict[str, Any]] = {}
    all_sources = dict.fromkeys((*technique.cef_fields_held, *technique.cef_fields_varied))

    for log_type, subtype in families:
        family = (log_type, subtype)
        field_map = {
            source: profile.detection_field_name(
                source,
                log_type=log_type,
                subtype=subtype,
            )
            for source in all_sources
        }
        mapped[family] = field_map
        family_json: dict[str, Any] = {"unavailable": {}}
        for role, fields in source_fields.items():
            family_available: list[str] = []
            for field in fields:
                native = field_map[field]
                if native is not None and native not in family_available:
                    family_available.append(native)
            family_json[role] = family_available
            family_json["unavailable"][role] = [
                field for field in fields if field_map[field] is None
            ]
        by_family[f"{log_type}:{subtype}"] = family_json

    aggregate: dict[str, list[str]] = {}
    aggregate_unavailable: dict[str, list[str]] = {}
    for role, fields in source_fields.items():
        aggregate_available: list[str] = []
        unavailable: list[str] = []
        for field in fields:
            native_names = [mapped[family][field] for family in families]
            emitted_names = [name for name in native_names if name is not None]
            if not emitted_names:
                unavailable.append(field)
            for name in emitted_names:
                if name not in aggregate_available:
                    aggregate_available.append(name)
        aggregate[role] = aggregate_available
        aggregate_unavailable[role] = unavailable

    return {
        "native_cef_fields_held": aggregate["held"],
        "native_cef_fields_varied": aggregate["varied"],
        "native_cef_fields_unavailable": aggregate_unavailable,
        "native_cef_fields_by_logical_family": by_family,
    }


def _technique_json(catalog: Catalog, profile: VendorProfile) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for technique in catalog.techniques:
        binding = technique.fortigate
        metadata = profile.detection_metadata(
            binding.log_type,
            binding.subtype,
            binding.signature_id,
            binding.action,
        )
        field_coverage = _native_field_coverage(technique, profile)
        out.append(
            {
                "id": technique.id,
                "name": technique.name,
                "ndr_rule": technique.ndr_rule,
                "ndr_uc": technique.ndr_uc,
                # What running this establishes. The UI used to synthesise a
                # sentence from log_type and rule id, which read as specific and
                # was identical in meaning for every catalog entry.
                "objective": technique.objective,
                "search_aliases": technique.search_aliases,
                "logical_log_type": binding.log_type,
                "logical_subtype": binding.subtype,
                "logical_families": [
                    f"{log_type}:{subtype}" for log_type, subtype in technique.logical_families()
                ],
                # Compatibility fields retain their catalog/FortiGate meanings.
                # Selected-profile identifiers are explicit below, never silent
                # semantic replacements for an existing API key.
                "log_type": binding.log_type,
                "subtype": binding.subtype,
                "native_log_type": metadata.log_type,
                "native_subtype": metadata.subtype,
                "native_metadata_scope": "primary",
                "native_metadata_semantics": metadata.semantics,
                "attack": technique.attack.techniques,
                "tactics": technique.attack.tactics,
                "intensities": sorted(technique.params.keys()),
                "implemented": technique.id in implemented_technique_ids(),
                "safety_notes": technique.safety_notes,
                "signature_id": binding.signature_id,
                "action": binding.action,
                "native_signature_id": metadata.signature_id,
                "native_action": metadata.action,
                "cef_fields_held": technique.cef_fields_held,
                "cef_fields_varied": technique.cef_fields_varied,
                **field_coverage,
                "params": technique.params,
                "distributions": technique.distributions,
                "benign_baseline": technique.benign_baseline,
                "transferability": technique.transferability,
                "transferability_note": technique.transferability_note,
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
    *,
    collector_policy: CollectorPolicy | None = None,
    evidence_keep: int = DEFAULT_EVIDENCE_KEEP,
    max_streams: int = MAX_STREAMS,
    clock: Any = None,
) -> FastAPI:
    policy = policy or AccessPolicy()
    collectors = collector_policy or CollectorPolicy()
    if evidence_keep < 1:
        raise ValueError("--evidence-keep must be at least 1")
    app = FastAPI(title="Replicant", version=__version__, docs_url=None, redoc_url=None)
    # Idempotent, so a test that builds several apps does not stack handlers.
    obs_log.install()
    manager = RunManager(catalog, settings, clock=clock)
    # Per app, not module-global: two apps in one process (the test suite builds
    # several) must not be able to authenticate each other's browsers.
    sessions = SessionStore()
    base_orchestrator = Orchestrator(catalog, settings)
    # Bytes, not str. ``compare_digest`` raises TypeError on a str holding any
    # non-ASCII character, and the cookie middleware authenticates every request,
    # so one such header turned every route into a 500, /api/health included.
    token_bytes = token.encode("utf-8")
    # Only a bare file name inside this directory may be used as a TLS CA file
    # from the web. Resolved once, like the rest of the app's configuration.
    ca_root = config_dir() / "ca"
    connect_buckets: dict[str, TokenBucket] = {}
    connect_global = TokenBucket(CONNECT_TEST_GLOBAL_BURST, CONNECT_TEST_WINDOW_S, clock=clock)
    connect_lock = threading.Lock()
    streams = StreamLimiter(max_streams)
    plan_gate = BuildGate()

    @contextlib.contextmanager
    def _plan_slot() -> Iterator[None]:
        """One whole-plan build at a time: pricing, samples, run starts, validation."""

        try:
            with plan_gate.slot():
                yield
        except GateBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=f"server is busy building another plan ({exc}); try again",
                headers={"Retry-After": "5"},
            ) from exc

    def _token_matches(supplied: str) -> bool:
        try:
            candidate = supplied.encode("utf-8", "surrogatepass")
        except UnicodeError:  # pragma: no cover - surrogatepass accepts any str
            return False
        return secrets.compare_digest(token_bytes, candidate)

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
        )
        for source, supplied in candidates:
            if supplied and _token_matches(supplied):
                return source
        # The cookie is checked against the session store, never against the
        # launch token. It used to hold that token verbatim, which made a value
        # the browser stores indefinitely into the master credential (F-04).
        if sessions.validate(request.cookies.get(SESSION_COOKIE) or ""):
            return "cookie"
        return None

    def _origin_ok(connection: HTTPConnection, *, required: bool) -> bool:
        """Validate the Origin header against the origin actually being served.

        ``required`` rejects its absence outright. Browsers always send Origin on
        a WebSocket handshake and on every non-GET, so absence means a non-browser
        client, which the ambient-cookie problem does not apply to.
        """

        origin = connection.headers.get("origin") or ""
        if not origin:
            return not required
        return policy.allows_origin(origin, connection.headers.get("host") or "")

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

    def _set_session_cookie(response: Any, request: Request) -> None:
        sid = request.cookies.get(SESSION_COOKIE) or ""
        if not sessions.validate(sid):
            sid = sessions.issue()
        response.set_cookie(
            SESSION_COOKIE,
            # A short-lived id, not the launch token. Reuse a valid id so a
            # bookmarked token URL cannot churn through the bounded store.
            sid,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=sessions.ttl_s,
            # Only over https, where it means anything. Setting it on the
            # loopback http the tool serves by default would stop the cookie
            # being sent at all, which is a worse outcome than not setting it.
            secure=request.url.scheme == "https",
        )

    @app.middleware("http")
    async def _authenticate_before_body(request: Request, call_next: Any) -> Any:
        """Refuse an unauthenticated API write before its body is read.

        FastAPI reads and parses the body before it runs ``require_token``, so an
        unauthenticated caller could make the server buffer whatever it sent.
        ``BodyLimitMiddleware`` bounds that; this removes it for anyone without a
        credential. Innermost of the HTTP middleware, so the Host guard and the
        launch-token exchange still run first.
        """

        path = request.url.path
        if (
            policy.require_auth
            and request.method not in _SAFE_METHODS
            and (path == "/api" or path.startswith("/api/"))
            and _authenticated_source(request) is None
        ):
            return JSONResponse(status_code=401, content={"detail": "invalid or missing token"})
        return await call_next(request)

    @app.middleware("http")
    async def _session_cookie(request: Request, call_next: Any) -> Any:
        """Exchange a browser launch token before serving the SPA document.

        ``StaticFiles`` owns ``/``, so middleware is the only place that can
        intercept the printed launch URL. Redirecting first means neither the SPA
        nor any dependency in its module graph ever executes while the persistent
        token remains readable from ``window.location``. Explicit query tokens on
        ``/api`` remain a programmatic authentication source and mint no sessions.
        """

        source = _authenticated_source(request)
        path = request.url.path
        is_browser_surface = not path.startswith("/api/") and path != "/api"
        if request.method == "GET" and is_browser_surface and "token" in request.query_params:
            clean_items = [
                (key, value) for key, value in request.query_params.multi_items() if key != "token"
            ]
            clean_query = urlencode(clean_items, doseq=True)
            # Keep this a same-host path even if an unusual request target began
            # with ``//`` (which a browser would interpret as a scheme-relative
            # redirect to another host).
            clean_path = "/" + path.lstrip("/")
            destination = clean_path + (f"?{clean_query}" if clean_query else "")
            response = RedirectResponse(destination, status_code=303)
            response.headers["Cache-Control"] = "no-store"
            # A valid query credential is exchanged exactly once. An invalid token
            # is still removed before document load, but earns no session.
            if source == "query":
                _set_session_cookie(response, request)
            return response

        return await call_next(request)

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
    def get_catalog(vendor: str | None = Query(default=None)) -> dict[str, Any]:
        resolved = _resolve_vendor(vendor)
        orch = _orchestrator_for(resolved)
        return {
            "vendor_profile": resolved,
            "timezone": catalog.timezone,
            "techniques": _technique_json(catalog, orch.profile),
        }

    @app.get(
        "/api/validation/contracts/{technique_id}",
        dependencies=[Depends(require_token)],
    )
    def validation_contract(technique_id: str) -> dict[str, Any]:
        try:
            contract = _orchestrator_for(None).validation_contract(technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return contract.model_dump(mode="json")

    def _validation_conflict(exc: ValidationInProgressError) -> HTTPException:
        return HTTPException(
            status_code=409,
            detail={"code": "validation_in_progress", "authoritative": True, "message": str(exc)},
        )

    @app.post("/api/validate", dependencies=[Depends(require_token)])
    def validate_technique(body: ValidationBody) -> dict[str, Any]:
        """One validation at a time, and never beside a run.

        A REP-004 high validation peaks at about 830 MB for about ten seconds, and
        nothing bounded how many ran at once: twelve concurrent calls had the
        server OOM-killed. A run is excluded too, because the two share the host
        and a run of the same technique holds about 400 MB of plan while it
        emits. Both conflicts are a 409 in the shape the run lock already uses.
        """

        try:
            catalog.by_id(body.technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        orch = _orchestrator_for(body.vendor)
        try:
            manager.begin_validation()
        except RunInProgressError as exc:
            raise _active_conflict(exc) from exc
        except ValidationInProgressError as exc:
            raise _validation_conflict(exc) from exc
        try:
            return _validate(orch, body)
        finally:
            manager.end_validation()
            # Every validation writes a directory and a ZIP of about 1.1 MB and
            # nothing removed them. Keep the newest N; see prune_evidence for
            # what is and is not a candidate.
            try:
                prune_evidence(Path(settings.manifest_dir) / "evidence", evidence_keep)
            except OSError as exc:  # pragma: no cover - reported, never fatal
                obs_log.get_logger("web").warning("evidence retention failed: %s", exc)

    def _validate(orch: Orchestrator, body: ValidationBody) -> dict[str, Any]:
        request = RunRequest(
            technique_id=body.technique_id,
            intensity=body.intensity,
            seed=body.seed if body.seed is not None else settings.default_seed,
            no_send=True,
            controls="both",
            anchor_epoch=settings.anchor_epoch,
            pace="burst",
        )
        try:
            with _plan_slot():
                result = orch.validate(
                    request,
                    tier=body.tier,
                    ingest_transport=body.transport,
                )
        except (RuntimeError, ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = result.model_dump(mode="json")
        payload["evidence_url"] = f"/api/evidence/{result.run_id}"
        return payload

    @app.get("/api/evidence/{run_id}", dependencies=[Depends(require_token)])
    def download_evidence(run_id: str) -> FileResponse:
        if Path(run_id).name != run_id or not run_id.startswith("RUN-"):
            raise HTTPException(status_code=404, detail="evidence pack not found")
        archive = Path(settings.manifest_dir) / "evidence" / f"{run_id}.zip"
        if not archive.is_file():
            raise HTTPException(status_code=404, detail="evidence pack not found")
        return FileResponse(
            archive,
            media_type="application/zip",
            filename=f"replicant-{run_id}-evidence.zip",
        )

    # Sample lines, cached by what determines them.
    #
    # The endpoint returns three lines and used to build the entire plan to get
    # them, every time the operator selected a technique: REP-004 at high
    # intensity is 180,000 events and about 1.6 seconds of pure CPU, discarded
    # immediately. It cannot simply build three and stop, because the sample is
    # deliberately the first, middle and last event, and the middle of three is
    # not the middle of the run.
    #
    # Caching is exact rather than approximate: the request is built from a fixed
    # seed and a fixed intensity, so (technique, intensity, vendor) determines the
    # output completely. Bounded because a server is long-lived and the catalog
    # times intensities times vendors is 26 * 3 * 3, which fits comfortably.
    sample_cache: dict[tuple[str, str, str], list[str]] = {}
    SAMPLE_CACHE_MAX = 256

    def _sample_lines(orch: Orchestrator, request: RunRequest, vendor_id: str) -> list[str]:
        key = (request.technique_id, request.intensity, vendor_id)
        cached = sample_cache.get(key)
        if cached is not None:
            return cached
        with _plan_slot():
            events = list(orch.build_plan(request).events)
        if events:
            idxs = sorted({0, len(events) // 2, len(events) - 1})
            lines = [orch.render_line(events[i]) for i in idxs]
        else:
            lines = []
        if len(sample_cache) >= SAMPLE_CACHE_MAX:  # pragma: no cover - 216 possible keys
            sample_cache.clear()
        sample_cache[key] = lines
        return lines

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
        lines = _sample_lines(orch, request, _resolve_vendor(vendor))
        binding = technique.fortigate
        metadata = orch.profile.detection_metadata(
            binding.log_type,
            binding.subtype,
            binding.signature_id,
            binding.action,
        )
        field_coverage = _native_field_coverage(technique, orch.profile)
        return {
            "technique_id": technique.id,
            "vendor": _resolve_vendor(vendor),
            "intensity": request.intensity,
            "logical_log_type": binding.log_type,
            "logical_subtype": binding.subtype,
            "logical_families": [
                f"{log_type}:{subtype}" for log_type, subtype in technique.logical_families()
            ],
            "log_type": binding.log_type,
            "subtype": binding.subtype,
            "native_log_type": metadata.log_type,
            "native_subtype": metadata.subtype,
            "signature_id": binding.signature_id,
            "native_signature_id": metadata.signature_id,
            "native_action": metadata.action,
            "native_metadata_scope": "primary",
            "native_metadata_semantics": metadata.semantics,
            "cef_fields_held": technique.cef_fields_held,
            "cef_fields_varied": technique.cef_fields_varied,
            **field_coverage,
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

    def _rate_key(request: Request) -> str:
        """Who a connect test is charged to: the browser session, else the token.

        Never a forwarded header, and the transport peer only when there is no
        credential at all (``--no-auth``).
        """

        sid = request.cookies.get(SESSION_COOKIE) or ""
        if sid and sessions.validate(sid):
            return f"session:{sid}"
        if policy.require_auth:
            return "launch-token"
        return f"peer:{request.client.host if request.client else 'unknown'}"

    def _charge_connect_test(request: Request) -> None:
        key = _rate_key(request)
        with connect_lock:
            bucket = connect_buckets.get(key)
            if bucket is None:
                if len(connect_buckets) >= 2 * MAX_BROWSER_SESSIONS:
                    connect_buckets.clear()  # bounded; worst case is a refilled bucket
                bucket = TokenBucket(CONNECT_TEST_BURST, CONNECT_TEST_WINDOW_S, clock=clock)
                connect_buckets[key] = bucket
        wait = bucket.take() or connect_global.take()
        if wait:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"too many connect tests; at most {CONNECT_TEST_BURST} per "
                    f"{CONNECT_TEST_WINDOW_S:.0f}s. Try again shortly."
                ),
                headers={"Retry-After": str(max(1, int(wait + 0.999)))},
            )

    def _check_destination(host: str, port: int) -> None:
        if not collectors.permits(host, port):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"collector {host}:{port} is not permitted by this server's "
                    f"--collector-allow list ({collectors.describe()})"
                ),
            )

    def _web_cafile(value: str | None) -> str | None:
        try:
            return confined_cafile(value, ca_root)
        except CAFileRefused as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/connect/test", dependencies=[Depends(require_token)])
    def connect_test(body: CollectorBody, request: Request) -> dict[str, Any]:
        # Policy and input checks come before the charge, so a refused request
        # does not use up the operator's allowance.
        _check_destination(body.host, body.port)
        cafile = _web_cafile(body.tls_cafile)
        _charge_connect_test(request)
        orch = _orchestrator_for(body.vendor)
        collector = CollectorProfile(
            name="web",
            host=body.host,
            port=body.port,
            transport=body.transport,
            tls_verify=body.tls_verify,
            tls_cafile=cafile,
        )
        # A test line to a non-loopback collector is a real send to a shared
        # collector, so it follows the same destination-conditional marking the
        # CLI connect test does (Orchestrator._resolve_marker). Without this the
        # web probe path sent an unmarked line where the CLI path marked it.
        mark_on, _ = orch._resolve_marker(send=True, collector=collector)
        line = orch.build_test_line(mark=mark_on)
        # A verdict, not a bool. The bool was rendered as a green "verified" and
        # on UDP its only guaranteed meaning is that the kernel accepted the
        # datagram, which is true whenever any route exists. It said "verified"
        # against an unreachable collector across two live lab sessions.
        report = probe_collector(collector, payload=line)
        # The verdict is kept; the exception text is not. A TCP or TLS failure
        # used to return ``f"{type(exc).__name__}: {exc}"`` verbatim.
        if report.verdict == "failed":
            report = dataclasses.replace(report, summary=CONNECT_FAILED_SUMMARY)
        elif report.verdict == "refused":
            report = dataclasses.replace(
                report,
                summary=(
                    f"The host answered: nothing is listening on "
                    f"{collector.transport}/{collector.port}."
                ),
            )
        return {
            # Retained so an older client still gets a sane answer, but nothing
            # in this UI decides anything from it any more.
            "ok": report.ok,
            "endpoint": collector.endpoint(),
            "line": line,
            "report": report.as_dict(),
        }

    def _confined_output(to_file: str | None) -> str | None:
        """Resolve a browser-supplied output path inside the run-output directory.

        ``FileSink`` opens with mode ``w``, which follows symlinks and truncates.
        Accepting any string from the API therefore made the web token worth more
        than the collector-run authority it is meant to carry: it could corrupt
        any file the service account can write, including this program's own
        source. Confining it keeps the blast radius to one directory.

        The CLI is deliberately unchanged. A caller already holding a shell has
        the same filesystem authority anyway, so restricting it there would buy
        nothing and break ``--to-file /tmp/x.log``.
        """

        if not to_file:
            return None
        # Shared with the web terminal's menu (`replicant.config.confine`). The
        # previous inline check called `.is_symlink()` on the already-resolved
        # path, which can never be a link, so a symlink planted inside `out/`
        # passed it. The helper checks the link before resolving.
        try:
            return confined_output_path(to_file, settings.manifest_dir)
        except ConfinementError as exc:
            raise HTTPException(status_code=400, detail="output path is not permitted") from exc

    def _run_request(body: RunBody) -> tuple[RunRequest, bool]:
        """One RunBody becomes one RunRequest, for the preview and the run alike.

        Shared so the figures the form shows before a run cannot describe a
        different run than the one that starts. Also returns whether events will
        actually reach a collector, which is what decides the default pace.
        """

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
            # Only a run that will open a socket is held to the allow list; a
            # --no-send run with a collector attached reaches nothing.
            if not body.no_send:
                _check_destination(body.collector.host, body.collector.port)
            collector = CollectorProfile(
                name="web",
                host=body.collector.host,
                port=body.collector.port,
                transport=body.collector.transport,
                tls_verify=body.collector.tls_verify,
                tls_cafile=_web_cafile(body.collector.tls_cafile),
            )
        request = RunRequest(
            technique_id=body.technique_id,
            intensity=body.intensity,
            seed=body.seed if body.seed is not None else settings.default_seed,
            duration=body.duration,
            to_file=_confined_output(body.to_file),
            no_send=body.no_send,
            collector=collector,
            anchor_epoch=anchor,
            rate_override=body.rate,
            param_overrides=(
                {"signature_mode": body.signature_mode} if body.signature_mode is not None else {}
            ),
            pace=body.pace,
            speed=body.speed,
        )
        return request, (not body.no_send and collector is not None)

    def _preview(body: RunBody) -> tuple[RunRequest, bool, PacingPreview]:
        request, sending = _run_request(body)
        try:
            with _plan_slot():
                preview = _orchestrator_for(body.vendor).preview_pacing(request, sending=sending)
        except (RuntimeError, NotImplementedError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return request, sending, preview

    def _validate_run_identity(technique_id: str, vendor: str | None) -> str:
        """Validate the cheap identity fields before reserving active ownership."""

        try:
            catalog.by_id(technique_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _resolve_vendor(vendor)

    def _active_conflict(exc: RunInProgressError) -> HTTPException:
        active = manager.get(exc.active_run_id)
        return HTTPException(
            status_code=409,
            detail={
                "code": "run_in_progress",
                "authoritative": True,
                "message": str(exc),
                "admission_id": active.admission_id if active is not None else None,
                "run_id": exc.active_run_id,
                "technique_id": exc.technique_id,
                "vendor": exc.vendor,
                "status": active.status if active is not None else None,
            },
        )

    def _admission_conflict(exc: RunAdmissionError) -> HTTPException:
        return HTTPException(
            status_code=409,
            detail={
                "code": exc.code,
                "authoritative": True,
                "message": str(exc),
                "admission_id": exc.admission_id,
                "admission_run_id": exc.admission_run_id,
                "run_id": exc.active_run_id,
                "technique_id": exc.active_technique_id,
                "vendor": exc.active_vendor,
                "status": exc.active_status,
            },
        )

    def _admission_json(handle: RunHandle) -> dict[str, Any]:
        return {
            "admission_id": handle.admission_id,
            "run_id": handle.run_id,
            "technique_id": handle.technique_id,
            "vendor": handle.vendor,
            "status": handle.status,
            "event_count": handle.event_count,
            "total": handle.total,
        }

    @app.post("/api/run-admissions", dependencies=[Depends(require_token)])
    def reserve_run(body: RunAdmissionBody) -> dict[str, Any]:
        """Reserve run ownership before the browser asks for a plan and start.

        The client supplies the idempotency key, so it can retry this exact call
        after a lost response. Once this response is observed, a later active
        probe cannot overtake reservation creation and incorrectly report null.
        """

        vendor = _validate_run_identity(body.technique_id, body.vendor)
        try:
            handle = manager.reserve(
                body.technique_id,
                vendor,
                str(body.admission_id) if body.admission_id is not None else None,
            )
        except RunInProgressError as exc:
            raise _active_conflict(exc) from exc
        except ValidationInProgressError as exc:
            raise _validation_conflict(exc) from exc
        except RunAdmissionError as exc:
            raise _admission_conflict(exc) from exc
        return _admission_json(handle)

    @app.get("/api/run-admissions/{admission_id}", dependencies=[Depends(require_token)])
    def run_admission(admission_id: UUID) -> dict[str, Any]:
        """Resolve a client-known admission id after an ambiguous response."""

        handle = manager.get_admission(str(admission_id))
        if handle is None:
            raise HTTPException(status_code=404, detail="unknown run admission")
        return _admission_json(handle)

    @app.post("/api/plan", dependencies=[Depends(require_token)])
    def preview_plan(body: RunBody) -> dict[str, Any]:
        """How long this run would take, without starting it.

        The run form needs real numbers to put beside each pacing option. Without
        them the control could only say "this may take a while", and the lesson
        this project keeps relearning is that the defects here are labels rather
        than logic. Takes the same body as POST /api/runs so the two cannot drift.
        """

        _, _, preview = _preview(body)
        return {
            "event_count": preview.event_count,
            "plan_span_s": preview.plan_span_s,
            "compressed_span_s": preview.compressed_span_s,
            "projected_s": preview.projected_s,
            "projected_by_pace": preview.projected_by_pace,
            "pace": preview.pace,
            "speed": preview.speed,
        }

    @app.post("/api/runs", dependencies=[Depends(require_token)])
    def start_run(body: RunBody) -> dict[str, Any]:
        vendor = _validate_run_identity(body.technique_id, body.vendor)
        try:
            if body.admission_id is not None:
                admission = manager.claim(str(body.admission_id), body.technique_id, vendor)
            else:
                # Backwards compatibility for scripts using the original one-call
                # endpoint. Browser clients use the acknowledged reservation
                # phase above so their ownership probes cannot overtake this call.
                admission = manager.reserve(body.technique_id, vendor)
                admission = manager.claim(admission.admission_id, body.technique_id, vendor)
        except RunInProgressError as exc:
            raise _active_conflict(exc) from exc
        except ValidationInProgressError as exc:
            raise _validation_conflict(exc) from exc
        except RunAdmissionError as exc:
            raise _admission_conflict(exc) from exc

        try:
            request, sending, preview = _preview(body)
            anchor = request.anchor_epoch or settings.anchor_epoch
            handle = manager.start(
                request,
                settings=_settings_for(vendor),
                # The preview just built this plan; REP-004 high is 180,000 events
                # and 1.6 seconds, so it is not worth building twice.
                total=preview.event_count,
                admission=admission,
            )
        except RunInProgressError as exc:
            manager.fail_admission(admission, str(exc))
            raise _active_conflict(exc) from exc
        except RunAdmissionError as exc:
            manager.fail_admission(admission, str(exc))
            raise _admission_conflict(exc) from exc
        except HTTPException as exc:
            manager.fail_admission(admission, str(exc.detail))
            raise
        except (RuntimeError, NotImplementedError) as exc:
            manager.fail_admission(admission, str(exc))
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            manager.fail_admission(admission, str(exc))
            raise
        return {
            "admission_id": handle.admission_id,
            "run_id": handle.run_id,
            "vendor": handle.vendor,
            "total": handle.total,
            "anchor_epoch": anchor,
            "anchor_warning": stale_anchor_warning(anchor, sending=sending),
            # The pace the server actually resolved, not the one the client hoped
            # for. A client that guesses the default wrong would otherwise label a
            # four hour run as a three second one.
            "pace": preview.pace,
            "speed": preview.speed,
            "projected_s": preview.projected_s,
            "projected_by_pace": preview.projected_by_pace,
            "plan_span_s": preview.plan_span_s,
            # Where the events actually go, decided by the server rather than
            # restated by the client. A run with neither destination is a render
            # with no output, and it looks exactly like a working run in the event
            # stream and the eps readout, so it has to be said in words.
            "destination": ("collector" if sending else "file" if body.to_file else "none"),
            # Where the file actually landed. The browser asks for a name and the
            # server decides the directory, so the client cannot know the path it
            # got unless the server says.
            "output_path": request.to_file,
            "destination_warning": (
                None
                if sending or body.to_file
                else (
                    "This run has no destination. Events will be rendered and neither sent "
                    "nor written, and the readout below measures rendering, not delivery."
                )
            ),
        }

    @app.post("/api/session/logout", dependencies=[Depends(require_token)])
    def logout(request: Request) -> JSONResponse:
        """End this browser's session without touching the launch token.

        The point of the exchange: revoking one browser used to mean
        regenerating the token file, which logged out every other client and
        every script. This remains authenticated because the session id is an
        ambient cookie. Without the normal write Origin check, a cross-site form
        could make the victim's browser revoke a value the attacker never knew.
        """

        sid = request.cookies.get(SESSION_COOKIE) or ""
        sessions.revoke(sid)
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # Declared before /api/runs/{run_id}: FastAPI matches in registration order,
    # and the parameterised route would otherwise swallow "active" as an id.
    @app.get("/api/runs/active", dependencies=[Depends(require_token)])
    def active_run() -> dict[str, Any]:
        """The run holding the single-run lock, or nulls.

        Only one run may be active, because each carries its own rate limiter and
        two against one collector would multiply the eps cap (safety rule 4).
        That is correct, but the form's ``running`` flag is per-panel state: it
        resets when the operator selects a different technique, so the panel
        showed an idle form while the server was four hours into a plan-paced
        run. The server is the only thing that knows, so it has to be askable.
        """
        handle = manager.active()
        if handle is None:
            return {
                "admission_id": None,
                "run_id": None,
                "technique_id": None,
                "vendor": None,
                "status": None,
            }
        return {
            "admission_id": handle.admission_id,
            "run_id": handle.run_id,
            "technique_id": handle.technique_id,
            "vendor": handle.vendor,
            "status": handle.status,
            "event_count": handle.event_count,
            "total": handle.total,
        }

    @app.get("/api/runs/{run_id}", dependencies=[Depends(require_token)])
    def run_status(run_id: str) -> dict[str, Any]:
        handle = manager.get(run_id)
        if handle is None:
            raise HTTPException(status_code=404, detail="unknown run")
        return {
            "admission_id": handle.admission_id,
            "run_id": handle.run_id,
            "vendor": handle.vendor,
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
        slot = _stream_slot()

        async def generator() -> Any:
            loop = asyncio.get_running_loop()
            # A private queue per consumer. The handle's queue used to be shared,
            # and `get()` removes the item, so two browser tabs on one run each
            # took a random subset of the lines and neither saw the whole stream.
            subscriber = handle.subscribe()
            getter = functools.partial(subscriber.get, True, 0.25)
            try:
                while True:
                    try:
                        item = await loop.run_in_executor(None, getter)
                    except queue.Empty:
                        if handle.stream_complete(subscriber):
                            break
                        yield ": keepalive\n\n"
                        continue
                    yield f"data: {json.dumps(item)}\n\n"
                    if item["type"] in ("done", "error"):
                        break
            finally:
                # Otherwise every closed tab leaves a queue the worker keeps
                # filling for the life of the run.
                handle.unsubscribe(subscriber)
                slot.release()

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def _stream_slot() -> Any:
        """Take a live-stream slot or refuse with 429.

        Each run stream polls its queue through the loop's default executor, a
        pool of at most 32 threads, so an unbounded number of open streams could
        starve every other use of it. Log streams share the cap because each is
        a polling task for as long as it lives.
        """

        slot = streams.acquire()
        if slot is None:
            raise HTTPException(
                status_code=429,
                detail=f"too many live streams open (limit {streams.cap}); close a tab",
            )
        return slot

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
        slot = _stream_slot()

        async def generator() -> Any:
            cursor = after
            try:
                # Unlike the run stream, this one has no natural end: the log
                # buffer outlives every run. Without the disconnect check each
                # closed Logs tab would leave a task polling the ring for the life
                # of the process.
                while not await request.is_disconnected():
                    entries = obs_log.snapshot(after=cursor)
                    if entries:
                        cursor = entries[-1].seq
                        for entry in entries:
                            yield sse_log_line(entry)
                    else:
                        yield SSE_KEEPALIVE
                    # Polling the ring rather than fanning out per-subscriber
                    # queues. One buffer, many readers, each holding only an
                    # integer cursor, so a slow client cannot stall the emit loop.
                    await asyncio.sleep(0.4)
            finally:
                slot.release()

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def _terminal_client_key(websocket: WebSocket, source: str) -> str:
        """Who a terminal session counts against for the per-client cap.

        It was the transport peer address, which uvicorn rewrites from
        X-Forwarded-For whenever the peer is a trusted proxy, and it trusted
        127.0.0.1 by default. Any local caller could therefore claim a fresh
        client per connection. The authenticated browser session is the identity
        that cannot be chosen by the caller; the peer is used only without one.
        """

        if source == "cookie":
            # A digest, not the id. The key only has to be stable per session,
            # and the bridge logs it when it refuses one; the raw cookie value
            # is a 12 hour bearer credential and reached the log ring, the SSE
            # log stream and the journal that way (2026-10-07 review, N-04).
            sid = websocket.cookies.get(SESSION_COOKIE) or ""
            return f"session:{hashlib.sha256(sid.encode()).hexdigest()[:16]}"
        if source in {"header", "query"}:
            return "launch-token"
        return f"peer:{websocket.client.host if websocket.client else 'unknown'}"

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
        # One policy for HTTP and websockets. They disagreed: the HTTP dependency
        # returned early when require_auth was false, while this path always
        # demanded a credential, so --no-auth left the API open and the terminal
        # unusable -- the opposite of what its own startup warning said. The Host
        # and Origin checks below are unaffected either way; --no-auth drops the
        # credential, never the browser-boundary controls.
        source = "none" if not policy.require_auth else _authenticated_source(websocket)
        if source is None:
            await websocket.close(code=1008)
            return
        # Required whatever the credential was. The terminal is a browser feature
        # and every browser sends Origin on a WebSocket handshake, so demanding it
        # costs a real client nothing and removes the case where a token in the
        # URL bought an unchecked cross-origin connection.
        if not _origin_ok(websocket, required=True):
            await websocket.close(code=1008)
            return
        if os.name != "posix":
            await websocket.accept()
            await websocket.send_text("Embedded terminal requires a POSIX host.\r\n")
            await websocket.close()
            return
        await websocket.accept()
        await bridge_terminal(websocket, client_key=_terminal_client_key(websocket, source))

    # Added after every other middleware except the security headers, so it sits
    # outside the auth and cookie layers: an oversized declared body is refused
    # before anything else looks at the request.
    app.add_middleware(BodyLimitMiddleware)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Any:
        """Defence in depth behind the Markdown fix, not instead of it.

        The Docs tab renders repository Markdown with this origin's privileges.
        Raw HTML is now escaped before it can become markup, but a policy that
        forbids inline script means a future regression in that pipeline stops
        being an execution primitive. ``frame-ancestors`` also removes clickjacking
        against the run controls, which nothing else covered.

        ``style-src`` allows inline styles: the bundled UI sets them, and removing
        that needs a nonce pipeline through the build rather than a header change.
        """

        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

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
    collectors: str | None = None,
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
    if collectors is not None:
        lines.append(f"  sends to : {collectors}")
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
    collector_allow: Iterable[str] = (),
    evidence_keep: int = DEFAULT_EVIDENCE_KEEP,
    forwarded_allow_ips: Iterable[str] = (),
) -> None:
    """Start the web server on a fixed port and print how to reach it."""

    check_unauthenticated_exposure(host, no_auth=no_auth, acknowledged=acknowledged_unauthenticated)
    # Parsed before anything is printed or bound, so a typo refuses startup with
    # the entry named rather than serving with an allow list it did not mean.
    collector_policy = CollectorPolicy.parse(collector_allow)
    if evidence_keep < 1:
        raise ValueError("--evidence-keep must be at least 1")
    trusted_proxies = [value.strip() for value in forwarded_allow_ips if value.strip()]

    if no_auth:
        token, token_state = "", "disabled (--no-auth)"
        for line in _no_auth_warning(host, port):
            print(line, flush=True)
    else:
        token, token_state = load_or_create_web_token(rotate=rotate_token)

    policy = AccessPolicy.for_bind(
        host,
        allowed_hosts,
        enable_terminal=enable_terminal,
        collector_restricted=collector_policy.restricted,
    )
    policy = dataclasses.replace(policy, require_auth=not no_auth)
    app = create_app(
        catalog,
        settings,
        token,
        policy,
        collector_policy=collector_policy,
        evidence_keep=evidence_keep,
    )

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
        collectors=collector_policy.describe(),
    ):
        print(line, flush=True)
    if not collector_policy.restricted:
        # Not a refusal: a lab with one collector on one laptop needs no list.
        # It is said once, at startup, where an operator exposing the UI reads.
        obs_log.get_logger("web").warning(
            "no --collector-allow set: web callers may send to and connect-test any "
            "host:port this machine can reach"
        )

    if open_browser and display_available(sys.platform, os.environ):
        url = display_url(host, bound_port, token or None)
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    # Force the stdlib asyncio loop rather than uvloop: the terminal bridge relies
    # on loop.add_reader on a PTY master fd, which the selector loop supports
    # reliably (uvloop does not re-fire it dependably for PTYs).
    server = uvicorn.Server(uvicorn_config(app, trusted_proxies))
    server.run(sockets=[sock])


def uvicorn_config(app: Any, trusted_proxies: Iterable[str] = ()) -> uvicorn.Config:
    """The server configuration, with forwarded-header trust stated explicitly.

    uvicorn trusts ``X-Forwarded-For`` from 127.0.0.1 unless told otherwise, and
    reads ``FORWARDED_ALLOW_IPS`` from the environment when the argument is
    omitted. Any local process could therefore choose the client address the app
    saw. Proxy headers are now off unless ``--forwarded-allow-ips`` names the
    proxy, and the value is always passed so the environment cannot widen it.
    """

    proxies = [value for value in trusted_proxies if value]
    return uvicorn.Config(
        app,
        log_level="warning",
        loop="asyncio",
        proxy_headers=bool(proxies),
        forwarded_allow_ips=proxies,
        # The terminal's frame bound, applied where the frame is read. The bridge
        # checks MAX_FRAME_BYTES after receipt, by which point uvicorn had already
        # buffered up to its 16 MiB default per frame (2026-10-07 review, N-05).
        ws_max_size=MAX_FRAME_BYTES,
        ws_max_queue=4,
    )
