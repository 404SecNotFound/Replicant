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
"""Resource and destination guards for the web server.

Each guard here answers one finding of the 2026-09-26 review
(``docs/security-review-2026-09-26.md``). They live apart from ``server.py`` so
each can be tested on its own, with an injectable clock where time matters,
rather than only through a running app.

None of these opens a socket. Safety rule 1 is unaffected: the collector allow
list only narrows where the existing single egress may go.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from replicant.obs.log import get_logger

_log = get_logger("web")

Clock = Callable[[], float]

# -- request bodies ------------------------------------------------------------

#: The largest request body the API accepts. The biggest legitimate body is a
#: RunBody with a collector, a few hundred bytes; 64 KiB leaves two orders of
#: magnitude of headroom and still bounds what an unauthenticated caller can make
#: the server buffer.
MAX_BODY_BYTES = 64 * 1024


class BodyTooLarge(HTTPException):
    """Raised from the wrapped ``receive`` once a streamed body passes the cap.

    An ``HTTPException`` on purpose: FastAPI turns any other exception raised
    while reading a body into a 400 "error parsing the body", which would hide
    the real reason. It re-raises ``HTTPException`` unchanged.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="request body too large")


def _json_response(status: int, detail: str) -> tuple[Message, Message]:
    body = json.dumps({"detail": detail}).encode("utf-8")
    start: Message = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
        ],
    }
    return start, {"type": "http.response.body", "body": body, "more_body": False}


class BodyLimitMiddleware:
    """Refuse request bodies over ``max_bytes``, declared or streamed.

    FastAPI reads the whole body before it resolves dependencies, so the token
    check ran only after an arbitrarily large upload had been buffered: a 400 MB
    unauthenticated POST took the server to about 1.3 GB RSS before the 401.

    ``Content-Length`` is checked before anything is read. A chunked body has no
    length to check, so the bytes are counted as they arrive and the request is
    abandoned the moment the count passes the cap, which bounds the buffer at
    ``max_bytes`` plus one chunk.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._reply(send, 400, "invalid content-length")
                    return
                if declared > self.max_bytes:
                    await self._reply(send, 413, "request body too large")
                    return

        received = 0
        exceeded = False
        replied = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise BodyTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            # Inner layers do not all let the exception through: FastAPI turns
            # most body-read failures into a 400, and BaseHTTPMiddleware can wrap
            # it in an exception group. Whatever response follows an overrun is
            # therefore replaced here, so the status is 413 however it surfaced.
            nonlocal replied
            if not exceeded:
                await send(message)
                return
            if message["type"] == "http.response.start" and not replied:
                replied = True
                await self._reply(send, 413, "request body too large")

        try:
            await self.app(scope, limited_receive, guarded_send)
        except BodyTooLarge:
            if not replied:
                replied = True
                await self._reply(send, 413, "request body too large")
        except Exception:
            if not exceeded:
                raise
            if not replied:  # pragma: no cover - an exception group around ours
                replied = True
                await self._reply(send, 413, "request body too large")

    @staticmethod
    async def _reply(send: Send, status: int, detail: str) -> None:
        start, body = _json_response(status, detail)
        await send(start)
        await send(body)


# -- rate limiting -------------------------------------------------------------


class TokenBucket:
    """A token bucket with an injectable clock.

    Used for the connect test, which was an unmetered way to ask the server
    whether a TCP port on any host it can route to is open: measured at 311
    probes a second against a live server, which is a port scanner.
    """

    def __init__(self, capacity: int, per_seconds: float, clock: Clock | None = None) -> None:
        if capacity <= 0 or per_seconds <= 0:
            raise ValueError("capacity and per_seconds must be positive")
        self.capacity = float(capacity)
        self.rate = capacity / per_seconds  # tokens per second
        self._clock = clock or time.monotonic
        self._tokens = float(capacity)
        self._stamp = self._clock()
        self._lock = threading.Lock()

    def take(self) -> float:
        """Spend one token. Returns 0.0 on success, else seconds until one is free."""

        with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._stamp)
            self._stamp = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            return (1.0 - self._tokens) / self.rate


# -- collector destinations ----------------------------------------------------


@dataclass(frozen=True)
class CollectorRule:
    """One ``--collector-allow`` entry: a network and an optional port."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port: int | None = None

    def __str__(self) -> str:
        net = str(self.network)
        if self.port is None:
            return net
        return f"[{net}]:{self.port}" if self.network.version == 6 else f"{net}:{self.port}"


def parse_collector_rule(text: str) -> CollectorRule:
    """Parse ``CIDR[:port]``. IPv6 with a port is bracketed: ``[2001:db8::/32]:514``.

    A bare address is a single-host network. Raises ValueError with an
    operator-facing message on anything else, so a typo refuses startup rather
    than silently allowing nothing or everything.
    """

    raw = text.strip()
    port_text: str | None = None
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"--collector-allow {text!r}: unbalanced '['")
        address, rest = raw[1:end], raw[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"--collector-allow {text!r}: expected ':PORT' after ']'")
            port_text = rest[1:]
    elif raw.count(":") == 1:
        address, port_text = raw.split(":", 1)
    else:
        address = raw
    try:
        network = ipaddress.ip_network(address.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(
            f"--collector-allow {text!r}: {address!r} is not an IP address or CIDR"
        ) from exc
    port: int | None = None
    if port_text is not None:
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ValueError(f"--collector-allow {text!r}: port must be 1-65535")
        port = int(port_text)
    return CollectorRule(network=network, port=port)


@dataclass(frozen=True)
class CollectorPolicy:
    """Where web callers may point the collector. Empty means anywhere.

    Enforced on connect tests and on runs that send, from the web API only. The
    CLI is unchanged, for the same reason ``_confined_output`` leaves it alone: a
    shell user already has that authority.

    Only IP literals can match. A hostname would be resolved again by the
    transport at send time, so checking it here would be a check of a different
    lookup than the one that decides the destination.
    """

    rules: tuple[CollectorRule, ...] = ()

    @classmethod
    def parse(cls, entries: Iterable[str]) -> CollectorPolicy:
        return cls(tuple(parse_collector_rule(entry) for entry in entries if entry.strip()))

    @property
    def restricted(self) -> bool:
        return bool(self.rules)

    def permits(self, host: str, port: int) -> bool:
        if not self.rules:
            return True
        text = host.strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        return any(
            address.version == rule.network.version
            and address in rule.network
            and (rule.port is None or rule.port == port)
            for rule in self.rules
        )

    def describe(self) -> str:
        if not self.rules:
            return "any destination (no --collector-allow set)"
        return ", ".join(str(rule) for rule in self.rules)


# -- TLS CA files --------------------------------------------------------------


class CAFileRefused(ValueError):
    """A browser-supplied CA file name that does not name a file in the CA dir."""


#: One message for every refusal, so the reply cannot be used to learn whether a
#: path exists or what kind of object it is.
CA_REFUSAL = (
    "tls_cafile must be the name of a CA bundle in the Replicant ca/ directory "
    "under the config directory"
)


def confined_cafile(value: str | None, ca_root: Path) -> str | None:
    """Resolve a web-supplied CA file name to a regular file inside ``ca_root``.

    ``ssl.create_default_context(cafile=...)`` opens whatever it is given, and the
    error it raised came back in the connect-test summary, so the field was a
    probe of any path the service account can stat. Only a bare file name is
    accepted, it must be a regular file directly inside ``ca_root``, and it must
    not be a symlink.
    """

    if value is None or not value.strip():
        return None
    name = value.strip()
    if name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise CAFileRefused(CA_REFUSAL)
    candidate = ca_root / name
    try:
        info = os.lstat(candidate)
    except OSError as exc:
        raise CAFileRefused(CA_REFUSAL) from exc
    if not stat.S_ISREG(info.st_mode):  # a symlink is S_ISLNK under lstat
        raise CAFileRefused(CA_REFUSAL)
    try:
        if candidate.resolve(strict=True).parent != ca_root.resolve(strict=True):
            raise CAFileRefused(CA_REFUSAL)
    except OSError as exc:  # pragma: no cover - raced away between lstat and resolve
        raise CAFileRefused(CA_REFUSAL) from exc
    return str(candidate)


# -- evidence retention --------------------------------------------------------

#: Evidence packs the web server keeps. Each is a directory plus a ZIP of about
#: 1.1 MB for REP-004 high, and nothing ever removed them.
DEFAULT_EVIDENCE_KEEP = 20

_RUN_ID = re.compile(r"^RUN-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")


def prune_evidence(root: Path, keep: int) -> list[str]:
    """Delete all but the newest ``keep`` evidence packs directly under ``root``.

    Returns the run ids removed. Only entries named like a run id
    (``RUN-<stamp>Z-<hex>`` or that plus ``.zip``) are candidates, so nothing
    else an operator keeps in the directory is touched. Symlinks are never
    followed or removed: a planted ``RUN-...`` link to somewhere else is left
    alone rather than resolved, and ``shutil.rmtree`` does not follow links
    inside a pack. Run ids sort chronologically by construction.
    """

    if keep < 1:
        raise ValueError("keep must be at least 1")
    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return []
    packs: dict[str, list[os.DirEntry[str]]] = {}
    for entry in entries:
        run_id = entry.name[:-4] if entry.name.endswith(".zip") else entry.name
        if not _RUN_ID.match(run_id) or entry.is_symlink():
            continue
        packs.setdefault(run_id, []).append(entry)
    removed: list[str] = []
    for run_id in sorted(packs)[:-keep]:
        for entry in packs[run_id]:
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    os.unlink(entry.path)
            except OSError as exc:  # pragma: no cover - permissions race
                _log.warning("could not remove evidence %s: %s", entry.path, exc)
        removed.append(run_id)
    return removed


# -- plan builds ---------------------------------------------------------------


class GateBusy(RuntimeError):
    """The build gate is full, or the wait for it timed out."""


class BuildGate:
    """At most ``concurrent`` plan builds at once, with a bounded wait queue.

    Pricing (``POST /api/plan``), samples and validation each build a whole
    plan, about 400 MB for REP-004 at high intensity and about 830 MB for its
    validation. None of them was bounded. Callers wait for a slot, because the
    run form re-prices on every change and the newest request is the one whose
    answer matters, but only ``max_waiting`` may wait at once: each waiter holds
    a worker thread, and an unbounded queue would move the exhaustion from memory
    to the thread pool.
    """

    def __init__(self, concurrent: int = 1, max_waiting: int = 4, timeout_s: float = 30.0) -> None:
        self._slots = threading.BoundedSemaphore(concurrent)
        self._lock = threading.Lock()
        self._waiting = 0
        self.max_waiting = max_waiting
        self.timeout_s = timeout_s

    @contextmanager
    def slot(self) -> Iterator[None]:
        with self._lock:
            if self._waiting >= self.max_waiting:
                raise GateBusy("too many plan builds queued")
            self._waiting += 1
        try:
            acquired = self._slots.acquire(timeout=self.timeout_s)
        finally:
            with self._lock:
                self._waiting -= 1
        if not acquired:
            raise GateBusy("timed out waiting for a plan build slot")
        try:
            yield
        finally:
            self._slots.release()


# -- stream subscribers --------------------------------------------------------

#: Concurrent server-sent-event streams (run and log streams together).
MAX_STREAMS = 16


class StreamSlot:
    """One held stream slot. Released explicitly, or when garbage collected.

    The collection path matters: a client that disconnects between the endpoint
    returning and the response starting leaves a generator that is never
    iterated, so its ``finally`` never runs. The generator's closure holds this
    object, so dropping the generator drops the slot.
    """

    def __init__(self, owner: StreamLimiter) -> None:
        self._owner: StreamLimiter | None = owner

    def release(self) -> None:
        owner, self._owner = self._owner, None
        if owner is not None:
            owner._release()

    def __del__(self) -> None:
        self.release()


class StreamLimiter:
    """Counts live SSE streams and refuses past a cap."""

    def __init__(self, cap: int = MAX_STREAMS) -> None:
        self.cap = cap
        self._live = 0
        self._lock = threading.Lock()

    @property
    def live(self) -> int:
        with self._lock:
            return self._live

    def acquire(self) -> StreamSlot | None:
        with self._lock:
            if self._live >= self.cap:
                return None
            self._live += 1
        return StreamSlot(self)

    def _release(self) -> None:
        with self._lock:
            self._live = max(0, self._live - 1)
