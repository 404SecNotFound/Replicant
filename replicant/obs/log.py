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
"""In-process logging with a bounded buffer the web UI can read.

This exists because of a specific failure. A live run reported 921 events per
second sent while nothing arrived at the collector, and the tool had no way to
say anything more. UDP ``sendto`` accepts a datagram into the kernel and returns
success whether or not it ever reaches the wire, so "sent" was the strongest
claim the code could make, and it was not a useful one.

Design notes:

- **Nothing here performs I/O to anywhere but memory.** Safety rule 1 says the
  only egress is the operator's collector. A log page that shipped telemetry
  somewhere would break that, so records live in a ring buffer in this process
  and are read back over the existing localhost API.
- **The buffer is bounded.** A run emits tens of thousands of events and VERBOSE
  logs one line each. An unbounded list would be a memory leak with a nice UI.
- **`propagate` is off.** Under systemd, stdout is the journal. This project has
  already leaked a secret that way once, and a logger that defaults to writing
  every record to the journal would be a second helping of the same mistake.
- **Records are redacted on the way in, not on the way out.** A redaction applied
  at render time protects one reader and leaves the secret sitting in memory for
  everything else.

Four levels, matching the four modes the operator asked for. VERBOSE sits between
DEBUG and INFO because per-event lines are higher volume than diagnostics but
lower value than a warning.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

# stdlib has DEBUG=10, INFO=20, WARNING=30. Per-event logging wants its own tier:
# noisier than INFO, quieter than the internals DEBUG carries.
VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")

ROOT_NAME = "replicant"

# The operator-facing names, ordered least to most severe. The API takes these
# strings; the numbers stay an implementation detail.
LEVEL_NAMES: tuple[str, ...] = ("debug", "verbose", "info", "warning")

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "verbose": VERBOSE,
    "info": logging.INFO,
    "warning": logging.WARNING,
}
_LEVEL_TO_NAME: dict[int, str] = {value: key for key, value in _LEVELS.items()}

DEFAULT_CAPACITY = 5000

# Anything that looks like a session token, wherever it appears. The web token is
# the one secret this process holds; it reaches log-adjacent places by way of the
# URL in the startup banner, so the pattern targets that shape specifically
# rather than trying to be a general secret scanner.
_TOKEN_PATTERNS = (
    re.compile(r"(?i)(token=)[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)(x-replicant-token[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-]{8,}"),
)


def redact(message: str) -> str:
    """Mask anything token-shaped. Applied before a record enters the buffer."""

    for pattern in _TOKEN_PATTERNS:
        message = pattern.sub(r"\1<redacted>", message)
    return message


@dataclass(frozen=True)
class LogEntry:
    """One record, as the API serves it.

    ``seq`` is monotonic for the life of the process and is what lets a client
    tail without re-reading: ask for everything after the last seq it saw. It is
    not a timestamp, because two records in the same millisecond need an order.
    """

    seq: int
    ts: float
    level: str
    logger: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "level": self.level,
            "logger": self.logger,
            "message": self.message,
        }


class RingBufferHandler(logging.Handler):
    """Keeps the last ``capacity`` records in memory, oldest evicted first.

    Locked because the emit loop runs on a worker thread while the API serves
    reads on another. ``deque`` operations are individually atomic under the GIL,
    but assigning a sequence number and appending are two operations, and without
    the lock two threads can interleave into a buffer whose seq order is a lie.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        super().__init__()
        self._entries: deque[LogEntry] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = redact(record.getMessage())
        except Exception:  # pragma: no cover - defensive, a bad format string
            self.handleError(record)
            return
        with self._lock:
            self._seq += 1
            self._entries.append(
                LogEntry(
                    seq=self._seq,
                    ts=record.created,
                    level=logging.getLevelName(record.levelno).lower(),
                    logger=record.name,
                    message=message,
                )
            )

    def snapshot(self, after: int = 0, limit: int | None = None) -> list[LogEntry]:
        with self._lock:
            entries = [entry for entry in self._entries if entry.seq > after]
        if limit is not None and len(entries) > limit:
            return entries[-limit:]
        return entries

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_handler: RingBufferHandler | None = None
_install_lock = threading.Lock()


def install(capacity: int = DEFAULT_CAPACITY, level: str = "info") -> RingBufferHandler:
    """Attach the buffer to the ``replicant`` logger. Idempotent.

    Safe to call from the CLI, the web server and a test without stacking
    handlers, which would otherwise duplicate every record once per call.
    """

    global _handler
    with _install_lock:
        if _handler is not None:
            return _handler
        handler = RingBufferHandler(capacity)
        logger = logging.getLogger(ROOT_NAME)
        logger.addHandler(handler)
        logger.setLevel(_LEVELS[level])
        # Do not hand records to the root logger. See the module docstring: under
        # systemd that is the journal, and this buffer is not a reason to start
        # writing run detail there.
        logger.propagate = False
        _handler = handler
        return handler


def get_logger(name: str) -> logging.Logger:
    """A child logger. ``name`` is a subsystem, e.g. ``transport``."""

    return logging.getLogger(f"{ROOT_NAME}.{name}")


def set_level(level: str) -> None:
    if level not in _LEVELS:
        raise ValueError(f"unknown level: {level!r}; expected one of {', '.join(LEVEL_NAMES)}")
    logging.getLogger(ROOT_NAME).setLevel(_LEVELS[level])


def current_level() -> str:
    effective = logging.getLogger(ROOT_NAME).getEffectiveLevel()
    return _LEVEL_TO_NAME.get(effective, logging.getLevelName(effective).lower())


def snapshot(after: int = 0, limit: int | None = None) -> list[LogEntry]:
    """Records newer than ``after``. Empty when logging was never installed."""

    if _handler is None:
        return []
    return _handler.snapshot(after=after, limit=limit)


def clear() -> None:
    if _handler is not None:
        _handler.clear()


def reset_for_tests() -> None:
    """Detach the handler. Tests only, so one test's records cannot reach another."""

    global _handler
    with _install_lock:
        logger = logging.getLogger(ROOT_NAME)
        if _handler is not None:
            logger.removeHandler(_handler)
        _handler = None
        logger.propagate = True


def verbose(logger: logging.Logger, message: str, *args: Any) -> None:
    """Log at VERBOSE. A helper because ``logging.Logger`` has no method for it."""

    if logger.isEnabledFor(VERBOSE):
        logger.log(VERBOSE, message, *args)


class RateCounter:
    """Counts events and bytes in the current wall-clock second.

    The emit loop needs a once-a-second summary without keeping per-event history,
    and without calling ``time.monotonic`` more than it already does.
    """

    def __init__(self) -> None:
        self.events = 0
        self.bytes = 0
        self.errors = 0
        self._window_start = time.monotonic()

    def add(self, byte_count: int, error: bool = False) -> None:
        self.events += 1
        self.bytes += byte_count
        if error:
            self.errors += 1

    def due(self, now: float | None = None) -> bool:
        return (now or time.monotonic()) - self._window_start >= 1.0

    def take(self, now: float | None = None) -> tuple[int, int, int, float]:
        """Return (events, bytes, errors, elapsed) and start a fresh window."""

        stamp = now or time.monotonic()
        elapsed = stamp - self._window_start
        result = (self.events, self.bytes, self.errors, elapsed)
        self.events = 0
        self.bytes = 0
        self.errors = 0
        self._window_start = stamp
        return result
