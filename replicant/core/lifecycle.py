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
"""Process-signal handling for foreground runs.

``systemd stop`` and ``docker stop`` send SIGTERM, not SIGINT. SIGINT already
ended a run cleanly (``KeyboardInterrupt`` is caught in the emit loop, so the
manifest finalized as ``stopped`` with ``partial=true``), but SIGTERM's default
action killed the process outright and left the manifest ``running`` with
``ended_at`` null: indistinguishable from a crash, which is the one thing safety
rule 5 exists to prevent.

:func:`stop_on_sigterm` routes SIGTERM to the orchestrator's kill switch for the
duration of one run and restores whatever handler was there before.
"""

from __future__ import annotations

import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import FrameType
from typing import Protocol


class Stoppable(Protocol):
    def stop(self) -> None: ...


@dataclass
class SignalState:
    """Whether SIGTERM arrived while the guard was installed."""

    received: bool = False


#: Exit status for a process ended by SIGTERM, by shell convention (128 + 15).
SIGTERM_EXIT = 128 + signal.SIGTERM


@contextmanager
def stop_on_sigterm(target: Stoppable) -> Iterator[SignalState]:
    """Make SIGTERM call ``target.stop()`` instead of killing the process.

    Only the main thread can install a signal handler; anywhere else this is a
    no-op that still yields a state, so a caller never has to branch. A previous
    handler installed from C reads back as None and is restored as the default.
    """

    state = SignalState()
    if threading.current_thread() is not threading.main_thread():
        yield state
        return

    def handler(_signum: int, _frame: FrameType | None) -> None:
        state.received = True
        target.stop()

    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, handler)
    try:
        yield state
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)
