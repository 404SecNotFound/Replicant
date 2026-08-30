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
"""One sending run per host, enforced.

Closes security review finding **F-08**: the events-per-second cap is applied by
the emit loop of a single process, so two Replicant processes sending at the
same time deliver twice the cap to the operator's collector, and neither one is
doing anything wrong. Safety rule 4 exists to protect that collector, and a cap
that any second invocation silently doubles is not protecting it.

Two remedies were on the table. A host-level lease keyed on collector
destination would let two runs aimed at different collectors proceed together
and share a budget when aimed at the same one. It is also a distributed-systems
problem in a lab tool: leases expire, clocks drift, a killed process leaves a
lease behind, and the failure modes are worse than the thing being fixed.

The chosen remedy is the other one the review offered: **state the scope and
enforce it.** The cap is per process, one sending process per host is the
supported configuration, and a second one is refused rather than allowed to
quietly double the rate. That is a smaller promise than a lease, and unlike a
lease it is one the code can actually keep.

## What this covers, and what it does not

Covered: any run that opens a socket to a collector, from the CLI, the Rich menu
or the web UI, on this host. `--no-send` and `--to-file` runs never acquire it,
because they cannot reach a collector and so cannot exceed anything.

Not covered, deliberately and stated rather than implied:

- **Other hosts.** Two laptops pointed at one collector are two processes on two
  machines. Nothing here sees that, and a host-level file lock never could.
- **A different config dir.** The lock lives beside the other per-user state, so
  `REPLICANT_CONFIG_DIR` moves it. That is what makes it testable, and it also
  means a second user account on the same host holds a different lock. Both are
  per-user tools writing to their own collector configuration.
- **`flock` semantics.** The lock is advisory and released by the kernel when the
  holder exits, including on kill -9, so there is no stale lock to clean up. It
  is not a mutex against a process that never opened it.
"""

from __future__ import annotations

import errno
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from replicant.config.settings import config_dir


def lock_path() -> Path:
    """Where the lock lives. Beside the other per-user state, so it moves with it."""

    return config_dir() / "send.lock"


class SendInProgressError(RuntimeError):
    """Another Replicant process on this host is already sending."""


@contextmanager
def sending_lock() -> Iterator[None]:
    """Hold the host's single sending slot, or refuse.

    Fails closed: if the slot is taken the run does not start at all, rather
    than starting and sharing a cap that neither process can see. The message
    names the holding pid because "another process" is not actionable and the
    holder is usually a forgotten web UI in another terminal.
    """

    path = lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Opened, never truncated on open: truncating would erase the holder's pid
    # before we know whether we can have the lock, which is the one moment the
    # pid is worth reading.
    handle = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            holder = os.read(handle, 32).decode("utf-8", "replace").strip() or "unknown"
            raise SendInProgressError(
                f"another Replicant process on this host is already sending (pid {holder}). "
                "The events-per-second cap is enforced per process, so a second sending run "
                "would deliver twice the cap to your collector. Wait for that run to finish, "
                "or use --no-send/--to-file, which never reach a collector."
            ) from None
        os.ftruncate(handle, 0)
        os.write(handle, str(os.getpid()).encode())
        os.fsync(handle)
        yield
    finally:
        # flock is released by close, and by process exit if we never get here.
        os.close(handle)
