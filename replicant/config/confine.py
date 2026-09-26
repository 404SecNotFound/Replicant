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
"""Filesystem confinement for surfaces driven by the web token.

The web API already confines a browser-supplied output path to one directory
(``replicant/web/server.py``). The embedded terminal runs ``replicant menu`` as
the same service account, so the same token reached every path the menu would
accept: an output file anywhere the account can write (``FileSink`` opens with
mode ``w``, which truncates and follows symlinks), any file as a TLS CA bundle,
and the saved collector profiles. The PTY spawner sets ``REPLICANT_WEB_CONFINED=1``
and the menu applies these rules when it is set.

A shell user running the CLI is deliberately unaffected: they already hold the
filesystem authority these rules withhold.
"""

from __future__ import annotations

import os
from pathlib import Path

from replicant.config.settings import config_dir

CONFINED_ENV = "REPLICANT_WEB_CONFINED"


class ConfinementError(ValueError):
    """A path or action the confined surface does not permit."""


def web_confined() -> bool:
    """True when this process was spawned by the web terminal."""

    return os.environ.get(CONFINED_ENV) == "1"


def _basename(value: str) -> str:
    name = Path(value.strip()).name
    if name in {"", ".", ".."}:
        raise ConfinementError(f"{value!r} does not name a file")
    return name


def output_root(manifest_dir: str) -> Path:
    """``<manifest_dir resolved parent>/out``, the one directory output may go."""

    return Path(manifest_dir).resolve().parent / "out"


def confined_output_path(to_file: str, manifest_dir: str) -> str:
    """Resolve an output path to its basename inside :func:`output_root`.

    Refuses a symlink at the target, checked BEFORE resolving: a check on the
    resolved path can never see the link, because resolving follows it. Refuses
    anything that would resolve outside the directory.
    """

    root = output_root(manifest_dir)
    root.mkdir(parents=True, exist_ok=True)
    real_root = root.resolve()
    target = real_root / _basename(to_file)
    if target.is_symlink():
        raise ConfinementError("output path is not permitted: it is a symbolic link")
    resolved = target.resolve()
    if not resolved.is_relative_to(real_root) or resolved.is_dir():
        raise ConfinementError("output path is not permitted")
    return str(resolved)


def ca_root() -> Path:
    """``<config dir>/ca``, the one directory a confined TLS CA bundle may come from."""

    return config_dir() / "ca"


def confined_cafile(value: str) -> str:
    """Resolve a CA bundle name to an existing regular file inside :func:`ca_root`.

    Only the basename is honoured, so ``/etc/shadow`` becomes ``ca/shadow`` and
    is refused unless an operator put a file of that name there on purpose.
    """

    root = ca_root()
    target = root / _basename(value)
    if target.is_symlink():
        raise ConfinementError("CA bundle is not permitted: it is a symbolic link")
    if not target.is_file():
        raise ConfinementError(
            f"CA bundle not found: in the web terminal a CA bundle must be a file in "
            f"{root} and is named by its file name only"
        )
    resolved = target.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ConfinementError("CA bundle is not permitted")
    return str(resolved)


PROFILE_SAVE_REFUSED = (
    "saving collector profiles is disabled in the web terminal; use this collector "
    "for the session, or save it from a shell with 'replicant connect --save NAME'"
)
