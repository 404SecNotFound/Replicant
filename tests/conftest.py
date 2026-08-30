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
"""Suite-wide isolation of per-user state.

``config_dir()`` resolves to ``~/.config/replicant`` unless
``REPLICANT_CONFIG_DIR`` says otherwise, and until now the suite let it. Running
the tests therefore read and wrote the operator's real configuration directory:
the saved collector profile, the persistent web token, and now the send lock.

That was already impolite and it became load-bearing with F-08. The send lock is
deliberately host-global, which is the entire point of it, so a web test that
starts a run and does not stop it holds a lock that the *next* test's sending run
is then correctly refused. Five tests failed that way, and every one of them was
a true report about global state rather than a defect in the thing under test.

Isolating the directory per test is the fix rather than making the lock weaker.
The guard's real behaviour, that a second sending process is refused, is proved
in ``test_sendlock.py`` by spawning an actual second process, which no amount of
directory isolation can fake.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every test at its own config directory.

    Autouse and unconditional: a test that wants the real one is a test that
    would mutate the machine it runs on. Tests that set the variable themselves
    still win, since they apply their own monkeypatch after this fixture.
    """

    home = tmp_path / "config"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("REPLICANT_CONFIG_DIR", str(home))
    return home
