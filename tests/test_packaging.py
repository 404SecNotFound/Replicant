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
"""Runtime files must live inside the package, or a wheel installs a broken tool.

The catalogs used to sit in a top-level ``data/`` directory reached by
``Path(__file__).parents[2]``, which is a repository path. A wheel contained none
of it, so ``pip install`` produced a binary that printed its version and then said
"catalog not found" on every command. It was also cwd-dependent, because the CLI
fell back to ``Path.cwd()``: it worked from a checkout and failed anywhere else,
which is why the whole test suite stayed green while the wheel was broken.

These are the cheap guards. The real one is the ``wheel`` CI job, which builds a
wheel, installs it into a clean virtualenv and runs it from a directory with no
repository in sight.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from replicant import resources
from replicant.cli.app import _find_catalog
from replicant.config.settings import Settings

PACKAGE = Path(resources.__file__).resolve().parent
PYPROJECT = PACKAGE.parent / "pyproject.toml"


def test_catalogs_are_inside_the_package() -> None:
    for path in (resources.TECHNIQUE_CATALOG, resources.SCENARIO_CATALOG):
        assert path.is_file(), f"missing runtime file: {path}"
        assert PACKAGE in path.parents, f"{path} is outside the package, so a wheel omits it"


def test_frontend_dist_is_inside_the_package() -> None:
    # The directory need not exist (the frontend may not be built), but the path
    # it resolves to has to be packageable.
    assert PACKAGE in resources.FRONTEND_DIST.parents


def test_package_data_covers_every_runtime_file() -> None:
    # A file inside the package still does not ship unless package-data lists it.
    # This catches "moved the file, forgot the glob", which produces exactly the
    # same broken wheel as before.
    patterns = tomllib.loads(PYPROJECT.read_text())["tool"]["setuptools"]["package-data"][
        "replicant"
    ]
    covered = {match.resolve() for pattern in patterns for match in PACKAGE.glob(pattern)}

    for required in (resources.TECHNIQUE_CATALOG, resources.SCENARIO_CATALOG):
        assert required.resolve() in covered, f"{required.name} is not matched by package-data"


def test_catalog_resolves_without_help_from_the_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    # The defining symptom of the old bug: correct from a checkout, broken from
    # anywhere else. Run the lookup from an empty directory and require it to work.
    monkeypatch.chdir(tmp_path)

    found = _find_catalog(Settings())

    assert found is not None, "catalog lookup depends on the working directory"
    assert found == resources.TECHNIQUE_CATALOG


def test_an_explicit_catalog_override_still_wins(tmp_path: Path, monkeypatch) -> None:
    # Preferring the packaged catalog must not take the override away from an
    # operator who points catalog_path at their own file.
    custom = tmp_path / "mine.yaml"
    custom.write_text("version: '0'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert _find_catalog(Settings(catalog_path=str(custom))) == custom


def test_docs_are_deliberately_not_packaged() -> None:
    # Not an oversight. docs/ is documentation, it is large, and duplicating it
    # inside the package would guarantee the copies drift. The Docs tab reports
    # its absence rather than failing. Asserted so nobody "fixes" it by accident.
    assert PACKAGE not in resources.DOCS_DIR.parents
