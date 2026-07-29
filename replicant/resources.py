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
"""Where Replicant's runtime files live, in a wheel and in a checkout.

Everything the tool needs at run time is now inside the package: the technique
and scenario catalogs under ``replicant/data``, and the built frontend under
``replicant/webui_dist``. Both therefore ship in a wheel.

This module exists because they did not always. The catalogs used to sit in a
top-level ``data/`` directory reached by ``Path(__file__).parents[2]``, which is
a repository path, not a package path. A wheel contained none of it, so
``pip install`` produced a tool that reported its version and then failed with
"catalog not found" on every command. Worse, it was cwd-dependent: the CLI also
tried ``Path.cwd()``, so it worked when run from a checkout and failed anywhere
else, which is the kind of bug that reaches a user before it reaches a test.

``docs/`` is deliberately NOT packaged. It is documentation, it is large, and
duplicating it inside the package would guarantee the two copies drift. The Docs
tab reads the repository copy and says so plainly when there is not one.
"""

from __future__ import annotations

from pathlib import Path

# The installed package directory. Under a wheel this is site-packages/replicant;
# in a checkout it is the repository's replicant/. Data lives beside this file in
# both cases, which is the entire point.
PACKAGE_ROOT = Path(__file__).resolve().parent

# The repository root, when running from a source checkout. None of the runtime
# lookups below depend on this; it is here for the things that legitimately are
# repository-only, like the reference documentation.
REPO_ROOT = PACKAGE_ROOT.parent

DATA_DIR = PACKAGE_ROOT / "data"
TECHNIQUE_CATALOG = DATA_DIR / "technique-catalog.yaml"
SCENARIO_CATALOG = DATA_DIR / "scenario-catalog.yaml"

# Vite writes here (see webui/vite.config.ts). Inside the package so that a wheel
# built after `npm run build` carries the UI.
FRONTEND_DIST = PACKAGE_ROOT / "webui_dist"

# Repository-only. Present in a checkout or an editable install, absent from a
# wheel, and the Docs tab handles that.
DOCS_DIR = REPO_ROOT / "docs"


def frontend_available() -> bool:
    return (FRONTEND_DIST / "index.html").is_file()


def docs_available() -> bool:
    return DOCS_DIR.is_dir()
