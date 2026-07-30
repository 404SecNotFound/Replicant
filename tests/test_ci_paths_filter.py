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
"""The CI path filter must not exclude a file the suite actually reads.

`.github/workflows/ci.yml` skips runs for prose-only changes. The saving is real
(a documentation commit used to queue ten jobs, three of them installer
containers) but the failure mode is silent: exclude the wrong path and the gate
stops running with nothing going red to say so. Two paths make that easy to do
by accident.

The first is `docs/`. It looks like pure prose and mostly is, but three files in
it are executable in practice: the vendor CEF references are the golden-line
oracle that `tests/test_*_golden.py` parse, so a typo in one fails the suite. Two
more are asserted to exist on disk by `tests/test_web_docs.py`. All five are
therefore re-included, and `test_every_served_doc_page_triggers` derives its list
from `DOC_PAGES` rather than repeating it, so adding a Docs tab page fails here
until the workflow re-includes it too.

The second is drift between the `push` and `pull_request` filters, which would
gate a commit on one leg and not the other.

`_triggers` is a deliberately small reimplementation of GitHub's filter-pattern
matching, not a specification of it. [Unverified] as a model of GitHub's engine in
full: it covers `*` (which does not cross `/`), `**` (which does), `?`, a leading
`!`, and last-match-wins, which is the whole of what this filter uses. Its job is
to catch an edit that swallows a load-bearing path, and for that it does not need
to be exact.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"

# Absent from a wheel and from an sdist, present in a checkout. Same reasoning as
# replicant.resources.docs_available.
pytestmark = pytest.mark.skipif(
    not CI_WORKFLOW.is_file(), reason="no .github/ in this tree (wheel or sdist)"
)

# Changing any of these must run the full gate.
LOAD_BEARING = [
    ".github/workflows/ci.yml",
    "pyproject.toml",
    "replicant/cef/serializer.py",
    "replicant/web/server.py",
    "replicant/data/technique-catalog.yaml",
    "replicant/data/scenario-catalog.yaml",
    "replicant/webui_dist/index.html",
    "tests/test_cef_serializer.py",
    "webui/src/App.tsx",
    "webui/package-lock.json",
    "webui/vite.config.ts",
    "scripts/install.sh",
    "scripts/replicant-web.service",
    ".gitignore",
]

# Prose. Nothing reads these, so a change to one need not spend ten runners.
PROSE_ONLY = [
    "README.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "LICENSE",
    "NOTICE",
    "docs/blueprint.md",
    "docs/prior-art-and-licensing.md",
    "docs/webui-reskin-design.md",
    "docs/images/cli-list.png",
    "tasks/uat-plan.md",
    "tasks/lessons.md",
]


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _triggers(patterns: list[str], path: str) -> bool:
    """Whether one changed path would start a run. Last matching pattern wins."""
    verdict = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        if _pattern_to_regex(pattern.lstrip("!")).match(path):
            verdict = not negated
    return verdict


def _workflow() -> dict[str, Any]:
    return dict(yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))


def _triggers_block(workflow: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 reads a bare `on` as a boolean, so the key is True and not "on".
    # PyYAML is right and the workflow is right; they just disagree on the spelling.
    block = workflow.get("on", workflow.get(True))
    assert isinstance(block, dict), "ci.yml has no usable `on:` block"
    return block


def _paths_for(event: str) -> list[str]:
    paths = _triggers_block(_workflow())[event]["paths"]
    assert isinstance(paths, list) and paths, f"{event} has no paths filter"
    return [str(p) for p in paths]


def test_push_and_pull_request_filters_are_identical() -> None:
    assert _paths_for("push") == _paths_for("pull_request")


@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("path", LOAD_BEARING)
def test_load_bearing_paths_trigger_a_run(event: str, path: str) -> None:
    assert _triggers(_paths_for(event), path), f"{path} would skip CI"


@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("path", PROSE_ONLY)
def test_prose_only_paths_do_not_trigger_a_run(event: str, path: str) -> None:
    assert not _triggers(_paths_for(event), path), f"{path} still spends a full matrix"


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_the_golden_line_oracles_trigger_a_run(event: str) -> None:
    """The files tests/test_*_golden.py parse. Globbed, not listed, so a fourth
    vendor reference is covered the moment it lands."""
    references = sorted(p.name for p in DOCS_DIR.glob("*-cef-reference.md"))
    assert len(references) >= 3, f"expected the vendor references, found {references}"

    patterns = _paths_for(event)
    for name in references:
        assert _triggers(patterns, f"docs/{name}"), f"docs/{name} is the oracle and would skip CI"


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_every_served_doc_page_triggers_a_run(event: str) -> None:
    """Derived from DOC_PAGES so it cannot go stale: test_web_docs asserts each of
    these exists on disk, which makes editing one able to fail the suite."""
    pytest.importorskip("fastapi")
    from replicant.web.server import DOC_PAGES

    patterns = _paths_for(event)
    for page in DOC_PAGES:
        assert _triggers(
            patterns, f"docs/{page.filename}"
        ), f"docs/{page.filename} is served by the Docs tab and would skip CI"
