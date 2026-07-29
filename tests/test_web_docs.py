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
"""The Docs tab's API: a fixed allowlist of reference pages, served as markdown."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.web import server as server_mod  # noqa: E402
from replicant.web.server import DOC_PAGES, create_app  # noqa: E402

TOKEN = "test-token"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    return TestClient(create_app(CATALOG, settings, token=TOKEN), base_url="http://localhost")


def test_index_lists_the_allowlisted_pages(client: TestClient) -> None:
    pages = client.get("/api/docs", headers=HEADERS).json()["pages"]

    ids = [page["id"] for page in pages]
    assert "fortigate-cef" in ids
    assert "paloalto-cef" in ids
    assert "checkpoint-cef" in ids
    assert all(page["title"] for page in pages)


def test_index_requires_a_token(client: TestClient) -> None:
    assert client.get("/api/docs").status_code == 401


def test_a_page_comes_back_as_markdown(client: TestClient) -> None:
    data = client.get("/api/docs/fortigate-cef", headers=HEADERS).json()

    assert data["id"] == "fortigate-cef"
    assert "CEF:" in data["markdown"], "expected the golden lines from the reference"


def test_page_requires_a_token(client: TestClient) -> None:
    assert client.get("/api/docs/fortigate-cef").status_code == 401


def test_an_unknown_id_is_404(client: TestClient) -> None:
    assert client.get("/api/docs/no-such-page", headers=HEADERS).status_code == 404


@pytest.mark.parametrize(
    "doc_id",
    ["..%2F..%2Fetc%2Fpasswd", "....//etc/passwd", "blueprint", "..", "%2e%2e"],
)
def test_only_allowlisted_ids_resolve(client: TestClient, doc_id: str) -> None:
    # The id is a dictionary key, never a path fragment joined onto a directory, so
    # there is no traversal to defend against. This asserts that stays true.
    resp = client.get(f"/api/docs/{doc_id}", headers=HEADERS)

    assert resp.status_code == 404
    assert "passwd" not in resp.text


def test_every_allowlisted_page_exists_in_this_checkout() -> None:
    # A typo in the allowlist would ship a tab whose every entry 404s, and nothing
    # else would notice.
    missing = [
        page.filename for page in DOC_PAGES if not (server_mod.DOCS_DIR / page.filename).is_file()
    ]

    assert missing == []


def test_a_missing_docs_directory_degrades_instead_of_crashing(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # docs/ lives outside the `replicant` package and is not in the wheel
    # (pyproject packages `replicant*` only, and there is no MANIFEST.in), exactly
    # like webui/dist. On a non-editable install the directory is simply absent.
    monkeypatch.setattr(server_mod, "DOCS_DIR", tmp_path / "absent")

    index = client.get("/api/docs", headers=HEADERS).json()
    page = client.get("/api/docs/fortigate-cef", headers=HEADERS)

    assert index["available"] is False
    assert all(p["available"] is False for p in index["pages"])
    assert page.status_code == 404
    assert "editable" in page.json()["detail"].lower()
