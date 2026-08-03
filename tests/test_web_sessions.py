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
"""The browser cookie must not be the master token.

F-04 of the 2026-08 security review. The launch token is persistent, lives in
``~/.config/replicant/web-token``, and was ALSO the value written into the
session cookie. So the cookie was the master credential itself: it never
expired, could not be rotated, could not be revoked without regenerating the
token file, and anything that read it held permanent access.

The same token was additionally placed in EventSource and WebSocket query
strings, where URLs are the least private part of a request: they reach server
logs, browser history, and the Referer header.

This replaces it with an exchange. The launch token still bootstraps, but what
the browser then holds is a short-lived random session id that the server can
expire, rotate and revoke, and that grants nothing if it leaks after expiry.

The rule this review adopted applies: each guard here was run against the
unfixed code and observed to fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.server import SESSION_COOKIE, SessionStore, create_app  # noqa: E402

TOKEN = "launch-token-value"
CATALOG = load_catalog(TECHNIQUE_CATALOG)


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(CATALOG, Settings(manifest_dir=str(tmp_path)), token=TOKEN)
    return TestClient(app, base_url="http://localhost")


class TestSessionStore:
    def test_issued_ids_are_not_the_launch_token(self) -> None:
        store = SessionStore(ttl_s=60)

        assert store.issue() != TOKEN

    def test_issued_ids_are_unique(self) -> None:
        store = SessionStore(ttl_s=60)

        assert len({store.issue() for _ in range(50)}) == 50

    def test_a_fresh_id_validates(self) -> None:
        store = SessionStore(ttl_s=60)

        assert store.validate(store.issue()) is True

    def test_an_unknown_id_does_not(self) -> None:
        store = SessionStore(ttl_s=60)

        assert store.validate("not-a-session") is False
        assert store.validate("") is False

    def test_an_expired_id_stops_working(self) -> None:
        """The whole point: a leaked cookie has a shelf life."""
        clock = {"now": 1000.0}
        store = SessionStore(ttl_s=60, clock=lambda: clock["now"])
        sid = store.issue()

        clock["now"] += 61

        assert store.validate(sid) is False

    def test_revoking_one_id_leaves_the_others(self) -> None:
        store = SessionStore(ttl_s=60)
        keep, drop = store.issue(), store.issue()

        store.revoke(drop)

        assert store.validate(drop) is False
        assert store.validate(keep) is True

    def test_revoke_all_ends_every_session(self) -> None:
        store = SessionStore(ttl_s=60)
        ids = [store.issue() for _ in range(3)]

        store.revoke_all()

        assert not any(store.validate(i) for i in ids)

    def test_expired_entries_do_not_accumulate(self) -> None:
        """Otherwise a reconnect loop is an unbounded dict on a long-lived server."""
        clock = {"now": 1000.0}
        store = SessionStore(ttl_s=10, clock=lambda: clock["now"])
        for _ in range(100):
            store.issue()
            clock["now"] += 1

        store.issue()

        assert len(store) < 100


class TestExchange:
    def test_the_cookie_is_not_the_launch_token(self, client: TestClient) -> None:
        """The defect, stated directly."""
        resp = client.get("/api/health", params={"token": TOKEN})

        cookie = resp.cookies.get(SESSION_COOKIE)
        assert cookie
        assert cookie != TOKEN

    def test_the_cookie_authenticates_on_its_own(self, client: TestClient) -> None:
        client.get("/api/config", params={"token": TOKEN})

        # No token in this one: the cookie the client kept must carry it.
        assert client.get("/api/config").status_code == 200

    def test_a_forged_cookie_is_refused(self, client: TestClient) -> None:
        client.cookies.set(SESSION_COOKIE, "forged-session-id")

        assert client.get("/api/config").status_code == 401

    def test_the_launch_token_in_a_cookie_is_refused(self, client: TestClient) -> None:
        """It used to be exactly this value, so this is the regression that matters."""
        client.cookies.set(SESSION_COOKIE, TOKEN)

        assert client.get("/api/config").status_code == 401

    def test_logging_out_revokes_the_session(self, client: TestClient) -> None:
        client.get("/api/config", params={"token": TOKEN})
        assert client.get("/api/config").status_code == 200

        client.post("/api/session/logout")

        assert client.get("/api/config").status_code == 401

    def test_the_launch_token_still_works_for_a_non_browser_client(
        self, client: TestClient
    ) -> None:
        """Scripts hold the token from the file and cannot run a cookie jar."""
        client.cookies.clear()

        resp = client.get("/api/config", headers={"x-replicant-token": TOKEN})

        assert resp.status_code == 200
