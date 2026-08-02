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
"""An origin is a scheme, a host AND a port. The old check read only the host.

Found by an external review on 2026-08-02 and reproduced before fixing: a page
served from ``http://localhost:9999`` was accepted as same-origin by a Replicant
server on ``localhost:9787``, because the Origin header was reduced to an
authority and then handed to the Host allowlist, which strips the port.

That is a host allowlist, not an origin check. RFC 6454 defines an origin as the
triple (scheme, host, port), and the consequence here is concrete rather than
theoretical: any other web application on the analyst's own machine could drive
the embedded terminal using the browser's ambient Replicant cookie, and the
terminal runs ``replicant menu`` as the service account.

A shared analyst host running several dev servers on different localhost ports is
the normal case, not an exotic one, so binding to loopback does not remove the
attack condition.

The Host allowlist is kept as a separate control. It defends DNS rebinding, which
is a different attack, and neither check subsumes the other.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from replicant.web.server import AccessPolicy  # noqa: E402

LOOPBACK = AccessPolicy()


# -- the origin predicate -----------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:9999",  # the reproduction from the review
        "https://localhost:31337",
        "http://127.0.0.1:1",
        "http://localhost",  # port 80, not the server's port
    ],
)
def test_a_different_port_on_the_same_host_is_not_the_same_origin(origin: str) -> None:
    assert not LOOPBACK.allows_origin(origin, "localhost:9787")


def test_the_scheme_is_constrained_but_not_compared_and_here_is_why() -> None:
    """A deliberate limit, asserted so it stays a decision rather than a gap.

    RFC 6454 counts the scheme, and this check does not compare it, because the
    only thing it can be compared against is ``Host`` -- which carries no scheme.
    Both ``http://localhost:9787`` and ``https://localhost:9787`` present the
    identical ``Host: localhost:9787``.

    Not comparing it is safe because the two cannot coexist: serving ``https``
    on that authority means holding that port, and holding the port means being
    the server rather than attacking it. There is no second origin for an
    attacker to occupy.

    The scheme is still constrained to the two Replicant is served over, so
    ``file://`` and friends are refused (see below). Comparing it exactly needs
    an explicit configured public origin, which is the right shape for a TLS
    proxy deployment and is not built.
    """

    assert LOOPBACK.allows_origin("https://localhost:9787", "localhost:9787")
    assert LOOPBACK.allows_origin("http://localhost:9787", "localhost:9787")


def test_the_serving_origin_is_accepted() -> None:
    assert LOOPBACK.allows_origin("http://localhost:9787", "localhost:9787")


def test_default_ports_compare_equal_to_their_explicit_form() -> None:
    """``http://localhost`` and ``http://localhost:80`` are the same origin, so a
    server actually reached on port 80 must accept both spellings."""

    assert LOOPBACK.allows_origin("http://localhost", "localhost:80")
    assert LOOPBACK.allows_origin("http://localhost:80", "localhost")


def test_a_foreign_host_is_still_rejected() -> None:
    assert not LOOPBACK.allows_origin("http://evil.example.com", "localhost:9787")


@pytest.mark.parametrize("origin", ["null", "", "file://", "not-a-url", "http://"])
def test_unusable_origins_are_rejected(origin: str) -> None:
    """``Origin: null`` is what a sandboxed iframe or a redirected form sends. It
    names no origin, so it cannot match one."""

    assert not LOOPBACK.allows_origin(origin, "localhost:9787")


def test_a_non_web_scheme_is_rejected() -> None:
    assert not LOOPBACK.allows_origin("ftp://localhost:9787", "localhost:9787")


def test_an_ipv6_authority_compares_by_its_own_rules() -> None:
    policy = AccessPolicy(allowed_hosts=frozenset({"::1", "localhost", "127.0.0.1"}))

    assert policy.allows_origin("http://[::1]:9787", "[::1]:9787")
    assert not policy.allows_origin("http://[::1]:9999", "[::1]:9787")


# -- through the real application ---------------------------------------------


def _client(tmp_path: object) -> object:
    from fastapi.testclient import TestClient

    from replicant.config.settings import Settings
    from replicant.core.models import load_catalog
    from replicant.resources import TECHNIQUE_CATALOG
    from replicant.web.server import create_app

    app = create_app(load_catalog(TECHNIQUE_CATALOG), Settings(), token="t")
    return TestClient(app, base_url="http://localhost")


POLICY_VIOLATION = 1008


def _terminal_close_code(client: object, origin: str | None) -> int:
    """Connect to the terminal and return the close code, or 0 if it was accepted.

    Two things this gets right that the pre-existing terminal tests did not.

    ``host`` is set explicitly. TestClient sends ``Host: testserver`` regardless
    of ``base_url``, which the Host guard rejects *before* the origin is ever
    looked at. Every terminal websocket test in the suite was therefore passing
    on the host gate while claiming to exercise something else, and would have
    kept passing with the origin check deleted entirely.

    The close code is asserted rather than "some exception happened". A bare
    ``pytest.raises(Exception)`` passes for a typo as readily as for a rejection,
    which makes a guard worthless in exactly the situation it exists for.
    """

    from starlette.websockets import WebSocketDisconnect

    headers = {"host": "localhost"}
    if origin is not None:
        headers["origin"] = origin
    try:
        with client.websocket_connect("/ws/terminal?token=t", headers=headers) as ws:  # type: ignore[attr-defined]
            ws.receive_text()
    except WebSocketDisconnect as exc:
        return exc.code
    return 0


def test_the_terminal_accepts_its_own_origin(tmp_path: object) -> None:
    """The positive control, without which the rejections below prove nothing.

    Every case in this file would 'pass' against a terminal that refused
    everything. This is the case that says the gate discriminates.
    """

    assert _terminal_close_code(_client(tmp_path), "http://localhost") == 0


def test_the_terminal_refuses_a_cross_port_origin(tmp_path: object) -> None:
    """The reproduction from the review, end to end.

    A page on another localhost port, holding the browser's ambient Replicant
    credential, must not reach the PTY.
    """

    assert _terminal_close_code(_client(tmp_path), "http://localhost:9999") == POLICY_VIOLATION


def test_the_terminal_refuses_a_handshake_with_no_origin_at_all(tmp_path: object) -> None:
    """A token in a URL used to buy an unchecked connection. Browsers always send
    Origin on a WebSocket handshake, so its absence is never the real UI."""

    assert _terminal_close_code(_client(tmp_path), None) == POLICY_VIOLATION


def test_the_terminal_refuses_a_foreign_origin(tmp_path: object) -> None:
    assert _terminal_close_code(_client(tmp_path), "http://evil.example") == POLICY_VIOLATION


def test_the_host_allowlist_is_still_enforced_alongside_the_origin() -> None:
    """Both controls, not one. An origin that matches the Host header exactly is
    still refused when the host itself was never allowed, which is what stops a
    rebound DNS name from carrying a self-consistent pair."""

    assert not LOOPBACK.allows_origin("http://attacker.test:9787", "attacker.test:9787")
