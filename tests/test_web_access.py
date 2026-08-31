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
"""How the web UI is reached: bind address, Host allowlist, auth, terminal gating.

The 0.1.0 hardening pass enforced a loopback bind and a per-session token. This
suite covers the deliberate relaxation of that bind and the controls that replace
it, so the compensating half of the trade cannot be quietly dropped later.
"""

from __future__ import annotations

import socket
import stat
from pathlib import Path

import pytest

from replicant.cli.app import build_parser, main  # noqa: E402
from replicant.config.settings import (  # noqa: E402
    WEB_DEFAULT_PORT,
    Settings,
    load_or_create_web_token,
    web_token_path,
)
from replicant.core.models import load_catalog  # noqa: E402

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.web.server import (  # noqa: E402
    SESSION_COOKIE,
    AccessPolicy,
    bind_socket,
    check_unauthenticated_exposure,
    create_app,
    display_available,
    startup_lines,
)

TOKEN = "test-token"
CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)


def make_client(
    tmp_path: Path,
    policy: AccessPolicy | None = None,
    *,
    base_url: str = "http://localhost",
) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN, policy=policy)
    return TestClient(app, base_url=base_url)


def establish_session(client: TestClient) -> None:
    """Authenticate once with the launch token so the server issues a session.

    These tests used to write the launch token straight into the cookie, because
    that is literally what the cookie held. F-04 replaced it with a short-lived
    id the server mints, so the only way to get a valid cookie is to be given
    one. That is the point of the change, and it is why this helper exists rather
    than a constant.
    """

    resp = client.get("/api/health", params={"token": TOKEN})
    assert resp.status_code == 200
    assert client.cookies.get(SESSION_COOKIE)


@pytest.fixture()
def config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the config dir at a temp path so tests never touch ~/.config."""
    home = tmp_path / "config"
    monkeypatch.setenv("REPLICANT_CONFIG_DIR", str(home))
    return home


# --- A1: the token persists ------------------------------------------------


def test_web_token_path_is_in_the_config_dir(config_home: Path) -> None:
    assert web_token_path().parent == config_home


def test_web_token_survives_a_restart(config_home: Path) -> None:
    first, first_state = load_or_create_web_token(rotate=False)
    second, second_state = load_or_create_web_token(rotate=False)

    assert first == second, "a restart must not invalidate the operator's bookmarked URL"
    assert first_state == "created"
    assert second_state == "persisted"


def test_rotate_replaces_the_stored_token(config_home: Path) -> None:
    original, _ = load_or_create_web_token(rotate=False)
    rotated, state = load_or_create_web_token(rotate=True)

    assert rotated != original
    assert state == "rotated"
    assert load_or_create_web_token(rotate=False)[0] == rotated, "rotation must be durable"


def test_token_file_is_readable_only_by_its_owner(config_home: Path) -> None:
    load_or_create_web_token(rotate=False)
    mode = stat.S_IMODE(web_token_path().stat().st_mode)

    assert mode == 0o600, f"token file is group/world readable: {mode:o}"


def test_config_dir_is_not_world_traversable(config_home: Path) -> None:
    load_or_create_web_token(rotate=False)
    mode = stat.S_IMODE(web_token_path().parent.stat().st_mode)

    assert mode & 0o077 == 0, f"config dir lets others in: {mode:o}"


def test_an_empty_token_file_is_replaced_rather_than_used(config_home: Path) -> None:
    # A truncated write, an interrupted install, or a `> web-token` typo must not
    # authenticate every caller against the empty string.
    load_or_create_web_token(rotate=False)
    web_token_path().write_text("   \n", encoding="utf-8")

    token, state = load_or_create_web_token(rotate=False)

    assert token.strip()
    assert state == "created"


# --- A2: the Host allowlist follows the bind address -----------------------


def test_default_policy_is_loopback_only() -> None:
    policy = AccessPolicy()

    assert policy.allows_host("localhost")
    assert policy.allows_host("127.0.0.1:9787")
    assert not policy.allows_host("evil.example.com")


def test_bind_address_is_allowed_without_extra_flags() -> None:
    # The old guard hardcoded localhost, so binding elsewhere meant the operator
    # had to defeat their own Host check to reach the thing they had just bound.
    policy = AccessPolicy.for_bind("10.20.0.50")

    assert policy.allows_host("10.20.0.50:9787")
    assert policy.allows_host("localhost:9787"), "loopback stays reachable on the host itself"
    assert not policy.allows_host("evil.example.com")


def test_allowed_host_flag_admits_a_hostname() -> None:
    policy = AccessPolicy.for_bind("10.20.0.50", extra=("replicant.lab",))

    assert policy.allows_host("replicant.lab:9787")
    assert not policy.allows_host("other.lab:9787")


def test_wildcard_bind_admits_ip_literals_but_not_hostnames() -> None:
    # A wildcard bind cannot enumerate the machine's addresses without probing the
    # network, and DNS rebinding needs a *hostname* whose resolution the attacker
    # controls. An IP-literal Host is therefore not a rebinding vector; a hostname
    # still has to be named explicitly.
    policy = AccessPolicy.for_bind("0.0.0.0")

    assert policy.allows_host("192.168.1.5:9787")
    assert policy.allows_host("10.20.0.50")
    assert not policy.allows_host("evil.example.com")


def test_ipv6_host_header_forms_are_equivalent() -> None:
    policy = AccessPolicy.for_bind("::1")

    assert policy.allows_host("[::1]:9787")
    assert policy.allows_host("[::1]")
    assert policy.allows_host("::1")


def test_host_guard_is_enforced_on_a_real_request(tmp_path: Path) -> None:
    client = make_client(tmp_path, AccessPolicy.for_bind("10.20.0.50"))

    assert client.get("/api/health", headers={"host": "10.20.0.50:9787"}).status_code == 200
    assert client.get("/api/health", headers={"host": "evil.example.com"}).status_code == 403


# --- A3: the token is accepted from four sources ---------------------------


def test_bearer_header_authenticates(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    resp = client.get("/api/catalog", headers={"Authorization": f"Bearer {TOKEN}"})

    assert resp.status_code == 200


def test_session_cookie_authenticates(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    establish_session(client)

    assert client.get("/api/catalog").status_code == 200


@pytest.mark.parametrize(
    "headers,params",
    [
        ({"Authorization": "Bearer wrong"}, {}),
        ({"x-replicant-token": "wrong"}, {}),
        ({}, {"token": "wrong"}),
    ],
)
def test_a_wrong_token_is_rejected_from_every_source(
    tmp_path: Path, headers: dict[str, str], params: dict[str, str]
) -> None:
    client = make_client(tmp_path)

    assert client.get("/api/catalog", headers=headers, params=params).status_code == 401


def test_a_wrong_cookie_is_rejected(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    client.cookies.set(SESSION_COOKIE, "wrong")

    assert client.get("/api/catalog").status_code == 401


# --- A4: the first authenticated load sets the cookie ----------------------


def test_authenticated_load_sets_an_httponly_session_cookie(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    resp = client.get("/api/catalog", params={"token": TOKEN})

    cookie = resp.headers.get("set-cookie", "")
    assert SESSION_COOKIE in cookie
    assert "httponly" in cookie.lower(), "the token must not be readable by page scripts"
    assert "samesite=strict" in cookie.lower().replace(" ", "")


def test_the_spa_document_sets_the_cookie_too(tmp_path: Path) -> None:
    # StaticFiles is mounted at "/", so the document response never reaches a
    # handler this module owns. If the cookie were set in a route instead of in
    # middleware, opening the printed URL would not establish the session at all.
    client = make_client(tmp_path)

    resp = client.get("/", params={"token": TOKEN})

    assert resp.status_code == 200
    assert SESSION_COOKIE in resp.headers.get("set-cookie", "")


def test_an_unauthenticated_request_sets_no_cookie(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    resp = client.get("/api/catalog", params={"token": "wrong"})

    assert resp.status_code == 401
    assert SESSION_COOKIE not in resp.headers.get("set-cookie", "")


def test_a_header_token_request_mints_no_session_cookie(tmp_path: Path) -> None:
    """A monitoring poller authenticates by header and keeps no cookie jar. Each
    such request used to mint a fresh SessionStore id retained for the full TTL,
    so a 1/s poller grew ~43k dead sessions in 12h. Only the browser's URL-token
    navigation is promoted to a cookie; the header API contract mints nothing."""
    client = make_client(tmp_path)

    resp = client.get("/api/catalog", headers={"x-replicant-token": TOKEN})

    assert resp.status_code == 200  # authenticated fine, just no cookie
    assert SESSION_COOKIE not in resp.headers.get("set-cookie", "")


def test_a_bearer_token_request_mints_no_session_cookie(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    resp = client.get("/api/catalog", headers={"Authorization": f"Bearer {TOKEN}"})

    assert resp.status_code == 200
    assert SESSION_COOKIE not in resp.headers.get("set-cookie", "")


# --- A5: cookie auth is the only path that needs an Origin -----------------


def test_cookie_authenticated_write_requires_a_matching_origin(tmp_path: Path) -> None:
    # The cookie is what makes CSRF reachable at all: a browser attaches it to a
    # cross-site POST automatically, which a token in a header or query string
    # never was.
    client = make_client(tmp_path)
    establish_session(client)

    resp = client.post(
        "/api/runs",
        headers={"origin": "http://evil.example"},
        json={"technique_id": "REP-001", "no_send": True},
    )

    assert resp.status_code == 403


def test_cookie_authenticated_write_accepts_a_same_origin_request(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    establish_session(client)

    resp = client.post(
        "/api/runs",
        headers={"origin": "http://localhost"},
        json={"technique_id": "REP-999", "no_send": True},
    )

    assert resp.status_code == 404, "rejected for the unknown id, not for the origin"


def test_cookie_authenticated_write_without_an_origin_is_refused(tmp_path: Path) -> None:
    # Browsers send Origin on every non-GET. A cookie-authenticated write with no
    # Origin at all is not something the SPA produces, so it fails closed.
    client = make_client(tmp_path)
    establish_session(client)

    resp = client.post("/api/runs", json={"technique_id": "REP-001", "no_send": True})

    assert resp.status_code == 403


def test_header_authenticated_write_needs_no_origin(tmp_path: Path) -> None:
    # curl and the CLI are not CSRF-reachable: nothing attaches an explicit header
    # on their behalf. Requiring an Origin here would break every non-browser
    # client for no gain.
    client = make_client(tmp_path)

    resp = client.post(
        "/api/runs",
        headers={"x-replicant-token": TOKEN},
        json={"technique_id": "REP-999", "no_send": True},
    )

    assert resp.status_code == 404


def test_cookie_authenticated_read_needs_no_origin(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    establish_session(client)

    assert client.get("/api/catalog").status_code == 200


# --- A6: the terminal tab is gated by the bind address ---------------------


def test_terminal_is_on_for_a_loopback_bind() -> None:
    assert AccessPolicy.for_bind("127.0.0.1").terminal_enabled


def test_terminal_is_off_by_default_when_bound_elsewhere() -> None:
    # The embedded terminal is a real PTY running the menu. Exposing it on a
    # routable address by default would hand a shell-shaped surface to the segment;
    # the CLI and the Rich menu already cover everything the tab does.
    assert not AccessPolicy.for_bind("10.20.0.50").terminal_enabled


def test_enable_terminal_restores_it_on_a_routable_bind() -> None:
    assert AccessPolicy.for_bind("10.20.0.50", enable_terminal=True).terminal_enabled


def test_config_reports_whether_the_terminal_is_available(tmp_path: Path) -> None:
    client = make_client(tmp_path, AccessPolicy.for_bind("10.20.0.50"))

    data = client.get(
        "/api/config", headers={"host": "10.20.0.50", "x-replicant-token": TOKEN}
    ).json()

    assert data["terminal_enabled"] is False


def test_disabled_terminal_websocket_refuses_a_valid_token(tmp_path: Path) -> None:
    client = make_client(tmp_path, AccessPolicy.for_bind("10.20.0.50"))

    with pytest.raises(Exception):  # noqa: B017 - starlette raises on a handshake close
        with client.websocket_connect(
            f"/ws/terminal?token={TOKEN}", headers={"host": "10.20.0.50"}
        ):
            pass


def test_terminal_websocket_rejects_a_foreign_host(tmp_path: Path) -> None:
    # Websocket scopes never pass through HTTP middleware, so the Host guard that
    # protects every /api route does not protect this one. It needs its own.
    client = make_client(tmp_path)

    with pytest.raises(Exception):  # noqa: B017
        with client.websocket_connect(
            f"/ws/terminal?token={TOKEN}", headers={"host": "evil.example.com"}
        ):
            pass


def test_terminal_websocket_rejects_a_foreign_origin(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    with pytest.raises(Exception):  # noqa: B017
        with client.websocket_connect(
            f"/ws/terminal?token={TOKEN}", headers={"origin": "http://evil.example"}
        ):
            pass


# --- A7: serving ------------------------------------------------------------


def test_no_auth_on_a_routable_bind_is_refused_without_the_acknowledgement() -> None:
    with pytest.raises(ValueError) as exc:
        check_unauthenticated_exposure("10.20.0.50", no_auth=True, acknowledged=False)

    assert "--i-understand-this-is-unauthenticated" in str(exc.value)


def test_no_auth_on_a_routable_bind_is_allowed_once_acknowledged() -> None:
    check_unauthenticated_exposure("10.20.0.50", no_auth=True, acknowledged=True)


def test_no_auth_on_loopback_needs_no_acknowledgement() -> None:
    check_unauthenticated_exposure("127.0.0.1", no_auth=True, acknowledged=False)


def test_a_wildcard_bind_counts_as_routable_for_the_no_auth_refusal() -> None:
    with pytest.raises(ValueError):
        check_unauthenticated_exposure("0.0.0.0", no_auth=True, acknowledged=False)


def test_no_auth_serves_the_api_without_a_token(tmp_path: Path) -> None:
    client = make_client(tmp_path, AccessPolicy(require_auth=False))

    assert client.get("/api/catalog").status_code == 200


def test_an_occupied_port_names_the_port_and_the_flag() -> None:
    # The spec is explicit that a busy port must not silently become a different
    # port: the whole point of a fixed port is that the URL stays predictable.
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    port = int(holder.getsockname()[1])
    try:
        with pytest.raises(OSError) as exc:
            bind_socket("127.0.0.1", port)
    finally:
        holder.close()

    message = str(exc.value)
    assert str(port) in message
    assert "--port" in message


def test_bind_socket_uses_the_port_it_was_given() -> None:
    sock = bind_socket("127.0.0.1", 0)
    try:
        assert sock.getsockname()[1] > 0
    finally:
        sock.close()


def test_startup_banner_reports_url_then_token_then_terminal() -> None:
    lines = startup_lines("127.0.0.1", 9787, token="abc", token_state="persisted", terminal=True)
    joined = "\n".join(lines)

    assert joined.index("URL") < joined.index("token") < joined.index("terminal")


def test_startup_banner_uses_the_bind_address_not_loopback() -> None:
    lines = startup_lines("10.20.0.50", 9787, token="abc", token_state="persisted", terminal=False)

    assert any("http://10.20.0.50:9787/" in line for line in lines)
    assert any("disabled" in line for line in lines)


def test_startup_banner_never_prints_an_unopenable_wildcard_url() -> None:
    # http://0.0.0.0:9787 is not a URL anyone can open. Print one that works and
    # say separately that the socket is on every interface.
    lines = startup_lines("0.0.0.0", 9787, token="abc", token_state="created", terminal=False)
    joined = "\n".join(lines)

    assert "http://0.0.0.0" not in joined
    assert "http://127.0.0.1:9787/" in joined
    assert "all interfaces" in joined


def test_banner_does_not_print_the_token_when_stdout_is_not_a_terminal() -> None:
    # Under systemd, stdout is the journal. Printing the token there writes it in
    # cleartext to a file readable by root and the systemd-journal group, which
    # gives away exactly what the 0600 token file protects. Found by running the
    # unit in a container: the token was sitting in `journalctl -u replicant-web`.
    lines = startup_lines(
        "0.0.0.0",
        9787,
        token="s3cret-token",
        token_state="created",
        terminal=False,
        reveal_token=False,
        token_path="/opt/replicant/.config/replicant/web-token",
    )
    joined = "\n".join(lines)

    assert "s3cret-token" not in joined
    assert "?token=" not in joined
    assert "/opt/replicant/.config/replicant/web-token" in joined


def test_banner_still_prints_the_token_on_a_terminal() -> None:
    # An operator running it by hand needs a URL they can click.
    joined = "\n".join(
        startup_lines("127.0.0.1", 9787, token="s3cret-token", token_state="created", terminal=True)
    )

    assert "?token=s3cret-token" in joined


def test_banner_omits_the_ctrl_c_hint_when_not_on_a_terminal() -> None:
    # There is no Ctrl-C to press when systemd owns the process.
    joined = "\n".join(
        startup_lines(
            "0.0.0.0",
            9787,
            token="t",
            token_state="created",
            terminal=False,
            reveal_token=False,
            token_path="/tmp/web-token",
        )
    )

    assert "Ctrl-C" not in joined


def test_startup_banner_says_when_authentication_is_off() -> None:
    lines = startup_lines("127.0.0.1", 9787, token=None, token_state="disabled", terminal=True)
    joined = "\n".join(lines)

    assert "?token=" not in joined
    assert "disabled" in joined


@pytest.mark.parametrize(
    "platform,env,expected",
    [
        ("darwin", {}, True),
        ("linux", {}, False),
        ("linux", {"DISPLAY": ":0"}, True),
        ("linux", {"WAYLAND_DISPLAY": "wayland-0"}, True),
    ],
)
def test_display_detection_keeps_headless_hosts_quiet(
    platform: str, env: dict[str, str], expected: bool
) -> None:
    # Without this, every headless start printed a `gio` "Operation not supported"
    # error from webbrowser.open before the banner the operator wanted to read.
    assert display_available(platform, env) is expected


# --- A8: the CLI surface ----------------------------------------------------


def test_web_defaults_to_the_fixed_port() -> None:
    args = build_parser().parse_args(["web"])

    assert args.port == WEB_DEFAULT_PORT == 9787
    assert args.host == "127.0.0.1"


def test_web_accepts_a_port_override() -> None:
    assert build_parser().parse_args(["web", "--port", "9000"]).port == 9000


def test_allowed_host_is_repeatable() -> None:
    args = build_parser().parse_args(
        ["web", "--allowed-host", "replicant.lab", "--allowed-host", "siem.lab"]
    )

    assert args.allowed_host == ["replicant.lab", "siem.lab"]


def test_access_relaxing_flags_are_all_off_by_default() -> None:
    args = build_parser().parse_args(["web"])

    assert args.no_auth is False
    assert args.i_understand_this_is_unauthenticated is False
    assert args.rotate_token is False
    assert args.enable_terminal is False


def test_web_command_reports_a_refused_bind_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # serve() refuses before binding; the CLI must turn that into an operator-facing
    # message and a non-zero exit, not a traceback.
    def refuse(*args: object, **kwargs: object) -> None:
        raise ValueError("--no-auth refused: 10.20.0.50 is reachable from other machines")

    monkeypatch.setattr("replicant.web.server.serve", refuse)
    code = main(["web", "--host", "10.20.0.50", "--no-auth", "--no-browser"])

    assert code == 1
    assert "--no-auth refused" in capsys.readouterr().err
