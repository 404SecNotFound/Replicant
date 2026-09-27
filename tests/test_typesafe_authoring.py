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
"""Offline contracts for an authoring tool that never executes its suggestions."""

from __future__ import annotations

import io
import json
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Any

import pytest

from replicant.core.models import load_catalog
from replicant.resources import TECHNIQUE_CATALOG
from tools import typesafe_authoring as tool

SECRET = "secret-for-offline-test-only"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("This test must never open a socket or resolve a host")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.delenv("REPLICANT_WEB_CONFINED", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)


def response_for(
    task: tool.PreparedTask,
    choice: str,
    *,
    probabilities: dict[str, float] | None = None,
    confidence: float = 0.95,
    exists: float = 0.95,
) -> dict[str, Any]:
    distribution = dict.fromkeys(task.request["questions"][task.action]["criteria"], 0.0)
    distribution.update(probabilities or {choice: 1.0})
    answers: dict[str, Any] = {
        task.action: {
            "type": "choice",
            "choice": choice,
            "probabilities": distribution,
            "confidence": confidence,
        }
    }
    if task.action == "find":
        answers["exists"] = {"type": "noul", "noul": exists}
    return {
        "model": tool.DEFAULT_MODEL,
        "answers": answers,
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }


class FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    def read(self, limit: int) -> bytes:
        assert limit == tool.MAX_RESPONSE_BYTES + 1
        return self.body[:limit]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.closed = True


class FakeOpener:
    def __init__(self, result: FakeResponse | Exception) -> None:
        self.result = result
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, *, timeout: int) -> FakeResponse:
        self.requests.append(request)
        assert timeout == tool.SOCKET_TIMEOUT_SECONDS
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def mock_transport(monkeypatch: pytest.MonkeyPatch, result: FakeResponse | Exception) -> FakeOpener:
    opener = FakeOpener(result)

    def build(*handlers: Any) -> FakeOpener:
        assert len(handlers) == 2
        assert isinstance(handlers[0], urllib.request.ProxyHandler)
        assert vars(handlers[0])["proxies"] == {}
        assert isinstance(handlers[1], tool.NoRedirect)
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", build)
    return opener


@pytest.mark.parametrize("action", ["find", "review"])
def test_preview_uses_no_environment_or_transport(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Preview must not inspect environment or build a transport")

    monkeypatch.setattr(tool, "os", SimpleNamespace(environ=SimpleNamespace(get=forbidden)))
    monkeypatch.setattr(urllib.request, "build_opener", forbidden)
    args = (
        ["find", "periodic callbacks"]
        if action == "find"
        else ["review", "REP-011", "The country tag proves live GeoIP enrichment."]
    )
    assert tool.main([*args, "--json"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["mode"] == "preview"
    assert result["requests_made"] == 0
    assert result["request"]["model"] == tool.DEFAULT_MODEL
    assert "Authorization" not in captured.out
    assert captured.err == ""


def test_catalog_evidence_uses_validated_defaults_and_is_cwd_independent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    task = tool.prepare_task("review", "Does this have a negative foil?", technique_id="REP-011")
    source = load_catalog(TECHNIQUE_CATALOG).by_id("REP-011")
    evidence = task.request["state"]["technique"]
    assert evidence["emits_foil"] is False
    assert evidence["transferability"] == "parser-only"
    assert evidence["transferability_note"] == source.transferability_note
    assert "GeoIP" in evidence["transferability_note"]
    assert set(evidence) == tool.CATALOG_FIELDS
    assert not any(key in evidence for key in ("collector", "settings", "entities", "params"))


@pytest.mark.parametrize(
    "args",
    [
        ["find", "callbacks", "--live"],
        ["review", "REP-999", "anything", "--live"],
        ["find", " ", "--live"],
        ["find", "x" * (tool.MAX_TEXT_CHARS + 1), "--live"],
        ["find", "callbacks", "--model", "bad\nmodel", "--live"],
    ],
)
def test_invalid_input_or_missing_key_never_builds_transport(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Must fail before building a transport")

    monkeypatch.setattr(urllib.request, "build_opener", forbidden)
    assert tool.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip()
    assert "Traceback" not in captured.err
    assert len(captured.err) < 150


def test_confined_terminal_allows_preview_but_refuses_live(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("REPLICANT_WEB_CONFINED", "1")
    monkeypatch.setenv("TYPESAFE_API_KEY", SECRET)
    opener = mock_transport(monkeypatch, RuntimeError("must not be used"))
    assert tool.main(["find", "callbacks", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "preview"
    assert tool.main(["find", "callbacks", "--live", "--json"]) == 2
    captured = capsys.readouterr()
    assert "confined web terminal" in captured.err
    assert SECRET not in captured.err
    assert not opener.requests


def test_one_fixed_endpoint_call_disables_proxies_and_retains_no_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task = tool.prepare_task("find", "periodic callbacks")
    reply = FakeResponse(json.dumps(response_for(task, "REP-001")).encode())
    opener = mock_transport(monkeypatch, reply)
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted-proxy.invalid:4444")
    monkeypatch.setenv("TYPESAFE_API_KEY", SECRET)
    assert tool.main(["find", "periodic callbacks", "--live", "--json"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url == tool.ENDPOINT
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer " + SECRET
    assert isinstance(request.data, bytes) and SECRET.encode() not in request.data
    assert SECRET not in captured.out + captured.err
    assert result["choice"] == "REP-001"
    assert result["candidates"][0]["objective"] == task.evidence["REP-001"]["objective"]
    assert reply.closed


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError(SECRET),
        TimeoutError(SECRET),
        OSError(SECRET),
        ValueError(SECRET),
        urllib.error.HTTPError(tool.ENDPOINT, 401, SECRET, Message(), io.BytesIO(SECRET.encode())),
    ],
)
def test_transport_failures_are_sanitized_without_retries(
    failure: Exception,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    opener = mock_transport(monkeypatch, failure)
    monkeypatch.setenv("TYPESAFE_API_KEY", SECRET)
    assert tool.main(["find", "callbacks", "--live", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert SECRET not in captured.err
    assert "no retry made" in json.loads(captured.err)["error"]
    assert len(opener.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_never_create_a_followup_request(status: int) -> None:
    request = urllib.request.Request(tool.ENDPOINT, headers={"Authorization": "Bearer " + SECRET})
    with pytest.raises(tool.AuthoringError, match="redirect refused"):
        tool.NoRedirect().redirect_request(
            request, None, status, SECRET, {}, "https://elsewhere.invalid/"
        )


@pytest.mark.parametrize(
    "body",
    [
        b"x" * (tool.MAX_RESPONSE_BYTES + 1),
        b"not json",
        b"\xff",
        b'{"answers":{},"answers":{}}',
    ],
)
def test_unusable_response_bytes_fail_closed(body: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    task = tool.prepare_task("find", "callbacks")
    reply = FakeResponse(body)
    mock_transport(monkeypatch, reply)
    with pytest.raises(tool.AuthoringError):
        tool.submit(task, SECRET)
    assert reply.closed


@pytest.mark.parametrize(
    "value", [True, False, "0.9", None, -0.1, 1.1, float("nan"), float("inf"), 10**400]
)
def test_nonfinite_unbounded_or_coerced_probabilities_are_rejected(value: Any) -> None:
    task = tool.prepare_task("find", "callbacks")
    response = response_for(task, "REP-001")
    response["answers"]["find"]["probabilities"]["REP-001"] = value
    with pytest.raises(tool.AuthoringError):
        tool.validate_response(task, response)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(unexpected="field"),
        lambda r: r["answers"].pop("exists"),
        lambda r: r["answers"].update(extra={}),
        lambda r: r["answers"]["find"].update(choice="REP-999"),
        lambda r: r["answers"]["find"].update(type="noul"),
        lambda r: r["answers"]["find"].update(confidence=True),
        lambda r: r["answers"]["exists"].update(type="choice"),
        lambda r: r["answers"]["exists"].update(noul=float("nan")),
        lambda r: r["answers"]["find"]["probabilities"].pop("NO_MATCH"),
        lambda r: r["answers"]["find"]["probabilities"].update({"REP-999": 0.0}),
        lambda r: r["answers"]["find"]["probabilities"].update({"REP-001": 0.1}),
        lambda r: r["answers"]["find"].update(choice="REP-002"),
        lambda r: r["usage"].update(input_tokens=True),
        lambda r: r["usage"].update(output_tokens=-1),
        lambda r: r.update(model="untrusted\nmodel"),
    ],
)
def test_malformed_response_contracts_are_rejected(
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    task = tool.prepare_task("find", "callbacks")
    response = response_for(task, "REP-001")
    mutate(response)
    with pytest.raises(tool.AuthoringError):
        tool.validate_response(task, response)


def test_tied_choices_and_rounded_distributions_remain_visible() -> None:
    task = tool.prepare_task("find", "ordinary or jittered callbacks")
    raw = response_for(
        task,
        "REP-012",
        confidence=0.2,
        probabilities={"REP-001": 0.49, "REP-012": 0.49, "NO_MATCH": 0.01},
    )
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert result["low_confidence"] and result["review_required"]
    assert [candidate["id"] for candidate in result["candidates"]] == ["REP-012", "REP-001"]
    assert result["probabilities"]["NO_MATCH"] == 0.01
    assert "Low confidence" in tool.render_text(result)


def test_no_match_never_emits_candidate_suggestions_even_with_other_mass() -> None:
    task = tool.prepare_task("find", "unavailable endpoint process telemetry")
    raw = response_for(
        task, "NO_MATCH", exists=0.1, probabilities={"NO_MATCH": 0.8, "REP-001": 0.2}
    )
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert result["candidates"] == []
    assert result["probabilities"]["REP-001"] == 0.2
    assert "No candidate suggestions" in tool.render_text(result)


def test_disagreeing_existence_signal_requires_review() -> None:
    task = tool.prepare_task("find", "callbacks")
    raw = response_for(task, "REP-001", exists=0.1)
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert result["catalog_exists_probability"] == 0.1
    assert result["judgments_disagree"] and result["review_required"]
    assert "not the selected entry" in result["existence_notice"]
    assert "disagree" in tool.render_text(result)


def test_weak_existence_signal_is_visible_without_discarding_candidates() -> None:
    task = tool.prepare_task("find", "callbacks")
    raw = response_for(task, "REP-001", confidence=0.95, exists=0.6)
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert result["weak_match_evidence"] and result["review_required"]
    assert result["candidates"][0]["id"] == "REP-001"
    assert "Weak evidence" in tool.render_text(result)


def test_alternatives_are_bounded_and_copy_catalog_limits() -> None:
    task = tool.prepare_task("find", "a synthetic test")
    raw = response_for(
        task,
        "REP-011",
        probabilities={"REP-011": 0.4, "REP-016": 0.3, "REP-020": 0.2, "REP-024": 0.1},
    )
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert len(result["candidates"]) == 3
    for candidate in result["candidates"]:
        assert candidate["probability"] > 0
        assert (
            candidate["transferability_note"]
            == task.evidence[candidate["id"]]["transferability_note"]
        )


def test_low_confidence_contradiction_is_never_hidden() -> None:
    task = tool.prepare_task(
        "review", "The technique has live WHOIS evidence.", technique_id="REP-020"
    )
    raw = response_for(
        task,
        "contradicted",
        confidence=0.1,
        probabilities={"contradicted": 0.4, "supported": 0.3, "unsupported": 0.3},
    )
    result = tool.format_result(task, tool.validate_response(task, raw))
    assert result["choice"] == "contradicted"
    assert result["low_confidence"] and result["review_required"]
    assert result["evidence"] == task.evidence["REP-020"]
    assert "WHOIS" in tool.render_text(result)
    assert "contradicted" in tool.render_text(result)
