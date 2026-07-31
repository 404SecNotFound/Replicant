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
"""The log buffer: levels, bounds, redaction, and the counters it feeds.

The redaction tests are the load-bearing ones. This project has already written a
secret to a log sink once, when the web token reached the systemd journal, and a
buffer the UI reads over HTTP is another sink with the same property.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from replicant.obs import log as obs_log


@pytest.fixture(autouse=True)
def fresh_buffer() -> Iterator[None]:
    obs_log.reset_for_tests()
    obs_log.install(capacity=50, level="debug")
    yield
    obs_log.reset_for_tests()


def test_records_land_in_the_buffer_with_their_level() -> None:
    log = obs_log.get_logger("t")
    log.info("hello")
    log.warning("careful")

    entries = obs_log.snapshot()
    assert [entry.level for entry in entries] == ["info", "warning"]
    assert [entry.message for entry in entries] == ["hello", "careful"]
    assert all(entry.logger == "replicant.t" for entry in entries)


def test_verbose_sits_between_debug_and_info() -> None:
    assert obs_log.VERBOSE > 10  # DEBUG
    assert obs_log.VERBOSE < 20  # INFO

    log = obs_log.get_logger("t")
    obs_log.set_level("info")
    obs_log.verbose(log, "per event")
    assert obs_log.snapshot() == []

    obs_log.set_level("verbose")
    obs_log.verbose(log, "per event")
    assert [entry.level for entry in obs_log.snapshot()] == ["verbose"]


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("debug", ["debug", "verbose", "info", "warning"]),
        ("verbose", ["verbose", "info", "warning"]),
        ("info", ["info", "warning"]),
        ("warning", ["warning"]),
    ],
)
def test_each_mode_admits_exactly_its_tier_and_above(level: str, expected: list[str]) -> None:
    obs_log.set_level(level)
    log = obs_log.get_logger("t")

    log.debug("d")
    obs_log.verbose(log, "v")
    log.info("i")
    log.warning("w")

    assert [entry.level for entry in obs_log.snapshot()] == expected


def test_the_buffer_is_bounded_and_evicts_oldest_first() -> None:
    log = obs_log.get_logger("t")
    for index in range(120):
        log.info("line %d", index)

    entries = obs_log.snapshot()
    assert len(entries) == 50
    assert entries[0].message == "line 70"
    assert entries[-1].message == "line 119"


def test_seq_is_monotonic_and_survives_eviction() -> None:
    log = obs_log.get_logger("t")
    for index in range(120):
        log.info("line %d", index)

    seqs = [entry.seq for entry in obs_log.snapshot()]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)
    # Eviction must not renumber: a tailing client holding seq 100 would
    # otherwise be handed records it has already seen.
    assert seqs[0] == 71


def test_snapshot_after_returns_only_newer_records() -> None:
    log = obs_log.get_logger("t")
    log.info("first")
    cursor = obs_log.snapshot()[-1].seq
    log.info("second")

    fresh = obs_log.snapshot(after=cursor)
    assert [entry.message for entry in fresh] == ["second"]


@pytest.mark.parametrize(
    "message",
    [
        "open http://127.0.0.1:9787/?token=Xy7_ab-cdEF12345",
        "headers {'x-replicant-token': 'Xy7_ab-cdEF12345'}",
        'curl -H "x-replicant-token: Xy7_ab-cdEF12345" http://host/api',
    ],
)
def test_the_web_token_never_reaches_the_buffer(message: str) -> None:
    obs_log.get_logger("web").info("%s", message)

    stored = obs_log.snapshot()[-1].message
    assert "Xy7_ab-cdEF12345" not in stored
    assert "<redacted>" in stored


def test_redaction_happens_on_write_not_on_read() -> None:
    """A record redacted at render time still sits in memory in the clear."""

    obs_log.get_logger("web").info("token=SuperSecretValue1")
    entry = obs_log.snapshot()[-1]
    assert "SuperSecretValue1" not in entry.message
    assert "SuperSecretValue1" not in str(entry.as_dict())


def test_set_level_rejects_an_unknown_mode() -> None:
    with pytest.raises(ValueError, match="unknown level"):
        obs_log.set_level("chatty")


def test_install_is_idempotent() -> None:
    first = obs_log.install()
    second = obs_log.install()
    assert first is second

    obs_log.get_logger("t").warning("once")
    assert len(obs_log.snapshot()) == 1


def test_records_do_not_propagate_to_the_root_logger() -> None:
    """Under systemd the root logger is the journal. See the module docstring."""

    import logging

    assert logging.getLogger(obs_log.ROOT_NAME).propagate is False


def test_snapshot_is_empty_when_logging_was_never_installed() -> None:
    obs_log.reset_for_tests()
    assert obs_log.snapshot() == []


class TestRateCounter:
    def test_accumulates_events_bytes_and_errors(self) -> None:
        counter = obs_log.RateCounter()
        counter.add(100)
        counter.add(250)
        counter.add(0, error=True)

        events, byte_count, errors, _ = counter.take()
        assert (events, byte_count, errors) == (3, 350, 1)

    def test_take_resets_the_window(self) -> None:
        counter = obs_log.RateCounter()
        counter.add(10)
        counter.take()

        events, byte_count, errors, _ = counter.take()
        assert (events, byte_count, errors) == (0, 0, 0)
