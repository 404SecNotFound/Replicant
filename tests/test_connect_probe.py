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
"""The connect test has to say what it proved, not that it succeeded.

The defect this guards: ``send_test`` returned a bare bool that the UI rendered
as a green ``verified``. On UDP that bool only means the kernel accepted the
datagram, which is true whenever a route exists. It read ``verified`` against a
collector that could not receive anything across two live lab sessions, both
caused by the same transposed address (``10.20.0.125`` typed for a collector at
``10.0.20.125``).

**What these tests can and cannot guarantee.** No automated test catches an
operator typo. What they catch is the regression where the disclosure that makes
a typo visible stops being computed or stops being rendered. Say so plainly,
because the temptation is to trust the probe for something it does not do: a
connected-UDP probe to the mistyped address returns no error at all, since the
datagram was discarded by a router that sent nothing back.

Safety rule 1: every test here either opens no socket or talks only to an
in-process loopback listener. ``connect`` on a UDP socket transmits nothing,
which ``tests/test_transport_path.py`` already pins.
"""

from __future__ import annotations

import socket

from replicant.core.models import CollectorProfile
from replicant.transport.syslog import probe_collector, segment_claim


class TestSegmentClaim:
    """Pure arithmetic over addresses. Opens no sockets at all."""

    def test_flags_a_cross_block_destination(self) -> None:
        # No netmask covering both is plausible: it would have to be /4 or shorter.
        claim = segment_claim("192.168.1.191", "10.20.0.125")

        assert claim is not None
        assert "router" in claim

    def test_calls_a_same_24_destination_likely_direct(self) -> None:
        claim = segment_claim("192.168.1.191", "192.168.1.50")

        assert claim is not None
        assert "direct" in claim

    def test_stays_silent_within_one_private_block(self) -> None:
        # The honest limit, stated as a test so it is a decision rather than a
        # surprise: 10.0.20.127 and 10.20.0.125 are the real lab pair, and both
        # sit inside 10/8. A /12 covering both is perfectly legal, so arithmetic
        # alone cannot call this wrong. On Linux the route lookup catches it; this
        # asserts the arithmetic does not overclaim in its absence.
        assert segment_claim("10.0.20.127", "10.20.0.125") is None

    def test_stays_silent_when_the_source_is_unknown(self) -> None:
        assert segment_claim(None, "10.20.0.125") is None

    def test_declines_ipv6_rather_than_guessing(self) -> None:
        assert segment_claim("fe80::1", "2001:db8::1") is None


class TestProbe:
    def test_a_live_listener_is_reported_as_sent_but_unconfirmed(self) -> None:
        """The honest UDP verdict: it left, and nothing can say more."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(2.0)
        port = listener.getsockname()[1]
        try:
            report = probe_collector(
                CollectorProfile(name="t", host="127.0.0.1", port=port, transport="udp"),
                payload="<13>probe",
            )
            # Structural containment: the datagram went to the listener this test
            # owns and nowhere else.
            data, _ = listener.recvfrom(4096)
        finally:
            listener.close()

        assert data
        assert report.verdict == "sent_unconfirmed"
        assert report.source is not None
        assert report.destination == "127.0.0.1"
        assert report.port == port
        # Never the word that caused this.
        assert "verified" not in report.summary.lower()

    def test_a_closed_udp_port_is_reported_as_refused(self) -> None:
        """The one thing a UDP probe genuinely proves, when it happens.

        A connected socket surfaces the peer's ICMP port-unreachable as
        ECONNREFUSED. Loopback delivers it reliably. Off the loopback it is
        best-effort, which is why its absence is never treated as success.
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        report = probe_collector(
            CollectorProfile(name="t", host="127.0.0.1", port=closed_port, transport="udp"),
            payload="<13>probe",
        )

        assert report.verdict == "refused"

    def test_an_unresolvable_name_is_not_reported_as_an_exec_format_error(self) -> None:
        """``gaierror`` carries an EAI_* number, not an ``errno``.

        Measured trap: an unresolvable host gives 8, and ``errno.errorcode[8]``
        is ENOEXEC on Darwin, so a naive lookup reports "exec format error" for a
        DNS failure.
        """
        report = probe_collector(
            CollectorProfile(name="t", host="collector.invalid", port=514, transport="udp"),
            payload="<13>probe",
        )

        assert report.verdict == "name_not_resolved"
        assert "exec format" not in report.summary.lower()

    def test_the_report_always_says_what_it_did_not_prove(self) -> None:
        """A verdict without its limits is the defect being fixed, restated."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        try:
            report = probe_collector(
                CollectorProfile(name="t", host="127.0.0.1", port=port, transport="udp"),
                payload="<13>probe",
            )
        finally:
            listener.close()

        assert report.does_not_prove
        assert report.proves


def test_the_syslog_month_does_not_follow_the_locale() -> None:
    """RFC 3164 fixes the month at three ASCII characters.

    ``strftime('%b')`` follows LC_TIME, so a caller that has called setlocale
    would put "févr." on the wire and shift every field a SIEM parser counts on.
    Latent rather than live today (CPython leaves LC_TIME at "C" and nothing here
    calls setlocale), which is exactly why it is worth pinning: the defect is one
    setlocale call away and nothing else would notice.
    """
    import locale
    from datetime import UTC, datetime

    from replicant.core.models import CollectorProfile
    from replicant.transport.syslog import SyslogEmitter

    emitter = SyslogEmitter(CollectorProfile(name="t", host="127.0.0.1", port=514, transport="udp"))
    stamp = datetime(2026, 2, 3, 12, 0, 0, tzinfo=UTC)

    saved = locale.setlocale(locale.LC_TIME)
    installed = None
    for candidate in ("fr_FR.UTF-8", "de_DE.UTF-8", "es_ES.UTF-8"):
        try:
            locale.setlocale(locale.LC_TIME, candidate)
            installed = candidate
            break
        except locale.Error:
            continue
    try:
        framed = emitter.frame("CEF:0|x|y|z|1|n|3|", level="notice", now=stamp).decode()
    finally:
        locale.setlocale(locale.LC_TIME, saved)

    assert "Feb " in framed, f"month was localised under {installed!r}: {framed[:40]!r}"
