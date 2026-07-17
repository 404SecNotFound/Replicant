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
"""Serializer escaping tests.

The escaping oracle is the ArcSight standard examples reproduced in
docs/fortigate-cef-reference.md section 1.2. Header escapes backslash and pipe;
extension escapes backslash and equals (pipe is literal). The seven byte-for-byte
FortiGate golden lines live in test_fortigate_golden.py because they require the
FortiGate profile to build the ordered extension.
"""

from __future__ import annotations

from replicant.cef.serializer import escape_extension, escape_header, to_cef
from replicant.core.models import CefHeader


def _header(name: str) -> CefHeader:
    return CefHeader(
        version=0,
        device_vendor="security",
        device_product="threatmanager",
        device_version="1.0",
        signature_id="100",
        name=name,
        severity=10,
    )


def test_header_escapes_pipe_but_not_equals() -> None:
    line = to_cef(
        _header("detected a | in message"),
        {"src": "10.0.0.1", "act": "blocked a |", "dst": "1.1.1.1"},
    )
    assert line == (
        "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|"
        "src=10.0.0.1 act=blocked a | dst=1.1.1.1"
    )


def test_header_and_extension_escape_backslash() -> None:
    line = to_cef(
        _header("detected a \\ in packet"),
        {"src": "10.0.0.1", "act": "blocked a \\", "dst": "1.1.1.1"},
    )
    assert line == (
        "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|"
        "src=10.0.0.1 act=blocked a \\\\ dst=1.1.1.1"
    )


def test_equals_literal_in_header_escaped_in_extension() -> None:
    line = to_cef(
        _header("detected a = in message"),
        {"src": "10.0.0.1", "act": "blocked a =", "dst": "1.1.1.1"},
    )
    assert line == (
        "CEF:0|security|threatmanager|1.0|100|detected a = in message|10|"
        "src=10.0.0.1 act=blocked a \\= dst=1.1.1.1"
    )


def test_escape_header_unit() -> None:
    assert escape_header("a|b") == "a\\|b"
    assert escape_header("a\\b") == "a\\\\b"
    assert escape_header("a=b") == "a=b"
    assert escape_header("a b") == "a b"


def test_escape_extension_unit() -> None:
    assert escape_extension("a=b") == "a\\=b"
    assert escape_extension("a\\b") == "a\\\\b"
    assert escape_extension("a|b") == "a|b"
    assert escape_extension("a\nb") == "a\\nb"
    assert escape_extension("a\rb") == "a\\rb"


def test_backslash_escaped_before_pipe_no_double_escape() -> None:
    # A literal backslash-pipe must become \\ then \| -> "\\\|", not "\\|".
    assert escape_header("\\|") == "\\\\\\|"


def test_empty_extension_keeps_trailing_pipe() -> None:
    line = to_cef(_header("evt"), {})
    assert line == "CEF:0|security|threatmanager|1.0|100|evt|10|"
