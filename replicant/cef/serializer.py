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
"""CEF serialization.

Vendor-neutral. Implements the header/extension escaping split from blueprint
section 9 and the FortiGate CEF reference section 1.2. Header and extension
escape different characters; applying the wrong rule per section is the most
common cause of downstream parser failures, so the split is enforced here.
"""

from __future__ import annotations

from collections.abc import Mapping

from replicant.core.models import CefHeader


def escape_header(value: str) -> str:
    """Escape a CEF header field value (fields 2-7).

    Backslash -> ``\\\\`` and pipe -> ``\\|``. Equals and spaces are literal.
    Backslash is escaped first so introduced backslashes are not re-escaped.
    """

    return value.replace("\\", "\\\\").replace("|", "\\|")


def escape_extension(value: str) -> str:
    """Escape a CEF extension value (field 8, the key=value section).

    Backslash -> ``\\\\`` and equals -> ``\\=``. Newlines/carriage returns encode
    as ``\\n`` / ``\\r``. Pipe is literal in the extension.
    """

    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def to_cef(header: CefHeader, extension: Mapping[str, str]) -> str:
    """Serialize a header and ordered extension into a single CEF payload.

    The returned string begins at ``CEF:`` and does not include any syslog
    prefix; that framing is added by the transport layer (blueprint s9).
    Extension key order is the caller's insertion order (dicts are ordered).
    """

    header_fields = "|".join(
        (
            f"CEF:{header.version}",
            escape_header(header.device_vendor),
            escape_header(header.device_product),
            escape_header(header.device_version),
            escape_header(header.signature_id),
            escape_header(header.name),
            str(header.severity),
        )
    )
    extension_str = " ".join(f"{key}={escape_extension(value)}" for key, value in extension.items())
    return f"{header_fields}|{extension_str}"
