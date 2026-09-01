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
"""Configuration and saved collector profiles.

Precedence is CLI flag over menu input over config file over built-in default
(blueprint s14); this module supplies the config-file and default layers, and the
CLI/menu apply the higher-precedence layers on top. Config and profiles live in an
OS-appropriate directory (override with ``REPLICANT_CONFIG_DIR``).
"""

from __future__ import annotations

import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from replicant.core.models import CollectorProfile, Intensity
from replicant.scenario.engine import DEFAULT_ANCHOR_EPOCH

_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION_TOKEN = re.compile(r"(\d+)\s*([smhd]?)")
# The whole string must be nothing but duration tokens. Accepts "30", "5m",
# "1h30m" and "1h 30m"; rejects "10x", "abc123", "-1h", "1h garbage", "1.5h".
_DURATION_FULL = re.compile(r"(?:\d+\s*[smhd]?\s*)+")

# Canonical vendor-profile ids. The Orchestrator (_build_profile) is the validator;
# the CLI --vendor choices, the Rich menu picker, and the web selector all derive
# their option list from here, so adding a vendor is one entry here plus the profile.
VENDORS: tuple[str, ...] = ("fortigate", "paloalto", "checkpoint")

# How far the anchor may drift from now before a live send is worth warning about.
STALE_ANCHOR_DAYS = 2
_DAY = 86400

# The web UI's fixed default port. Fixed rather than random so the URL an operator
# bookmarks, puts in a systemd unit, or opens a firewall for stays valid across
# restarts. 8787 was the first candidate and was rejected on evidence: RStudio
# Server defaults to it, and it was already held on the author's own machine by an
# unrelated local tool, which is precisely the failure a fixed port exists to avoid.
# [Unverified] against the IANA registry. Override with ``replicant web --port``.
WEB_DEFAULT_PORT = 9787
_WEB_TOKEN_BYTES = 32


def parse_anchor(value: str) -> int:
    """Resolve an ``--anchor`` argument to an epoch.

    Accepts ``now``, a bare epoch, or an ISO-8601 timestamp. A naive ISO value is
    read as UTC rather than as local time, so the same string means the same
    instant on every machine.
    """
    text = value.strip()
    if text.lower() == "now":
        return int(datetime.now(UTC).timestamp())
    if re.fullmatch(r"\d+", text):
        return int(text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"anchor must be 'now', an epoch, or an ISO-8601 timestamp (got {value!r})"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def stale_anchor_warning(anchor_epoch: int, *, sending: bool, now: int | None = None) -> str | None:
    """Warn when a live send would carry event times far from the present.

    The default anchor is deliberately fixed so identical seeds produce
    byte-identical output. That is right for artifacts written with ``--to-file``
    and for the golden tests, and wrong the moment events go to a real collector:
    the syslog header is stamped at send time while the CEF ``eventtime`` stays at
    the anchor, so the two disagree by however long ago the anchor was.

    Whether that matters depends on the receiving SIEM. If it keys on receipt
    time, the run looks normal. If it keys on the parsed event time, the events
    land outside any recent-window rule and nothing fires, which is
    indistinguishable from the detection being broken. That ambiguity is the exact
    thing this project exists to remove, so it gets a warning rather than a
    footnote.

    Returns None when not sending, or when the anchor is close enough to now.
    """
    if not sending:
        return None
    current = int(datetime.now(UTC).timestamp()) if now is None else now
    drift_days = (current - anchor_epoch) / _DAY
    if abs(drift_days) < STALE_ANCHOR_DAYS:
        return None
    direction = "in the past" if drift_days > 0 else "in the future"
    return (
        f"event times are {abs(drift_days):.0f} days {direction} "
        f"(anchor {anchor_epoch}), while the syslog header is stamped now. "
        "If your SIEM keys on the parsed event time rather than receipt time, "
        "recent-window rules will not fire. Use --anchor now to emit at the "
        "current time."
    )


class Settings(BaseModel):
    """Operator defaults. The default layer of the precedence chain."""

    default_seed: int = 1337
    # Positive by construction: the emit loop treats a non-positive cap as "no
    # limit", so a zero or negative value would silently disable safety rule 4.
    eps_cap: int = Field(default=2000, gt=0)
    default_intensity: Intensity = "medium"
    vendor: str = "fortigate"  # fortigate | paloalto | checkpoint (selects the VendorProfile)
    # The synthetic-data marker (flexString1). Default is destination-conditional
    # (see Orchestrator._resolve_marker): off for --to-file and loopback where the
    # golden line is the oracle, on for a non-loopback send where an analyst on a
    # shared collector needs lab data separable from production. These two are the
    # explicit overrides: benign_marker forces it on everywhere (--mark-synthetic),
    # no_marker forces it off (--no-marker) and is logged when it overrides a
    # non-loopback send. no_marker wins if both are set.
    benign_marker: bool = False
    no_marker: bool = False
    byte_key_out: str = "out"
    byte_key_in: str = "in"
    anchor_epoch: int = DEFAULT_ANCHOR_EPOCH
    # None means "use the active vendor profile's identity" (the correct default);
    # a value here is an explicit operator override that wins for every vendor.
    hostname: str | None = None
    accepted_as: str | None = None
    catalog_path: str = "data/technique-catalog.yaml"
    manifest_dir: str = "manifests"


def config_dir() -> Path:
    override = os.environ.get("REPLICANT_CONFIG_DIR")
    if override:
        return Path(override)
    return Path.home() / ".config" / "replicant"


def settings_path() -> Path:
    return config_dir() / "config.yaml"


def profiles_path() -> Path:
    return config_dir() / "profiles.yaml"


def web_token_path() -> Path:
    return config_dir() / "web-token"


def _write_secret(path: Path, value: str) -> None:
    """Write a secret so only its owner can read it.

    This is the first value Replicant stores that is worth stealing, so it does not
    reuse the plain ``write_text`` that ``save_settings`` and ``save_profile`` use.
    Two details matter and neither is the default:

    - ``mkdir(mode=...)`` is ignored when the directory already exists, and the
      process umask masks it when it does not, so the directory mode is set
      explicitly afterwards.
    - The mode argument to ``os.open`` applies only when the file is *created*. An
      existing file keeps whatever mode it had, which is exactly the case that
      matters on rotation, so the mode is set explicitly there too.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    os.chmod(path, 0o600)


def load_or_create_web_token(*, rotate: bool = False) -> tuple[str, str]:
    """Return ``(token, state)`` for the web UI, minting one if needed.

    ``state`` is ``persisted``, ``created``, or ``rotated``, which is what the
    startup banner reports. A per-session token meant the URL changed on every
    restart; persisting it is what lets a bookmark and a systemd unit keep working.

    An unreadable or blank file is treated as absent rather than as a valid token.
    An interrupted write would otherwise leave the empty string as the shared
    secret, and ``compare_digest("", "")`` is true.
    """

    path = web_token_path()
    if not rotate:
        try:
            existing = path.read_text(encoding="utf-8").strip()
        except OSError:
            existing = ""
        if existing:
            return existing, "persisted"
    token = secrets.token_urlsafe(_WEB_TOKEN_BYTES)
    _write_secret(path, token)
    return token, "rotated" if rotate else "created"


def load_settings(path: str | Path | None = None) -> Settings:
    target = Path(path) if path is not None else settings_path()
    if not target.exists():
        return Settings()
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return Settings.model_validate(raw)


def save_settings(settings: Settings, path: str | Path | None = None) -> Path:
    target = Path(path) if path is not None else settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(settings.model_dump(), sort_keys=False), encoding="utf-8")
    return target


def load_profiles(path: str | Path | None = None) -> dict[str, CollectorProfile]:
    target = Path(path) if path is not None else profiles_path()
    if not target.exists():
        return {}
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return {name: CollectorProfile.model_validate(data) for name, data in raw.items()}


def save_profile(profile: CollectorProfile, path: str | Path | None = None) -> Path:
    target = Path(path) if path is not None else profiles_path()
    profiles = load_profiles(target)
    profiles[profile.name] = profile
    target.parent.mkdir(parents=True, exist_ok=True)
    dumped = {name: prof.model_dump() for name, prof in profiles.items()}
    target.write_text(yaml.safe_dump(dumped, sort_keys=False), encoding="utf-8")
    return target


def parse_duration(text: str) -> int:
    """Parse a duration like ``30s``, ``2m``, ``30m``, ``1h30m`` into seconds.

    A bare integer is seconds. Raises ValueError on an unparseable string.
    """

    cleaned = text.strip().lower()
    # Anchored first. `findall` alone scavenged digits out of any surrounding
    # text: "10x" was 10 seconds, "abc123" was 123, "-1h" was a positive hour
    # because the minus sign belonged to no token, and "1h30junk" was 1h+30s
    # because a trailing word leaves the second unit empty and "" maps to 1s.
    # Every one of those is worse than an error: the operator gets a run of a
    # different length and no signal that anything was misread.
    if not _DURATION_FULL.fullmatch(cleaned):
        raise ValueError(f"cannot parse duration: {text!r}")
    total = 0
    for number, unit in _DURATION_TOKEN.findall(cleaned):
        total += int(number) * _DURATION_UNITS[unit]
    return total
