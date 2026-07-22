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
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from replicant.core.models import CollectorProfile, Intensity
from replicant.scenario.engine import DEFAULT_ANCHOR_EPOCH

_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION_TOKEN = re.compile(r"(\d+)\s*([smhd]?)")

# Canonical vendor-profile ids. The Orchestrator (_build_profile) is the validator;
# the CLI --vendor choices, the Rich menu picker, and the web selector all derive
# their option list from here, so adding a vendor is one entry here plus the profile.
VENDORS: tuple[str, ...] = ("fortigate", "paloalto", "checkpoint")

# How far the anchor may drift from now before a live send is worth warning about.
STALE_ANCHOR_DAYS = 2
_DAY = 86400


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
    benign_marker: bool = False
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
    total = 0
    matched = False
    for number, unit in _DURATION_TOKEN.findall(cleaned):
        matched = True
        total += int(number) * _DURATION_UNITS[unit]
    if not matched:
        raise ValueError(f"cannot parse duration: {text!r}")
    return total
