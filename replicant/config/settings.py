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
from pathlib import Path

import yaml
from pydantic import BaseModel

from replicant.core.models import CollectorProfile, Intensity
from replicant.scenario.engine import DEFAULT_ANCHOR_EPOCH

_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION_TOKEN = re.compile(r"(\d+)\s*([smhd]?)")

# Canonical vendor-profile ids. The Orchestrator (_build_profile) is the validator;
# the CLI --vendor choices, the Rich menu picker, and the web selector all derive
# their option list from here, so adding a vendor is one entry here plus the profile.
VENDORS: tuple[str, ...] = ("fortigate", "paloalto", "checkpoint")


class Settings(BaseModel):
    """Operator defaults. The default layer of the precedence chain."""

    default_seed: int = 1337
    eps_cap: int = 2000
    default_intensity: Intensity = "medium"
    vendor: str = "fortigate"  # fortigate | paloalto | checkpoint (selects the VendorProfile)
    benign_marker: bool = False
    byte_key_out: str = "out"
    byte_key_in: str = "in"
    anchor_epoch: int = DEFAULT_ANCHOR_EPOCH
    hostname: str = "FGT-LAB-01"
    accepted_as: str = "Syslog - Fortinet FortiGate v5.6 CEF"
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
