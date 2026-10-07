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
"""REP-028: an administrator login from outside the management pool, then a
burst of configuration changes (Defense Evasion, T1562.004 and T1078).

What the catalog promises and this file measures, over seeds and presets:

- one successful admin login precedes every change, from a host that is NOT in
  the management pool, and every change is by the same account from the same
  source inside the preset's window;
- the change count is inside the preset's range, the paths are the weighted
  set the catalog names, and the actions carry the catalog's mix;
- the benign foil is the same shape from the management jump host: same count
  range, same path set, same action mix, comparable timing, and the only
  feature that separates it is the source's asset role;
- the config-change record renders on all three vendors with the change path
  carried, and the login still renders as the existing admin-login record;
- ``--duration`` sets the window and preserves the count.

Positive controls (recorded in the PR): with the foil drawn from the
workstation pool the role guard went red on every seed; with the login moved
after the first change the order guard went red on every seed.
"""

from __future__ import annotations

import statistics
from collections import Counter

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import CFG_ACTION_WEIGHTS, CFG_PATH_WEIGHTS, ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
INTENSITIES = ("low", "medium", "high")
MGMT = set(ENTITIES.mgmt_hosts)
PATHS = {path for path, _ in CFG_PATH_WEIGHTS}
ACTIONS = {action for action, _ in CFG_ACTION_WEIGHTS}


def _plan(intensity: str, seed: int):
    return ENGINE.plan(CATALOG.by_id("REP-028"), intensity, ENTITIES, seed, anchor_epoch=ANCHOR)


def _split(plan):
    positive = [e for e in plan.events if e.control == "positive"]
    negative = [e for e in plan.events if e.control != "positive"]
    return positive, negative


def _login_and_changes(events):
    logins = [e for e in events if e.action == "login"]
    changes = [e for e in events if "cfgpath" in e.extra]
    return logins, changes


# -- the attack --------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_one_login_from_outside_the_management_pool_precedes_the_burst(
    intensity: str, seed: int
) -> None:
    preset = CATALOG.by_id("REP-028").params[intensity]
    positive, _ = _split(_plan(intensity, seed))
    logins, changes = _login_and_changes(positive)
    tag = f"{intensity} seed {seed}"

    assert len(logins) == 1, f"{tag}: {len(logins)} logins"
    login = logins[0]
    assert login.extra["status"] == "success" and login.log_type == "event"
    assert login.src not in MGMT, f"{tag}: the login came from the management pool"
    assert login.src in ENTITIES.internal_hosts

    lo, hi = preset["changes"]
    assert lo <= len(changes) <= hi, f"{tag}: {len(changes)} changes outside [{lo}, {hi}]"
    window = preset["window_min"] * 60
    for change in changes:
        assert change.eventtime > login.eventtime, f"{tag}: a change precedes the login"
        assert change.eventtime - login.eventtime <= window, f"{tag}: change outside the window"
        assert change.duser == login.duser and change.src == login.src
        assert change.extra["cfgpath"] in PATHS
        assert change.action in ACTIONS
        assert change.log_type == "event" and change.subtype == "system"


def test_paths_and_actions_follow_the_catalog_mix() -> None:
    """Pooled over seeds at high, the empirical mix is within reach of the
    weights the catalog states, so the catalog text is a description of the
    stream rather than an aspiration."""
    paths: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    for seed in SEEDS:
        positive, _ = _split(_plan("high", seed))
        _, changes = _login_and_changes(positive)
        paths.update(e.extra["cfgpath"] for e in changes)
        actions.update(e.action for e in changes)
    total = sum(paths.values())
    assert total >= 400
    for path, weight in CFG_PATH_WEIGHTS:
        share = paths[path] / total
        assert abs(share - weight) < 0.08, f"{path}: {share:.2f} against weight {weight}"
    for action, weight in CFG_ACTION_WEIGHTS:
        share = actions[action] / total
        assert abs(share - weight) < 0.08, f"{action}: {share:.2f} against weight {weight}"


# -- the foil ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("intensity", INTENSITIES)
def test_the_foil_is_the_same_shape_from_the_jump_host(intensity: str, seed: int) -> None:
    preset = CATALOG.by_id("REP-028").params[intensity]
    positive, negative = _split(_plan(intensity, seed))
    p_logins, p_changes = _login_and_changes(positive)
    n_logins, n_changes = _login_and_changes(negative)
    tag = f"{intensity} seed {seed}"

    assert len(n_logins) == 1, f"{tag}: foil has {len(n_logins)} logins"
    assert n_logins[0].src in MGMT, f"{tag}: the foil did not come from the management pool"
    assert n_logins[0].duser != p_logins[0].duser  # the on-duty administrator, not the account
    lo, hi = preset["changes"]
    assert lo <= len(n_changes) <= hi, f"{tag}: foil count {len(n_changes)} outside [{lo}, {hi}]"
    window = preset["window_min"] * 60
    assert all(0 < e.eventtime - n_logins[0].eventtime <= window for e in n_changes)
    assert all(e.src == n_logins[0].src and e.duser == n_logins[0].duser for e in n_changes)
    # Same vocabulary: the foil cannot be told apart by what was changed.
    assert {e.extra["cfgpath"] for e in n_changes} <= PATHS
    assert {e.action for e in n_changes} <= ACTIONS
    # Same timing shape: both bursts are irregular, neither is a metronome.
    for label, changes in (("attack", p_changes), ("foil", n_changes)):
        times = sorted(e.eventtime for e in changes)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        if len(gaps) >= 4:
            cv = statistics.pstdev(gaps) / max(statistics.mean(gaps), 1e-9)
            assert cv > 0.2, f"{tag}: {label} burst is a metronome (gap CV {cv:.2f})"


def test_role_is_the_only_separating_feature_pooled_over_seeds() -> None:
    """Counts, paths and actions pooled over seeds at medium: the two streams
    are drawn from the same distributions, and a detection that ignores the
    source's role has nothing to key on."""
    p_counts: list[int] = []
    n_counts: list[int] = []
    p_paths: Counter[str] = Counter()
    n_paths: Counter[str] = Counter()
    for seed in SEEDS:
        positive, negative = _split(_plan("medium", seed))
        _, pc = _login_and_changes(positive)
        _, nc = _login_and_changes(negative)
        p_counts.append(len(pc))
        n_counts.append(len(nc))
        p_paths.update(e.extra["cfgpath"] for e in pc)
        n_paths.update(e.extra["cfgpath"] for e in nc)
    assert abs(statistics.mean(p_counts) - statistics.mean(n_counts)) < 3
    for path in PATHS:
        p_share = p_paths[path] / max(sum(p_paths.values()), 1)
        n_share = n_paths[path] / max(sum(n_paths.values()), 1)
        assert abs(p_share - n_share) < 0.1, f"{path}: attack {p_share:.2f} foil {n_share:.2f}"


# -- rendering -------------------------------------------------------------------------


def test_config_change_renders_on_every_vendor_with_the_path() -> None:
    positive, _ = _split(_plan("medium", 1337))
    login, changes = _login_and_changes(positive)
    change = changes[0]

    header, fgt = FortiGateProfile().render(change)
    assert header.signature_id == "44547"
    assert header.name.startswith("event:system")
    assert fgt["FTNTFGTcfgpath"] == change.extra["cfgpath"]
    assert fgt["FTNTFGTlogdesc"] == "Object attribute configured"
    assert fgt["duser"] == change.duser and fgt["src"] == change.src
    assert "FTNTFGTstatus" not in fgt  # a change is not a login verdict
    login_header, login_ext = FortiGateProfile().render(login[0])
    assert login_header.signature_id == "32001" and login_ext["FTNTFGTstatus"] == "success"

    pan_header, pan = PaloAltoProfile().render(change)
    assert pan_header.name == "CONFIG" and pan_header.signature_id == "config"
    assert pan["cs2"] == change.extra["cfgpath"] and pan["cs2Label"] == "Path"
    assert pan["PanOSCommand"] == change.action.lower()

    cp_header, cp = CheckPointProfile().render(change)
    assert cp["object_name"] == change.extra["cfgpath"]
    assert cp["operation"] == f"{change.action} Object"
    assert cp["administrator"] == change.duser
    assert cp["act"] == "Accept"


# -- duration ---------------------------------------------------------------------------


def test_duration_sets_the_window_and_keeps_the_count(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path / "manifests")))
    natural = orch.build_plan(RunRequest(technique_id="REP-028", intensity="medium", seed=7))
    short = orch.build_plan(
        RunRequest(technique_id="REP-028", intensity="medium", seed=7, duration="2m")
    )
    nat_changes = [e for e in natural.events if e.control == "positive" and "cfgpath" in e.extra]
    short_changes = [e for e in short.events if e.control == "positive" and "cfgpath" in e.extra]
    assert len(short_changes) == len(nat_changes)
    span = max(e.eventtime for e in short_changes) - min(
        e.eventtime for e in short.events if e.control == "positive"
    )
    assert span <= 120
