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
from __future__ import annotations

from pathlib import Path

from replicant.cli.app import main


def test_scenario_list(capsys) -> None:
    rc = main(["scenario", "list"])
    out = capsys.readouterr().out
    assert rc == 0 and "SCEN-001" in out and "SCEN-003" in out


def test_scenario_show(capsys) -> None:
    rc = main(["scenario", "show", "SCEN-001"])
    out = capsys.readouterr().out
    assert rc == 0 and "Kill chain" in out and "correlate on these" in out.lower()


def test_scenario_run_to_file(tmp_path: Path, capsys) -> None:
    out = tmp_path / "s.log"
    rc = main(["scenario", "run", "SCEN-001", "--seed", "1337", "--to-file", str(out), "--no-send"])
    assert rc == 0 and out.exists() and out.stat().st_size > 0


def test_scenario_run_unknown_id(capsys) -> None:
    rc = main(["scenario", "run", "SCEN-404", "--to-file", "/tmp/x.log", "--no-send"])
    assert rc == 1 and "unknown scenario" in capsys.readouterr().out.lower()
