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
"""Rich interactive menu (blueprint s7).

Startup banner -> connect wizard -> test log -> main technique menu -> params ->
run view -> stop. Every action delegates to the Orchestrator; no behavior lives
only here (the CLI can do everything the menu can).
"""

from __future__ import annotations

from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from replicant import __version__
from replicant.config.settings import VENDORS, Settings, load_profiles, save_profile
from replicant.core.models import (
    SCENARIO_CATALOG_PATH,
    Catalog,
    CollectorProfile,
    RunRequest,
    Scenario,
    ScenarioCatalog,
    ScenarioRunRequest,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator
from replicant.core.pacing import Pace
from replicant.entities.model import EntityModel
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

_VENDORS = list(VENDORS)
_VENDOR_LABELS = {
    "fortigate": "FortiGate",
    "paloalto": "Palo Alto (PAN-OS)",
    "checkpoint": "Check Point",
}


def _vendor_label(vendor: str) -> str:
    return _VENDOR_LABELS.get(vendor, vendor)


def _banner(console: Console, settings: Settings) -> None:
    console.print(
        Panel.fit(
            f"[bold green]Replicant online.[/bold green]  v{__version__}\n"
            f"vendor profile: [bold]{_vendor_label(settings.vendor)}[/bold]"
            "   |   output: synthetic CEF over syslog\n"
            "[dim]For environments you own or are authorized to test. All entities are "
            "synthetic; the only egress is your configured collector.[/dim]",
            title="Replicant",
        )
    )


def _pick_saved_profile(
    console: Console, saved: dict[str, CollectorProfile]
) -> CollectorProfile | None:
    """Offer the saved collectors; return the chosen one, or None to enter a new one."""

    names = sorted(saved)
    console.print("  [bold]Saved collectors[/bold]")
    for index, name in enumerate(names, start=1):
        console.print(f"    [{index}] {name}  ->  {saved[name].endpoint()}")
    console.print(r"    \[n] new collector")
    choices = [str(i) for i in range(1, len(names) + 1)] + ["n"]
    choice = Prompt.ask(
        r"  Pick a saved collector, or \[n] for a new one", choices=choices, default="n"
    )
    if choice == "n":
        return None
    return saved[names[int(choice) - 1]]


def _pick_vendor(console: Console, current: str) -> str:
    """Offer the vendor profiles; return the chosen vendor id (default keeps current)."""

    console.print("  [bold]Vendor profile[/bold]")
    for index, vendor in enumerate(_VENDORS, start=1):
        marker = "  [dim](current)[/dim]" if vendor == current else ""
        console.print(f"    [{index}] {_vendor_label(vendor)}{marker}")
    choices = [str(i) for i in range(1, len(_VENDORS) + 1)]
    default = str(_VENDORS.index(current) + 1) if current in _VENDORS else "1"
    choice = Prompt.ask("  Select vendor", choices=choices, default=default)
    return _VENDORS[int(choice) - 1]


def _pick_scenario(console: Console, scenarios: ScenarioCatalog) -> Scenario:
    """Offer the scenario catalog; return the chosen scenario."""

    console.print("  [bold]Attack scenario[/bold]")
    for index, scenario in enumerate(scenarios.scenarios, start=1):
        console.print(
            f"    [{index}] {scenario.id}  {scenario.name} "
            f"[dim]({len(scenario.stages)} stages)[/dim]"
        )
    choices = [str(i) for i in range(1, len(scenarios.scenarios) + 1)]
    choice = Prompt.ask("  Select scenario", choices=choices, default="1")
    return scenarios.scenarios[int(choice) - 1]


def _run_scenario(
    orchestrator: Orchestrator,
    scenario: Scenario,
    scenarios: ScenarioCatalog,
    seed: int,
    collector: CollectorProfile | None,
    console: Console,
) -> None:
    request = ScenarioRunRequest(
        scenario_id=scenario.id,
        seed=seed,
        collector=collector,
        no_send=collector is None,
        to_file=None,
    )
    # show the coverage/advisory preview first, whether or not a collector is set.
    composed = compose(
        scenario,
        orchestrator.catalog.by_id,
        ScenarioEngine(),
        seed,
        orchestrator.settings.anchor_epoch,
        EntityModel.build(),
    )
    text, _ = build_advisory(scenario, composed, orchestrator.catalog)
    console.print(text)
    if collector is None:
        console.print(
            r"  [yellow]no collector set; use \[c] to connect, or run headless with "
            "'replicant scenario run --to-file'[/yellow]"
        )
        return
    with Progress(console=console) as progress:
        task = progress.add_task(f"emitting {scenario.id}", total=composed.total_count)
        result = orchestrator.run_scenario(
            request, scenarios, on_progress=lambda c, t: progress.update(task, completed=c)
        )
    console.print(f"  {result.event_count} events · manifest {result.manifest_path}")
    console.print(f"  advisory {result.advisory_path}")


def _connection_wizard(console: Console) -> CollectorProfile:
    console.print("[bold]Connection settings[/bold]")
    saved = load_profiles()
    if saved:
        chosen = _pick_saved_profile(console, saved)
        if chosen is not None:
            return chosen
    host = Prompt.ask("  Collector IP or host")
    port = IntPrompt.ask("  Port", default=514)
    transport = Prompt.ask("  Transport", choices=["udp", "tcp", "tls"], default="udp")
    tls_verify, tls_cafile = True, None
    if transport == "tls":
        tls_verify = Confirm.ask("  Verify the collector certificate?", default=True)
        cafile = Prompt.ask("  CA bundle path (blank for system CAs)", default="")
        tls_cafile = cafile.strip() or None
    profile = CollectorProfile(
        name="menu",
        host=host,
        port=port,
        transport=transport,
        tls_verify=tls_verify,
        tls_cafile=tls_cafile,
    )
    if Confirm.ask("  Save as a named profile?", default=False):
        name = Prompt.ask("  Profile name", default="default")
        profile = profile.model_copy(update={"name": name})
        path = save_profile(profile)
        console.print(f"  [green]saved[/green] -> {path}")
    return profile


def _connect_flow(orchestrator: Orchestrator, console: Console) -> CollectorProfile | None:
    profile = _connection_wizard(console)
    console.print(f"  sending one benign test log to {profile.endpoint()} ...")
    ok = orchestrator.send_test(profile)
    if not ok:
        console.print("  [red]transport error[/red] sending the test log.")
        if not Confirm.ask("  Keep this collector anyway?", default=False):
            return None
        return profile
    console.print("  [green]test log sent.[/green]")
    if Confirm.ask("  Did your collector receive the test log?", default=True):
        console.print("  [green]collector confirmed.[/green]")
    return profile


def _key_hint(catalog: Catalog) -> str:
    """The key legend under the menu table.

    The technique range is derived from the catalog rather than written out.
    It was hardcoded as ``[1-11]`` and silently became wrong when the catalog
    grew to 24, contradicting the selection validator in the menu loop, which
    has always bounded on ``len(catalog.techniques)``.
    """

    return (
        rf"  [dim]\[1-{len(catalog.techniques)}] technique   \[a] scenario   "
        r"\[c] connection   \[v] vendor   \[s] seed   \[q] quit[/dim]"
    )


def _main_table(
    catalog: Catalog, collector: CollectorProfile | None, seed: int, vendor: str
) -> Table:
    endpoint = collector.endpoint() if collector else "not connected"
    label = _vendor_label(vendor)
    title = f"Replicant  |  vendor {label}  |  collector {endpoint}  |  seed {seed}"
    table = Table(title=title)
    table.add_column("Key", justify="right")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("UC")
    for index, technique in enumerate(catalog.techniques, start=1):
        table.add_row(str(index), technique.id, technique.name, technique.ndr_uc)
    return table


def _params_flow(
    console: Console,
    technique_id: str,
    seed: int,
    collector: CollectorProfile | None,
) -> RunRequest:
    intensity = Prompt.ask("  Intensity", choices=["low", "medium", "high"], default="medium")
    duration = Prompt.ask("  Duration (e.g. 2m, 30m; blank uses the preset)", default="")
    dry_run = Confirm.ask("  Dry run to file only (no send)?", default=collector is None)
    to_file = None
    pace: Pace | None = None
    speed = 1.0
    if dry_run:
        to_file = Prompt.ask("  Output file", default="./out/replicant.log")
    else:
        # Only asked when the events are going somewhere with a clock. A file has
        # no wall time to reproduce, so the question would have no answer worth
        # having, and the resolution is left to the orchestrator either way.
        console.print(
            "  [dim]plan = reproduce the gaps in the plan's timeline; "
            "burst = send as fast as the rate cap allows[/dim]"
        )
        pace = cast(Pace, Prompt.ask("  Pacing", choices=["plan", "burst"], default="plan"))
        if pace == "plan":
            raw = Prompt.ask(
                "  Speed (1 = real time; higher compresses event times with the schedule)",
                default="1",
            )
            try:
                speed = max(1.0, float(raw))
            except ValueError:
                speed = 1.0
    return RunRequest(
        technique_id=technique_id,
        intensity=intensity,
        seed=seed,
        duration=duration or None,
        to_file=to_file,
        no_send=dry_run,
        collector=None if dry_run else collector,
        pace=pace,
        speed=speed,
    )


def _run_technique(orchestrator: Orchestrator, request: RunRequest, console: Console) -> None:
    try:
        plan = orchestrator.build_plan(request)
    except (NotImplementedError, KeyError) as exc:
        console.print(f"  [red]cannot plan[/red]: {exc}")
        return
    total = len(plan.events)
    console.print(f"  estimated events: [bold]{total}[/bold]  (anchor {plan.anchor_epoch})")
    # The count alone made a 238 minute run look identical to a three second one,
    # and this prompt is the last point at which the operator can decline. An
    # interactive interface is the worst place to hide a four hour commitment.
    try:
        preview = orchestrator.preview_pacing(
            request,
            sending=not request.no_send and request.collector is not None,
            plan=plan,
        )
    except (RuntimeError, NotImplementedError) as exc:
        console.print(f"  [red]cannot run[/red]: {exc}")
        return
    console.print(f"  {preview.describe()}")
    if not Confirm.ask("  Start run?", default=True):
        return

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("  streaming", total=max(total, 1))

        def on_progress(count: int, _total: int) -> None:
            progress.update(task, completed=count)

        try:
            result = orchestrator.run(request, on_progress=on_progress)
        except (RuntimeError, NotImplementedError) as exc:
            console.print(f"  [red]run refused[/red]: {exc}")
            return
        progress.update(task, completed=result.event_count)

    console.print(Panel.fit(result.summary(), title="Run summary"))
    if result.stopped:
        console.print("  [yellow]stopped early (kill switch)[/yellow]")


def run_menu(catalog: Catalog, settings: Settings, console: Console) -> int:
    _banner(console, settings)
    orchestrator = Orchestrator(catalog, settings)
    scenarios = load_scenario_catalog(SCENARIO_CATALOG_PATH, catalog)
    collector: CollectorProfile | None = None
    seed = settings.default_seed

    if Confirm.ask("Connect to a syslog collector now?", default=True):
        collector = _connect_flow(orchestrator, console)

    while True:
        console.print(_main_table(catalog, collector, seed, settings.vendor))
        console.print(_key_hint(catalog))
        choice = Prompt.ask("Select").strip().lower()
        if choice == "q":
            console.print("Replicant offline.")
            return 0
        if choice == "c":
            collector = _connect_flow(orchestrator, console)
            continue
        if choice == "v":
            new_vendor = _pick_vendor(console, settings.vendor)
            if new_vendor != settings.vendor:
                settings = settings.model_copy(update={"vendor": new_vendor})
                orchestrator = Orchestrator(catalog, settings)
                console.print(f"  [green]vendor set[/green] -> {_vendor_label(new_vendor)}")
            continue
        if choice == "s":
            seed = IntPrompt.ask("New seed", default=seed)
            continue
        if choice == "a":
            scenario = _pick_scenario(console, scenarios)
            _run_scenario(orchestrator, scenario, scenarios, seed, collector, console)
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(catalog.techniques)):
            console.print("  [yellow]invalid selection[/yellow]")
            continue
        technique = catalog.techniques[int(choice) - 1]
        request = _params_flow(console, technique.id, seed, collector)
        try:
            _run_technique(orchestrator, request, console)
        except KeyboardInterrupt:
            orchestrator.stop()
            console.print("  [yellow]interrupted[/yellow]")
