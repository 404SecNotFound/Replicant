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

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from replicant import __version__
from replicant.config.settings import Settings, load_profiles, save_profile
from replicant.core.models import Catalog, CollectorProfile, RunRequest
from replicant.core.orchestrator import Orchestrator


def _banner(console: Console, settings: Settings) -> None:
    console.print(
        Panel.fit(
            f"[bold green]Replicant online.[/bold green]  v{__version__}\n"
            "vendor profile: [bold]FortiGate[/bold]   |   output: synthetic CEF over syslog\n"
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


def _main_table(catalog: Catalog, collector: CollectorProfile | None, seed: int) -> Table:
    endpoint = collector.endpoint() if collector else "not connected"
    table = Table(title=f"Replicant  |  collector {endpoint}  |  seed {seed}")
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
    if dry_run:
        to_file = Prompt.ask("  Output file", default="./out/replicant.log")
    return RunRequest(
        technique_id=technique_id,
        intensity=intensity,
        seed=seed,
        duration=duration or None,
        to_file=to_file,
        no_send=dry_run,
        collector=None if dry_run else collector,
    )


def _run_technique(orchestrator: Orchestrator, request: RunRequest, console: Console) -> None:
    try:
        plan = orchestrator.build_plan(request)
    except (NotImplementedError, KeyError) as exc:
        console.print(f"  [red]cannot plan[/red]: {exc}")
        return
    total = len(plan.events)
    console.print(f"  estimated events: [bold]{total}[/bold]  (anchor {plan.anchor_epoch})")
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
    collector: CollectorProfile | None = None
    seed = settings.default_seed

    if Confirm.ask("Connect to a syslog collector now?", default=True):
        collector = _connect_flow(orchestrator, console)

    while True:
        console.print(_main_table(catalog, collector, seed))
        console.print("  [dim][1-11] technique   [c] connection   [s] seed   [q] quit[/dim]")
        choice = Prompt.ask("Select").strip().lower()
        if choice == "q":
            console.print("Replicant offline.")
            return 0
        if choice == "c":
            collector = _connect_flow(orchestrator, console)
            continue
        if choice == "s":
            seed = IntPrompt.ask("New seed", default=seed)
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
