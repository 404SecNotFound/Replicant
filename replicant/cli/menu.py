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

import math
from typing import cast

from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from replicant import __version__
from replicant.cli.app import print_path, print_probe_report
from replicant.config.confine import (
    PROFILE_SAVE_REFUSED,
    ConfinementError,
    confined_cafile,
    confined_output_path,
    web_confined,
)
from replicant.config.settings import (
    VENDORS,
    Settings,
    load_profiles,
    parse_anchor,
    parse_duration,
    save_profile,
    stale_anchor_warning,
)
from replicant.core.lifecycle import SIGTERM_EXIT, stop_on_sigterm
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
from replicant.core.pacing import MAX_SPEED, Pace
from replicant.entities.model import EntityModel
from replicant.obs.log import install_stderr
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


def _ask_anchor(console: Console, *, sending: bool, default_epoch: int) -> int:
    """Ask for the event-time anchor, with the same meanings as ``--anchor``.

    ``now``, ``default`` (the fixed anchor that makes a seed reproduce byte for
    byte), an epoch, or an ISO-8601 timestamp. The menu had no way to set it, so
    every menu live send carried event times over a year old while the syslog
    header said now, and a SIEM keying on event time saw nothing recent. ``now``
    is therefore the suggested answer for a live send; a file keeps the default.
    """

    console.print(
        "  [dim]event-time anchor: now, default (fixed, reproducible), an epoch, "
        "or an ISO-8601 time[/dim]"
    )
    suggested = "now" if sending else "default"
    while True:
        raw = Prompt.ask("  Anchor", default=suggested).strip() or suggested
        if raw.lower() in {"default", "fixed"}:
            anchor = default_epoch
        else:
            try:
                anchor = parse_anchor(raw)
            except ValueError as exc:
                console.print(f"  [yellow]{escape(str(exc))}[/yellow]")
                continue
        warning = stale_anchor_warning(anchor, sending=sending)
        if warning:
            console.print(f"  [yellow]note[/yellow]: {escape(warning)}")
        return anchor


def _ask_duration(console: Console) -> str | None:
    """A duration the run will accept, or None for the preset. Re-asks on nonsense."""

    while True:
        raw = Prompt.ask("  Duration (e.g. 2m, 30m; blank uses the preset)", default="").strip()
        if not raw:
            return None
        try:
            if parse_duration(raw) > 0:
                return raw
        except ValueError:
            pass
        console.print(
            f"  [yellow]not a duration: {escape(raw)!s}. Use a number with s, m, h or d, "
            "for example 90s, 30m or 1h30m.[/yellow]"
        )


def _ask_speed(console: Console) -> float:
    """A plan-pacing speed, 1 to MAX_SPEED. Re-asks rather than guessing."""

    while True:
        raw = (
            Prompt.ask(
                "  Speed (1 = real time; higher compresses event times with the schedule)",
                default="1",
            ).strip()
            or "1"
        )
        try:
            value = float(raw)
        except ValueError:
            value = math.nan
        if math.isfinite(value) and 0 < value <= MAX_SPEED:
            return max(1.0, value)
        console.print(
            f"  [yellow]speed must be a number from 1 to {MAX_SPEED:.0f} "
            f"(got {escape(raw)})[/yellow]"
        )


def _ask_output(console: Console, manifest_dir: str) -> str:
    """The output file. Confined to one directory when driven from the web terminal."""

    confined = web_confined()
    if confined:
        console.print(
            "  [dim]web terminal: output goes to the run-output directory, "
            "named by file name only[/dim]"
        )
    while True:
        raw = Prompt.ask("  Output file", default="./out/replicant.log").strip()
        if not confined:
            return raw
        try:
            return confined_output_path(raw, manifest_dir)
        except ConfinementError as exc:
            console.print(f"  [red]{escape(str(exc))}[/red]")


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
) -> bool:
    """Preview and, with a collector, run one scenario. True if SIGTERM ended it."""

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
        return False
    anchor = _ask_anchor(console, sending=True, default_epoch=orchestrator.settings.anchor_epoch)
    request = ScenarioRunRequest(
        scenario_id=scenario.id,
        seed=seed,
        collector=collector,
        no_send=False,
        to_file=None,
        anchor_epoch=anchor,
    )
    print_path(collector, sending=True)
    with Progress(console=console) as progress:
        task = progress.add_task(f"emitting {scenario.id}", total=composed.total_count)
        try:
            with stop_on_sigterm(orchestrator) as signalled:
                result = orchestrator.run_scenario(
                    request,
                    scenarios,
                    on_progress=lambda c, t: progress.update(task, completed=c),
                )
        except (RuntimeError, NotImplementedError, OSError) as exc:
            # This path had no handler at all, unlike its _run_technique sibling.
            # A refused collector therefore left the menu with a traceback and no
            # menu, which is the worst of the failure modes in this file.
            console.print(f"  [red]run refused[/red]: {escape(str(exc))}")
            return False
    console.print(f"  {result.event_count} events · manifest {result.manifest_path}")
    console.print(f"  advisory {result.advisory_path}")
    return signalled.received


def _first_error(exc: ValidationError) -> str:
    return str(exc.errors()[0]["msg"]).removeprefix("Value error, ")


def _ask_cafile(console: Console, *, confined: bool) -> str | None:
    """A CA bundle path, or None for system CAs. Confined to <config>/ca/ from the web."""

    label = (
        "  CA bundle file name in the config ca/ directory (blank for system CAs)"
        if confined
        else "  CA bundle path (blank for system CAs)"
    )
    while True:
        raw = Prompt.ask(label, default="").strip()
        if not raw or not confined:
            return raw or None
        try:
            return confined_cafile(raw)
        except ConfinementError as exc:
            console.print(f"  [red]{escape(str(exc))}[/red]")


def _connection_wizard(console: Console) -> CollectorProfile | None:
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
    confined = web_confined()
    if transport == "tls":
        tls_verify = Confirm.ask("  Verify the collector certificate?", default=True)
        tls_cafile = _ask_cafile(console, confined=confined)
    try:
        profile = CollectorProfile(
            name="menu",
            host=host,
            port=port,
            transport=transport,
            tls_verify=tls_verify,
            tls_cafile=tls_cafile,
        )
    except ValidationError as exc:
        console.print(f"  [red]collector refused[/red]: {escape(_first_error(exc))}")
        return None
    if confined:
        # Not asked: a question whose yes always fails is decoration. Said once
        # so the operator knows why the collector will not be there next time.
        console.print(f"  [dim]{PROFILE_SAVE_REFUSED}[/dim]")
        return profile
    if Confirm.ask("  Save as a named profile?", default=False):
        name = Prompt.ask("  Profile name", default="default")
        profile = profile.model_copy(update={"name": name})
        path = save_profile(profile)
        console.print(f"  [green]saved[/green] -> {path}")
    return profile


def _connect_flow(orchestrator: Orchestrator, console: Console) -> CollectorProfile | None:
    profile = _connection_wizard(console)
    if profile is None:
        return None
    console.print(f"  sending one benign test log to {profile.endpoint()} ...")
    # The same probe as `replicant connect --test` and the web card: a verdict
    # with its limits, never a bare "sent". The old bool said "test log sent"
    # for a UDP datagram to a closed port.
    report = orchestrator.probe(profile)
    print_probe_report(report, console)
    if not report.ok:
        if not Confirm.ask("  Keep this collector anyway?", default=False):
            return None
        return profile
    if Confirm.ask("  Did your collector receive the test log?", default=True):
        console.print("  receipt confirmed by you on the collector.")
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
    *,
    settings: Settings | None = None,
) -> RunRequest:
    """Ask for a run's parameters until they make a request the model accepts.

    Each answer that can be wrong is checked where it is asked. The request model
    is still the final word, and a refusal there re-asks the whole set rather than
    ending the menu with a traceback, which is what ``banana`` and ``inf`` did.
    """

    resolved = settings or Settings()
    while True:
        try:
            return _params_once(console, technique_id, seed, collector, resolved)
        except ValidationError as exc:
            console.print(f"  [yellow]not accepted[/yellow]: {escape(_first_error(exc))}")


def _params_once(
    console: Console,
    technique_id: str,
    seed: int,
    collector: CollectorProfile | None,
    settings: Settings,
) -> RunRequest:
    intensity = Prompt.ask("  Intensity", choices=["low", "medium", "high"], default="medium")
    duration = _ask_duration(console)
    dry_run = Confirm.ask("  Dry run to file only (no send)?", default=collector is None)
    to_file = None
    pace: Pace | None = None
    speed = 1.0
    param_overrides: dict[str, str] = {}
    if technique_id == "REP-009":
        param_overrides["signature_mode"] = Prompt.ask(
            "  IPS signatures",
            choices=["mixed", "single"],
            default="mixed",
        )
    if dry_run:
        to_file = _ask_output(console, settings.manifest_dir)
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
            speed = _ask_speed(console)
    sending = not dry_run and collector is not None
    anchor = _ask_anchor(console, sending=sending, default_epoch=settings.anchor_epoch)
    return RunRequest(
        technique_id=technique_id,
        intensity=intensity,
        seed=seed,
        duration=duration,
        to_file=to_file,
        no_send=dry_run,
        collector=None if dry_run else collector,
        anchor_epoch=anchor,
        param_overrides=param_overrides,
        pace=pace,
        speed=speed,
    )


def _run_technique(orchestrator: Orchestrator, request: RunRequest, console: Console) -> bool:
    """Preview, confirm and run one technique. True if SIGTERM ended the run."""

    try:
        plan = orchestrator.build_plan(request)
    except (NotImplementedError, KeyError) as exc:
        console.print(f"  [red]cannot plan[/red]: {exc}")
        return False
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
    except (RuntimeError, NotImplementedError, OSError) as exc:
        console.print(f"  [red]cannot run[/red]: {exc}")
        return False
    console.print(f"  {preview.describe()}")
    if preview.future_warning:
        console.print(f"  [yellow]note[/yellow]: {escape(preview.future_warning)}")
    if not Confirm.ask("  Start run?", default=True):
        return False
    sending = not request.no_send and request.collector is not None
    print_path(request.collector, sending=sending)

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
            with stop_on_sigterm(orchestrator) as signalled:
                result = orchestrator.run(request, on_progress=on_progress)
        except (RuntimeError, NotImplementedError, OSError) as exc:
            console.print(f"  [red]run refused[/red]: {escape(str(exc))}")
            return False
        progress.update(task, completed=result.event_count)

    console.print(Panel.fit(result.summary(), title="Run summary"))
    if result.stopped:
        console.print("  [yellow]stopped early (kill switch)[/yellow]")
    return signalled.received


def run_menu(catalog: Catalog, settings: Settings, console: Console) -> int:
    install_stderr()
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
            if _run_scenario(orchestrator, scenario, scenarios, seed, collector, console):
                # systemd or docker asked the process to stop. The run is
                # finalized; leave rather than wait at a prompt to be killed.
                console.print("Replicant offline (SIGTERM).")
                return SIGTERM_EXIT
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(catalog.techniques)):
            console.print("  [yellow]invalid selection[/yellow]")
            continue
        technique = catalog.techniques[int(choice) - 1]
        request = _params_flow(console, technique.id, seed, collector, settings=settings)
        try:
            terminated = _run_technique(orchestrator, request, console)
        except KeyboardInterrupt:
            orchestrator.stop()
            console.print("  [yellow]interrupted[/yellow]")
            continue
        if terminated:
            console.print("Replicant offline (SIGTERM).")
            return SIGTERM_EXIT
