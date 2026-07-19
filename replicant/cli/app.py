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
"""Headless CLI entry point.

Verbs: ``list``, ``connect``, ``run``, ``menu``. Every verb calls the Orchestrator,
so the CLI and the Rich menu share one code path (blueprint s7). Uses stdlib
argparse to keep the dependency set small.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from replicant import __version__
from replicant.config.settings import (
    VENDORS,
    Settings,
    load_profiles,
    load_settings,
    save_profile,
)
from replicant.core.models import (
    SCENARIO_CATALOG_PATH,
    Catalog,
    CollectorProfile,
    RunRequest,
    ScenarioRunRequest,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose


def _find_catalog(settings: Settings) -> Path | None:
    candidates = [
        Path(settings.catalog_path),
        Path.cwd() / settings.catalog_path,
        Path(__file__).resolve().parents[2] / settings.catalog_path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _load_catalog(settings: Settings, console: Console) -> Catalog | None:
    path = _find_catalog(settings)
    if path is None:
        console.print(f"[red]catalog not found[/red]: {settings.catalog_path}")
        return None
    try:
        return load_catalog(path)
    except Exception as exc:  # noqa: BLE001 - surface any validation error to the operator
        console.print(f"[red]catalog failed to load[/red]: {exc}")
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="replicant",
        description="Safe synthetic FortiGate CEF telemetry for detection engineering.",
    )
    parser.add_argument("--version", action="version", version=f"replicant {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="print the technique catalog")
    sub.add_parser("menu", help="launch the interactive Rich menu")

    web = sub.add_parser("web", help="launch the web UI on a random loopback port")
    web.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    web.add_argument("--host", default="127.0.0.1", help="bind address (loopback by default)")

    connect = sub.add_parser("connect", help="configure a collector and optionally send a test log")
    connect.add_argument("--host", required=True, help="collector IP or hostname")
    connect.add_argument("--port", type=int, default=514)
    connect.add_argument("--transport", choices=["udp", "tcp", "tls"], default="udp")
    connect.add_argument(
        "--facility", type=int, default=23, help="syslog facility (default local7=23)"
    )
    connect.add_argument(
        "--tls-cafile", metavar="PATH", help="CA bundle for a private TLS collector"
    )
    connect.add_argument(
        "--tls-insecure",
        action="store_true",
        help="skip TLS certificate verification (lab self-signed collectors only)",
    )
    connect.add_argument("--test", action="store_true", help="send one benign test log")
    connect.add_argument("--save", metavar="NAME", help="save this collector as a named profile")
    connect.add_argument(
        "--vendor",
        choices=list(VENDORS),
        help="vendor profile (default from settings)",
    )

    run = sub.add_parser("run", help="run a technique")
    run.add_argument("id", help="technique id, e.g. REP-001")
    run.add_argument("--intensity", choices=["low", "medium", "high"], default="medium")
    run.add_argument("--duration", help="run duration, e.g. 2m, 30m, 1h")
    run.add_argument("--seed", type=int, help="RNG seed (default from settings)")
    run.add_argument("--to-file", metavar="PATH", help="mirror CEF payloads to a file")
    run.add_argument("--no-send", action="store_true", help="do not send to a collector")
    run.add_argument("--rate", type=int, help="events-per-second cap override")
    run.add_argument("--host", help="collector host (ad-hoc, instead of a saved profile)")
    run.add_argument("--port", type=int, default=514)
    run.add_argument("--transport", choices=["udp", "tcp", "tls"], default="udp")
    run.add_argument("--tls-cafile", metavar="PATH", help="CA bundle for a private TLS collector")
    run.add_argument(
        "--tls-insecure",
        action="store_true",
        help="skip TLS certificate verification (lab self-signed collectors only)",
    )
    run.add_argument("--profile", help="use a saved collector profile by name")
    run.add_argument(
        "--vendor",
        choices=list(VENDORS),
        help="vendor profile (default from settings)",
    )

    scenario = sub.add_parser("scenario", help="compose and run a multi-stage scenario")
    scen_actions = scenario.add_subparsers(dest="action")
    scen_actions.add_parser("list", help="list scenarios")
    scen_show = scen_actions.add_parser("show", help="show a scenario's stages + coverage, no emit")
    scen_show.add_argument("id", help="scenario id, e.g. SCEN-001")
    scen_run = scen_actions.add_parser("run", help="run a scenario")
    scen_run.add_argument("id", help="scenario id, e.g. SCEN-001")
    scen_run.add_argument("--seed", type=int)
    scen_run.add_argument(
        "--intensity", choices=["low", "medium", "high"], help="override all stages"
    )
    scen_run.add_argument("--to-file", dest="to_file")
    scen_run.add_argument("--no-send", dest="no_send", action="store_true")
    scen_run.add_argument("--rate", type=int)
    scen_run.add_argument("--host")
    scen_run.add_argument("--port", type=int, default=514)
    scen_run.add_argument("--transport", choices=["udp", "tcp", "tls"], default="udp")
    scen_run.add_argument("--tls-cafile", dest="tls_cafile")
    scen_run.add_argument("--tls-insecure", dest="tls_insecure", action="store_true")
    scen_run.add_argument("--profile", help="saved collector profile name")
    scen_run.add_argument("--vendor", choices=list(VENDORS))
    return parser


def cmd_list(catalog: Catalog, console: Console) -> int:
    table = Table(title=f"Replicant technique catalog  (vendor: {catalog.vendor_profile})")
    table.add_column("#", justify="right")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("UC")
    table.add_column("Log type")
    table.add_column("ATT&CK")
    for index, technique in enumerate(catalog.techniques, start=1):
        table.add_row(
            str(index),
            technique.id,
            technique.name,
            technique.ndr_uc,
            f"{technique.fortigate.log_type}:{technique.fortigate.subtype}",
            ", ".join(technique.attack.techniques),
        )
    console.print(table)
    return 0


def cmd_connect(
    args: argparse.Namespace, catalog: Catalog, settings: Settings, console: Console
) -> int:
    profile = CollectorProfile(
        name=args.save or "default",
        host=args.host,
        port=args.port,
        transport=args.transport,
        facility=args.facility,
        tls_verify=not args.tls_insecure,
        tls_cafile=args.tls_cafile,
    )
    if args.save:
        path = save_profile(profile)
        console.print(f"[green]saved profile[/green] '{profile.name}' -> {path}")
    console.print(f"collector: {profile.endpoint()}  (eps cap {settings.eps_cap})")
    if not args.test:
        return 0
    orchestrator = Orchestrator(catalog, settings)
    console.print("sending one benign traffic:forward accept test log ...")
    ok = orchestrator.send_test(profile)
    if ok:
        console.print("[green]test log sent[/green]. Confirm receipt on your collector.")
        return 0
    console.print("[red]test failed[/red]: transport error (is the collector reachable?)")
    return 1


def _resolve_collector(
    args: argparse.Namespace, console: Console
) -> tuple[CollectorProfile | None, bool]:
    """Return (collector, ok). ok is False only on an explicit resolution error."""

    if args.profile:
        profiles = load_profiles()
        if args.profile not in profiles:
            console.print(f"[red]no saved profile named[/red] '{args.profile}'")
            return None, False
        return profiles[args.profile], True
    if args.host:
        return (
            CollectorProfile(
                name="adhoc",
                host=args.host,
                port=args.port,
                transport=args.transport,
                tls_verify=not args.tls_insecure,
                tls_cafile=args.tls_cafile,
            ),
            True,
        )
    return None, True


def cmd_run(
    args: argparse.Namespace, catalog: Catalog, settings: Settings, console: Console
) -> int:
    try:
        catalog.by_id(args.id)
    except KeyError:
        console.print(f"[red]unknown technique[/red]: {args.id}. Try 'replicant list'.")
        return 1

    collector, ok = _resolve_collector(args, console)
    if not ok:
        return 1

    request = RunRequest(
        technique_id=args.id,
        intensity=args.intensity,
        seed=args.seed if args.seed is not None else settings.default_seed,
        duration=args.duration,
        to_file=args.to_file,
        no_send=args.no_send,
        rate_override=args.rate,
        collector=collector,
    )
    orchestrator = Orchestrator(catalog, settings)
    try:
        result = orchestrator.run(request)
    except (RuntimeError, NotImplementedError) as exc:
        console.print(f"[red]run refused[/red]: {exc}")
        return 1

    console.print(result.summary())
    if result.stopped:
        console.print("[yellow]run stopped early (kill switch)[/yellow]")
    return 0


def cmd_scenario(
    args: argparse.Namespace, catalog: Catalog, settings: Settings, console: Console
) -> int:
    scenarios = load_scenario_catalog(SCENARIO_CATALOG_PATH, catalog)
    action = args.action or "list"

    if action == "list":
        for scenario in scenarios.scenarios:
            tactics = sorted(
                {
                    t
                    for stage in scenario.stages
                    for t in catalog.by_id(stage.technique_id).attack.tactics
                }
            )
            console.print(
                f"[bold]{scenario.id}[/bold]  {scenario.name}  "
                f"[dim]{len(scenario.stages)} stages · {', '.join(tactics)}[/dim]"
            )
        return 0

    try:
        scenario = scenarios.by_id(args.id)
    except KeyError:
        console.print(f"[red]unknown scenario[/red]: {args.id}. Try 'replicant scenario list'.")
        return 1

    if action == "show":
        from replicant.entities.model import EntityModel
        from replicant.scenario.engine import ScenarioEngine

        composed = compose(
            scenario,
            catalog.by_id,
            ScenarioEngine(),
            settings.default_seed,
            settings.anchor_epoch,
            EntityModel.build(),
        )
        text, _ = build_advisory(scenario, composed, catalog)
        console.print(text)
        return 0

    # action == "run"
    collector, ok = _resolve_collector(args, console)
    if not ok:
        return 1
    request = ScenarioRunRequest(
        scenario_id=args.id,
        seed=args.seed if args.seed is not None else settings.default_seed,
        intensity_override=args.intensity,
        to_file=args.to_file,
        no_send=args.no_send,
        rate_override=args.rate,
        collector=collector,
    )
    orchestrator = Orchestrator(catalog, settings)
    try:
        result = orchestrator.run_scenario(request, scenarios)
    except (RuntimeError, NotImplementedError) as exc:
        console.print(f"[red]run refused[/red]: {exc}")
        return 1
    console.print(
        f"scenario {result.manifest.scenario_id}: {result.event_count} events across "
        f"{len(result.manifest.stages)} stages"
    )
    console.print(f"manifest: {result.manifest_path}")
    console.print(f"advisory: {result.advisory_path}")
    if result.stopped:
        console.print("[yellow]run stopped early (kill switch)[/yellow]")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    settings = load_settings()
    if getattr(args, "vendor", None):
        settings = settings.model_copy(update={"vendor": args.vendor})
    catalog = _load_catalog(settings, console)
    if catalog is None:
        return 1

    command = args.command or "menu"
    if command == "list":
        return cmd_list(catalog, console)
    if command == "connect":
        return cmd_connect(args, catalog, settings, console)
    if command == "run":
        return cmd_run(args, catalog, settings, console)
    if command == "scenario":
        return cmd_scenario(args, catalog, settings, console)
    if command == "menu":
        from replicant.cli.menu import run_menu

        return run_menu(catalog, settings, console)
    if command == "web":
        try:
            from replicant.web.server import serve
        except ImportError:
            console.print(
                "[red]web dependencies missing[/red]. Install them with: " "pip install -e '.[web]'"
            )
            return 1
        serve(catalog, settings, host=args.host, open_browser=not args.no_browser)
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
