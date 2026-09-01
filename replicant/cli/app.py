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

Verbs: ``list``, ``connect``, ``run``, ``scenario``, ``web``, ``menu``. Every verb
calls the Orchestrator, so the CLI and the Rich menu share one code path
(blueprint s7). Uses stdlib argparse to keep the dependency set small.

Output convention: command results go to stdout, operator-facing errors go to
stderr via ``_fail``, so redirecting stdout never hides the reason something
refused.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from replicant import __version__
from replicant.config.settings import (
    VENDORS,
    WEB_DEFAULT_PORT,
    Settings,
    load_profiles,
    load_settings,
    parse_anchor,
    save_profile,
    stale_anchor_warning,
)
from replicant.core.models import (
    SCENARIO_CATALOG_PATH,
    Catalog,
    CollectorProfile,
    RunRequest,
    ScenarioRunRequest,
    Technique,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose


def _find_catalog(settings: Settings) -> Path | None:
    """Locate the technique catalog, preferring the copy that ships in the package.

    The packaged catalog comes first so the tool behaves identically wherever it is
    run from. It used to come last, behind two repository-relative guesses, which
    made the CLI cwd-dependent: fine from a checkout, "catalog not found" anywhere
    else, and absent from a wheel entirely.

    An operator who points ``catalog_path`` at their own file still wins, since an
    explicit override is checked before the default.
    """
    configured = settings.catalog_path
    relative = [Path(configured), Path.cwd() / configured]
    overridden = configured != Settings().catalog_path
    # An explicit override wins; otherwise the packaged catalog does. The relative
    # guesses stay at the end either way so a checkout that edits the catalog in
    # place still behaves, but they no longer decide the outcome.
    candidates = (
        (relative + [TECHNIQUE_CATALOG]) if overridden else ([TECHNIQUE_CATALOG] + relative)
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


# Diagnostics go to stderr, data goes to stdout. Without this, `replicant run
# ... > events.log` silently swallows the reason a run refused, and anything
# piping stdout has to filter error text out of its input. Rich needs a distinct
# Console for stderr; the `console` threaded through the handlers stays stdout,
# so command OUTPUT is unaffected.
_err_console = Console(stderr=True)


def _fail(message: str) -> None:
    """Print an operator-facing error to stderr. Callers still return their own exit code."""
    _err_console.print(message)


def _first_error(exc: ValidationError) -> str:
    """The readable half of a pydantic failure.

    A request model rejecting a flag combination is an operator error, not a
    stack trace: the raw ValidationError buries one sentence under a type name, a
    location tuple and a documentation URL.
    """

    message = str(exc.errors()[0]["msg"])
    return message.removeprefix("Value error, ")


def _load_catalog(settings: Settings, console: Console) -> Catalog | None:
    path = _find_catalog(settings)
    if path is None:
        _fail(
            f"[red]catalog not found[/red]: tried the packaged catalog at "
            f"{TECHNIQUE_CATALOG} and {settings.catalog_path!r}"
        )
        return None
    try:
        return load_catalog(path)
    except Exception as exc:  # noqa: BLE001 - surface any validation error to the operator
        _fail(f"[red]catalog failed to load[/red]: {exc}")
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="replicant",
        description="Safe synthetic firewall CEF telemetry for detection engineering.",
    )
    parser.add_argument("--version", action="version", version=f"replicant {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="print the technique catalog")
    sub.add_parser("menu", help="launch the interactive Rich menu")

    web = sub.add_parser("web", help=f"launch the web UI on port {WEB_DEFAULT_PORT}")
    web.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    web.add_argument("--host", default="127.0.0.1", help="bind address (loopback by default)")
    web.add_argument(
        "--port",
        type=int,
        default=WEB_DEFAULT_PORT,
        help=f"listening port (default {WEB_DEFAULT_PORT}); a busy port is an error, "
        "not a reason to pick another",
    )
    web.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        metavar="HOST",
        help="additional Host header value to accept; repeatable. The bind address "
        "and localhost are always accepted",
    )
    web.add_argument(
        "--rotate-token",
        action="store_true",
        help="mint a new persistent token, invalidating the previous URL",
    )
    web.add_argument(
        "--no-auth",
        action="store_true",
        help="serve without a token (loopback only unless acknowledged)",
    )
    web.add_argument(
        "--i-understand-this-is-unauthenticated",
        action="store_true",
        help="required to combine --no-auth with a bind address other machines can reach",
    )
    web.add_argument(
        "--enable-terminal",
        action="store_true",
        help="keep the embedded terminal tab on a non-loopback bind (off by default there)",
    )

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
    run.add_argument(
        "--anchor",
        metavar="WHEN",
        help="event-time anchor: 'now', an epoch, or an ISO-8601 timestamp. "
        "Defaults to a fixed anchor so identical seeds give byte-identical output; "
        "pass 'now' when sending to a SIEM that keys on event time",
    )
    run.add_argument("--to-file", metavar="PATH", help="mirror CEF payloads to a file")
    run.add_argument("--no-send", action="store_true", help="do not send to a collector")
    run.add_argument(
        "--controls",
        choices=["both", "positive", "negative"],
        default="both",
        help="which streams to emit: both (attack + benign foil, the default), "
        "positive (attack alone), or negative (the benign foil alone, for measuring "
        "false positives). Only techniques with emits_foil have a negative stream.",
    )
    run.add_argument(
        "--mark-synthetic",
        action="store_true",
        help="force the ReplicantSynthetic marker (with the run id) onto every line, "
        "including --to-file and loopback where it is off by default",
    )
    run.add_argument(
        "--no-marker",
        action="store_true",
        help="never stamp the ReplicantSynthetic marker. Since it is applied by "
        "default on a non-loopback send (so lab data stays separable on a shared "
        "collector), overriding it on a live send is logged",
    )
    run.add_argument("--rate", type=int, help="events-per-second cap override")
    run.add_argument(
        "--pace",
        choices=["burst", "plan"],
        help="delivery shape. 'plan' reproduces the gaps the plan's own timeline "
        "holds, so a four hour beacon takes four hours; 'burst' sends as fast as "
        "--rate allows and ignores those gaps. Defaults to plan when sending to a "
        "collector, burst for --to-file",
    )
    run.add_argument(
        "--speed",
        type=float,
        default=1.0,
        metavar="N",
        help="compress the plan timeline N times (plan pacing only). Event times "
        "compress with it, so a rule keyed on five minute gaps will not match a "
        "run compressed 60x. Real time to validate a rule, compressed for a smoke test",
    )
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
        "--anchor",
        metavar="WHEN",
        help="event-time anchor: 'now', an epoch, or an ISO-8601 timestamp",
    )
    scen_run.add_argument(
        "--intensity", choices=["low", "medium", "high"], help="override all stages"
    )
    scen_run.add_argument("--to-file", dest="to_file")
    scen_run.add_argument("--no-send", dest="no_send", action="store_true")
    scen_run.add_argument("--rate", type=int)
    scen_run.add_argument(
        "--duration",
        help="how long the whole chain should take, e.g. 2h. Scales stage offsets "
        "and each stage's window, so the order and the per-technique intervals "
        "survive and each stage simply emits fewer events",
    )
    scen_run.add_argument("--pace", choices=["burst", "plan"])
    scen_run.add_argument("--speed", type=float, default=1.0, metavar="N")
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
    table.add_column("Transfers")
    noted: list[Technique] = []
    for index, technique in enumerate(catalog.techniques, start=1):
        transfers = "no" if technique.transferability == "parser-only" else "yes"
        table.add_row(
            str(index),
            technique.id,
            technique.name,
            technique.ndr_uc,
            f"{technique.fortigate.log_type}:{technique.fortigate.subtype}",
            ", ".join(technique.attack.techniques),
            transfers,
        )
        if technique.transferability_note:
            noted.append(technique)
    console.print(table)
    # CLI-first (roadmap item 2): the transferability reasons an engineer needs
    # before spending a validation cycle are printed here, not only in the web UI.
    # Covers parser-only techniques AND transferring ones that carry a disclosed
    # limit (REP-024's integer-second eventtime ceiling), which the earlier
    # parser-only-only footer silently dropped.
    if noted:
        console.print(
            "\n[bold]Transferability notes[/bold] " "(what a green result does and does not prove):"
        )
        for technique in noted:
            kind = (
                "parser-only" if technique.transferability == "parser-only" else "disclosed limit"
            )
            console.print(
                f"  [bold]{technique.id}[/bold] ({kind})  {technique.transferability_note}"
            )
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
    _fail("[red]test failed[/red]: transport error (is the collector reachable?)")
    return 1


def _resolve_collector(
    args: argparse.Namespace, console: Console
) -> tuple[CollectorProfile | None, bool]:
    """Return (collector, ok). ok is False only on an explicit resolution error."""

    if args.profile:
        profiles = load_profiles()
        if args.profile not in profiles:
            _fail(f"[red]no saved profile named[/red] '{args.profile}'")
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
        _fail(f"[red]unknown technique[/red]: {args.id}. Try 'replicant list'.")
        return 1

    collector, ok = _resolve_collector(args, console)
    if not ok:
        return 1

    anchor = settings.anchor_epoch
    if getattr(args, "anchor", None):
        try:
            anchor = parse_anchor(args.anchor)
        except ValueError as exc:
            _fail(f"[red]bad --anchor[/red]: {exc}")
            return 1
    # Warn before emitting, not after: once the events are on the wire the
    # operator is already debugging a rule that did not fire.
    warning = stale_anchor_warning(anchor, sending=not args.no_send and collector is not None)
    if warning:
        console.print(f"[yellow]note[/yellow]: {warning}")

    if args.controls == "negative" and not catalog.by_id(args.id).emits_foil:
        console.print(
            f"[yellow]note[/yellow]: {args.id} has no benign foil (emits_foil is false), "
            "so --controls negative will emit nothing."
        )

    try:
        request = RunRequest(
            technique_id=args.id,
            intensity=args.intensity,
            seed=args.seed if args.seed is not None else settings.default_seed,
            duration=args.duration,
            to_file=args.to_file,
            no_send=args.no_send,
            controls=args.controls,
            rate_override=args.rate,
            collector=collector,
            anchor_epoch=anchor,
            pace=args.pace,
            speed=args.speed,
        )
    except ValidationError as exc:
        _fail(f"[red]run refused[/red]: {_first_error(exc)}")
        return 1

    if getattr(args, "mark_synthetic", False):
        # Per-run override of the standing benign_marker switch. model_copy so the
        # loaded settings object is not mutated for anything else in the process.
        settings = settings.model_copy(update={"benign_marker": True})
    if getattr(args, "no_marker", False):
        # Forces the marker off even where the destination-conditional default
        # would apply it; _resolve_marker gives this precedence over benign_marker.
        settings = settings.model_copy(update={"no_marker": True})

    orchestrator = Orchestrator(catalog, settings)
    # Said before the run, not after it. Plan pacing turns a three second run into
    # a four hour one, and an operator who finds that out by watching a prompt not
    # come back has been surprised by their own tool.
    try:
        preview = orchestrator.preview_pacing(
            request, sending=not args.no_send and collector is not None
        )
    except (RuntimeError, NotImplementedError, OSError) as exc:
        _fail(f"[red]run refused[/red]: {exc}")
        return 1
    console.print(preview.describe())

    try:
        result = orchestrator.run(request)
    except (RuntimeError, NotImplementedError, OSError) as exc:
        _fail(f"[red]run refused[/red]: {exc}")
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
        _fail(f"[red]unknown scenario[/red]: {args.id}. Try 'replicant scenario list'.")
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
    anchor = settings.anchor_epoch
    if getattr(args, "anchor", None):
        try:
            anchor = parse_anchor(args.anchor)
        except ValueError as exc:
            _fail(f"[red]bad --anchor[/red]: {exc}")
            return 1
    # Warn before emitting, not after: once the events are on the wire the
    # operator is already debugging a rule that did not fire.
    warning = stale_anchor_warning(anchor, sending=not args.no_send and collector is not None)
    if warning:
        console.print(f"[yellow]note[/yellow]: {warning}")

    try:
        request = ScenarioRunRequest(
            scenario_id=args.id,
            seed=args.seed if args.seed is not None else settings.default_seed,
            intensity_override=args.intensity,
            duration=args.duration,
            to_file=args.to_file,
            no_send=args.no_send,
            rate_override=args.rate,
            collector=collector,
            anchor_epoch=anchor,
            pace=args.pace,
            speed=args.speed,
        )
    except ValidationError as exc:
        _fail(f"[red]run refused[/red]: {_first_error(exc)}")
        return 1

    orchestrator = Orchestrator(catalog, settings)
    try:
        preview = orchestrator.preview_scenario_pacing(
            request, scenarios, sending=not args.no_send and collector is not None
        )
    except (RuntimeError, NotImplementedError, OSError) as exc:
        _fail(f"[red]run refused[/red]: {exc}")
        return 1
    console.print(preview.describe())

    try:
        result = orchestrator.run_scenario(request, scenarios)
    except (RuntimeError, NotImplementedError, OSError) as exc:
        _fail(f"[red]run refused[/red]: {exc}")
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
            _fail(
                "[red]web dependencies missing[/red]. Install them with: " "pip install -e '.[web]'"
            )
            return 1
        try:
            serve(
                catalog,
                settings,
                host=args.host,
                port=args.port,
                open_browser=not args.no_browser,
                allowed_hosts=args.allowed_host,
                no_auth=args.no_auth,
                acknowledged_unauthenticated=args.i_understand_this_is_unauthenticated,
                rotate_token=args.rotate_token,
                enable_terminal=args.enable_terminal,
            )
        except (OSError, ValueError) as exc:
            # A refused bind and a refused exposure are both operator errors, not
            # crashes. Report them on stderr and exit non-zero.
            _fail(f"[red]web server did not start[/red]: {exc}")
            return 1
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
